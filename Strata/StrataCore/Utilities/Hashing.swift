import Foundation
import CryptoKit

/// Streaming file hasher. Computes MD5 + SHA-256 over a file in one pass without
/// ever holding the whole file in memory - disk images run to tens of GB, so a
/// `Data(contentsOf:)` is not an option.
///
/// `nonisolated` and value-only so it runs inside a `Task.detached`, off the
/// main actor. Honours cooperative cancellation between chunks.
///
/// MD5 is computed via `Insecure.MD5` deliberately: it is required to match the
/// MD5 acquisition hashes that imaging tools (FTK Imager, EnCase, dd+md5sum)
/// emit and that E01 containers embed. This is integrity matching, not a
/// security primitive - do not "upgrade" it away.
public nonisolated enum FileHasher {
    public struct Result: Sendable, Equatable {
        public let md5: String      // lowercase hex
        public let sha256: String   // lowercase hex

        public init(md5: String, sha256: String) {
            self.md5 = md5
            self.sha256 = sha256
        }
    }

    public enum HashError: Error, Sendable {
        case cannotOpen(path: String)
    }

    /// Hash the file at `url`, streaming `chunkSize` bytes at a time. `progress`
    /// receives `(bytesRead, totalBytes)` after each chunk; `totalBytes` is 0 if
    /// the size could not be determined. Throws `CancellationError` if the
    /// surrounding task is cancelled.
    public static func hash(
        fileAt url: URL,
        chunkSize: Int = 4 << 20,                       // 4 MiB
        progress: ((Int64, Int64) -> Void)? = nil
    ) throws -> Result {
        let attrs = try? FileManager.default.attributesOfItem(atPath: url.path)
        let total = (attrs?[.size] as? Int64) ?? 0

        guard let handle = try? FileHandle(forReadingFrom: url) else {
            throw HashError.cannotOpen(path: url.path)
        }
        defer { try? handle.close() }

        var md5 = Insecure.MD5()
        var sha = SHA256()
        var read: Int64 = 0
        var lastPercent = -1
        var lastReportedBytes: Int64 = 0

        while true {
            try Task.checkCancellation()
            // Each `read(upToCount:)` returns an autoreleased NSData-backed
            // buffer. This loop runs on a background task with no run loop, so
            // without an explicit pool those buffers accumulate for the whole
            // (multi-GB) image and exhaust memory. Drain per chunk.
            let eof = try autoreleasepool { () throws -> Bool in
                guard let chunk = try handle.read(upToCount: chunkSize),
                      !chunk.isEmpty else { return true }
                md5.update(data: chunk)
                sha.update(data: chunk)
                read += Int64(chunk.count)
                // Throttle progress: at most once per 1% (known size) or per
                // 32 MiB (unknown size). A per-chunk callback floods the caller
                // (which hops to the main actor each time).
                if let progress {
                    if total > 0 {
                        let percent = Int((read * 100) / total)
                        if percent != lastPercent { lastPercent = percent; progress(read, total) }
                    } else if read - lastReportedBytes >= (32 << 20) {
                        lastReportedBytes = read; progress(read, total)
                    }
                }
                return false
            }
            if eof { break }
        }

        progress?(read, total)   // final 100% tick
        return Result(md5: hex(md5.finalize()), sha256: hex(sha.finalize()))
    }

    /// Lowercase hex string for any CryptoKit digest.
    private static func hex<D: Sequence>(_ digest: D) -> String where D.Element == UInt8 {
        digest.map { String(format: "%02x", $0) }.joined()
    }
}
