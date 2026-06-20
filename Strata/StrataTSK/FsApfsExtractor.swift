import Foundation

#if os(macOS)

/// Extracts a single file's bytes out of an **APFS** volume in a raw image by
/// shelling out to our vendored `fsapfscat` tool (libfsapfs) and redirecting its
/// stdout to a scratch file. The macOS-image equivalent of `TSKFileExtractor`
/// (`icat`): The Sleuth Kit crashes on real APFS, so the APFS ingest path reads
/// content via libfsapfs instead.
public actor FsApfsExtractor {
    private let environment: TSKEnvironment
    /// The raw image (the source itself for a raw/dd image, or the `ewfexport`
    /// scratch conversion of an E01).
    private let rawURL: URL

    public init(environment: TSKEnvironment, rawURL: URL) {
        self.environment = environment
        self.rawURL = rawURL
    }

    /// Extract `volumePath` (a volume-relative path, e.g. `/Users/jane/…`) from
    /// the APFS volume at the given 0-based `volumeIndex`, whose container starts
    /// at `offsetBytes` in the raw image. `password`/`recovery` unlock FileVault.
    public func extract(volumePath: String, volumeIndex: Int64, offsetBytes: Int64,
                        to destination: URL,
                        password: String? = nil, recovery: String? = nil) async throws {
        let tool = try environment.url(for: "fsapfscat")
        try? FileManager.default.removeItem(at: destination)
        FileManager.default.createFile(atPath: destination.path, contents: nil)

        var args = ["-o", "\(offsetBytes)", "-f", "\(volumeIndex)"]
        if let password { args.append(contentsOf: ["-p", password]) }
        if let recovery { args.append(contentsOf: ["-r", recovery]) }
        args.append(rawURL.path)
        args.append(volumePath)

        let process = Process()
        process.executableURL = tool
        process.arguments = args

        let outHandle = try FileHandle(forWritingTo: destination)
        defer { try? outHandle.close() }   // close on every path, incl. a launch throw
        let stderrPipe = Pipe()
        process.standardOutput = outHandle
        process.standardError = stderrPipe

        // Drain stderr continuously to avoid the classic pipe-buffer deadlock.
        let collector = PipeTextCollector()
        stderrPipe.fileHandleForReading.readabilityHandler = { handle in
            let chunk = handle.availableData
            guard !chunk.isEmpty else { return }
            collector.append(String(decoding: chunk, as: UTF8.self))
        }

        try await process.runAndWait()
        stderrPipe.fileHandleForReading.readabilityHandler = nil

        // rc 2 == "no such file" (a candidate path that doesn't exist on this
        // volume) - treat as an empty extraction, not a hard failure.
        if process.terminationReason == .exit, process.terminationStatus == 2 { return }
        guard process.terminationReason == .exit, process.terminationStatus == 0 else {
            throw TSKError.ingestionFailed(exitCode: process.terminationStatus,
                                           stderr: "fsapfscat: \(collector.text)")
        }
    }
}

#endif
