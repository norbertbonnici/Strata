import Foundation
import Compression

/// Decoder for Apple's **LZ4 block-stream** framing (the `bv4x` blocks), used to
/// compress the chunkset payloads inside a `.tracev3` unified-log file (and a
/// handful of other Apple formats). The stream is a sequence of blocks, each
/// introduced by a 4-byte magic:
///
///  - `bv41` — a compressed block: `magic(4) | decoded_size(u32 LE) |
///    encoded_size(u32 LE) | <LZ4-raw bytes>`. The body is raw LZ4 (no frame),
///    inflated via the Compression framework's `COMPRESSION_LZ4_RAW`.
///  - `bv4-` — a stored (uncompressed) block: `magic(4) | size(u32 LE) | <bytes>`.
///  - `bv4$` — the 4-byte end-of-stream marker.
///
/// Concatenating the decoded blocks yields the original payload. Pure
/// Foundation/Compression — no third-party dependency (mirrors `GzipDecoder`).
public nonisolated enum AppleLZ4 {

    private static let magicCompressed: [UInt8] = [0x62, 0x76, 0x34, 0x31]   // "bv41"
    private static let magicUncompressed: [UInt8] = [0x62, 0x76, 0x34, 0x2D] // "bv4-"
    private static let magicEnd: [UInt8] = [0x62, 0x76, 0x34, 0x24]          // "bv4$"

    /// Decode a complete `bv4x` block stream. Returns the concatenated payload,
    /// or nil if a block is malformed / a raw-LZ4 inflate fails.
    public static func decompress(_ data: Data) -> Data? {
        let bytes = [UInt8](data)
        var out = Data()
        var i = 0
        while i + 4 <= bytes.count {
            let magic = Array(bytes[i..<i + 4])
            if magic == magicEnd { return out }
            if magic == magicCompressed {
                guard i + 12 <= bytes.count else { return nil }
                let decodedSize = Int(readU32(bytes, i + 4))
                let encodedSize = Int(readU32(bytes, i + 8))
                let start = i + 12, end = start + encodedSize
                // Cap the per-block decoded size: `decoded_size` is an attacker
                // field, so a 12-byte block could otherwise force a ~4 GB
                // zero-filled allocation (decompression bomb). 256 MB/block is far
                // above any real unified-log chunkset.
                guard end <= bytes.count, decodedSize >= 0, decodedSize <= 256 << 20 else { return nil }
                guard let block = lz4RawDecode(Array(bytes[start..<end]), decodedSize: decodedSize)
                else { return nil }
                out.append(block)
                i = end
            } else if magic == magicUncompressed {
                guard i + 8 <= bytes.count else { return nil }
                let size = Int(readU32(bytes, i + 4))
                let start = i + 8, end = start + size
                guard end <= bytes.count else { return nil }
                out.append(contentsOf: bytes[start..<end])
                i = end
            } else {
                // Not a recognised block boundary - stop cleanly.
                break
            }
        }
        return out
    }

    /// Inflate a raw-LZ4 block (no frame header) of known decoded size via the
    /// Compression framework.
    private static func lz4RawDecode(_ src: [UInt8], decodedSize: Int) -> Data? {
        guard decodedSize > 0 else { return Data() }
        var dst = [UInt8](repeating: 0, count: decodedSize)
        let written = src.withUnsafeBufferPointer { srcBuf in
            dst.withUnsafeMutableBufferPointer { dstBuf in
                compression_decode_buffer(dstBuf.baseAddress!, decodedSize,
                                          srcBuf.baseAddress!, src.count,
                                          nil, COMPRESSION_LZ4_RAW)
            }
        }
        guard written == decodedSize else { return nil }
        return Data(dst)
    }

    private static func readU32(_ b: [UInt8], _ i: Int) -> UInt32 {
        UInt32(b[i]) | (UInt32(b[i + 1]) << 8) | (UInt32(b[i + 2]) << 16) | (UInt32(b[i + 3]) << 24)
    }
}
