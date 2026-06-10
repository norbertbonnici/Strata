import Foundation
import Compression

/// Decompresses gzip (`.gz`) data - used to read rotated logs (`auth.log.2.gz`,
/// `syslog.1.gz`, …) that would otherwise be skipped. Apple's `Compression`
/// framework exposes raw DEFLATE (`COMPRESSION_ZLIB`), so we strip the gzip
/// wrapper (RFC 1952 header + trailer) ourselves and stream-inflate the body.
/// Pure Foundation/Compression - no third-party dependency.
public nonisolated enum GzipDecoder {

    public enum GzipError: Error { case notGzip, truncated, inflateFailed }

    /// Inflate a complete gzip member. Returns the decompressed bytes.
    public static func decompress(_ data: Data) throws -> Data {
        let bytes = [UInt8](data)
        guard bytes.count > 18, bytes[0] == 0x1f, bytes[1] == 0x8b, bytes[2] == 0x08 else {
            throw GzipError.notGzip
        }
        let flags = bytes[3]
        var offset = 10   // fixed header

        // FEXTRA: 2-byte length + payload.
        if flags & 0x04 != 0 {
            guard offset + 2 <= bytes.count else { throw GzipError.truncated }
            let xlen = Int(bytes[offset]) | (Int(bytes[offset + 1]) << 8)
            offset += 2 + xlen
        }
        // FNAME / FCOMMENT: NUL-terminated strings.
        if flags & 0x08 != 0 { offset = try skipCString(bytes, from: offset) }
        if flags & 0x10 != 0 { offset = try skipCString(bytes, from: offset) }
        // FHCRC: 2-byte header CRC.
        if flags & 0x02 != 0 { offset += 2 }

        // The trailer is CRC32 (4) + ISIZE (4); ISIZE hints the output size.
        guard bytes.count >= offset + 8 else { throw GzipError.truncated }
        let isize = bytes[(bytes.count - 4)...].enumerated()
            .reduce(0) { $0 | (Int($1.element) << (8 * $1.offset)) }
        let deflateBody = bytes[offset..<(bytes.count - 8)]

        return try inflate(Array(deflateBody), hint: max(isize, deflateBody.count * 4))
    }

    private static func skipCString(_ bytes: [UInt8], from start: Int) throws -> Int {
        var i = start
        while i < bytes.count, bytes[i] != 0 { i += 1 }
        guard i < bytes.count else { throw GzipError.truncated }
        return i + 1   // step past the NUL
    }

    /// Stream-inflate raw DEFLATE bytes; grows the output buffer as needed so an
    /// unknown (large) decompressed size is handled without a giant up-front
    /// allocation.
    private static func inflate(_ deflate: [UInt8], hint: Int) throws -> Data {
        var stream = compression_stream(dst_ptr: UnsafeMutablePointer<UInt8>(bitPattern: 0x1)!,
                                        dst_size: 0,
                                        src_ptr: UnsafeMutablePointer<UInt8>(bitPattern: 0x1)!,
                                        src_size: 0,
                                        state: nil)
        guard compression_stream_init(&stream, COMPRESSION_STREAM_DECODE, COMPRESSION_ZLIB)
                == COMPRESSION_STATUS_OK else {
            throw GzipError.inflateFailed
        }
        defer { compression_stream_destroy(&stream) }

        var output = Data()
        let chunkSize = max(64 << 10, min(hint, 8 << 20))
        var dst = [UInt8](repeating: 0, count: chunkSize)

        return try deflate.withUnsafeBufferPointer { src -> Data in
            stream.src_ptr = src.baseAddress!
            stream.src_size = src.count
            while true {
                let status = dst.withUnsafeMutableBufferPointer { dstBuf -> compression_status in
                    stream.dst_ptr = dstBuf.baseAddress!
                    stream.dst_size = dstBuf.count
                    let s = compression_stream_process(&stream, Int32(COMPRESSION_STREAM_FINALIZE.rawValue))
                    output.append(dstBuf.baseAddress!, count: dstBuf.count - stream.dst_size)
                    return s
                }
                switch status {
                case COMPRESSION_STATUS_END: return output
                case COMPRESSION_STATUS_OK:  continue   // dst full, loop for more
                default: throw GzipError.inflateFailed
                }
            }
        }
    }
}
