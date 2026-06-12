import Foundation

/// Pure-Swift byte-parser for the macOS **FSEvents** store (`/.fseventsd/`).
///
/// Each file under `/.fseventsd/` is a **gzip-compressed** stream of one or more
/// **DLS pages**. A page is a 12-byte header - the magic `1SLD` (DLS v1) or
/// `2SLD` (DLS v2), four reserved bytes, and the little-endian page length
/// (including the header) - followed by variable-length records until the page
/// length is consumed. Each record is a NUL-terminated path, an 8-byte
/// little-endian **event ID**, and a 4-byte **flags** mask; DLS v2 appends an
/// 8-byte **node ID** (inode).
///
/// No vendored tool, no I/O beyond the bundled `GzipDecoder` (Apple's
/// Compression framework). The core entry point takes an already-decompressed
/// page stream so it is unit-testable with hand-built DLS bytes; a convenience
/// overload inflates a gzip member first.
public nonisolated enum FSEventsParser {

    private static let magicDLS1: [UInt8] = [0x31, 0x53, 0x4C, 0x44]   // "1SLD"
    private static let magicDLS2: [UInt8] = [0x32, 0x53, 0x4C, 0x44]   // "2SLD"

    /// Inflate a gzip-compressed `/.fseventsd/` log and parse it. Returns `[]`
    /// if the bytes aren't gzip (a name collision) or inflate fails.
    public static func parse(gzipped data: Data, sourceFile: String) -> [FSEventRecord] {
        guard let inflated = try? GzipDecoder.decompress(data) else { return [] }
        return parse(decompressed: inflated, sourceFile: sourceFile)
    }

    /// Parse an already-decompressed DLS page stream (one fseventsd log can hold
    /// several pages, each possibly a different DLS version). Malformed pages
    /// stop the parse cleanly rather than throwing.
    public static func parse(decompressed data: Data, sourceFile: String) -> [FSEventRecord] {
        let bytes = [UInt8](data)
        var records: [FSEventRecord] = []
        var offset = 0

        while offset + 12 <= bytes.count {
            let magic = Array(bytes[offset..<offset + 4])
            let version: Int
            if magic == magicDLS1 { version = 1 }
            else if magic == magicDLS2 { version = 2 }
            else { break }   // not a page boundary - stop

            // Page length (incl. the 12-byte header) at offset+8, LE uint32.
            let pageLen = Int(readU32(bytes, offset + 8))
            guard pageLen >= 12 else { break }
            let pageEnd = min(offset + pageLen, bytes.count)

            var p = offset + 12
            while p < pageEnd {
                // Path: NUL-terminated UTF-8.
                guard let nul = indexOfZero(bytes, from: p, end: pageEnd) else { break }
                let path = String(decoding: bytes[p..<nul], as: UTF8.self)
                var q = nul + 1

                // eventID (8) + flags (4) [+ nodeID (8) for v2].
                let trailer = version == 2 ? 20 : 12
                guard q + trailer <= pageEnd else { break }
                let eventID = readU64(bytes, q); q += 8
                let flags = readU32(bytes, q); q += 4
                var nodeID: UInt64?
                if version == 2 { nodeID = readU64(bytes, q); q += 8 }

                // Skip the empty terminator record some pages carry.
                if !path.isEmpty || flags != 0 {
                    records.append(FSEventRecord(path: path, eventID: eventID, flags: flags,
                                                 nodeID: nodeID, sourceFile: sourceFile))
                }
                p = q
            }
            offset = pageEnd
        }
        return records
    }

    // MARK: - Little-endian readers (bounds are guaranteed by the callers)

    private static func readU32(_ b: [UInt8], _ i: Int) -> UInt32 {
        UInt32(b[i]) | (UInt32(b[i + 1]) << 8) | (UInt32(b[i + 2]) << 16) | (UInt32(b[i + 3]) << 24)
    }

    private static func readU64(_ b: [UInt8], _ i: Int) -> UInt64 {
        var v: UInt64 = 0
        for k in 0..<8 { v |= UInt64(b[i + k]) << (8 * k) }
        return v
    }

    private static func indexOfZero(_ b: [UInt8], from start: Int, end: Int) -> Int? {
        var i = start
        while i < end { if b[i] == 0 { return i }; i += 1 }
        return nil
    }
}
