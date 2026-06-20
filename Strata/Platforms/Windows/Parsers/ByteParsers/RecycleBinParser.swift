import Foundation

/// Pure byte-parser of a Windows `$I` Recycle Bin index file
/// (`\$Recycle.Bin\<SID>\$I<id>`). Returns nil on a structurally malformed
/// record; otherwise reconstructs the deleted file's original path, size, and
/// deletion time.
///
/// `$I` format (all little-endian):
///   - off 0  : 8-byte header version (1 = pre-Win10, 2 = Win10+)
///   - off 8  : 8-byte original file size (uint64)
///   - off 16 : 8-byte deletion FILETIME (uint64)
///   - off 24 : original path —
///       * version 1: fixed 520 bytes = 260 UTF-16LE code units, NUL-terminated
///       * version 2: 4-byte char-count (uint32) at off 24, then count*2 bytes
///         UTF-16LE at off 28 (count INCLUDES the trailing NUL per MS format)
///
/// LE primitives + UTF-16 decode mirror `UsnJournalParser` (bounds-checked,
/// Optional). Pure + cross-platform.
public nonisolated enum RecycleBinParser {
    /// Sanity ceiling for the v2 char-count — a path far longer than `MAX_PATH`
    /// (260) is corruption, not a real record. Generous (32768) to allow long
    /// paths while rejecting absurd lengths.
    private static let maxV2CharCount: UInt32 = 32_768
    /// Fixed UTF-16LE path region for a v1 record: 260 code units.
    private static let v1PathBytes = 520

    /// Parse one `$I` index file. `recycledName`/`sourceFile`/`sid` are supplied
    /// by the caller (filesystem context the bytes don't carry).
    public static func parse(data: Data, recycledName: String,
                             sourceFile: String, sid: String?) -> RecycleBinEntry? {
        let b = [UInt8](data)
        // Need header + size + filetime (24 bytes) to be a valid record.
        guard b.count >= 24 else { return nil }

        guard let version = u64(b, 0), version == 1 || version == 2 else { return nil }
        guard let rawSize = u64(b, 8) else { return nil }
        let sizeBytes = rawSize > UInt64(Int64.max) ? Int64.max : Int64(rawSize)

        let ft = u64(b, 16) ?? 0
        let deletedAt = FileTime.date(ft)

        let originalPath: String
        switch version {
        case 1:
            // Decode up to first NUL within whatever path bytes are present
            // (tolerate a truncated v1 shorter than the fixed 520 region).
            let start = 24
            let end = min(start + v1PathBytes, b.count)
            originalPath = start < end ? utf16(b, start, end) : ""
        default: // version == 2
            guard let count = u32(b, 24), count <= maxV2CharCount else { return nil }
            let byteLen = Int(count) * 2
            let start = 28
            let end = start + byteLen
            guard end <= b.count else { return nil }
            originalPath = start < end ? utf16(b, start, end) : ""
        }

        return RecycleBinEntry(
            originalPath: originalPath,
            deletedAt: deletedAt,
            sizeBytes: sizeBytes,
            recycledName: recycledName,
            sid: sid,
            sourceFile: sourceFile)
    }

    // MARK: - Primitives (little-endian, bounds-checked)

    private static func u32(_ b: [UInt8], _ o: Int) -> UInt32? {
        guard o >= 0, o + 4 <= b.count else { return nil }
        return (0..<4).reduce(UInt32(0)) { $0 | (UInt32(b[o + $1]) << (8 * $1)) }
    }
    private static func u64(_ b: [UInt8], _ o: Int) -> UInt64? {
        guard o >= 0, o + 8 <= b.count else { return nil }
        return (0..<8).reduce(UInt64(0)) { $0 | (UInt64(b[o + $1]) << (8 * UInt64($1))) }
    }
    /// Decode UTF-16LE units in `[start, end)`, stopping at the first NUL unit
    /// (NUL-terminated paths) and trimming a single trailing NUL.
    private static func utf16(_ b: [UInt8], _ start: Int, _ end: Int) -> String {
        guard start >= 0, end <= b.count, start < end else { return "" }
        var units: [UInt16] = []
        var i = start
        while i + 1 < end {
            let unit = UInt16(b[i]) | (UInt16(b[i + 1]) << 8)
            if unit == 0 { break }   // NUL terminator: rest of the fixed region is padding
            units.append(unit)
            i += 2
        }
        return String(decoding: units, as: UTF16.self)
    }
}
