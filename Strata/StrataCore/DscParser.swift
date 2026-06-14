import Foundation

/// A parsed macOS `dsc` shared-cache strings file
/// (`/var/db/uuidtext/dsc/<uuid>`) — the format-string catalog the unified log
/// references for **shared-cache** format strings (the dyld shared cache, where
/// most system-library `os_log` strings live). One `dsc` aggregates the strings
/// of many images via a range table + a UUID table.
///
/// Layout (little-endian), confirmed against a real macOS-12 `dsc`:
///   header (16 bytes):
///     0x00 u32  signature = 0x64736368 ("hcsd", little-endian)
///     0x04 u16  major version   (2 on Monterey+)
///     0x06 u16  minor version
///     0x08 u32  number of ranges
///     0x0C u32  number of UUIDs
///   range table (v2: 24 bytes each):
///     0x00 u64  range_offset    (the offset space format-string locations live in)
///     0x08 u32  data_offset     (where this range's string bytes live in the file)
///     0x0C u32  range_size
///     0x10 u64  uuid_index      (into the UUID table)
///   UUID table (v2: 32 bytes each):
///     0x00 u64  text_offset
///     0x08 u32  text_size
///     0x0C u16  uuid (16 bytes, big-endian)
///     0x1C u32  path_offset     (NUL-terminated image path in the file)
public nonisolated struct DscFile: Sendable {
    public let uuid: String
    public let majorVersion: UInt16

    struct Range: Sendable { let rangeOffset: UInt64; let dataOffset: UInt32; let rangeSize: UInt32; let uuidIndex: Int }
    struct UUIDEntry: Sendable { let pathOffset: UInt32 }

    let ranges: [Range]              // sorted ascending by rangeOffset
    let uuidEntries: [UUIDEntry]
    let bytes: [UInt8]               // whole file (offsets index into it)

    /// Resolve a shared-cache format string + its image path for a
    /// `format_string_location` offset: binary-search the range covering the
    /// offset, read the string at `data_offset + (offset - range_offset)`, and
    /// read the image path via the range's UUID entry.
    public func resolve(offset: UInt64) -> (formatString: String, imagePath: String)? {
        guard let r = range(covering: offset) else { return nil }
        let pos = Int(r.dataOffset) + Int(offset - r.rangeOffset)
        guard let fmt = UUIDTextFile.cString(bytes, at: pos) else { return nil }
        var path = ""
        if r.uuidIndex >= 0, r.uuidIndex < uuidEntries.count {
            path = UUIDTextFile.cString(bytes, at: Int(uuidEntries[r.uuidIndex].pathOffset)) ?? ""
        }
        return (fmt, path)
    }

    /// Binary search for the range whose `[rangeOffset, rangeOffset+rangeSize)`
    /// contains `offset`.
    func range(covering offset: UInt64) -> Range? {
        var lo = 0, hi = ranges.count - 1
        while lo <= hi {
            let mid = (lo + hi) / 2
            let r = ranges[mid]
            if offset < r.rangeOffset {
                hi = mid - 1
            } else if offset >= r.rangeOffset &+ UInt64(r.rangeSize) {
                lo = mid + 1
            } else {
                return r
            }
        }
        return nil
    }
}

/// Parser for `dsc` shared-cache strings files (version 2 / Monterey+).
public enum DscParser {
    public static let signature: UInt32 = 0x6473_6368   // "hcsd" little-endian

    public static func parse(_ data: Data, uuid: String) -> DscFile? {
        let b = [UInt8](data)
        let n = b.count
        guard n >= 16 else { return nil }
        func u16(_ o: Int) -> UInt16 { UInt16(b[o]) | (UInt16(b[o + 1]) << 8) }
        func u32(_ o: Int) -> UInt32 {
            UInt32(b[o]) | (UInt32(b[o + 1]) << 8) | (UInt32(b[o + 2]) << 16) | (UInt32(b[o + 3]) << 24)
        }
        func u64(_ o: Int) -> UInt64 { var v: UInt64 = 0; for k in 0..<8 { v |= UInt64(b[o + k]) << (8 * k) }; return v }
        guard u32(0) == signature else { return nil }
        let major = u16(4)
        let numberRanges = Int(u32(8))
        let numberUUIDs = Int(u32(12))
        // Only the v2 (Monterey+) layout is supported; the test image is v2.
        guard major >= 2 else { return nil }

        let rangeStride = 24, uuidStride = 32
        let rangeBase = 16
        let uuidBase = rangeBase + numberRanges * rangeStride
        guard numberRanges >= 0, numberUUIDs >= 0,
              uuidBase + numberUUIDs * uuidStride <= n else { return nil }

        var ranges: [DscFile.Range] = []
        ranges.reserveCapacity(numberRanges)
        for i in 0..<numberRanges {
            let o = rangeBase + i * rangeStride
            ranges.append(.init(rangeOffset: u64(o), dataOffset: u32(o + 8),
                                rangeSize: u32(o + 12), uuidIndex: Int(u64(o + 16))))
        }
        var uuidEntries: [DscFile.UUIDEntry] = []
        uuidEntries.reserveCapacity(numberUUIDs)
        for i in 0..<numberUUIDs {
            let o = uuidBase + i * uuidStride
            uuidEntries.append(.init(pathOffset: u32(o + 0x1C)))
        }
        // Resolution binary-searches by rangeOffset, so keep ranges sorted.
        ranges.sort { $0.rangeOffset < $1.rangeOffset }
        return DscFile(uuid: uuid, majorVersion: major, ranges: ranges,
                       uuidEntries: uuidEntries, bytes: b)
    }
}
