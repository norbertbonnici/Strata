import Foundation

/// A parsed macOS `.uuidtext` file (`/var/db/uuidtext/XX/YYYY…`) — the per-image
/// format-string catalog the unified log references for **main-executable** and
/// **absolute/uuid-relative** format strings. Each file is keyed by a UUID and
/// holds the sender image's format strings plus its on-disk path (which gives
/// the emitting **process/library name**).
///
/// Layout (little-endian), confirmed against a real macOS-12 `.uuidtext`:
///   header (16 bytes):
///     0x00 u32  signature = 0x66778899
///     0x04 u32  major version
///     0x08 u32  minor version
///     0x0C u32  number of entries
///   entry table: `number_of_entries` × (range_start_offset u32, entry_size u32)
///   footer: each entry's `entry_size`-byte format-string block, concatenated in
///     entry order, then the NUL-terminated image path at the very end.
public nonisolated struct UUIDTextFile: Sendable, Hashable {
    public let uuid: String
    /// The sender image's on-disk path (e.g.
    /// `/System/Library/…/Support/syncdefaultsd`).
    public let imagePath: String
    public let majorVersion: UInt32
    public let minorVersion: UInt32

    public struct Entry: Sendable, Hashable {
        public let rangeStartOffset: UInt32
        public let size: UInt32
        /// Cumulative offset of this entry's block within the footer string data.
        let cumulative: Int
    }
    let entries: [Entry]
    /// The footer string data (format-string blocks + trailing image path).
    let footer: [UInt8]

    /// The emitting process/library leaf name.
    public var processName: String {
        (imagePath as NSString).lastPathComponent
    }

    /// Resolve the format string at a tracepoint's `format_string_location`:
    /// find the entry whose range covers the offset, then read the
    /// NUL-terminated string from that entry's footer block.
    public func formatString(at offset: UInt32) -> String? {
        for e in entries where offset >= e.rangeStartOffset && offset < e.rangeStartOffset &+ e.size {
            let pos = e.cumulative + Int(offset - e.rangeStartOffset)
            return UUIDTextFile.cString(footer, at: pos)
        }
        return nil
    }

    /// Read a NUL-terminated UTF-8 string from `b` at `pos`.
    static func cString(_ b: [UInt8], at pos: Int) -> String? {
        guard pos >= 0, pos < b.count else { return nil }
        var end = pos
        while end < b.count, b[end] != 0 { end += 1 }
        return String(decoding: b[pos..<end], as: UTF8.self)
    }
}

/// Parser for `.uuidtext` files.
public enum UUIDTextParser {
    public static let signature: UInt32 = 0x6677_8899

    /// Parse a `.uuidtext` file. `uuid` is the file's UUID (from its path); it is
    /// not stored inside the file.
    public static func parse(_ data: Data, uuid: String) -> UUIDTextFile? {
        let b = [UInt8](data)
        guard b.count >= 16 else { return nil }
        func u32(_ o: Int) -> UInt32 {
            UInt32(b[o]) | (UInt32(b[o + 1]) << 8) | (UInt32(b[o + 2]) << 16) | (UInt32(b[o + 3]) << 24)
        }
        guard u32(0) == signature else { return nil }
        let major = u32(4), minor = u32(8)
        let count = Int(u32(12))
        let tableEnd = 16 + count * 8
        guard count >= 0, tableEnd <= b.count else { return nil }

        var entries: [UUIDTextFile.Entry] = []
        var cumulative = 0
        for i in 0..<count {
            let o = 16 + i * 8
            let start = u32(o)
            let size = u32(o + 4)
            entries.append(.init(rangeStartOffset: start, size: size, cumulative: cumulative))
            cumulative += Int(size)
        }
        let footer = Array(b[tableEnd...])
        // Image path is the NUL-terminated string after all format-string blocks.
        let imagePath = UUIDTextFile.cString(footer, at: cumulative) ?? ""
        return UUIDTextFile(uuid: uuid, imagePath: imagePath, majorVersion: major,
                            minorVersion: minor, entries: entries, footer: footer)
    }
}
