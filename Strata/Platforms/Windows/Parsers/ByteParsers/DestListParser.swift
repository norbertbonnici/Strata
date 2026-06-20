import Foundation

/// One record of the `DestList` stream inside an AutomaticDestinations JumpList -
/// the MRU index that gives each numbered LNK stream its forensic metadata.
public nonisolated struct DestListRecord: Sendable, Hashable {
    /// Entry number; also the LNK stream's (lowercase, non-zero-padded) hex name.
    public let entryID: Int
    /// Last time this destination was opened (FILETIME), nil if unset/implausible.
    public let lastAccessed: Date?
    /// Interaction / access count (DestList v3+), nil on Win7 v1.
    public let accessCount: Int?
    /// NetBIOS hostname that recorded the access.
    public let hostname: String?
    /// Pinned (pin status >= 0) vs a normal recent entry (-1).
    public let pinned: Bool
    /// Target path as the DestList recorded it (the embedded LNK is authoritative,
    /// but this is a useful fallback / cross-check).
    public let path: String?
}

/// Decodes a JumpList `DestList` stream (raw bytes from `DestList/StreamData.bin`).
/// Pure + cross-platform; version-aware (Win7 v1, Win8/10 v3, Win10 1709+/Win11
/// v4). Records are variable length (a UTF-16 path tail), so parsed strictly
/// sequentially with bounds checks; anything malformed stops the parse cleanly.
///
/// Validated against synthetic fixtures only - the per-version record tail is the
/// main accuracy risk, so confirm against a real `.automaticDestinations-ms`.
public nonisolated enum DestListParser {
    private static let headerSize = 0x20
    private static let defensiveEntryCap = 16_384

    public static func parse(bytes b: [UInt8]) -> [DestListRecord] {
        guard b.count >= headerSize, let version = u32(b, 0), let numEntries = u32(b, 4) else { return [] }
        guard version == 1 || version == 3 || version == 4 else { return [] }

        // Fixed block ends just before the StringSize u16. v4 carries 4 extra
        // bytes in the fixed portion; the early fields (host/entry/time/pin) keep
        // the same offsets across versions.
        let fixedSize = version >= 4 ? 0x74 : 0x70
        let trailing = version >= 3 ? 4 : 0   // u32 after the path on v3/v4

        var out: [DestListRecord] = []
        var off = headerSize
        let limit = min(Int(numEntries), defensiveEntryCap)

        while out.count < limit, off + fixedSize + 2 <= b.count {
            let hostname = ascii(b, off + 0x48, 16)
            guard let entryID = u32(b, off + 0x58) else { break }
            let lastAccessed = u64(b, off + 0x60).flatMap(date(fromFiletime:))
            let pinRaw = i32(b, off + 0x68)
            let pinned = (pinRaw ?? -1) >= 0
            let accessCount: Int? = version >= 3 ? u32(b, off + 0x6C).map(Int.init) : nil

            guard let strLen = u16(b, off + fixedSize) else { break }
            let pathStart = off + fixedSize + 2
            let pathEnd = pathStart + Int(strLen) * 2
            guard pathEnd <= b.count else { break }
            let path = utf16(b, pathStart, pathEnd)

            out.append(DestListRecord(
                entryID: Int(entryID),
                lastAccessed: lastAccessed,
                accessCount: accessCount,
                hostname: hostname.isEmpty ? nil : hostname,
                pinned: pinned,
                path: path.isEmpty ? nil : path))

            off = pathEnd + trailing
        }
        return out
    }

    // MARK: - Primitives (little-endian, bounds-checked)

    private static func u16(_ b: [UInt8], _ o: Int) -> UInt16? {
        guard o >= 0, o + 2 <= b.count else { return nil }
        return UInt16(b[o]) | (UInt16(b[o + 1]) << 8)
    }
    private static func u32(_ b: [UInt8], _ o: Int) -> UInt32? {
        guard o >= 0, o + 4 <= b.count else { return nil }
        return (0..<4).reduce(UInt32(0)) { $0 | (UInt32(b[o + $1]) << (8 * $1)) }
    }
    private static func i32(_ b: [UInt8], _ o: Int) -> Int32? { u32(b, o).map { Int32(bitPattern: $0) } }
    private static func u64(_ b: [UInt8], _ o: Int) -> UInt64? {
        guard o >= 0, o + 8 <= b.count else { return nil }
        return (0..<8).reduce(UInt64(0)) { $0 | (UInt64(b[o + $1]) << (8 * UInt64($1))) }
    }

    private static func ascii(_ b: [UInt8], _ start: Int, _ len: Int) -> String {
        guard start >= 0, start + len <= b.count else { return "" }
        let bytes = b[start..<start + len].prefix { $0 != 0 }
        return String(decoding: bytes, as: UTF8.self).trimmingCharacters(in: .whitespaces)
    }

    private static func utf16(_ b: [UInt8], _ start: Int, _ end: Int) -> String {
        guard start >= 0, end <= b.count, start < end else { return "" }
        var units: [UInt16] = []
        var i = start
        while i + 1 < end {
            units.append(UInt16(b[i]) | (UInt16(b[i + 1]) << 8))
            i += 2
        }
        if units.last == 0 { units.removeLast() }
        return String(decoding: units, as: UTF16.self)
    }

    /// FILETIME → Date, rejecting 0 and implausible values (~1990–2100).
    static func date(fromFiletime ft: UInt64) -> Date? {
        guard ft != 0 else { return nil }
        let seconds = Double(ft) / 10_000_000 - 11_644_473_600
        guard seconds > 631_152_000, seconds < 4_102_444_800 else { return nil }
        return Date(timeIntervalSince1970: seconds)
    }
}
