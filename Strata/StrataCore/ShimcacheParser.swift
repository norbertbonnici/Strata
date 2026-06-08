import Foundation

/// Decodes the Windows AppCompatCache (Shimcache) REG_BINARY blob into
/// `[ShimcacheEntry]`. Pure + cross-platform: it takes the value's bytes (or the
/// hex string the registry pipeline already produced) and parses the
/// version-specific binary layout in Swift — no vendored tool does this.
///
/// Design for an unforgiving format with no validation oracle:
///  - Detect the version by header magic / per-entry signature rather than
///    hardcoding offsets (they shifted across Win10 builds).
///  - Bounds-check every read; return `[]` (never crash) on anything malformed
///    or unrecognized.
///  - Prefer the reliable signals (path + insertion order). The FILETIME is read
///    at the modern offset and range-validated; if it looks implausible we store
///    nil rather than a bogus date.
///
/// Tested against synthetic per-version fixtures (`ShimcacheParserTests`); the
/// byte offsets are cross-checked against the public AppCompatCache spec. Flagged
/// for confirmation against a real SYSTEM hive.
public nonisolated enum ShimcacheParser {

    private static let ts10: [UInt8] = [0x31, 0x30, 0x74, 0x73]   // "10ts"
    private static let ts00: [UInt8] = [0x30, 0x30, 0x74, 0x73]   // "00ts"
    private static let defensiveEntryCap = 8192

    // MARK: - Entry points

    /// Locate the AppCompatCache value among parsed registry values and decode
    /// it. Prefers ControlSet001 when several control sets are present.
    public static func fromRegistry(_ values: [RegistryValue]) -> [ShimcacheEntry] {
        let candidates = values.filter {
            $0.hive.caseInsensitiveCompare("SYSTEM") == .orderedSame
                && $0.name.caseInsensitiveCompare("AppCompatCache") == .orderedSame
                && $0.path.lowercased().contains("appcompatcache")
        }
        guard !candidates.isEmpty else { return [] }
        let chosen = candidates.first { $0.path.lowercased().contains("controlset001") } ?? candidates[0]
        return parse(hex: chosen.data, sourceFile: chosen.sourceFile)
    }

    public static func parse(hex: String, sourceFile: String) -> [ShimcacheEntry] {
        guard let bytes = decodeHex(hex) else { return [] }
        return parse(bytes: bytes, sourceFile: sourceFile)
    }

    public static func parse(bytes: [UInt8], sourceFile: String) -> [ShimcacheEntry] {
        let (version, start) = detect(bytes)
        switch version {
        case .windows10: return parseTS(bytes, start: start, version: .windows10, signature: ts10, sourceFile: sourceFile)
        case .windows81: return parseTS(bytes, start: start, version: .windows81, signature: ts10, sourceFile: sourceFile)
        case .windows8:  return parseTS(bytes, start: start, version: .windows8,  signature: ts00, sourceFile: sourceFile)
        case .windows7:  return parseWin7(bytes, sourceFile: sourceFile)
        case .windowsXP, .unknown: return []
        }
    }

    // MARK: - Version detection

    /// Returns the detected version and the byte offset of the first entry.
    static func detect(_ b: [UInt8]) -> (ShimcacheEntry.Version, Int) {
        guard b.count >= 8, let magic = u32(b, 0) else { return (.unknown, 0) }
        if magic == 0xBADC_0FEE { return (.windows7, 0x80) }
        if magic == 0xDEAD_BEEF { return (.windowsXP, 0) }
        // Win10/11: the header size (0x30 on 1507, 0x34 on 1511+) sits at offset
        // 0 and the first "10ts" entry begins there.
        if magic == 0x30 || magic == 0x34 {
            let h = Int(magic)
            if h + 4 <= b.count, Array(b[h..<h + 4]) == ts10 { return (.windows10, h) }
        }
        // Win8.x: 0x80 header; per-entry signature distinguishes 8.0 vs 8.1.
        if magic == 0x80, b.count >= 0x84 {
            let sig = Array(b[0x80..<0x84])
            if sig == ts10 { return (.windows81, 0x80) }
            if sig == ts00 { return (.windows8, 0x80) }
        }
        return (.unknown, 0)
    }

    // MARK: - Win8 / Win10 ("ts"-signature, inline path)

    /// Win10 and Win8.x share a self-describing entry: a 12-byte head
    /// (signature, unknown, cacheEntrySize) then a `cacheEntrySize`-byte body
    /// beginning with pathSize + UTF-16LE path. The body advance is driven by
    /// cacheEntrySize, so we always reach the next entry even if inner fields
    /// vary by version; we read the FILETIME at the Win10 offset (right after the
    /// path) and range-validate it, leaving nil when implausible.
    private static func parseTS(_ b: [UInt8], start: Int, version: ShimcacheEntry.Version,
                                signature: [UInt8], sourceFile: String) -> [ShimcacheEntry] {
        var out: [ShimcacheEntry] = []
        var off = start
        var order = 0
        while off + 12 <= b.count, out.count < defensiveEntryCap {
            guard Array(b[off..<off + 4]) == signature else { break }
            guard let ceSize = u32(b, off + 8) else { break }
            let bodyStart = off + 12
            let bodyEnd = bodyStart + Int(ceSize)
            guard ceSize >= 2, bodyEnd <= b.count else { break }
            guard let pathSize = u16(b, bodyStart) else { break }
            let pathStart = bodyStart + 2
            let pathEnd = pathStart + Int(pathSize)
            guard pathEnd <= bodyEnd else { break }
            let path = utf16(b, pathStart, pathEnd)
            let lastModified = u64(b, pathEnd).flatMap(date(fromFiletime:))
            if !path.isEmpty {
                out.append(ShimcacheEntry(path: path, lastModified: lastModified,
                                          insertionOrder: order, version: version,
                                          sourceFile: sourceFile))
                order += 1
            }
            off = bodyEnd
        }
        return out
    }

    // MARK: - Win7 (offset-referenced paths)

    /// Win7/Server 2008 R2: 0x80 header, magic 0xBADC0FEE, entry count at +4,
    /// fixed-stride entries at 0x80 whose paths live in a string area referenced
    /// by offset. x86 and x64 differ in field widths, so we try x64 first and
    /// fall back to x86, keeping whichever yields valid paths.
    private static func parseWin7(_ b: [UInt8], sourceFile: String) -> [ShimcacheEntry] {
        guard let count = u32(b, 4) else { return [] }
        let entriesStart = 0x80
        for (stride, is64) in [(48, true), (32, false)] {
            var out: [ShimcacheEntry] = []
            var order = 0
            for i in 0..<min(Int(count), defensiveEntryCap) {
                let base = entriesStart + i * stride
                guard base + stride <= b.count, let pathLen = u16(b, base) else { break }
                let pathOffset: Int
                let ftOffset: Int
                if is64 {
                    pathOffset = Int(u64(b, base + 8) ?? 0); ftOffset = base + 16
                } else {
                    pathOffset = Int(u32(b, base + 4) ?? 0); ftOffset = base + 8
                }
                guard pathOffset > 0, pathOffset + Int(pathLen) <= b.count else { continue }
                let path = utf16(b, pathOffset, pathOffset + Int(pathLen))
                guard !path.isEmpty else { continue }
                out.append(ShimcacheEntry(path: path,
                                          lastModified: u64(b, ftOffset).flatMap(date(fromFiletime:)),
                                          insertionOrder: order, version: .windows7,
                                          sourceFile: sourceFile))
                order += 1
            }
            if !out.isEmpty { return out }
        }
        return []
    }

    // MARK: - Primitives (little-endian, bounds-checked)

    static func decodeHex(_ s: String) -> [UInt8]? {
        let clean = s.filter { !$0.isWhitespace }
        guard !clean.isEmpty, clean.count % 2 == 0 else { return nil }
        var out = [UInt8](); out.reserveCapacity(clean.count / 2)
        var i = clean.startIndex
        while i < clean.endIndex {
            let next = clean.index(i, offsetBy: 2)
            guard let byte = UInt8(clean[i..<next], radix: 16) else { return nil }
            out.append(byte); i = next
        }
        return out
    }

    private static func u16(_ b: [UInt8], _ o: Int) -> UInt16? {
        guard o >= 0, o + 2 <= b.count else { return nil }
        return UInt16(b[o]) | (UInt16(b[o + 1]) << 8)
    }
    private static func u32(_ b: [UInt8], _ o: Int) -> UInt32? {
        guard o >= 0, o + 4 <= b.count else { return nil }
        return (0..<4).reduce(UInt32(0)) { $0 | (UInt32(b[o + $1]) << (8 * $1)) }
    }
    private static func u64(_ b: [UInt8], _ o: Int) -> UInt64? {
        guard o >= 0, o + 8 <= b.count else { return nil }
        return (0..<8).reduce(UInt64(0)) { $0 | (UInt64(b[o + $1]) << (8 * UInt64($1))) }
    }

    private static func utf16(_ b: [UInt8], _ start: Int, _ end: Int) -> String {
        guard start >= 0, end <= b.count, start < end else { return "" }
        var units: [UInt16] = []
        var i = start
        while i + 1 < end {   // need a full 2-byte code unit
            units.append(UInt16(b[i]) | (UInt16(b[i + 1]) << 8))
            i += 2
        }
        if units.last == 0 { units.removeLast() }   // drop NUL terminator
        return String(decoding: units, as: UTF16.self)
    }

    /// FILETIME (100ns ticks since 1601) → Date, rejecting 0 and implausible
    /// values (outside ~1990–2100) so a misread offset yields nil, not a bogus date.
    static func date(fromFiletime ft: UInt64) -> Date? {
        guard ft != 0 else { return nil }
        let seconds = Double(ft) / 10_000_000 - 11_644_473_600
        guard seconds > 631_152_000, seconds < 4_102_444_800 else { return nil }
        return Date(timeIntervalSince1970: seconds)
    }
}
