import Foundation

/// Decodes the NTFS USN journal (`$UsnJrnl:$J` bytes) into `[UsnRecord]`.
///
/// Pure + cross-platform; version-aware (V2 = 64-bit refs, V3 = 128-bit refs, V4
/// = extent record / no name). The `$J` stream is **sparse**: its oldest region
/// is a long run of zeros, so the parser walks strictly by `RecordLength` and, on
/// a zero gap or any malformed length, **skips forward to the next plausible
/// record** rather than stopping (a naive stop-on-zero truncates the whole parse
/// at the start). Every read is bounds-checked; defensively capped against a
/// runaway/malformed stream.
///
/// Validated against synthetic V2/V3 fixtures AND a real extracted `$J`.
public nonisolated enum UsnJournalParser {
    private static let minRecord = 0x3C            // V2 fixed header; floor for "real record"
    private static let maxRecord = 0x10000         // 64 KB sanity ceiling (names max ~510 bytes)
    private static let defensiveCap = 3_000_000

    public static func parse(bytes b: [UInt8], sourceFile: String) -> [UsnRecord] {
        var out: [UsnRecord] = []
        out.reserveCapacity(4096)
        let n = b.count
        var off = 0
        while off + 4 <= n, out.count < defensiveCap {
            let recLen = Int(u32(b, off) ?? 0)
            // Zero gap / padding / implausible length → resync to the next record.
            if recLen < minRecord || recLen > maxRecord || recLen % 8 != 0 || off + recLen > n {
                guard let next = nextRecordStart(b, after: off, n: n), next > off else { break }
                off = next
                continue
            }
            if let major = u16(b, off + 4), major == 2 || major == 3,
               let rec = decode(b, off: off, recLen: recLen, major: major, sourceFile: sourceFile) {
                out.append(rec)
            }
            // V4 (no name) and undecodable records still advance by recLen.
            off += recLen
        }
        return out
    }

    /// Decode a V2 (64-bit refs) or V3 (128-bit refs) record.
    private static func decode(_ b: [UInt8], off: Int, recLen: Int, major: UInt16,
                               sourceFile: String) -> UsnRecord? {
        // Field base offsets shift by +16 for V3's 128-bit file references.
        let shift = major == 3 ? 16 : 0
        guard let frn = u64(b, off + 0x08),
              let parent = u64(b, off + 0x10 + shift),
              let usn = u64(b, off + 0x18 + shift),
              let reason = u32(b, off + 0x28 + shift),
              let attrs = u32(b, off + 0x34 + shift),
              let nameLen = u16(b, off + 0x38 + shift),
              let nameOff = u16(b, off + 0x3A + shift) else { return nil }
        let ts = u64(b, off + 0x20 + shift).flatMap(date(fromFiletime:))

        var fileName = ""
        let nameStart = off + Int(nameOff)
        let nameEnd = nameStart + Int(nameLen)
        if Int(nameLen) > 0, Int(nameLen) % 2 == 0, nameOff >= UInt16(major == 3 ? 0x4C : 0x3C),
           nameEnd <= off + recLen, nameEnd <= b.count {
            fileName = utf16(b, nameStart, nameEnd)
        }

        return UsnRecord(
            usn: usn,
            timestamp: ts,
            fileName: fileName,
            isDirectory: attrs & 0x10 != 0,
            mftEntry: frn & 0x0000_FFFF_FFFF_FFFF,
            mftSequence: UInt16(truncatingIfNeeded: frn >> 48),
            parentMftEntry: parent & 0x0000_FFFF_FFFF_FFFF,
            reasonRaw: reason,
            fileAttributes: attrs,
            sourceFile: sourceFile)
    }

    /// Resync after a zero gap / bad record: find the next non-zero byte, align
    /// down to an 8-byte boundary, and return it (guaranteeing forward progress).
    private static func nextRecordStart(_ b: [UInt8], after: Int, n: Int) -> Int? {
        var i = max(after + 8, 8)
        while i < n, b[i] == 0 { i += 1 }
        guard i < n else { return nil }
        let aligned = i - (i % 8)
        return aligned > after ? aligned : after + 8
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
    private static func u64(_ b: [UInt8], _ o: Int) -> UInt64? {
        guard o >= 0, o + 8 <= b.count else { return nil }
        return (0..<8).reduce(UInt64(0)) { $0 | (UInt64(b[o + $1]) << (8 * UInt64($1))) }
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
