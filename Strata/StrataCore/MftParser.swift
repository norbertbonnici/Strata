import Foundation

/// Decodes a raw NTFS `$MFT` into `[MftEntry]`.
///
/// Pure + cross-platform; no vendored tool (mirrors `UsnJournalParser`). Each MFT
/// record is a fixed-size `FILE` record (1 KB by convention). The parser:
///  1. applies the **update-sequence-array fixup** (NTFS overwrites the last 2
///     bytes of every 512-byte sector with a check value; the originals live in
///     the USA and must be restored before the record is read),
///  2. walks the attribute list for `$STANDARD_INFORMATION` (0x10) and the best
///     `$FILE_NAME` (0x30, Win32 namespace preferred over the DOS 8.3 alias),
///  3. resolves full paths in a second pass by following `$FN` parent references.
///
/// Both `$SI` and `$FN` MACB sets are kept so timestomping can be detected.
/// Every read is bounds-checked; defensively capped against a malformed stream.
///
/// Validated against real `$MFT` records (libfsntfs test corpus) + synthetic
/// fixtures.
public nonisolated enum MftParser {
    public static let recordSize = 1024
    private static let defensiveCap = 3_000_000
    private static let fileSignature: UInt32 = 0x454C_4946   // "FILE" (46 49 4C 45) little-endian
    private static let rootRecord: UInt64 = 5                // NTFS root directory "."

    /// One decoded record before path resolution.
    private struct Raw {
        var recordNumber: UInt64
        var sequence: UInt16
        var inUse: Bool
        var isDirectory: Bool
        var fileName: String?
        var fileNameNamespace: UInt8   // 0 POSIX, 1 Win32, 2 DOS, 3 Win32&DOS
        var parentRecord: UInt64?
        var si: (Date?, Date?, Date?, Date?)   // created, modified, changed, accessed
        var fn: (Date?, Date?, Date?, Date?)
        var size: Int64?
    }

    public static func parse(bytes b: [UInt8], sourceFile: String) -> [MftEntry] {
        // Pass 1: decode each record.
        var raws: [Raw] = []
        raws.reserveCapacity(b.count / recordSize + 1)
        var off = 0
        while off + recordSize <= b.count, raws.count < defensiveCap {
            if u32(b, off) == fileSignature, let raw = decodeRecord(b, at: off, sourceFile: sourceFile) {
                raws.append(raw)
            }
            off += recordSize
        }

        // Pass 2: resolve full paths from parent references.
        var byNumber: [UInt64: Raw] = [:]
        byNumber.reserveCapacity(raws.count)
        for r in raws { byNumber[r.recordNumber] = r }

        var out: [MftEntry] = []
        out.reserveCapacity(raws.count)
        for r in raws {
            out.append(MftEntry(
                recordNumber: r.recordNumber, sequence: r.sequence,
                inUse: r.inUse, isDirectory: r.isDirectory,
                fileName: r.fileName,
                fullPath: resolvePath(of: r, in: byNumber),
                parentRecord: r.parentRecord,
                siCreated: r.si.0, siModified: r.si.1, siChanged: r.si.2, siAccessed: r.si.3,
                fnCreated: r.fn.0, fnModified: r.fn.1, fnChanged: r.fn.2, fnAccessed: r.fn.3,
                size: r.size, sourceFile: sourceFile))
        }
        return out
    }

    // MARK: - Record decoding

    private static func decodeRecord(_ b: [UInt8], at base: Int, sourceFile: String) -> Raw? {
        guard let usaOffset = u16(b, base + 0x04), let usaCount = u16(b, base + 0x06),
              let seq = u16(b, base + 0x10), let attrOffset = u16(b, base + 0x14),
              let flags = u16(b, base + 0x16) else { return nil }

        // Apply the fixup into a local 1 KB copy.
        guard base + recordSize <= b.count else { return nil }
        var rec = Array(b[base ..< base + recordSize])
        applyFixup(&rec, usaOffset: Int(usaOffset), usaCount: Int(usaCount))

        // Record number: the 0x2C field is authoritative on modern NTFS; fall
        // back to deriving it from the on-disk position when zero.
        let recordNumber: UInt64
        if let n = u32(rec, 0x2C), n != 0 { recordNumber = UInt64(n) }
        else { recordNumber = UInt64(base / recordSize) }

        var raw = Raw(recordNumber: recordNumber, sequence: seq,
                      inUse: flags & 0x0001 != 0, isDirectory: flags & 0x0002 != 0,
                      fileName: nil, fileNameNamespace: 0, parentRecord: nil,
                      si: (nil, nil, nil, nil), fn: (nil, nil, nil, nil), size: nil)

        // Walk attributes.
        var ao = Int(attrOffset)
        var guardCount = 0
        while ao + 8 <= recordSize, guardCount < 256 {
            guardCount += 1
            guard let type = u32(rec, ao) else { break }
            if type == 0xFFFF_FFFF { break }               // end marker
            guard let len = u32(rec, ao + 0x04), len >= 8, ao + Int(len) <= recordSize else { break }
            let nonResident = rec[ao + 0x08] != 0

            if !nonResident, let cOff = u16(rec, ao + 0x14), let cLen = u32(rec, ao + 0x10) {
                let cStart = ao + Int(cOff)
                let cEnd = cStart + Int(cLen)
                if cEnd <= ao + Int(len), cEnd <= recordSize {
                    if type == 0x10 { decodeStandardInformation(rec, cStart, cEnd, into: &raw) }
                    else if type == 0x30 { decodeFileName(rec, cStart, cEnd, into: &raw) }
                }
            }
            ao += Int(len)
        }
        return raw
    }

    /// Restore the bytes NTFS replaced with the update-sequence number at the end
    /// of each sector. USA layout: [check value][fixup_1][fixup_2]…; for sector i
    /// (1-based) the last 2 bytes were swapped with `fixup_i`.
    private static func applyFixup(_ rec: inout [UInt8], usaOffset: Int, usaCount: Int) {
        guard usaCount >= 2, usaOffset >= 0, usaOffset + usaCount * 2 <= rec.count else { return }
        for i in 1 ..< usaCount {
            let sectorEnd = i * 512 - 2
            let src = usaOffset + i * 2
            guard sectorEnd >= 0, sectorEnd + 2 <= rec.count, src + 2 <= rec.count else { continue }
            rec[sectorEnd] = rec[src]
            rec[sectorEnd + 1] = rec[src + 1]
        }
    }

    private static func decodeStandardInformation(_ b: [UInt8], _ s: Int, _ e: Int, into raw: inout Raw) {
        guard e - s >= 32 else { return }
        raw.si = (ft(b, s + 0x00), ft(b, s + 0x08), ft(b, s + 0x10), ft(b, s + 0x18))
    }

    private static func decodeFileName(_ b: [UInt8], _ s: Int, _ e: Int, into raw: inout Raw) {
        guard e - s >= 0x42 else { return }
        let namespace = b[s + 0x41]
        let nameLen = Int(b[s + 0x40])
        let nameStart = s + 0x42
        let nameEnd = nameStart + nameLen * 2
        guard nameEnd <= e else { return }
        let name = utf16(b, nameStart, nameEnd)

        // Prefer a Win32 / Win32&DOS name over a DOS 8.3 alias when a record has
        // several $FN attributes; take the parent + $FN times from the same one.
        let better = raw.fileName == nil || preferNamespace(namespace, over: raw.fileNameNamespace)
        guard better else { return }
        raw.fileName = name
        raw.fileNameNamespace = namespace
        raw.parentRecord = (u64(b, s + 0x00) ?? 0) & 0x0000_FFFF_FFFF_FFFF
        raw.fn = (ft(b, s + 0x08), ft(b, s + 0x10), ft(b, s + 0x18), ft(b, s + 0x20))
        if let real = u64(b, s + 0x30) { raw.size = Int64(bitPattern: real) }
    }

    /// Win32&DOS (3) and Win32 (1) beat DOS (2); anything beats POSIX(0)/unset.
    private static func preferNamespace(_ candidate: UInt8, over current: UInt8) -> Bool {
        func rank(_ ns: UInt8) -> Int { ns == 3 ? 3 : ns == 1 ? 2 : ns == 0 ? 1 : 0 }
        return rank(candidate) > rank(current)
    }

    // MARK: - Path resolution

    private static func resolvePath(of r: Raw, in byNumber: [UInt64: Raw]) -> String? {
        guard let name = r.fileName else { return nil }
        if r.recordNumber == rootRecord { return "\\" }
        var components = [name]
        var cursor = r.parentRecord
        // A `visited` set breaks any parent-reference cycle (not just an immediate
        // self-loop) in a malformed/crafted $MFT; also bounds the walk depth.
        var visited: Set<UInt64> = [r.recordNumber]
        while let cur = cursor, visited.count < 256 {
            if cur == rootRecord { break }
            guard !visited.contains(cur), let parent = byNumber[cur], let pName = parent.fileName else { break }
            visited.insert(cur)
            components.append(pName)
            cursor = parent.parentRecord
        }
        // Best-effort: return a partial path even if the chain didn't reach root
        // (orphaned / incomplete parent chains still yield a useful suffix).
        return "\\" + components.reversed().joined(separator: "\\")
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
        while i + 1 < end { units.append(UInt16(b[i]) | (UInt16(b[i + 1]) << 8)); i += 2 }
        return String(decoding: units, as: UTF16.self)
    }

    /// FILETIME → Date. Rejects 0 (unset) and values outside ~1601–2200; that
    /// window is deliberately wide so backdated (timestomped) times still decode.
    static func ft(_ b: [UInt8], _ o: Int) -> Date? {
        guard let v = u64(b, o), v != 0 else { return nil }
        let secs = Double(v) / 10_000_000 - 11_644_473_600
        guard secs > -11_644_473_600, secs < 7_258_118_400 else { return nil }
        return Date(timeIntervalSince1970: secs)
    }
}
