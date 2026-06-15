import Foundation

/// Pure-Swift **signature carver**: scans raw bytes for known file magic headers
/// and recovers the embedded files, independent of any filesystem. This is how
/// Strata recovers content the allocated-metadata walk can't reach — deleted
/// files in unallocated space, and (on macOS) sealed System-snapshot / locked
/// FileVault files that libfsapfs won't surface — because it reads the image
/// bytes directly.
///
/// No vendored tool, no I/O in the core (`carve(_:)` is a pure function over a
/// buffer, synthetic-fixture tested like `MftParser` / `UsnJournalParser`);
/// `carveFile(at:)` memory-maps an image and runs the same scan.
///
/// **Sizing.** SQLite (header page-size × page-count), PNG (`IEND` chunk), JPEG
/// (`FFD9`), PDF (last `%%EOF`), and ZIP (end-of-central-directory) carry a
/// recoverable length → `sizeExact == true`. bplist and gzip have no
/// forward-recoverable length, so they're capped and flagged inexact.
public enum FileCarver {
    /// Upper bound for an exact carve + the footer-scan window. A header field
    /// claiming more than this is treated as corrupt and the carve is capped.
    public static let defaultMaxFileSize = 256 * 1024 * 1024
    /// Cap applied to formats with no recoverable length (bplist/gzip).
    static let inexactCap = 8 * 1024 * 1024

    private static let sqliteMagic: [UInt8] = Array("SQLite format 3\u{0}".utf8)
    private static let bplistMagic: [UInt8] = Array("bplist00".utf8)
    private static let pngMagic: [UInt8] = [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]
    private static let pdfMagic: [UInt8] = Array("%PDF-".utf8)
    private static let zipMagic: [UInt8] = [0x50, 0x4B, 0x03, 0x04]

    /// Carve `data`, reporting offsets relative to `baseOffset` (so a chunked
    /// caller can report image-absolute positions).
    public static func carve(_ data: Data, baseOffset: Int64 = 0, source: String = "",
                             maxFileSize: Int = defaultMaxFileSize) -> [CarvedFile] {
        var results: [CarvedFile] = []
        let n = data.count
        guard n >= 3 else { return [] }      // smallest magic we match (gzip/JPEG)

        data.withUnsafeBytes { (raw: UnsafeRawBufferPointer) in
            let b = raw.bindMemory(to: UInt8.self)
            var i = 0
            while i < n {
                var hit: (kind: CarvedFile.Kind, size: Int, exact: Bool)?
                switch b[i] {
                case 0x53:                                   // 'S' — SQLite
                    if matches(b, i, n, sqliteMagic), let s = sqliteSize(b, i, n, maxFileSize) {
                        hit = (.sqlite, s.size, s.exact)
                    }
                case 0x62:                                   // 'b' — bplist
                    if matches(b, i, n, bplistMagic) {
                        hit = (.bplist, min(inexactCap, n - i), false)
                    }
                case 0x89:                                   // PNG
                    if matches(b, i, n, pngMagic) {
                        let s = pngSize(b, i, n, maxFileSize); hit = (.png, s.size, s.exact)
                    }
                case 0xFF:                                   // JPEG (FF D8 FF)
                    if i + 3 <= n, b[i + 1] == 0xD8, b[i + 2] == 0xFF {
                        let s = jpegSize(b, i, n, maxFileSize); hit = (.jpeg, s.size, s.exact)
                    }
                case 0x25:                                   // '%' — PDF
                    if matches(b, i, n, pdfMagic) {
                        let s = pdfSize(b, i, n, maxFileSize); hit = (.pdf, s.size, s.exact)
                    }
                case 0x50:                                   // 'P' — ZIP (PK\x03\x04)
                    if matches(b, i, n, zipMagic) {
                        let s = zipSize(b, i, n, maxFileSize); hit = (.zip, s.size, s.exact)
                    }
                case 0x1F:                                   // gzip (1F 8B 08)
                    if i + 3 <= n, b[i + 1] == 0x8B, b[i + 2] == 0x08 {
                        hit = (.gzip, min(inexactCap, n - i), false)
                    }
                default:
                    break
                }
                if let hit, hit.size > 0 {
                    results.append(CarvedFile(kind: hit.kind, offset: baseOffset + Int64(i),
                                              size: Int64(hit.size), sizeExact: hit.exact,
                                              source: source))
                    // Skip an exact carve's body so signatures inside it aren't
                    // re-emitted; for an inexact/capped guess, keep scanning.
                    i += hit.exact ? max(hit.size, 1) : 1
                } else {
                    i += 1
                }
            }
        }
        return results
    }

    /// Memory-map an image file and carve it. `.mappedIfSafe` keeps a multi-GB
    /// image off the heap; the scan pages through it.
    public static func carveFile(at url: URL, source: String? = nil,
                                 maxFileSize: Int = defaultMaxFileSize) throws -> [CarvedFile] {
        let data = try Data(contentsOf: url, options: .mappedIfSafe)
        return carve(data, source: source ?? url.lastPathComponent, maxFileSize: maxFileSize)
    }

    // MARK: - Signature matching

    private static func matches(_ b: UnsafeBufferPointer<UInt8>, _ i: Int, _ n: Int,
                                _ magic: [UInt8]) -> Bool {
        guard i + magic.count <= n else { return false }
        for k in 0..<magic.count where b[i + k] != magic[k] { return false }
        return true
    }

    private static func be32(_ b: UnsafeBufferPointer<UInt8>, _ p: Int) -> Int {
        (Int(b[p]) << 24) | (Int(b[p + 1]) << 16) | (Int(b[p + 2]) << 8) | Int(b[p + 3])
    }

    // MARK: - Sizers

    private static func sqliteSize(_ b: UnsafeBufferPointer<UInt8>, _ i: Int, _ n: Int,
                                   _ maxFileSize: Int) -> (size: Int, exact: Bool)? {
        guard i + 32 <= n else { return nil }
        let raw = (Int(b[i + 16]) << 8) | Int(b[i + 17])
        let pageSize = raw == 1 ? 65536 : raw
        guard pageSize >= 512, pageSize <= 65536, (pageSize & (pageSize - 1)) == 0 else { return nil }
        let pageCount = be32(b, i + 28)
        guard pageCount > 0 else { return nil }
        let total = pageSize * pageCount
        guard total > 0 else { return nil }
        if total > maxFileSize { return (min(maxFileSize, n - i), false) }
        return i + total <= n ? (total, true) : (n - i, false)
    }

    private static func jpegSize(_ b: UnsafeBufferPointer<UInt8>, _ i: Int, _ n: Int,
                                 _ maxFileSize: Int) -> (size: Int, exact: Bool) {
        let limit = min(n - 1, i + maxFileSize)
        var j = i + 2
        while j < limit {
            if b[j] == 0xFF, b[j + 1] == 0xD9 { return (j + 2 - i, true) }
            j += 1
        }
        return (min(maxFileSize, n - i), false)
    }

    private static func pngSize(_ b: UnsafeBufferPointer<UInt8>, _ i: Int, _ n: Int,
                                _ maxFileSize: Int) -> (size: Int, exact: Bool) {
        // IEND chunk type, followed by its 4-byte CRC, ends the stream.
        let iend: [UInt8] = [0x49, 0x45, 0x4E, 0x44]
        let limit = min(n - 4, i + maxFileSize)
        var j = i + 8
        while j < limit {
            if b[j] == iend[0], b[j + 1] == iend[1], b[j + 2] == iend[2], b[j + 3] == iend[3] {
                let end = j + 4 + 4                          // IEND + CRC
                return (min(end, n) - i, end <= n)
            }
            j += 1
        }
        return (min(maxFileSize, n - i), false)
    }

    private static func pdfSize(_ b: UnsafeBufferPointer<UInt8>, _ i: Int, _ n: Int,
                                _ maxFileSize: Int) -> (size: Int, exact: Bool) {
        // The last %%EOF within the window ends the (possibly incrementally
        // updated) document.
        let eof: [UInt8] = [0x25, 0x25, 0x45, 0x4F, 0x46]
        let limit = min(n - eof.count, i + maxFileSize)
        var last = -1
        var j = i + pdfMagic.count
        while j <= limit {
            if b[j] == eof[0], b[j + 1] == eof[1], b[j + 2] == eof[2], b[j + 3] == eof[3], b[j + 4] == eof[4] {
                last = j
            }
            j += 1
        }
        if last >= 0 { return (last + eof.count - i, true) }
        return (min(maxFileSize, n - i), false)
    }

    private static func zipSize(_ b: UnsafeBufferPointer<UInt8>, _ i: Int, _ n: Int,
                                _ maxFileSize: Int) -> (size: Int, exact: Bool) {
        // End-of-central-directory record: PK\x05\x06, then 18 bytes, then a
        // 2-byte comment length at offset 20.
        let eocd: [UInt8] = [0x50, 0x4B, 0x05, 0x06]
        let limit = min(n - 22, i + maxFileSize)
        var j = i + 4
        while j <= limit {
            if b[j] == eocd[0], b[j + 1] == eocd[1], b[j + 2] == eocd[2], b[j + 3] == eocd[3] {
                let commentLen = Int(b[j + 20]) | (Int(b[j + 21]) << 8)
                let end = j + 22 + commentLen
                return (min(end, n) - i, end <= n)
            }
            j += 1
        }
        return (min(maxFileSize, n - i), false)
    }
}
