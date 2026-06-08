import Foundation

/// A program-presence record reconstructed from `Amcache.hve`
/// (`C:\Windows\AppCompat\Programs\Amcache.hve`).
///
/// Amcache is a registry hive Windows uses for application-compatibility
/// bookkeeping. For DFIR it's high value because each file entry carries the
/// executable's full path, size, PE link date, and — critically — a **SHA-1
/// hash**, which feeds IOC/hash matching even after the binary is deleted.
///
/// Caveat worth stating loudly: Amcache proves a file was *present / registered*
/// on the system, NOT that it executed (use Prefetch/Shimcache + event logs for
/// execution). And the SHA-1 is computed over only the first ~31 MB of the file,
/// so for larger files it won't equal a full-file hash.
///
/// Reconstructed (not parsed from raw bytes): `Amcache.hve` rides the existing
/// regfexport pipeline into `[RegistryValue]`, and `reconstruct(from:)` groups
/// those by key into structured entries — see `AppModel.parseRegistry`.
public nonisolated struct AmcacheEntry: Identifiable, Hashable, Sendable, Codable {
    /// Which Amcache subkey tree the entry came from. The schema changed across
    /// Windows versions, so we record the provenance.
    public enum Source: String, Sendable, Codable {
        case inventoryApplicationFile   // Win10 1607+  Root\InventoryApplicationFile
        case legacyFile                 // Win8 / Win10 ≤1511  Root\File\<vol>\<ref>
    }

    public let id: UUID
    /// Display name — the executable's file name, derived from the path.
    public let name: String
    /// Full path as Amcache recorded it (lowercased on modern builds), if present.
    public let fullPath: String?
    /// Recovered SHA-1 (the stored FileId with its leading "0000" padding
    /// stripped), lowercased hex, when available.
    public let sha1: String?
    /// File size in bytes, if recorded.
    public let size: Int64?
    /// PE header link/compile time, if parseable.
    public let linkDate: Date?
    public let productName: String?
    public let publisher: String?
    /// e.g. "pe32_i386" / "pe64_amd64".
    public let binaryType: String?
    /// The entry key's registry last-write time — approximately when Amcache
    /// registered the file (a registration time, NOT an execution time).
    public let registeredAt: Date?
    public let source: Source
    /// Hive path the entry came from.
    public let sourceFile: String

    public init(id: UUID = UUID(), name: String, fullPath: String? = nil, sha1: String? = nil,
                size: Int64? = nil, linkDate: Date? = nil, productName: String? = nil,
                publisher: String? = nil, binaryType: String? = nil, registeredAt: Date? = nil,
                source: Source, sourceFile: String) {
        self.id = id
        self.name = name
        self.fullPath = fullPath
        self.sha1 = sha1
        self.size = size
        self.linkDate = linkDate
        self.productName = productName
        self.publisher = publisher
        self.binaryType = binaryType
        self.registeredAt = registeredAt
        self.source = source
        self.sourceFile = sourceFile
    }

    // MARK: - Reconstruction from parsed registry values

    /// Rebuild structured entries from the flat `[RegistryValue]` that the
    /// registry pipeline produced for the Amcache hive (tagged hive == "AMCACHE").
    /// Pure + cross-platform so it can run on iOS and be unit-tested without the
    /// regfexport binary.
    public static func reconstruct(from values: [RegistryValue]) -> [AmcacheEntry] {
        let amcache = values.filter { $0.hive.caseInsensitiveCompare("AMCACHE") == .orderedSame }
        guard !amcache.isEmpty else { return [] }

        var out: [AmcacheEntry] = []
        for (path, group) in Dictionary(grouping: amcache, by: \.path) {
            let lower = path.lowercased()
            // Look up a value by any of several candidate names (legacy uses
            // numeric IDs), returning the first non-empty data string.
            func value(_ names: String...) -> String? {
                for n in names {
                    if let hit = group.first(where: { $0.name.caseInsensitiveCompare(n) == .orderedSame }) {
                        let trimmed = hit.data.trimmingCharacters(in: .whitespacesAndNewlines)
                        if !trimmed.isEmpty { return trimmed }
                    }
                }
                return nil
            }
            let registeredAt = group.compactMap(\.lastWritten).max()
            let sourceFile = group.first?.sourceFile ?? ""

            if lower.contains("\\inventoryapplicationfile\\") {
                let fullPath = value("LowerCaseLongPath")
                let sha1 = sha1(fromFileId: value("FileId"))
                guard fullPath != nil || sha1 != nil else { continue }   // skip container keys
                out.append(AmcacheEntry(
                    name: fileName(fromPath: fullPath) ?? lastSegment(of: path) ?? "(unknown)",
                    fullPath: fullPath,
                    sha1: sha1,
                    size: parseInt(value("Size")),
                    linkDate: parseDate(value("LinkDate")),
                    productName: value("ProductName"),
                    publisher: value("Publisher", "ProductVersion"),
                    binaryType: value("BinaryType"),
                    registeredAt: registeredAt,
                    source: .inventoryApplicationFile,
                    sourceFile: sourceFile))
            } else if lower.contains("\\file\\") {
                // Legacy Root\File\<VolumeGUID>\<FileReference>; values are
                // addressed by numeric IDs: 15=path, 101=SHA-1, 6=size,
                // 17/12=dates, 0/100=product.
                let fullPath = value("15")
                let sha1 = sha1(fromFileId: value("101"))
                guard fullPath != nil || sha1 != nil else { continue }
                out.append(AmcacheEntry(
                    name: fileName(fromPath: fullPath) ?? lastSegment(of: path) ?? "(unknown)",
                    fullPath: fullPath,
                    sha1: sha1,
                    size: parseInt(value("6")),
                    linkDate: parseDate(value("17", "12")),
                    productName: value("0", "100"),
                    publisher: value("1"),
                    binaryType: nil,
                    registeredAt: registeredAt,
                    source: .legacyFile,
                    sourceFile: sourceFile))
            }
        }
        // Most-recently registered first; stable by name within equal times.
        return out.sorted {
            let l = $0.registeredAt ?? .distantPast, r = $1.registeredAt ?? .distantPast
            return l != r ? l > r : $0.name.localizedCaseInsensitiveCompare($1.name) == .orderedAscending
        }
    }

    /// FileId is the SHA-1 stored as a 44-char string padded with a leading
    /// "0000". Strip the padding; return nil for anything that isn't 40 hex.
    static func sha1(fromFileId fileId: String?) -> String? {
        guard let raw = fileId?.trimmingCharacters(in: .whitespaces), !raw.isEmpty else { return nil }
        let hex = (raw.count == 44 && raw.hasPrefix("0000")) ? String(raw.dropFirst(4)) : raw
        guard hex.count == 40, hex.allSatisfy(\.isHexDigit) else { return nil }
        return hex.lowercased()
    }

    private static func fileName(fromPath path: String?) -> String? {
        guard let path, !path.isEmpty else { return nil }
        let comp = path.split(whereSeparator: { $0 == "\\" || $0 == "/" }).last
        return comp.map(String.init)
    }

    private static func lastSegment(of keyPath: String) -> String? {
        keyPath.split(separator: "\\").last.map(String.init)
    }

    /// Parse a size that regfexport may render as decimal or "0x"-prefixed hex.
    private static func parseInt(_ s: String?) -> Int64? {
        guard let s = s?.trimmingCharacters(in: .whitespaces), !s.isEmpty else { return nil }
        if s.lowercased().hasPrefix("0x") { return Int64(s.dropFirst(2), radix: 16) }
        return Int64(s)
    }

    /// Best-effort parse of an Amcache date string (commonly "MM/dd/yyyy
    /// HH:mm:ss"); returns nil rather than guessing when the shape is unknown.
    private static func parseDate(_ s: String?) -> Date? {
        guard let s = s?.trimmingCharacters(in: .whitespaces), !s.isEmpty else { return nil }
        for format in ["MM/dd/yyyy HH:mm:ss", "yyyy-MM-dd HH:mm:ss", "MMM dd, yyyy HH:mm:ss.SSS zzz"] {
            let f = DateFormatter()
            f.locale = Locale(identifier: "en_US_POSIX")
            f.timeZone = TimeZone(identifier: "UTC")
            f.dateFormat = format
            if let d = f.date(from: s) { return d }
        }
        return nil
    }
}
