import Foundation

/// One reconstructed row from a web-browser history database — either a page
/// **visit** (one row per distinct URL, carrying its visit/typed counts and the
/// last-visit time) or a **download**.
///
/// Browser history is forensic gold for the **delivery** stage: it shows what a
/// user (or an attacker on a hands-on-keyboard session) navigated to and pulled
/// down — second-stage payloads, tooling, paste/anonymous-sharing services, and
/// raw-IP infrastructure. Chromium-family browsers (Chrome/Edge/Brave/Opera/
/// Vivaldi) store this in a SQLite `History` database; Firefox in `places.sqlite`.
///
/// The value type stays `nonisolated`/`Sendable` and free of any DB/FS I/O so it
/// is unit-testable off-main and usable on iOS — the macOS-only
/// `BrowserHistoryParser` reads the SQLite databases (via GRDB) and builds these.
public nonisolated struct BrowserHistoryEntry: Identifiable, Hashable, Sendable, Codable {
    /// Whether this row is a page visit or a file download.
    public enum Kind: String, Sendable, Codable, CaseIterable {
        case visit
        case download
        public var label: String {
            switch self {
            case .visit:    return "Visit"
            case .download: return "Download"
            }
        }
    }

    /// Which browser the source database belonged to (derived from its path).
    public enum Browser: String, Sendable, Codable, CaseIterable {
        case chrome, edge, brave, opera, vivaldi, firefox, unknown
        public var label: String {
            switch self {
            case .chrome:  return "Chrome"
            case .edge:    return "Edge"
            case .brave:   return "Brave"
            case .opera:   return "Opera"
            case .vivaldi: return "Vivaldi"
            case .firefox: return "Firefox"
            case .unknown: return "Browser"
            }
        }
    }

    public let id: UUID
    public let browser: Browser
    public let kind: Kind
    /// The visited page URL (visit) or the source/origin URL of a download.
    public let url: String
    public let title: String?
    /// Last-visit time (visit) or download start time (download). nil if absent.
    public let timestamp: Date?
    // Visits:
    /// Total recorded visits to this URL (Chromium `urls.visit_count` /
    /// Firefox `moz_places.visit_count`).
    public let visitCount: Int?
    /// Times the URL was *manually typed* into the address bar — a strong
    /// intent/awareness signal (Chromium `typed_count`; Firefox `typed` 0/1).
    public let typedCount: Int?
    // Downloads:
    /// Local on-disk path the download was saved to.
    public let targetPath: String?
    public let receivedBytes: Int64?
    public let totalBytes: Int64?
    /// The page that initiated the download (Chromium `downloads.tab_url`).
    public let referrer: String?
    /// The browser profile the database lived under ("Default", "Profile 1", a
    /// Firefox `xxxx.default-release` folder, …), recovered from the source path.
    public let userProfile: String?
    /// The source database's in-image path, retained for display.
    public let sourceFile: String

    public init(id: UUID = UUID(), browser: Browser, kind: Kind,
                url: String, title: String? = nil, timestamp: Date?,
                visitCount: Int? = nil, typedCount: Int? = nil,
                targetPath: String? = nil, receivedBytes: Int64? = nil,
                totalBytes: Int64? = nil, referrer: String? = nil,
                userProfile: String? = nil, sourceFile: String) {
        self.id = id
        self.browser = browser
        self.kind = kind
        self.url = url
        self.title = title
        self.timestamp = timestamp
        self.visitCount = visitCount
        self.typedCount = typedCount
        self.targetPath = targetPath
        self.receivedBytes = receivedBytes
        self.totalBytes = totalBytes
        self.referrer = referrer
        self.userProfile = userProfile
        self.sourceFile = sourceFile
    }

    // MARK: - Display helpers

    /// Host portion of the URL, lowercased (e.g. `evil.example.com`). nil if the
    /// URL has no parseable host (about:, chrome://, malformed).
    public var host: String? { Self.host(ofURL: url) }

    /// Leaf filename of a download's target path (handles Windows `\` and `/`).
    public var targetLeaf: String? {
        guard let targetPath, !targetPath.isEmpty else { return nil }
        let parts = targetPath.split(whereSeparator: { $0 == "\\" || $0 == "/" })
        return parts.last.map(String.init) ?? targetPath
    }

    /// The best single label for a row: page title, else the target leaf (for a
    /// titleless download), else the URL.
    public var displayTitle: String {
        if let title, !title.isEmpty { return title }
        if kind == .download, let leaf = targetLeaf { return leaf }
        return url
    }

    /// One-line, kind-specific summary for table rows.
    public var detailSummary: String {
        switch kind {
        case .visit:
            let visits = visitCount ?? 0
            var s = "\(visits) visit\(visits == 1 ? "" : "s")"
            if let typed = typedCount, typed > 0 { s += " · typed \(typed)×" }
            return s
        case .download:
            let leaf = targetLeaf ?? "download"
            return "\(leaf) · \(Self.humanBytes(receivedBytes ?? 0))"
        }
    }

    // MARK: - Pure decoders (testable; no I/O)

    /// Seconds between the Windows/WebKit epoch (1601-01-01) and the Unix epoch.
    private static let webkitEpochOffset: Double = 11_644_473_600

    /// Convert a Chromium timestamp (microseconds since 1601-01-01 UTC, the
    /// WebKit epoch) to a `Date`. Returns nil for 0/negative ("never").
    public static func chromeTime(_ micros: Int64?) -> Date? {
        guard let micros, micros > 0 else { return nil }
        return Date(timeIntervalSince1970: Double(micros) / 1_000_000 - webkitEpochOffset)
    }

    /// Convert a Firefox timestamp (microseconds since the Unix epoch) to a
    /// `Date`. Returns nil for 0/negative/absent.
    public static func firefoxTime(_ micros: Int64?) -> Date? {
        guard let micros, micros > 0 else { return nil }
        return Date(timeIntervalSince1970: Double(micros) / 1_000_000)
    }

    /// Classify the browser from a source-database path (case-insensitive).
    public static func browser(forPath path: String) -> Browser {
        let p = path.lowercased()
        if p.contains("bravesoftware") || p.contains("\\brave") || p.contains("/brave") { return .brave }
        if p.contains("microsoft\\edge") || p.contains("microsoft/edge") || p.contains("\\edge\\") { return .edge }
        if p.contains("google\\chrome") || p.contains("google/chrome") { return .chrome }
        if p.contains("opera software") || p.contains("opera stable") || p.contains("\\opera") { return .opera }
        if p.contains("vivaldi") { return .vivaldi }
        if p.contains("mozilla\\firefox") || p.contains("mozilla/firefox")
            || p.hasSuffix("places.sqlite") { return .firefox }
        return .unknown
    }

    /// Recover the browser-profile folder name (the directory immediately
    /// containing the history DB), e.g. "Default", "Profile 1", or a Firefox
    /// "abcd1234.default-release". nil if the path has no parent component.
    public static func profile(forPath path: String) -> String? {
        let parts = path.split(whereSeparator: { $0 == "\\" || $0 == "/" })
        guard parts.count >= 2 else { return nil }
        return String(parts[parts.count - 2])
    }

    /// Extract a lowercased host from a URL. Tolerant of the percent-encoded,
    /// occasionally-malformed URLs found in history DBs: tries `URLComponents`
    /// first, then a manual `scheme://host/…` split.
    public static func host(ofURL url: String) -> String? {
        if let h = URLComponents(string: url)?.host, !h.isEmpty { return h.lowercased() }
        guard let schemeRange = url.range(of: "://") else { return nil }
        let afterScheme = url[schemeRange.upperBound...]
        let hostPart = afterScheme.prefix { $0 != "/" && $0 != "?" && $0 != "#" }
        // Strip any userinfo@ and :port.
        let noUser = hostPart.split(separator: "@").last ?? hostPart
        let noPort = noUser.split(separator: ":").first ?? noUser
        let h = noPort.lowercased()
        return h.isEmpty ? nil : String(h)
    }

    /// Pure byte formatter (avoids ByteCountFormatter so the value type stays
    /// trivially `nonisolated`/`Sendable` and unit-testable off-main).
    public static func humanBytes(_ n: Int64) -> String {
        let units = ["B", "KB", "MB", "GB", "TB"]
        var value = Double(max(0, n))
        var unit = 0
        while value >= 1024 && unit < units.count - 1 { value /= 1024; unit += 1 }
        if unit == 0 { return "\(n) B" }
        return String(format: "%.1f %@", value, units[unit])
    }
}
