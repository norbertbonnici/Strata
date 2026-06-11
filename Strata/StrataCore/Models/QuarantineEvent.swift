import Foundation

/// One row from the macOS **LaunchServices quarantine** store
/// (`com.apple.LaunchServices.QuarantineEventsV2`).
///
/// Every time a quarantine-aware application (a browser, a mail client, a
/// messaging app, `curl`/`wget` with the right flags, an installer) writes a
/// file that came from the network, LaunchServices appends a row recording
/// **which app downloaded it**, **the file's URL**, **the page that referred
/// it**, and **when**. This is macOS download provenance — the equivalent of
/// the `com.apple.metadata:kMDItemWhereFroms` extended attribute, but in a
/// single queryable store that survives the file being moved or its xattr
/// stripped.
///
/// Forensically it is a primary **delivery** / **user-execution** source
/// (T1204 User Execution, and T1566 Phishing-delivery context): it ties a
/// suspicious file on disk back to the application and origin URL that pulled
/// it down, which is exactly what you need to reconstruct how an attacker's
/// payload arrived on a macOS host.
///
/// The value type is `nonisolated`/`Sendable` and carries no DB/FS I/O so it
/// is unit-testable off-main and usable on iOS — the macOS-only
/// `QuarantineParser` reads the SQLite store (via GRDB) and builds these.
public nonisolated struct QuarantineEvent: Identifiable, Hashable, Sendable, Codable {
    public let id: UUID
    /// The application that downloaded the file
    /// (`LSQuarantineAgentName`), e.g. "Safari", "Google Chrome", "curl".
    public let agentName: String?
    /// The URL of the downloaded file itself (`LSQuarantineDataURLString`).
    public let dataURL: String?
    /// The referrer / page the download was initiated from
    /// (`LSQuarantineOriginURLString`).
    public let originURL: String?
    /// When the download was recorded. Decoded from `LSQuarantineTimeStamp`,
    /// which is a `CFAbsoluteTime` (seconds since 2001-01-01 UTC).
    public let timestamp: Date?
    /// The store's row identifier (`LSQuarantineEventIdentifier`), a UUID
    /// string — retained for cross-referencing and de-duplication.
    public let eventID: String?
    /// The source store's in-image path, retained for display.
    public let sourceFile: String

    public init(id: UUID = UUID(), agentName: String? = nil,
                dataURL: String? = nil, originURL: String? = nil,
                timestamp: Date? = nil, eventID: String? = nil,
                sourceFile: String) {
        self.id = id
        self.agentName = agentName
        self.dataURL = dataURL
        self.originURL = originURL
        self.timestamp = timestamp
        self.eventID = eventID
        self.sourceFile = sourceFile
    }

    // MARK: - Pure decoders (testable; no I/O)

    /// Seconds between the Unix epoch (1970-01-01) and the
    /// `CFAbsoluteTime`/Cocoa reference date (2001-01-01 UTC). 31 years, 8 of
    /// which are leap years.
    public static let cfAbsoluteTimeOffset: Double = 978_307_200

    /// Convert a `CFAbsoluteTime` (seconds since 2001-01-01 UTC, the value the
    /// quarantine store keeps in `LSQuarantineTimeStamp`) to a `Date`. Returns
    /// nil for a nil/non-positive stamp ("no time recorded"). A genuine
    /// 2001-01-01 stamp (exactly 0) is treated as absent — that boundary value
    /// never appears in real provenance data.
    public static func quarantineTime(_ cfSeconds: Double?) -> Date? {
        guard let cfSeconds, cfSeconds > 0 else { return nil }
        return Date(timeIntervalSince1970: cfSeconds + cfAbsoluteTimeOffset)
    }

    // MARK: - Display helpers

    /// Host portion of the download's data URL, lowercased. nil if absent or
    /// unparseable. (Reuses the tolerant URL-host parser via `Self.host`.)
    public var dataHost: String? { dataURL.flatMap(Self.host(ofURL:)) }

    /// Host portion of the referring/origin URL, lowercased.
    public var originHost: String? { originURL.flatMap(Self.host(ofURL:)) }

    /// Leaf filename of the downloaded data URL (handles `/` separators and
    /// strips any query/fragment), or nil.
    public var dataLeaf: String? {
        guard let dataURL, !dataURL.isEmpty else { return nil }
        // Drop query/fragment, then take the last path component — but never the
        // scheme or host. For "scheme://host/a/b/file" the `://` yields an empty
        // segment that omitting drops, leaving [scheme:, host, a, b, file], so a
        // genuine leaf only exists at index >= 2 (count >= 3). A bare
        // "scheme://host/" has no leaf.
        let stripped = dataURL.split(separator: "?").first.map(String.init) ?? dataURL
        let noFragment = stripped.split(separator: "#").first.map(String.init) ?? stripped
        let parts = noFragment.split(separator: "/", omittingEmptySubsequences: true)
        guard parts.count >= 3, let last = parts.last else { return nil }
        return String(last)
    }

    /// Best single label for a row: the downloaded file leaf, else its URL,
    /// else the agent.
    public var displayTitle: String {
        if let leaf = dataLeaf { return leaf }
        if let dataURL, !dataURL.isEmpty { return dataURL }
        return agentName ?? "Quarantined download"
    }

    /// Extract a lowercased host from a URL. Tolerant of the percent-encoded,
    /// occasionally-malformed URLs found in provenance stores: tries
    /// `URLComponents` first, then a manual `scheme://host/…` split.
    public static func host(ofURL url: String) -> String? {
        if let h = URLComponents(string: url)?.host, !h.isEmpty { return h.lowercased() }
        guard let schemeRange = url.range(of: "://") else { return nil }
        let afterScheme = url[schemeRange.upperBound...]
        let hostPart = afterScheme.prefix { $0 != "/" && $0 != "?" && $0 != "#" }
        let noUser = hostPart.split(separator: "@").last ?? hostPart
        let noPort = noUser.split(separator: ":").first ?? noUser
        let h = noPort.lowercased()
        return h.isEmpty ? nil : String(h)
    }
}
