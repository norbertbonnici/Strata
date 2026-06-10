import Foundation

/// The **first** waterfall tier: a local known-good *hash* set (NSRL — the NIST
/// National Software Reference Library, or any RDS-style allowlist export). No
/// network, no third-party call — purely a local membership test. A hash that
/// NSRL knows is good is *definitively benign* (`.knownGood`), which
/// short-circuits the whole cascade so it never reaches MISP/OpenCTI or
/// VirusTotal. Doubles as a file-tree noise-reduction source.
///
/// Hash-only by design: `supports` returns true *only* for `.hash`. IPs,
/// domains and URLs have no NSRL tier and fall straight through to the next
/// provider.
///
/// **Opt-in / fail-open:** an empty set (no hash list loaded) means every
/// `lookup` returns nil — the provider is a silent no-op the cascade skips,
/// and no evidence leaves the host.
public nonisolated struct NSRLProvider: CTIProvider {
    public let name = "NSRL"
    public let tier: CTITier = .nsrl

    /// Normalised (lowercased, trimmed) known-good hashes. md5/sha1/sha256 are
    /// all welcome — membership is a plain string match, so any digest width
    /// works as long as the looked-up hash is normalised the same way.
    public let hashes: Set<String>

    /// Injectable clock so tests can stamp a fixed `retrievedAt`.
    private let now: @Sendable () -> Date

    /// In-memory init (tests + a caller that already holds the set).
    public init(hashes: Set<String>, now: @escaping @Sendable () -> Date = { Date() }) {
        self.hashes = Set(hashes.map(Self.normalise))
        self.now = now
    }

    /// Load a newline-delimited hash file: one hash per line, blank lines and
    /// `#` comments ignored, everything lowercased/trimmed. File I/O is wrapped
    /// in `try?` — an unreadable/missing file yields an **empty** set (a no-op
    /// provider) rather than throwing, keeping the cascade fail-open.
    public init(loading fileURL: URL, now: @escaping @Sendable () -> Date = { Date() }) {
        let text = (try? String(contentsOf: fileURL, encoding: .utf8)) ?? ""
        self.hashes = Self.parse(text)
        self.now = now
    }

    public func supports(_ kind: IOCKind) -> Bool { kind == .hash }

    public func lookup(_ indicator: String, kind: IOCKind) async -> EnrichmentVerdict? {
        // Hash-only. Anything else → nil so the cascade keeps going.
        guard kind == .hash else { return nil }
        // Unconfigured (no set loaded) → silent no-op.
        guard !hashes.isEmpty else { return nil }
        guard hashes.contains(Self.normalise(indicator)) else {
            // Not in the allowlist: NSRL has *nothing definitive* to say. Return
            // nil (NOT `.unknown`) so the engine keeps cascading to the next tier
            // — absence from NSRL is not evidence of badness.
            return nil
        }
        return verdict(.knownGood, for: indicator, kind: kind,
                       detail: "In NSRL known-good set", at: now())
    }

    // MARK: - Pure helpers

    /// Normalise one hash token the same way the set is built: trim whitespace,
    /// lowercase. (No hex validation — an RDS export can carry odd rows; a
    /// non-hex line simply never matches a real hash lookup.)
    nonisolated static func normalise(_ s: String) -> String {
        s.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
    }

    /// Pure parser for a newline-delimited hash list (factored out for testing):
    /// drops blank lines and `#` comments, normalises the rest.
    nonisolated static func parse(_ text: String) -> Set<String> {
        var out = Set<String>()
        for rawLine in text.split(whereSeparator: \.isNewline) {
            let line = normalise(String(rawLine))
            if line.isEmpty || line.hasPrefix("#") { continue }
            out.insert(line)
        }
        return out
    }
}
