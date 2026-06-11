import Foundation

/// A **threat-intel** tier provider backed by a local *known-bad* hash set: the
/// dual of `NSRLProvider`. Where NSRL emits `.knownGood` to short-circuit the
/// cascade for benign files, this provider emits `.malicious` for a hash the
/// analyst (or an org feed export) has flagged as confirmed bad. It sits at
/// `CTITier.threatIntel` — queried after NSRL's known-good filter but before any
/// third-party (VirusTotal) call, so a local hit avoids a network round-trip.
///
/// Hash-only by design: `supports` returns true *only* for `.hash`. IPs, domains
/// and URLs have no known-bad-hash tier and fall straight through to the next
/// provider.
///
/// **Opt-in / fail-open:** an empty set (no hash list loaded) means every
/// `lookup` returns nil — the provider is a silent no-op the cascade skips, so a
/// caller who hasn't configured a known-bad list pays nothing and leaks nothing.
public nonisolated struct KnownBadHashProvider: CTIProvider {
    public let name = "Known-Bad Hashes"
    public let tier: CTITier = .threatIntel

    /// Normalised (lowercased, trimmed) malicious hashes. md5/sha1/sha256 are all
    /// welcome — membership is a plain string match, so any digest width works as
    /// long as the looked-up hash is normalised the same way.
    public let hashes: Set<String>

    /// Injectable clock so tests can stamp a fixed `retrievedAt`.
    private let now: @Sendable () -> Date

    /// In-memory init (tests + a caller that already holds the set).
    public init(hashes: Set<String>, now: @escaping @Sendable () -> Date = { Date() }) {
        self.hashes = Set(hashes.map(Self.normalise))
        self.now = now
    }

    /// Load a newline-delimited hash file: one hash per line, blank lines and `#`
    /// comments ignored, everything lowercased/trimmed (identical format to the
    /// NSRL loader). File I/O is wrapped in `try?` — an unreadable/missing file
    /// yields an **empty** set (a no-op provider) rather than throwing, keeping
    /// the cascade fail-open.
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
            // Not in the known-bad set: this provider has *nothing definitive* to
            // say. Return nil (NOT `.unknown`) so the engine keeps cascading to
            // the next tier — absence from a local bad list is not evidence of
            // goodness.
            return nil
        }
        return verdict(.malicious, for: indicator, kind: kind,
                       detail: "In known-bad hash set", at: now())
    }

    // MARK: - Pure helpers

    /// Normalise one hash token the same way the set is built: trim whitespace,
    /// lowercase. (No hex validation — a feed export can carry odd rows; a
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
