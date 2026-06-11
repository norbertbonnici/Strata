import Foundation

/// A single enrichment source (one waterfall tier). Implementations are pure
/// w.r.t. Strata state — they take an indicator, do their own I/O (local hash
/// set, REST, GraphQL), and return a provenance-stamped verdict (or nil when
/// they have nothing / aren't configured).
///
/// All CTI is **opt-in**: a provider that isn't configured (no NSRL set loaded,
/// no token in the Keychain) returns nil from `lookup` and is effectively a
/// no-op, so the cascade silently skips it. Evidence/IOCs never leave the host
/// unless a network provider is explicitly enabled and configured.
public protocol CTIProvider: Sendable {
    /// Display name recorded as the verdict's `source`.
    nonisolated var name: String { get }
    /// Which waterfall tier this provider occupies.
    nonisolated var tier: CTITier { get }
    /// Whether this provider can resolve the given indicator kind. NSRL is
    /// hash-only; the others take hash/ip/domain/url.
    nonisolated func supports(_ kind: IOCKind) -> Bool
    /// Look up one indicator. Returns nil when the provider is unconfigured or
    /// has nothing to say (treated as "keep cascading"). A definitive verdict
    /// (`.knownGood`/`.malicious`/`.suspicious`) stops the waterfall.
    nonisolated func lookup(_ indicator: String, kind: IOCKind) async -> EnrichmentVerdict?
}

public extension CTIProvider {
    /// Convenience to stamp a verdict with this provider's identity + now.
    nonisolated func verdict(_ v: ThreatVerdict, for indicator: String, kind: IOCKind,
                             score: Double? = nil, detail: String = "", reference: String? = nil,
                             at now: Date) -> EnrichmentVerdict {
        EnrichmentVerdict(indicator: indicator, kind: kind, verdict: v, score: score,
                          source: name, tier: tier, detail: detail,
                          reference: reference, retrievedAt: now)
    }
}
