import Foundation

/// Thread-safe verdict cache so a given indicator is looked up at most once per
/// session (and persists per-case + globally). Keyed by `EnrichmentVerdict.key`
/// (kind + normalised value). An actor so concurrent enrichment tasks can share
/// it without races.
public actor EnrichmentCache {
    private var store: [String: EnrichmentVerdict]

    /// Seed from previously persisted verdicts (per-case `enrichment.json` +
    /// any global cache).
    public init(seed: [EnrichmentVerdict] = []) {
        store = Dictionary(seed.map { ($0.id, $0) }, uniquingKeysWith: { _, new in new })
    }

    public func cached(kind: IOCKind, value: String) -> EnrichmentVerdict? {
        store[EnrichmentVerdict.key(kind: kind, value: value)]
    }

    public func put(_ verdict: EnrichmentVerdict) {
        store[verdict.id] = verdict
    }

    /// All cached verdicts (for persistence / display).
    public func snapshot() -> [EnrichmentVerdict] {
        Array(store.values)
    }

    public var count: Int { store.count }
}
