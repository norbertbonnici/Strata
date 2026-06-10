import Foundation

/// The tiered CTI waterfall: NSRL → MISP/OpenCTI → VirusTotal. For each
/// indicator it walks the configured providers in ascending tier order and
/// **short-circuits on the first definitive verdict**, so a hash that NSRL
/// knows is good never reaches MISP/VT, and an indicator MISP confirms
/// malicious never costs a (rate-limited / paid) VirusTotal call.
///
/// Design points realised here:
///  - **Cache first** — a previously resolved indicator returns instantly.
///  - **Provenance** — every verdict carries its producing tier/source.
///  - **Opt-in / fail-open** — an unconfigured provider returns nil and is
///    skipped; a provider error is non-fatal (cascade continues).
///  - Indicators with no resolved verdict get a synthesised `.unknown` so the
///    UI can show "checked, nothing found" vs. "never checked".
public nonisolated struct EnrichmentEngine: Sendable {
    /// Providers in query order (sorted by tier ascending at init).
    public let providers: [any CTIProvider]
    public let cache: EnrichmentCache
    /// Injectable clock (tests pass a fixed instant; the app uses `Date.init`).
    private let now: @Sendable () -> Date

    public init(providers: [any CTIProvider], cache: EnrichmentCache = EnrichmentCache(),
                now: @escaping @Sendable () -> Date = { Date() }) {
        self.providers = providers.sorted { $0.tier < $1.tier }
        self.cache = cache
        self.now = now
    }

    /// Resolve one indicator through the waterfall. Returns the definitive
    /// verdict if any tier produced one, else the last non-definitive result,
    /// else a synthesised `.unknown`. Always writes the result to the cache.
    public func enrich(_ indicator: String, kind: IOCKind) async -> EnrichmentVerdict {
        if let hit = await cache.cached(kind: kind, value: indicator) { return hit }

        var fallback: EnrichmentVerdict?
        for provider in providers where provider.supports(kind) {
            guard let v = await provider.lookup(indicator, kind: kind) else { continue }
            if v.verdict.isDefinitive {
                await cache.put(v)
                return v
            }
            // Keep the most informative non-definitive result (unknown over error).
            if fallback == nil || (fallback?.verdict == .error && v.verdict == .unknown) {
                fallback = v
            }
        }
        let result = fallback ?? EnrichmentVerdict(
            indicator: indicator, kind: kind, verdict: .unknown,
            source: "—", tier: .nsrl, detail: "No configured source had a verdict.",
            retrievedAt: now())
        await cache.put(result)
        return result
    }

    /// Enrich many indicators with bounded concurrency, returning every verdict.
    /// De-dupes by (kind,value) first so the same indicator isn't fetched twice.
    public func enrichAll(_ indicators: [(value: String, kind: IOCKind)],
                          maxConcurrent: Int = 8) async -> [EnrichmentVerdict] {
        var seen = Set<String>()
        let unique = indicators.filter { seen.insert(EnrichmentVerdict.key(kind: $0.kind, value: $0.value)).inserted }
        var out: [EnrichmentVerdict] = []
        var index = 0
        while index < unique.count {
            let slice = unique[index..<min(index + maxConcurrent, unique.count)]
            let batch = await withTaskGroup(of: EnrichmentVerdict.self) { group in
                for item in slice {
                    group.addTask { await self.enrich(item.value, kind: item.kind) }
                }
                var results: [EnrichmentVerdict] = []
                for await v in group { results.append(v) }
                return results
            }
            out.append(contentsOf: batch)
            index += maxConcurrent
        }
        return out
    }
}
