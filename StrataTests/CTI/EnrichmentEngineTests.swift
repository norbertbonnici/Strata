import Testing
import Foundation
@testable import Strata

/// Locks the CTI waterfall semantics: tier ordering, short-circuit on a
/// definitive verdict, cache reuse, provenance, and kind support filtering.
struct EnrichmentEngineTests {
    private static let now = Date(timeIntervalSince1970: 1_700_000_000)

    /// A scripted provider that records whether it was queried.
    final class MockProvider: CTIProvider, @unchecked Sendable {
        let name: String
        let tier: CTITier
        let kinds: Set<IOCKind>
        let result: ((String, IOCKind) -> EnrichmentVerdict?)
        private(set) var queried = false

        init(name: String, tier: CTITier, kinds: Set<IOCKind> = [.hash, .ip, .domain, .url],
             result: @escaping (String, IOCKind) -> EnrichmentVerdict?) {
            self.name = name; self.tier = tier; self.kinds = kinds; self.result = result
        }
        func supports(_ kind: IOCKind) -> Bool { kinds.contains(kind) }
        func lookup(_ indicator: String, kind: IOCKind) async -> EnrichmentVerdict? {
            queried = true
            return result(indicator, kind)
        }
    }

    private func v(_ verdict: ThreatVerdict, _ name: String, _ tier: CTITier,
                   indicator: String = "abc", kind: IOCKind = .hash) -> EnrichmentVerdict {
        EnrichmentVerdict(indicator: indicator, kind: kind, verdict: verdict,
                          source: name, tier: tier, retrievedAt: Self.now)
    }

    @Test func nsrlKnownGoodShortCircuitsDownstream() async {
        let nsrl = MockProvider(name: "NSRL", tier: .nsrl) { ind, k in self.v(.knownGood, "NSRL", .nsrl, indicator: ind, kind: k) }
        let vt = MockProvider(name: "VirusTotal", tier: .virusTotal) { ind, k in self.v(.malicious, "VirusTotal", .virusTotal, indicator: ind, kind: k) }
        let engine = EnrichmentEngine(providers: [vt, nsrl], now: { Self.now })  // unsorted input
        let out = await engine.enrich("abc", kind: .hash)
        #expect(out.verdict == .knownGood)
        #expect(out.tier == .nsrl)            // provenance: NSRL produced it
        #expect(nsrl.queried)
        #expect(!vt.queried)                  // VT never reached (the whole point)
    }

    @Test func threatIntelMaliciousStopsBeforeVirusTotal() async {
        let nsrl = MockProvider(name: "NSRL", tier: .nsrl) { _, _ in nil }       // unconfigured
        let misp = MockProvider(name: "MISP", tier: .threatIntel) { ind, k in self.v(.malicious, "MISP", .threatIntel, indicator: ind, kind: k) }
        let vt = MockProvider(name: "VirusTotal", tier: .virusTotal) { ind, k in self.v(.malicious, "VirusTotal", .virusTotal, indicator: ind, kind: k) }
        let engine = EnrichmentEngine(providers: [nsrl, misp, vt], now: { Self.now })
        let out = await engine.enrich("abc", kind: .hash)
        #expect(out.source == "MISP")
        #expect(!vt.queried)
    }

    @Test func unknownFallsThroughToNextTier() async {
        let nsrl = MockProvider(name: "NSRL", tier: .nsrl) { ind, k in self.v(.unknown, "NSRL", .nsrl, indicator: ind, kind: k) }
        let vt = MockProvider(name: "VirusTotal", tier: .virusTotal) { ind, k in self.v(.malicious, "VirusTotal", .virusTotal, indicator: ind, kind: k) }
        let engine = EnrichmentEngine(providers: [nsrl, vt], now: { Self.now })
        let out = await engine.enrich("abc", kind: .hash)
        #expect(out.verdict == .malicious)
        #expect(vt.queried)                   // unknown at NSRL did not short-circuit
    }

    @Test func cacheServesSecondLookupWithoutQuerying() async {
        let cache = EnrichmentCache(seed: [v(.malicious, "VirusTotal", .virusTotal)])
        let vt = MockProvider(name: "VirusTotal", tier: .virusTotal) { ind, k in self.v(.knownGood, "VirusTotal", .virusTotal, indicator: ind, kind: k) }
        let engine = EnrichmentEngine(providers: [vt], cache: cache, now: { Self.now })
        let out = await engine.enrich("abc", kind: .hash)
        #expect(out.verdict == .malicious)    // came from the cache, not the live (knownGood) provider
        #expect(!vt.queried)
    }

    @Test func nsrlHashOnlyIsSkippedForDomains() async {
        let nsrl = MockProvider(name: "NSRL", tier: .nsrl, kinds: [.hash]) { ind, k in self.v(.knownGood, "NSRL", .nsrl, indicator: ind, kind: k) }
        let engine = EnrichmentEngine(providers: [nsrl], now: { Self.now })
        let out = await engine.enrich("evil.example", kind: .domain)
        #expect(out.verdict == .unknown)      // NSRL doesn't support domains → synthesised unknown
        #expect(!nsrl.queried)
    }

    @Test func noConfiguredProviderYieldsUnknownNotCrash() async {
        let engine = EnrichmentEngine(providers: [], now: { Self.now })
        let out = await engine.enrich("1.2.3.4", kind: .ip)
        #expect(out.verdict == .unknown)
        #expect(out.indicator == "1.2.3.4")
    }
}
