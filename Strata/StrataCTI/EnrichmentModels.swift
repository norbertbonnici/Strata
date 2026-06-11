import Foundation

/// The verdict a CTI lookup returns for one indicator. Ordered by "how much it
/// should stop the cascade": a `knownGood` (NSRL) or a `malicious`/`suspicious`
/// (threat-intel/VT) is **definitive** and short-circuits further lookups;
/// `unknown`/`error` let the cascade fall through to the next tier.
public nonisolated enum ThreatVerdict: String, Codable, Sendable, Hashable, CaseIterable {
    case knownGood     // allowlisted (NSRL) — definitively benign
    case malicious     // confirmed bad
    case suspicious    // flagged, lower confidence
    case unknown       // looked up, nothing known
    case error         // the lookup itself failed (network/auth/rate-limit)

    public var label: String {
        switch self {
        case .knownGood:  return "Known good"
        case .malicious:  return "Malicious"
        case .suspicious: return "Suspicious"
        case .unknown:    return "Unknown"
        case .error:      return "Lookup error"
        }
    }

    /// A verdict that ends the waterfall — we don't query slower/costlier tiers
    /// once we have one. (`unknown`/`error` are not definitive: keep cascading.)
    public var isDefinitive: Bool {
        self == .knownGood || self == .malicious || self == .suspicious
    }
}

/// The waterfall tiers, in query order. Lower rawValue = queried first =
/// cheaper / more org-controlled. The cascade walks these ascending and stops
/// on the first definitive verdict, minimising third-party (VirusTotal) calls.
public nonisolated enum CTITier: Int, Codable, Sendable, Comparable, CaseIterable {
    case nsrl = 0           // local known-good hash set (no network)
    case threatIntel = 1    // self-hosted MISP / OpenCTI (org-controlled)
    case virusTotal = 2     // third-party, rate-limited / paid — last resort

    public static func < (l: CTITier, r: CTITier) -> Bool { l.rawValue < r.rawValue }

    public var label: String {
        switch self {
        case .nsrl:        return "NSRL"
        case .threatIntel: return "Threat Intel"
        case .virusTotal:  return "VirusTotal"
        }
    }
}

/// A single enrichment result with full **provenance** — which tier/source
/// produced the verdict and when. This is the field `IOCMatch` lacked; an
/// `EnrichmentVerdict` is stored per indicator (value+kind) and joined to
/// matches/IOCs/file hashes in the UI.
public nonisolated struct EnrichmentVerdict: Identifiable, Hashable, Sendable, Codable {
    /// Stable identity: one verdict per (kind, normalised value).
    public var id: String { Self.key(kind: kind, value: indicator) }

    public let indicator: String       // the looked-up value (as provided)
    public let kind: IOCKind
    public let verdict: ThreatVerdict
    public let score: Double?          // provider-native confidence/ratio (0…1) when available
    public let source: String          // provider display name, e.g. "VirusTotal"
    public let tier: CTITier           // which tier produced this
    public let detail: String          // human-readable summary (e.g. "54/72 engines flagged")
    public let reference: String?      // deep link to the provider record
    public let retrievedAt: Date

    public init(indicator: String, kind: IOCKind, verdict: ThreatVerdict,
                score: Double? = nil, source: String, tier: CTITier,
                detail: String = "", reference: String? = nil, retrievedAt: Date) {
        self.indicator = indicator; self.kind = kind; self.verdict = verdict
        self.score = score; self.source = source; self.tier = tier
        self.detail = detail; self.reference = reference; self.retrievedAt = retrievedAt
    }

    /// Cache/identity key: kind + lowercased, trimmed value.
    public static func key(kind: IOCKind, value: String) -> String {
        "\(kind.rawValue):\(value.trimmingCharacters(in: .whitespacesAndNewlines).lowercased())"
    }
}
