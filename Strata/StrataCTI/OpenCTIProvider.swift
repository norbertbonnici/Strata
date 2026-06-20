import Foundation

/// Self-hosted **OpenCTI** threat-intel provider (waterfall tier `.threatIntel`,
/// alongside MISP). Queries the platform's GraphQL endpoint — `POST
/// {baseURL}/graphql` with `Authorization: Bearer <token>` — for a STIX cyber
/// observable matching the indicator, and reads the `x_opencti_score` of any
/// attached indicator to derive a verdict.
///
/// Design (mirrors the other network providers):
///  - **Opt-in / fail-closed**: missing `baseURL` *or* `token` ⇒ `lookup`
///    returns nil immediately, no network, so the cascade silently skips us.
///  - **Injectable transport**: the live `URLSession` call is behind a
///    `Transport` closure so tests drive the decoder with a fixture body and
///    never touch the network.
///  - **Pure decoder**: `decode(_:indicator:kind:at:)` is a static, side-effect
///    free function over the raw GraphQL response — unit-tested directly.
public nonisolated struct OpenCTIProvider: CTIProvider {
    public let name = "OpenCTI"
    public let tier: CTITier = .threatIntel

    /// Platform base URL (e.g. `https://opencti.example.org`). Nil ⇒ unconfigured.
    public let baseURL: URL?
    /// API token (Bearer). Nil/empty ⇒ unconfigured.
    public let token: String?
    /// Injectable HTTP transport: returns (body, statusCode) or nil on failure.
    private let fetch: Transport
    /// Injectable clock so verdicts get a deterministic `retrievedAt` in tests.
    private let now: @Sendable () -> Date

    public init(baseURL: URL?, token: String?,
                fetch: @escaping Transport = OpenCTIProvider.liveTransport,
                now: @escaping @Sendable () -> Date = { Date() }) {
        self.baseURL = baseURL
        // Treat an all-whitespace token as "not configured".
        let t = token?.trimmingCharacters(in: .whitespacesAndNewlines)
        self.token = (t?.isEmpty == false) ? t : nil
        self.fetch = fetch
        self.now = now
    }

    /// OpenCTI resolves observables for hashes, IPs, domains, and URLs.
    public func supports(_ kind: IOCKind) -> Bool {
        switch kind {
        case .hash, .ip, .domain, .url: return true
        }
    }

    public func lookup(_ indicator: String, kind: IOCKind) async -> EnrichmentVerdict? {
        // Opt-in: no base URL or no token ⇒ no network, keep cascading.
        guard let baseURL, let token, supports(kind) else { return nil }
        let value = indicator.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !value.isEmpty else { return nil }

        guard let request = Self.makeRequest(baseURL: baseURL, token: token,
                                             indicator: value, kind: kind) else { return nil }

        guard let (body, status) = await fetch(request) else {
            // Network/transport failure ⇒ non-definitive error, cascade continues.
            return verdict(.error, for: indicator, kind: kind,
                           detail: "OpenCTI request failed.", at: now())
        }
        guard (200...299).contains(status) else {
            return verdict(.error, for: indicator, kind: kind,
                           detail: "OpenCTI returned HTTP \(status).", at: now())
        }
        // Hand the raw body to the pure decoder (passing the configured baseURL so
        // it can build the dashboard deep link). A nil decode (malformed envelope)
        // becomes a non-definitive error so the cascade keeps going.
        return Self.decode(body, indicator: indicator, kind: kind, at: now(), baseURL: baseURL)
            ?? verdict(.error, for: indicator, kind: kind,
                       detail: "OpenCTI response was unparseable.", at: now())
    }

    // MARK: - Verdict stamping reference

    /// Deep link to the observable in the OpenCTI dashboard.
    static func reference(baseURL: URL, observableID: String) -> String {
        let base = baseURL.absoluteString.hasSuffix("/")
            ? String(baseURL.absoluteString.dropLast())
            : baseURL.absoluteString
        return "\(base)/dashboard/observations/observables/\(observableID)"
    }
}

// MARK: - Transport

public extension OpenCTIProvider {
    /// HTTP transport seam: maps a request to `(responseBody, statusCode)`, or
    /// nil when the call itself failed. Tests inject a closure returning a
    /// fixture; production uses `liveTransport`.
    typealias Transport = @Sendable (URLRequest) async -> (Data, Int)?

    /// The default, real `URLSession` transport. Kept tiny + isolated so it's
    /// obvious this is the only place live HTTP happens.
    static let liveTransport: Transport = { request in
        guard let (data, response) = try? await URLSession.shared.data(for: request),
              let http = response as? HTTPURLResponse else { return nil }
        return (data, http.statusCode)
    }
}

// MARK: - Request building

extension OpenCTIProvider {
    /// Build the `POST {baseURL}/graphql` request: Bearer auth + a JSON body
    /// carrying a minimal `stixCyberObservables` query filtered by value.
    static func makeRequest(baseURL: URL, token: String,
                            indicator: String, kind: IOCKind) -> URLRequest? {
        let endpoint = baseURL.appendingPathComponent("graphql")
        var request = URLRequest(url: endpoint)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")

        let payload: [String: Any] = [
            "query": graphQLQuery(for: kind, value: indicator),
            "variables": ["value": indicator],
        ]
        guard let data = try? JSONSerialization.data(withJSONObject: payload) else { return nil }
        request.httpBody = data
        return request
    }

    /// STIX observable types we filter on, per indicator kind. (IPs match either
    /// IPv4 or IPv6 observables.)
    static func observableTypes(for kind: IOCKind) -> [String] {
        switch kind {
        case .hash:   return ["StixFile", "Artifact"]
        case .ip:     return ["IPv4-Addr", "IPv6-Addr"]
        case .domain: return ["Domain-Name", "Hostname"]
        case .url:    return ["Url"]
        }
    }

    /// A minimal GraphQL query: filter `stixCyberObservables` by observable value
    /// (hashes match any of the File hash fields), requesting the id, value, and
    /// each attached indicator's `x_opencti_score` + `indicator_types`.
    static func graphQLQuery(for kind: IOCKind, value: String) -> String {
        // For hashes the filter key is the specific `hashes.<ALGO>` subfield, keyed
        // off the digest length — a single `.hash` IOCKind covers MD5/SHA-1/SHA-256,
        // and filtering every digest against `hashes.MD5` silently never matches a
        // SHA-1/SHA-256 (the dominant DFIR hash). Everything else filters `value`.
        let filterKey: String
        if kind == .hash {
            switch value.count {
            case 64: filterKey = "hashes.SHA-256"
            case 40: filterKey = "hashes.SHA-1"
            default: filterKey = "hashes.MD5"   // 32-hex MD5, or unknown length
            }
        } else {
            filterKey = "value"
        }
        let types = observableTypes(for: kind)
            .map { "\"\($0)\"" }
            .joined(separator: ", ")
        return """
        query StrataObservableLookup($value: Any!) {
          stixCyberObservables(
            filters: {
              mode: and
              filterGroups: []
              filters: [
                { key: "entity_type", values: [\(types)], mode: or }
                { key: "\(filterKey)", values: [$value] }
              ]
            }
            first: 5
          ) {
            edges {
              node {
                id
                entity_type
                observable_value
                indicators {
                  edges {
                    node {
                      id
                      x_opencti_score
                      indicator_types
                    }
                  }
                }
              }
            }
          }
        }
        """
    }
}

// MARK: - Pure decoder

extension OpenCTIProvider {
    /// Parse a raw OpenCTI GraphQL response into an `EnrichmentVerdict`.
    ///
    /// Walks `data.stixCyberObservables.edges[].node` and across every returned
    /// observable's indicators takes the **highest** `x_opencti_score`:
    ///   - `>= 80` → `.malicious` (score/100)
    ///   - `50...79` → `.suspicious` (score/100)
    ///   - present but `< 50` → `.unknown` (looked up, not actionable)
    /// An observable with no scored indicator, or no matching observable at all,
    /// → `.unknown`. `detail` summarises the score + indicator types; `reference`
    /// (when a `baseURL` is supplied) deep-links to the observable in the OpenCTI
    /// dashboard.
    ///
    /// Returns nil **only** when `body` is not a decodable GraphQL envelope
    /// (missing/non-object `data`), so the live provider can record a transport
    /// error and the cascade keeps going. This is the pure, side-effect-free core
    /// the tests exercise directly.
    public static func decode(_ body: Data, indicator: String, kind: IOCKind,
                              at now: Date, baseURL: URL? = nil) -> EnrichmentVerdict? {
        guard
            let root = try? JSONSerialization.jsonObject(with: body) as? [String: Any],
            let data = root["data"] as? [String: Any],
            let observables = data["stixCyberObservables"] as? [String: Any],
            let edges = observables["edges"] as? [[String: Any]]
        else { return nil }

        // Reduce to the best (highest-scored) indicator across all returned
        // observables, remembering which observable carried it (for the deep link).
        var bestScore: Int? = nil
        var bestTypes: [String] = []
        var firstObservableID: String? = nil
        var scoredObservableID: String? = nil
        var sawAnyIndicator = false

        for edge in edges {
            guard let node = edge["node"] as? [String: Any] else { continue }
            let id = node["id"] as? String
            if firstObservableID == nil { firstObservableID = id }

            guard
                let indicators = node["indicators"] as? [String: Any],
                let indEdges = indicators["edges"] as? [[String: Any]]
            else { continue }

            for indEdge in indEdges {
                guard let indNode = indEdge["node"] as? [String: Any] else { continue }
                sawAnyIndicator = true
                let types = (indNode["indicator_types"] as? [String]) ?? []
                guard let score = intScore(indNode["x_opencti_score"]) else { continue }
                if bestScore == nil || score > bestScore! {
                    bestScore = score
                    bestTypes = types
                    scoredObservableID = id
                }
            }
        }

        // No matching observable at all → unknown (checked, nothing found).
        if edges.isEmpty {
            return EnrichmentVerdict(
                indicator: indicator, kind: kind, verdict: .unknown,
                source: "OpenCTI", tier: .threatIntel,
                detail: "No OpenCTI observable matched.", reference: nil, retrievedAt: now)
        }

        let referenceID = scoredObservableID ?? firstObservableID
        let reference = reference(baseURL: baseURL, observableID: referenceID)
        let detail = describe(score: bestScore, types: bestTypes, sawAnyIndicator: sawAnyIndicator)

        guard let score = bestScore else {
            // Observable exists but no scored indicator → unknown.
            return EnrichmentVerdict(
                indicator: indicator, kind: kind, verdict: .unknown,
                source: "OpenCTI", tier: .threatIntel,
                detail: detail, reference: reference, retrievedAt: now)
        }

        let verdict: ThreatVerdict
        if score >= 80 { verdict = .malicious }
        else if score >= 50 { verdict = .suspicious }
        else { verdict = .unknown }

        // Native score only carries confidence when it informed an actionable verdict.
        let nativeScore = (verdict == .unknown) ? nil : Double(score) / 100.0

        return EnrichmentVerdict(
            indicator: indicator, kind: kind, verdict: verdict, score: nativeScore,
            source: "OpenCTI", tier: .threatIntel, detail: detail,
            reference: reference, retrievedAt: now)
    }

    /// `x_opencti_score` can arrive as Int, Double, numeric String, or NSNumber.
    static func intScore(_ raw: Any?) -> Int? {
        switch raw {
        case let n as Int:      return n
        // intExact, not Int(d): a hostile/MITM'd score (1e308 / NaN) would trap.
        case let d as Double:   return intExact(d.rounded())
        case let n as NSNumber: return n.intValue
        case let s as String:   return Int(s)
        default:                return nil
        }
    }

    private static func describe(score: Int?, types: [String], sawAnyIndicator: Bool) -> String {
        let typePart = types.isEmpty ? "" : " (\(types.joined(separator: ", ")))"
        if let score {
            return "OpenCTI indicator score \(score)/100\(typePart)."
        }
        return sawAnyIndicator
            ? "OpenCTI observable found; indicator carried no score."
            : "OpenCTI observable found with no indicators."
    }

    /// Dashboard deep link — nil when we have neither a base URL nor an observable id.
    static func reference(baseURL: URL?, observableID: String?) -> String? {
        guard let baseURL, let observableID, !observableID.isEmpty else { return nil }
        return reference(baseURL: baseURL, observableID: observableID)
    }
}
