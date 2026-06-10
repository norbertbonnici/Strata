import Foundation

/// `.threatIntel`-tier provider backed by a **self-hosted MISP** instance.
///
/// MISP is an org-controlled threat-sharing platform, so it sits in the
/// confidentiality-friendly middle tier of the waterfall (NSRL → **MISP /
/// OpenCTI** → VirusTotal): a hit here records a definitive verdict and spares
/// the case a (rate-limited / paid) VirusTotal call.
///
/// Looks an indicator up via `POST {baseURL}/attributes/restSearch` with the
/// API key in the `Authorization` header. The provider is **opt-in**: with no
/// `baseURL` or no `token` configured, `lookup` returns nil immediately and
/// never touches the network, so evidence/IOCs never leave the host unless the
/// analyst has explicitly wired MISP up.
///
/// The wire decode lives in a **pure, static** `decode(_:indicator:kind:at:)`
/// so the verdict logic is unit-testable without any I/O; the only impure part
/// is the injectable `Transport`, which tests replace with a fixture closure.
public nonisolated struct MISPProvider: CTIProvider {
    /// Injectable HTTP transport. Returns `(responseBody, httpStatusCode)`, or
    /// nil on a transport failure (DNS/TLS/timeout) so `lookup` can fail-open
    /// to `.error`. The default performs the real `URLSession` request; tests
    /// pass a closure that returns a canned fixture and status.
    public typealias Transport = @Sendable (URLRequest) async -> (Data, Int)?

    public let name = "MISP"
    public let tier: CTITier = .threatIntel

    /// Base URL of the MISP instance, e.g. `https://misp.example.org`. nil ⇒
    /// unconfigured ⇒ `lookup` is a no-op.
    public let baseURL: URL?
    /// MISP API key (the value of the `Authorization` header). nil/empty ⇒
    /// unconfigured ⇒ `lookup` is a no-op.
    public let token: String?

    private let fetch: Transport

    public init(baseURL: URL?, token: String?, fetch: @escaping Transport = MISPProvider.liveTransport) {
        self.baseURL = baseURL
        self.token = token
        self.fetch = fetch
    }

    /// The real network transport. Kept as an obvious, isolated `static` so the
    /// default in `init` reads as "do the live URLSession call".
    public static let liveTransport: Transport = { request in
        guard let (data, response) = try? await URLSession.shared.data(for: request),
              let http = response as? HTTPURLResponse else { return nil }
        return (data, http.statusCode)
    }

    /// MISP attribute types cover hashes (md5/sha1/sha256/filename|hash…), IPs
    /// (ip-src/ip-dst), domains, and URLs — all four IOC kinds.
    public func supports(_ kind: IOCKind) -> Bool {
        switch kind {
        case .hash, .ip, .domain, .url: return true
        }
    }

    public func lookup(_ indicator: String, kind: IOCKind) async -> EnrichmentVerdict? {
        // Opt-in gate: unconfigured ⇒ no network, no verdict (keep cascading).
        guard let base = baseURL,
              let token, !token.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
        else { return nil }

        guard let request = Self.makeRequest(base: base, token: token, indicator: indicator) else {
            return nil
        }

        let now = Date()
        guard let (body, status) = await fetch(request) else {
            // Transport failure (DNS/TLS/timeout): non-definitive, cascade on.
            return verdict(.error, for: indicator, kind: kind,
                           detail: "MISP request failed (no response).", at: now)
        }
        guard (200...299).contains(status) else {
            return verdict(.error, for: indicator, kind: kind,
                           detail: "MISP returned HTTP \(status).", at: now)
        }

        // Pure decode of the response body into a provenance-stamped verdict.
        return Self.decode(body, indicator: indicator, kind: kind, at: now)
            ?? verdict(.error, for: indicator, kind: kind,
                       detail: "MISP response could not be parsed.", at: now)
    }

    // MARK: - Request construction (pure)

    /// Build the `restSearch` POST. Body: `{"value": <ind>, "limit": 25,
    /// "returnFormat": "json"}`; headers carry the API key + JSON content
    /// negotiation. Returns nil only if the body can't be encoded.
    static func makeRequest(base: URL, token: String, indicator: String) -> URLRequest? {
        let endpoint = base.appendingPathComponent("attributes").appendingPathComponent("restSearch")
        var request = URLRequest(url: endpoint)
        request.httpMethod = "POST"
        request.setValue(token, forHTTPHeaderField: "Authorization")
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")

        let payload: [String: Any] = [
            "value": indicator,
            "limit": 25,
            "returnFormat": "json"
        ]
        guard let data = try? JSONSerialization.data(withJSONObject: payload) else { return nil }
        request.httpBody = data
        return request
    }

    // MARK: - Pure decoder

    /// Decode a MISP `restSearch` JSON body into a verdict. Pure — no I/O, no
    /// clock (the caller supplies `now`), so it's the unit-test seam.
    ///
    /// Verdict rules:
    ///  - Walk `response.Attribute[]`; keep the attributes whose `value` (or
    ///    a composite `a|b` value's parts) equals the looked-up indicator
    ///    (case-insensitive). If none match by value we still treat any
    ///    returned attribute as a hit (MISP only returns matches), but the
    ///    explicit value match lets us pick the most relevant one.
    ///  - A matching attribute with `to_ids == true`, **or** any of its / its
    ///    event's tags containing a threat marker (`malicious`, `tlp`, or a
    ///    `type:OSINT`-style malicious tag), ⇒ `.malicious`.
    ///  - A matching attribute with `to_ids == false` and no threat tag ⇒
    ///    `.suspicious` (present in intel, not actioned).
    ///  - No `Attribute` entries ⇒ `.unknown` (looked up, nothing known).
    ///
    /// `reference` is the **relative** event link `/events/view/{event_id}` when
    /// an `event_id` is present (kept relative so the decoder stays pure and
    /// baseURL-free; the UI resolves it against the configured instance).
    public static func decode(_ body: Data, indicator: String, kind: IOCKind,
                              at now: Date) -> EnrichmentVerdict? {
        guard let root = try? JSONSerialization.jsonObject(with: body) as? [String: Any] else {
            return nil
        }
        // `restSearch` wraps results under "response"; some deployments return
        // the object directly — accept both shapes.
        let container = (root["response"] as? [String: Any]) ?? root
        guard let attributes = container["Attribute"] as? [[String: Any]] else {
            // Malformed: no Attribute array at all → can't decode.
            return nil
        }

        // Empty Attribute set: looked up, MISP knows nothing.
        guard !attributes.isEmpty else {
            return EnrichmentVerdict(
                indicator: indicator, kind: kind, verdict: .unknown,
                source: "MISP", tier: .threatIntel,
                detail: "No matching MISP attributes.", reference: nil, retrievedAt: now)
        }

        let needle = indicator.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()

        // Prefer an attribute whose value matches the indicator; else fall back
        // to the first attribute (MISP only returns hits for the queried value).
        let matched = attributes.first(where: { attributeMatches($0, needle: needle) })
        let chosen = matched ?? attributes[0]

        let toIds = boolValue(chosen["to_ids"])
        let tags = collectTags(attribute: chosen)
        let hasThreatTag = tags.contains { isThreatTag($0) }
        let verdict: ThreatVerdict = (toIds || hasThreatTag) ? .malicious : .suspicious

        let eventID = stringValue(chosen["event_id"])
        let category = stringValue(chosen["category"])
        let type = stringValue(chosen["type"])
        let eventInfo = eventInfo(for: chosen)

        var parts: [String] = []
        if let info = eventInfo, !info.isEmpty { parts.append("Event: \(info)") }
        if let category, let type { parts.append("\(category)/\(type)") }
        else if let type { parts.append(type) }
        if !tags.isEmpty { parts.append("tags: \(tags.prefix(4).joined(separator: ", "))") }
        parts.append(toIds ? "to_ids set" : "to_ids unset")
        let detail = parts.joined(separator: " · ")

        // reference deep-links to the MISP event when we know its id. We don't
        // have baseURL in this pure decoder, so we emit a relative reference the
        // UI can resolve against the configured instance.
        let reference = eventID.map { "/events/view/\($0)" }

        return EnrichmentVerdict(
            indicator: indicator, kind: kind, verdict: verdict,
            source: "MISP", tier: .threatIntel,
            detail: detail, reference: reference, retrievedAt: now)
    }

    // MARK: - Decode helpers (pure)

    /// Does this attribute reference the looked-up indicator? Matches the raw
    /// `value`, and the `a|b` halves of a composite value (e.g. `filename|sha256`).
    private static func attributeMatches(_ attribute: [String: Any], needle: String) -> Bool {
        guard let value = stringValue(attribute["value"])?.lowercased() else { return false }
        if value == needle { return true }
        return value.split(separator: "|").contains { String($0) == needle }
    }

    /// A threat-bearing tag: explicit `malicious`, any TLP marking (presence of
    /// a TLP tag implies curated/shared intel), or a misp-galaxy/threat marking.
    private static func isThreatTag(_ tag: String) -> Bool {
        let t = tag.lowercased()
        return t.contains("malicious") || t.contains("tlp")
            || t.contains("threat") || t.hasPrefix("misp-galaxy")
    }

    /// Gather tag names from the attribute and its embedding event (both places
    /// MISP attaches `Tag[].name`).
    private static func collectTags(attribute: [String: Any]) -> [String] {
        var out: [String] = []
        out.append(contentsOf: tagNames(attribute["Tag"]))
        if let event = attribute["Event"] as? [String: Any] {
            out.append(contentsOf: tagNames(event["Tag"]))
        }
        // De-dupe preserving order.
        var seen = Set<String>()
        return out.filter { seen.insert($0.lowercased()).inserted }
    }

    private static func tagNames(_ raw: Any?) -> [String] {
        guard let tags = raw as? [[String: Any]] else { return [] }
        return tags.compactMap { stringValue($0["name"]) }
    }

    private static func eventInfo(for attribute: [String: Any]) -> String? {
        if let event = attribute["Event"] as? [String: Any] {
            return stringValue(event["info"])
        }
        return nil
    }

    /// MISP serialises booleans as `true`/`false`, `1`/`0`, or `"1"`/`"0"`.
    private static func boolValue(_ raw: Any?) -> Bool {
        if let b = raw as? Bool { return b }
        if let n = raw as? NSNumber { return n.boolValue }
        if let s = raw as? String { return s == "1" || s.lowercased() == "true" }
        return false
    }

    private static func stringValue(_ raw: Any?) -> String? {
        if let s = raw as? String { return s }
        if let n = raw as? NSNumber { return n.stringValue }
        return nil
    }
}
