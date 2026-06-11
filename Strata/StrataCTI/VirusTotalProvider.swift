import Foundation

/// VirusTotal (API v3) enrichment provider — the **third-party, last-resort**
/// tier of the CTI waterfall. It is queried only for indicators that NSRL and
/// the org-controlled threat-intel tier couldn't resolve, minimising calls
/// against VT's rate-limited / paid quota.
///
/// Design (mirrors the other providers, see `CTIProvider`):
///  - **Opt-in.** Without a non-empty API key `lookup` returns nil *before any
///    network I/O* — evidence never leaves the host unless explicitly enabled.
///  - **Pure decoder, injectable transport.** All JSON → verdict logic lives in
///    the static `decode(_:indicator:kind:at:)`, unit-tested directly. The HTTP
///    call goes through an injectable `Transport` closure so tests never touch
///    the live API; the default transport does the real `URLSession` call.
///  - **VT clean ≠ NSRL-good.** A VT response with zero detections is *not*
///    `.knownGood` (which is reserved for the NSRL allowlist and short-circuits
///    the cascade). VT "clean" maps to `.unknown` so the waterfall semantics
///    stay honest — see the decoder.
public nonisolated struct VirusTotalProvider: CTIProvider {

    /// The injectable network transport: a request in, an optional
    /// (response body, HTTP status code) out. Returns nil on a transport-level
    /// failure (no response / not an HTTP response), which the provider maps to
    /// a non-definitive `.error` so the cascade keeps going. Tests inject a
    /// closure that returns a fixture without hitting the network.
    public typealias Transport = @Sendable (URLRequest) async -> (Data, Int)?

    public let name = "VirusTotal"
    public let tier: CTITier = .virusTotal

    /// The VT API v3 base. Stored so it could be repointed (e.g. a private
    /// gateway) without touching the URL-building code.
    public let baseURL: URL
    /// VT API key. `nil`/empty ⇒ unconfigured ⇒ `lookup` is a no-op (opt-in).
    private let apiKey: String?
    private let transport: Transport
    private let now: @Sendable () -> Date

    public init(apiKey: String?,
                baseURL: URL = URL(string: "https://www.virustotal.com/api/v3")!,
                now: @escaping @Sendable () -> Date = { Date() },
                fetch: @escaping Transport = VirusTotalProvider.liveTransport) {
        self.apiKey = apiKey
        self.baseURL = baseURL
        self.now = now
        self.transport = fetch
    }

    /// The default, real-network transport. Kept in a named static so the live
    /// `URLSession` path is the only place that touches the network and is
    /// obvious / easy to avoid in tests.
    public static let liveTransport: Transport = { request in
        guard let (data, response) = try? await URLSession.shared.data(for: request),
              let http = response as? HTTPURLResponse else { return nil }
        return (data, http.statusCode)
    }

    // VT v3 resolves all four indicator kinds.
    public func supports(_ kind: IOCKind) -> Bool {
        switch kind {
        case .hash, .ip, .domain, .url: return true
        }
    }

    public func lookup(_ indicator: String, kind: IOCKind) async -> EnrichmentVerdict? {
        // Opt-in: no key ⇒ no network, return nil so the cascade silently skips us.
        guard let key = apiKey, !key.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
        else { return nil }

        guard let request = Self.request(indicator: indicator, kind: kind,
                                         baseURL: baseURL, apiKey: key)
        else { return nil }

        guard let (body, status) = await transport(request) else {
            // Transport failure (offline / non-HTTP): non-definitive error,
            // keep cascading (though VT is normally the last tier).
            return verdict(.error, for: indicator, kind: kind,
                           detail: "Network error reaching VirusTotal.",
                           reference: Self.guiURL(indicator: indicator, kind: kind), at: now())
        }

        switch status {
        case 200:
            // Parse via the pure decoder; a malformed 200 body ⇒ error.
            return Self.decode(body, indicator: indicator, kind: kind, at: now())
                ?? verdict(.error, for: indicator, kind: kind,
                           detail: "Could not parse VirusTotal response.",
                           reference: Self.guiURL(indicator: indicator, kind: kind), at: now())
        case 404:
            // VT has never seen this indicator — looked up, nothing known.
            return verdict(.unknown, for: indicator, kind: kind,
                           detail: "Not found in VirusTotal.",
                           reference: Self.guiURL(indicator: indicator, kind: kind), at: now())
        case 401, 403:
            return verdict(.error, for: indicator, kind: kind,
                           detail: "VirusTotal authentication failed (\(status)).",
                           reference: Self.guiURL(indicator: indicator, kind: kind), at: now())
        case 429:
            return verdict(.error, for: indicator, kind: kind,
                           detail: "VirusTotal rate limit exceeded (429).",
                           reference: Self.guiURL(indicator: indicator, kind: kind), at: now())
        default:
            return verdict(.error, for: indicator, kind: kind,
                           detail: "VirusTotal returned HTTP \(status).",
                           reference: Self.guiURL(indicator: indicator, kind: kind), at: now())
        }
    }

    // MARK: - Request building (pure)

    /// Build the VT v3 GET for a given indicator, with the `x-apikey` header.
    /// Endpoints: hash→/files/{hash}, ip→/ip_addresses/{ip},
    /// domain→/domains/{domain}, url→/urls/{base64url-no-padding(url)}.
    /// Returns nil for an empty/unencodable indicator.
    static func request(indicator: String, kind: IOCKind,
                        baseURL: URL, apiKey: String) -> URLRequest? {
        let raw = indicator.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !raw.isEmpty else { return nil }

        guard let url = endpointURL(indicator: raw, kind: kind, baseURL: baseURL) else { return nil }
        var request = URLRequest(url: url)
        request.httpMethod = "GET"
        request.setValue(apiKey, forHTTPHeaderField: "x-apikey")
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        return request
    }

    /// The endpoint URL for an indicator (no key). Exposed for testing the
    /// URL-shaping (esp. the base64url-no-padding URL id).
    static func endpointURL(indicator: String, kind: IOCKind, baseURL: URL) -> URL? {
        let raw = indicator.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !raw.isEmpty else { return nil }

        let pathComponent: String
        switch kind {
        case .hash:
            pathComponent = "files/\(raw.lowercased())"
        case .ip:
            pathComponent = "ip_addresses/\(raw)"
        case .domain:
            pathComponent = "domains/\(raw)"
        case .url:
            // VT identifies a URL by the unpadded base64url of the raw URL.
            pathComponent = "urls/\(base64URLNoPadding(raw))"
        }
        // Append as raw path segments (the id is already URL-safe — base64url
        // for URLs, hex for hashes, host text for ip/domain).
        return URL(string: pathComponent, relativeTo: ensureTrailingSlash(baseURL))?.absoluteURL
    }

    /// Unpadded base64url (RFC 4648 §5): standard base64 with `+`→`-`, `/`→`_`,
    /// and trailing `=` stripped — VT's URL-object identifier scheme.
    static func base64URLNoPadding(_ s: String) -> String {
        Data(s.utf8).base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }

    /// The human-facing VT GUI deep link recorded as the verdict `reference`.
    static func guiURL(indicator: String, kind: IOCKind) -> String {
        let raw = indicator.trimmingCharacters(in: .whitespacesAndNewlines)
        switch kind {
        case .hash:   return "https://www.virustotal.com/gui/file/\(raw.lowercased())"
        case .ip:     return "https://www.virustotal.com/gui/ip-address/\(raw)"
        case .domain: return "https://www.virustotal.com/gui/domain/\(raw)"
        case .url:    return "https://www.virustotal.com/gui/url/\(base64URLNoPadding(raw))"
        }
    }

    private static func ensureTrailingSlash(_ url: URL) -> URL {
        url.absoluteString.hasSuffix("/") ? url
            : URL(string: url.absoluteString + "/") ?? url
    }

    // MARK: - Pure decoder

    /// Decode a VT v3 200-OK response body into a verdict. Reads
    /// `data.attributes.last_analysis_stats` {malicious, suspicious, harmless,
    /// undetected, timeout}:
    ///  - `malicious >= 1`  → `.malicious`  (score = malicious/total)
    ///  - else `suspicious >= 1` → `.suspicious` (score = suspicious/total)
    ///  - else (some engines reported) → `.unknown` ("no engines flagged") —
    ///    **never `.knownGood`** (VT clean ≠ NSRL allowlisted).
    /// Returns nil when the body is not the expected JSON shape (caller maps
    /// that to an `.error`).
    static func decode(_ body: Data, indicator: String, kind: IOCKind, at now: Date) -> EnrichmentVerdict? {
        guard let root = try? JSONSerialization.jsonObject(with: body) as? [String: Any],
              let data = root["data"] as? [String: Any],
              let attributes = data["attributes"] as? [String: Any],
              let stats = attributes["last_analysis_stats"] as? [String: Any]
        else { return nil }

        func count(_ name: String) -> Int {
            // VT renders these as JSON numbers; tolerate string-encoded too.
            if let n = stats[name] as? Int { return n }
            if let d = stats[name] as? Double { return Int(d) }
            if let s = stats[name] as? String, let n = Int(s) { return n }
            return 0
        }

        let malicious  = count("malicious")
        let suspicious = count("suspicious")
        let harmless   = count("harmless")
        let undetected = count("undetected")
        let timeout    = count("timeout")
        let total = malicious + suspicious + harmless + undetected + timeout

        let reference = guiURL(indicator: indicator, kind: kind)

        if malicious >= 1 {
            let score = total > 0 ? Double(malicious) / Double(total) : nil
            return EnrichmentVerdict(
                indicator: indicator, kind: kind, verdict: .malicious, score: score,
                source: "VirusTotal", tier: .virusTotal,
                detail: "\(malicious)/\(total) engines flagged this as malicious.",
                reference: reference, retrievedAt: now)
        }
        if suspicious >= 1 {
            let score = total > 0 ? Double(suspicious) / Double(total) : nil
            return EnrichmentVerdict(
                indicator: indicator, kind: kind, verdict: .suspicious, score: score,
                source: "VirusTotal", tier: .virusTotal,
                detail: "\(suspicious)/\(total) engines flagged this as suspicious.",
                reference: reference, retrievedAt: now)
        }
        // Some engines reported, none flagged it → looked up, nothing bad known.
        // NOT knownGood: VT clean does not allowlist (that's NSRL's job).
        if total > 0 {
            return EnrichmentVerdict(
                indicator: indicator, kind: kind, verdict: .unknown, score: nil,
                source: "VirusTotal", tier: .virusTotal,
                detail: "No engines flagged this (\(harmless + undetected)/\(total) clean).",
                reference: reference, retrievedAt: now)
        }
        // Well-formed but no analysis stats at all (e.g. queued, never scanned).
        return EnrichmentVerdict(
            indicator: indicator, kind: kind, verdict: .unknown, score: nil,
            source: "VirusTotal", tier: .virusTotal,
            detail: "No analysis results in VirusTotal.",
            reference: reference, retrievedAt: now)
    }
}
