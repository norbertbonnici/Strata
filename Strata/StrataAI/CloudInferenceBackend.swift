import Foundation

/// Opt-in, **non-sovereign** backend that routes generation to a cloud model via
/// the Anthropic Messages API (`POST {baseURL}/v1/messages`). It produces the
/// same FM-free `ProposedSummary` the on-device backend does - so the *identical*
/// `SummaryValidator` gates its output. Escalation buys more model capability
/// without giving up evidence-reference validation.
///
/// Confidentiality: this sends the **digest** (aggregated finding summaries),
/// never raw evidence, and only when the analyst has explicitly enabled cloud
/// mode and stored a credential. `isSovereign` is `false` so the run is labelled
/// and custody-logged.
///
/// Design mirrors the CTI providers: pure request-builders + response-decoders
/// (static, unit-tested) over an injectable `Transport`; the default transport is
/// the only place that touches the network. `baseURL` is configurable for a
/// self-hosted / sovereign-cloud Anthropic-compatible gateway.
public nonisolated struct CloudInferenceBackend: InferenceBackend {

    /// Request in, (body, HTTP status) out; nil on a transport-level failure.
    /// Tests inject a closure returning a fixture without hitting the network.
    public typealias Transport = @Sendable (URLRequest) async -> (Data, Int)?

    public var label: String { "Cloud · \(model)" }
    public let sovereignty: SovereigntyTier = .thirdPartyCloud

    /// A third-party cloud model's window dwarfs the digest, so this is a safe
    /// large default rather than a per-model lookup — the aggregated digest never
    /// approaches it. (claude-opus-4-8 is 1M; 200k is conservative headroom.)
    public let contextWindowTokens = 200_000

    public let baseURL: URL
    public let model: String
    private let apiKey: String?
    private let maxTokens: Int
    private let transport: Transport

    public init(baseURL: URL = URL(string: "https://api.anthropic.com")!,
                model: String = "claude-opus-4-8",
                apiKey: String?,
                maxTokens: Int = 4096,
                transport: @escaping Transport = CloudInferenceBackend.liveTransport) {
        self.baseURL = baseURL
        self.model = model
        self.apiKey = apiKey
        self.maxTokens = maxTokens
        self.transport = transport
    }

    public func availability() -> SummarizerAvailability {
        guard let k = apiKey, !k.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
            return .unavailable(reason: "No API key is configured for the cloud model.")
        }
        return .available
    }

    public static let liveTransport: Transport = { request in
        guard let (data, response) = try? await URLSession.shared.data(for: request),
              let http = response as? HTTPURLResponse else { return nil }
        return (data, http.statusCode)
    }

    // MARK: - Backend primitives

    public func proposeSummary(instructions: String, prompt: String,
                               context: InferenceContext) async throws -> ProposedSummary {
        let text = try await complete(system: instructions, prompt: prompt,
                                      schema: Self.summarySchema)
        return try Self.decodeSummary(text)
    }

    public func proposeClaims(instructions: String, prompt: String,
                              context: InferenceContext) async throws -> [ProposedClaim] {
        let text = try await complete(system: instructions, prompt: prompt,
                                      schema: Self.claimSetSchema)
        return try Self.decodeClaimSet(text)
    }

    public func synthesizeOverview(instructions: String, prompt: String) async throws -> String {
        try await complete(system: instructions, prompt: prompt, schema: nil)
            .trimmingCharacters(in: .whitespacesAndNewlines)
    }

    /// One Messages API round-trip; returns the concatenated text content.
    private func complete(system: String, prompt: String, schema: [String: Any]?) async throws -> String {
        guard let key = apiKey, !key.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
            throw InferenceError.unavailable("No API key is configured for the cloud model.")
        }
        let request = try Self.request(baseURL: baseURL, apiKey: key, model: model,
                                       maxTokens: maxTokens, system: system, prompt: prompt, schema: schema)
        guard let (body, status) = await transport(request) else {
            throw InferenceError.transport("no response (offline or non-HTTP)")
        }
        guard status == 200 else {
            throw InferenceError.http(status: status, body: String(decoding: body, as: UTF8.self))
        }
        return try Self.extractText(body)
    }

    // MARK: - Request building (pure)

    static func request(baseURL: URL, apiKey: String, model: String, maxTokens: Int,
                        system: String, prompt: String, schema: [String: Any]?) throws -> URLRequest {
        var body: [String: Any] = [
            "model": model,
            "max_tokens": maxTokens,
            "system": system,
            "messages": [["role": "user", "content": prompt]],
        ]
        if let schema {
            body["output_config"] = ["format": ["type": "json_schema", "schema": schema]]
        }
        guard let data = try? JSONSerialization.data(withJSONObject: body) else {
            throw InferenceError.transport("could not encode request body")
        }
        var request = URLRequest(url: messagesURL(baseURL))
        request.httpMethod = "POST"
        request.httpBody = data
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.setValue(apiKey, forHTTPHeaderField: "x-api-key")
        request.setValue("2023-06-01", forHTTPHeaderField: "anthropic-version")
        return request
    }

    static func messagesURL(_ baseURL: URL) -> URL {
        let base = baseURL.absoluteString.hasSuffix("/")
            ? String(baseURL.absoluteString.dropLast()) : baseURL.absoluteString
        return URL(string: base + "/v1/messages") ?? baseURL
    }

    // MARK: - Response decoding (pure)

    private struct MessagesResponse: Decodable {
        struct Block: Decodable { let type: String; let text: String? }
        let content: [Block]?
        let stop_reason: String?
    }

    /// The first text block of a Messages API 200 body. Throws on a refusal or a
    /// shape we don't recognise.
    static func extractText(_ body: Data) throws -> String {
        guard let resp = try? JSONDecoder().decode(MessagesResponse.self, from: body) else {
            throw InferenceError.decode("response was not a Messages API object")
        }
        if resp.stop_reason == "refusal" {
            throw InferenceError.refused("safety classifier declined the request")
        }
        // Distinct from a schema mismatch: the JSON is truncated, not malformed.
        // The fix is a higher max_tokens, so say so rather than blaming the schema.
        if resp.stop_reason == "max_tokens" {
            throw InferenceError.decode("response was truncated at the cloud max_tokens limit; raise it and retry")
        }
        let text = (resp.content ?? []).compactMap { $0.type == "text" ? $0.text : nil }
            .joined(separator: "\n")
            .trimmingCharacters(in: .whitespacesAndNewlines)
        guard !text.isEmpty else { throw InferenceError.decode("empty content") }
        return text
    }

    private struct CloudClaim: Decodable {
        let statement: String
        let phase: String
        let severity: String
        let findingRefs: [String]
    }
    private struct CloudSummary: Decodable { let overview: String; let claims: [CloudClaim] }
    private struct CloudClaimSet: Decodable { let claims: [CloudClaim] }

    static func decodeSummary(_ text: String) throws -> ProposedSummary {
        guard let data = jsonData(in: text),
              let s = try? JSONDecoder().decode(CloudSummary.self, from: data) else {
            throw InferenceError.decode("structured summary JSON did not match the schema")
        }
        return ProposedSummary(overview: s.overview, claims: s.claims.map(toProposed))
    }

    static func decodeClaimSet(_ text: String) throws -> [ProposedClaim] {
        guard let data = jsonData(in: text),
              let s = try? JSONDecoder().decode(CloudClaimSet.self, from: data) else {
            throw InferenceError.decode("structured claims JSON did not match the schema")
        }
        return s.claims.map(toProposed)
    }

    private static func toProposed(_ c: CloudClaim) -> ProposedClaim {
        ProposedClaim(statement: c.statement,
                      phase: KillChainPhase(rawValue: c.phase) ?? .installation,
                      severity: severity(c.severity),
                      findingRefs: c.findingRefs)
    }

    private static func severity(_ s: String) -> Severity {
        switch s.lowercased() {
        case "info":     return .info
        case "low":      return .low
        case "medium":   return .medium
        case "high":     return .high
        case "critical": return .critical
        default:         return .medium
        }
    }

    /// Tolerate a model that wraps the JSON in prose or a ```json fence: take the
    /// outermost `{ … }` span. (`output_config.format` returns bare JSON, but the
    /// no-schema / self-hosted-gateway paths may not.)
    static func jsonData(in text: String) -> Data? {
        if let first = text.firstIndex(of: "{"), let last = text.lastIndex(of: "}"), first < last {
            return String(text[first...last]).data(using: .utf8)
        }
        return text.data(using: .utf8)
    }

    // MARK: - Schemas (Anthropic output_config.format - additionalProperties:false, no min/max)

    private static let claimSchema: [String: Any] = [
        "type": "object",
        "additionalProperties": false,
        "properties": [
            "statement": ["type": "string"],
            "phase": ["type": "string",
                      "enum": KillChainPhase.allCases.map { $0.rawValue }],
            "severity": ["type": "string",
                         "enum": ["info", "low", "medium", "high", "critical"]],
            "findingRefs": ["type": "array", "items": ["type": "string"]],
        ],
        "required": ["statement", "phase", "severity", "findingRefs"],
    ]

    static let summarySchema: [String: Any] = [
        "type": "object",
        "additionalProperties": false,
        "properties": [
            "overview": ["type": "string"],
            "claims": ["type": "array", "items": claimSchema],
        ],
        "required": ["overview", "claims"],
    ]

    static let claimSetSchema: [String: Any] = [
        "type": "object",
        "additionalProperties": false,
        "properties": ["claims": ["type": "array", "items": claimSchema]],
        "required": ["claims"],
    ]
}
