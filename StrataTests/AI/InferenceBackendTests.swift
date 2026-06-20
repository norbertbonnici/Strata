//
//  InferenceBackendTests.swift
//  StrataTests
//
//  Covers the escalation layer: the cloud backend's pure Anthropic Messages API
//  request builders + response decoders (with a stub transport - no network),
//  that the SAME SummaryValidator gates cloud output, and that
//  InferenceConfiguration selects backends and fails safe to sovereign on-device.
//  The on-device generation + a real cloud endpoint need a host and are verified
//  manually.
//

import Testing
import Foundation
@testable import Strata

struct InferenceBackendTests {

    // A canned Anthropic Messages API 200 body with one text block.
    private func anthropic(_ text: String, stop: String = "end_turn") -> Data {
        try! JSONSerialization.data(withJSONObject: [
            "content": [["type": "text", "text": text]], "stop_reason": stop,
        ])
    }

    // MARK: - Request building

    @Test func cloudRequestHasAnthropicHeadersAndSchema() throws {
        let req = try CloudInferenceBackend.request(
            baseURL: URL(string: "https://api.anthropic.com")!, apiKey: "secret",
            model: "claude-opus-4-8", maxTokens: 1234,
            system: "sys", prompt: "user", schema: CloudInferenceBackend.summarySchema)
        #expect(req.url?.absoluteString == "https://api.anthropic.com/v1/messages")
        #expect(req.httpMethod == "POST")
        #expect(req.value(forHTTPHeaderField: "x-api-key") == "secret")
        #expect(req.value(forHTTPHeaderField: "anthropic-version") == "2023-06-01")
        #expect(req.value(forHTTPHeaderField: "Content-Type") == "application/json")
        let body = try #require(req.httpBody)
        let obj = try #require(try JSONSerialization.jsonObject(with: body) as? [String: Any])
        #expect(obj["model"] as? String == "claude-opus-4-8")
        #expect(obj["max_tokens"] as? Int == 1234)
        #expect(obj["system"] as? String == "sys")
        #expect(obj["output_config"] != nil)   // structured-output schema attached
    }

    @Test func cloudBaseURLTrailingSlashHandledForSelfHostedGateway() {
        #expect(CloudInferenceBackend.messagesURL(URL(string: "https://gw.example/anthropic/")!)
                .absoluteString == "https://gw.example/anthropic/v1/messages")
    }

    // MARK: - Response decoding

    @Test func extractTextAndRefusal() throws {
        #expect(try CloudInferenceBackend.extractText(anthropic("hello")) == "hello")
        #expect(throws: InferenceError.self) {
            try CloudInferenceBackend.extractText(anthropic("x", stop: "refusal"))
        }
        // Truncation is reported distinctly (not as a schema mismatch).
        #expect(throws: InferenceError.self) {
            try CloudInferenceBackend.extractText(anthropic("{partial", stop: "max_tokens"))
        }
    }

    @Test func decodeSummaryMapsPhaseAndSeverity() throws {
        let json = """
        {"overview":"o","claims":[{"statement":"s","phase":"commandAndControl","severity":"high","findingRefs":["F01"]}]}
        """
        let p = try CloudInferenceBackend.decodeSummary(json)
        #expect(p.overview == "o")
        #expect(p.claims.first?.phase == .commandAndControl)
        #expect(p.claims.first?.severity == .high)
        #expect(p.claims.first?.findingRefs == ["F01"])
    }

    // MARK: - End-to-end (stub transport) → SAME validator

    @Test func cloudProposeRunsThroughTheSameValidator() async throws {
        // The cloud model proposes a low-severity claim citing a phantom ref; the
        // SAME SummaryValidator clamps severity to the evidence and strips it.
        let json = """
        {"overview":"Incident overview.","claims":[{"statement":"persistence","phase":"installation","severity":"low","findingRefs":["F01","F99"]}]}
        """
        let body = anthropic(json)
        let backend = CloudInferenceBackend(apiKey: "k", transport: { _ in (body, 200) })
        let proposed = try await backend.proposeSummary(instructions: "i", prompt: "p",
                                                        context: InferenceContext())

        let f = Finding(title: "t", detail: "d", severity: .critical,
                        phase: .commandAndControl, evidencePaths: ["/a"])
        let item = FindingsSummarizer.DigestItem(id: "F01", rep: f, count: 1, maxSeverity: .critical)
        let out = SummaryValidator(idMap: FindingsSummarizer.idMap([item]), knownPaths: [])
            .validate(proposed)
        #expect(out.claims.count == 1)
        #expect(out.claims.first?.severity == .critical)   // cloud said "low"; evidence wins
        #expect(out.report.phantomRefsDropped == 1)         // F99 stripped
    }

    @Test func cloudHTTPErrorThrows() async {
        let backend = CloudInferenceBackend(apiKey: "k", transport: { _ in (Data("nope".utf8), 401) })
        await #expect(throws: InferenceError.self) {
            _ = try await backend.synthesizeOverview(instructions: "i", prompt: "p")
        }
    }

    // MARK: - Configuration selection + fail-safe

    @Test func configSelectsBackendsAndFailsSafeToSovereign() {
        let store = InMemoryCredentialStore()
        #expect(InferenceConfiguration(mode: .onDevice).makeBackend(credentials: store).sovereignty == .onDevice)
        // Cloud selected but no token → fail safe to the sovereign on-device backend.
        #expect(InferenceConfiguration(mode: .cloud).makeBackend(credentials: store).isSovereign)
        // Cloud selected + credentialed → the non-sovereign third-party backend.
        store.save(CTICredentials(token: "key"), for: InferenceConfiguration.keychainService)
        let cloud = InferenceConfiguration(mode: .cloud).makeBackend(credentials: store)
        #expect(cloud.sovereignty == .thirdPartyCloud)
        #expect(!cloud.isSovereign)
        #expect(cloud is CloudInferenceBackend)
    }

    /// Private Cloud Compute is the middle tier: off-device (so gated + labeled,
    /// `isSovereign == false`) but its own tier. On an OS without the API,
    /// `makeBackend` falls back to on-device since PCC can't run there.
    @Test func privateCloudModeSelectsPCCWhenAvailable() {
        let backend = InferenceConfiguration(mode: .privateCloud).makeBackend(credentials: InMemoryCredentialStore())
        if #available(macOS 27.0, iOS 27.0, visionOS 27.0, *) {
            #expect(backend.sovereignty == .applePrivateCloud)
            #expect(!backend.isSovereign)
            #expect(backend is PrivateCloudComputeBackend)
        } else {
            #expect(backend.sovereignty == .onDevice)
        }
    }

    /// The egress confirmation is keyed on the destination fingerprint, so
    /// changing the endpoint or model re-prompts and acknowledging is per-target.
    /// Mode-aware now PCC exists: PCC is one fixed destination, distinct from any
    /// third-party endpoint and from on-device.
    @Test func destinationFingerprintTracksEndpointAndModel() {
        let a = InferenceConfiguration(mode: .cloud, cloudBaseURL: "https://api.anthropic.com", cloudModel: "claude-opus-4-8")
        // Whitespace around the URL/model doesn't spuriously re-prompt.
        let aPadded = InferenceConfiguration(mode: .cloud, cloudBaseURL: " https://api.anthropic.com ", cloudModel: " claude-opus-4-8 ")
        #expect(a.destinationFingerprint == aPadded.destinationFingerprint)
        // A different gateway or model is a different destination → re-prompt.
        let gw = InferenceConfiguration(mode: .cloud, cloudBaseURL: "https://gw.internal/anthropic", cloudModel: "claude-opus-4-8")
        let model = InferenceConfiguration(mode: .cloud, cloudBaseURL: "https://api.anthropic.com", cloudModel: "claude-sonnet-4-6")
        #expect(a.destinationFingerprint != gw.destinationFingerprint)
        #expect(a.destinationFingerprint != model.destinationFingerprint)
        // PCC: one fixed destination, independent of the (irrelevant) cloud fields,
        // distinct from any third-party endpoint and from on-device.
        let pcc = InferenceConfiguration(mode: .privateCloud, cloudBaseURL: "https://api.anthropic.com", cloudModel: "claude-opus-4-8")
        let pccOtherFields = InferenceConfiguration(mode: .privateCloud, cloudBaseURL: "https://whatever", cloudModel: "x")
        #expect(pcc.destinationFingerprint == pccOtherFields.destinationFingerprint)
        #expect(pcc.destinationFingerprint != a.destinationFingerprint)
        #expect(pcc.destinationFingerprint != InferenceConfiguration(mode: .onDevice).destinationFingerprint)
    }
}
