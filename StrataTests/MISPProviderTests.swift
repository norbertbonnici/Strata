import Testing
import Foundation
@testable import Strata

/// Locks the MISP provider contract: the pure `restSearch` decoder's verdict
/// derivation (to_ids / threat-tag ⇒ malicious; bare hit ⇒ suspicious; no
/// attributes ⇒ unknown), the opt-in gate (unconfigured ⇒ nil, no network),
/// and the injectable-transport `lookup` so live HTTP is never hit in tests.
struct MISPProviderTests {
    private static let now = Date(timeIntervalSince1970: 1_700_000_000)
    private static let base = URL(string: "https://misp.example.org")!

    // MARK: - Fixtures (realistic MISP restSearch JSON)

    /// One malicious attribute: `to_ids: true`, a TLP + malicious-activity tag,
    /// embedded Event with info + its own tags.
    private static let maliciousJSON = """
    {
      "response": {
        "Attribute": [
          {
            "id": "918273",
            "event_id": "4242",
            "object_id": "0",
            "category": "Payload delivery",
            "type": "sha256",
            "to_ids": true,
            "uuid": "5e1f9c8a-aaaa-bbbb-cccc-1234567890ab",
            "timestamp": "1699900000",
            "value": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "Tag": [
              { "id": "10", "name": "tlp:amber", "colour": "#FFC000" }
            ],
            "Event": {
              "id": "4242",
              "info": "Emotet C2 infrastructure - Oct 2023",
              "Tag": [
                { "id": "11", "name": "misp-galaxy:malpedia=\\"Emotet\\"" },
                { "id": "12", "name": "type:malicious-activity" }
              ]
            }
          }
        ]
      }
    }
    """.data(using: .utf8)!

    /// A bare hit: the value is present but `to_ids: false` and no threat tag,
    /// so the analyst should see it flagged but lower-confidence (suspicious).
    private static let suspiciousJSON = """
    {
      "response": {
        "Attribute": [
          {
            "id": "555",
            "event_id": "777",
            "category": "Network activity",
            "type": "ip-dst",
            "to_ids": false,
            "value": "203.0.113.55",
            "Tag": [],
            "Event": { "id": "777", "info": "Mixed observation set", "Tag": [] }
          }
        ]
      }
    }
    """.data(using: .utf8)!

    /// Empty result: MISP looked it up and has nothing.
    private static let emptyJSON = #"{"response":{"Attribute":[]}}"#.data(using: .utf8)!

    // MARK: - Pure decoder

    @Test func decodesMaliciousFromToIdsAndTags() throws {
        let v = MISPProvider.decode(
            Self.maliciousJSON,
            indicator: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            kind: .hash, at: Self.now)
        let verdict = try #require(v)
        #expect(verdict.verdict == .malicious)
        #expect(verdict.source == "MISP")
        #expect(verdict.tier == .threatIntel)
        #expect(verdict.retrievedAt == Self.now)
        // detail summarises the matching event info + that to_ids was set.
        #expect(verdict.detail.contains("Emotet C2 infrastructure"))
        #expect(verdict.detail.contains("to_ids set"))
        // reference deep-links to the event.
        #expect(verdict.reference == "/events/view/4242")
    }

    @Test func decodesSuspiciousWhenToIdsUnsetAndNoThreatTag() throws {
        let v = MISPProvider.decode(Self.suspiciousJSON, indicator: "203.0.113.55",
                                    kind: .ip, at: Self.now)
        let verdict = try #require(v)
        #expect(verdict.verdict == .suspicious)
        #expect(verdict.detail.contains("to_ids unset"))
        #expect(verdict.reference == "/events/view/777")
    }

    @Test func decodesUnknownWhenNoAttributes() throws {
        let v = MISPProvider.decode(Self.emptyJSON, indicator: "1.2.3.4",
                                    kind: .ip, at: Self.now)
        let verdict = try #require(v)
        #expect(verdict.verdict == .unknown)
        #expect(verdict.tier == .threatIntel)
        #expect(verdict.reference == nil)
    }

    @Test func decoderReturnsNilOnMalformedBody() {
        // No `Attribute` key at all ⇒ can't decode ⇒ nil (lookup turns this into
        // an `.error`, which keeps the cascade going).
        let junk = #"{"response":{"foo":1}}"#.data(using: .utf8)!
        #expect(MISPProvider.decode(junk, indicator: "x", kind: .hash, at: Self.now) == nil)
    }

    @Test func decoderAcceptsUnwrappedResponseShape() {
        // Some deployments return the object without the `response` envelope.
        let unwrapped = #"{"Attribute":[]}"#.data(using: .utf8)!
        let v = MISPProvider.decode(unwrapped, indicator: "abc", kind: .hash, at: Self.now)
        #expect(v?.verdict == .unknown)
    }

    @Test func decoderMatchesCompositeValueHalf() {
        // A composite `filename|sha256` attribute should still match a query for
        // just the hash half, and to_ids true ⇒ malicious.
        let composite = """
        {"response":{"Attribute":[
          {"event_id":"9","type":"filename|sha256","to_ids":true,
           "value":"dropper.exe|deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
           "Event":{"id":"9","info":"dropper"}}
        ]}}
        """.data(using: .utf8)!
        let v = MISPProvider.decode(
            composite,
            indicator: "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
            kind: .hash, at: Self.now)
        #expect(v?.verdict == .malicious)
    }

    // MARK: - Opt-in gate (no network when unconfigured)

    @Test func unconfiguredBaseURLReturnsNilWithoutFetching() async {
        var fetched = false
        let provider = MISPProvider(baseURL: nil, token: "key") { _ in
            fetched = true; return (Data(), 200)
        }
        let out = await provider.lookup("abc", kind: .hash)
        #expect(out == nil)
        #expect(!fetched)   // opt-in: never touched the transport
    }

    @Test func missingTokenReturnsNilWithoutFetching() async {
        var fetched = false
        let provider = MISPProvider(baseURL: Self.base, token: nil) { _ in
            fetched = true; return (Data(), 200)
        }
        #expect(await provider.lookup("abc", kind: .hash) == nil)
        #expect(!fetched)
    }

    @Test func emptyTokenReturnsNilWithoutFetching() async {
        var fetched = false
        let provider = MISPProvider(baseURL: Self.base, token: "   ") { _ in
            fetched = true; return (Data(), 200)
        }
        #expect(await provider.lookup("abc", kind: .hash) == nil)
        #expect(!fetched)
    }

    // MARK: - Injected transport (end-to-end lookup, no live HTTP)

    @Test func lookupDecodesMaliciousViaInjectedTransport() async throws {
        let provider = MISPProvider(baseURL: Self.base, token: "key") { request in
            // Assert the request is built the way MISP expects.
            #expect(request.httpMethod == "POST")
            #expect(request.url?.absoluteString == "https://misp.example.org/attributes/restSearch")
            #expect(request.value(forHTTPHeaderField: "Authorization") == "key")
            #expect(request.value(forHTTPHeaderField: "Accept") == "application/json")
            #expect(request.value(forHTTPHeaderField: "Content-Type") == "application/json")
            // Body carries value/limit/returnFormat.
            if let body = request.httpBody,
               let obj = try? JSONSerialization.jsonObject(with: body) as? [String: Any] {
                #expect(obj["value"] as? String == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
                #expect(obj["limit"] as? Int == 25)
                #expect(obj["returnFormat"] as? String == "json")
            } else {
                Issue.record("request body was not JSON")
            }
            return (Self.maliciousJSON, 200)
        }
        let out = await provider.lookup(
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", kind: .hash)
        let verdict = try #require(out)
        #expect(verdict.verdict == .malicious)
        #expect(verdict.source == "MISP")
    }

    @Test func lookupReturnsErrorOnHTTPFailureStatus() async throws {
        let provider = MISPProvider(baseURL: Self.base, token: "key") { _ in
            (Data("unauthorized".utf8), 403)
        }
        let out = await provider.lookup("abc", kind: .hash)
        let verdict = try #require(out)
        #expect(verdict.verdict == .error)        // non-definitive ⇒ cascade continues
        #expect(verdict.detail.contains("403"))
    }

    @Test func lookupReturnsErrorOnTransportFailure() async {
        let provider = MISPProvider(baseURL: Self.base, token: "key") { _ in nil }
        let out = await provider.lookup("abc", kind: .hash)
        #expect(out?.verdict == .error)
    }

    @Test func supportsAllNetworkIndicatorKinds() {
        let provider = MISPProvider(baseURL: Self.base, token: "key")
        #expect(provider.supports(.hash))
        #expect(provider.supports(.ip))
        #expect(provider.supports(.domain))
        #expect(provider.supports(.url))
        #expect(provider.tier == .threatIntel)
    }
}
