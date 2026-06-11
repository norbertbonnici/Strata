import Testing
import Foundation
@testable import Strata

/// Locks the OpenCTI provider's two halves:
///  - the **pure decoder** (`OpenCTIProvider.decode`) over realistic OpenCTI
///    GraphQL response bodies — verdict thresholds, score→native-score, detail,
///    and the dashboard deep-link reference;
///  - the **opt-in / injectable-transport** contract on `lookup` — unconfigured
///    ⇒ nil with no network, and a fixture transport drives an end-to-end verdict
///    without touching live HTTP.
struct OpenCTIProviderTests {
    private static let now = Date(timeIntervalSince1970: 1_700_000_000)
    private static let base = URL(string: "https://opencti.example.org")!

    // MARK: - Fixtures

    /// A high-score (90) observable with an indicator — should read as malicious.
    private static let maliciousBody = Data("""
    {
      "data": {
        "stixCyberObservables": {
          "edges": [
            {
              "node": {
                "id": "observable--11111111-2222-3333-4444-555555555555",
                "entity_type": "StixFile",
                "observable_value": "44d88612fea8a8f36de82e1278abb02f",
                "indicators": {
                  "edges": [
                    {
                      "node": {
                        "id": "indicator--aaaa",
                        "x_opencti_score": 90,
                        "indicator_types": ["malicious-activity"]
                      }
                    }
                  ]
                }
              }
            }
          ]
        }
      }
    }
    """.utf8)

    /// A mid-score (65) observable — should read as suspicious.
    private static let suspiciousBody = Data("""
    {
      "data": {
        "stixCyberObservables": {
          "edges": [
            {
              "node": {
                "id": "observable--sus",
                "entity_type": "Domain-Name",
                "observable_value": "evil.example",
                "indicators": {
                  "edges": [
                    { "node": { "id": "ind--s", "x_opencti_score": 65, "indicator_types": ["anomalous-activity"] } }
                  ]
                }
              }
            }
          ]
        }
      }
    }
    """.utf8)

    /// A low-score (20) observable — looked up but not actionable → unknown.
    private static let lowScoreBody = Data("""
    {
      "data": {
        "stixCyberObservables": {
          "edges": [
            {
              "node": {
                "id": "observable--low",
                "entity_type": "IPv4-Addr",
                "observable_value": "203.0.113.7",
                "indicators": {
                  "edges": [
                    { "node": { "id": "ind--l", "x_opencti_score": 20, "indicator_types": ["benign"] } }
                  ]
                }
              }
            }
          ]
        }
      }
    }
    """.utf8)

    /// No matching observable at all → unknown (checked, nothing found).
    private static let emptyBody = Data("""
    { "data": { "stixCyberObservables": { "edges": [] } } }
    """.utf8)

    /// A multi-edge body where the highest score wins across observables.
    private static let multiEdgeBody = Data("""
    {
      "data": {
        "stixCyberObservables": {
          "edges": [
            { "node": { "id": "obs--a", "indicators": { "edges": [
              { "node": { "id": "i1", "x_opencti_score": 40, "indicator_types": ["benign"] } }
            ] } } },
            { "node": { "id": "obs--b", "indicators": { "edges": [
              { "node": { "id": "i2", "x_opencti_score": 85, "indicator_types": ["malicious-activity"] } }
            ] } } }
          ]
        }
      }
    }
    """.utf8)

    // MARK: - Pure decoder: positive (malicious)

    @Test func decodeHighScoreIsMalicious() throws {
        let v = try #require(OpenCTIProvider.decode(
            Self.maliciousBody, indicator: "44d88612fea8a8f36de82e1278abb02f",
            kind: .hash, at: Self.now, baseURL: Self.base))
        #expect(v.verdict == .malicious)
        #expect(v.source == "OpenCTI")
        #expect(v.tier == .threatIntel)
        #expect(v.score == 0.9)                       // 90/100
        #expect(v.detail.contains("90/100"))
        #expect(v.detail.contains("malicious-activity"))
        // Deep link is built from the configured baseURL + observable id.
        #expect(v.reference ==
            "https://opencti.example.org/dashboard/observations/observables/observable--11111111-2222-3333-4444-555555555555")
        #expect(v.retrievedAt == Self.now)
    }

    @Test func decodeMidScoreIsSuspicious() {
        let v = OpenCTIProvider.decode(Self.suspiciousBody, indicator: "evil.example",
                                       kind: .domain, at: Self.now, baseURL: Self.base)
        #expect(v?.verdict == .suspicious)
        #expect(v?.score == 0.65)
    }

    @Test func decodeLowScoreIsUnknownWithNoNativeScore() {
        let v = OpenCTIProvider.decode(Self.lowScoreBody, indicator: "203.0.113.7",
                                       kind: .ip, at: Self.now, baseURL: Self.base)
        #expect(v?.verdict == .unknown)               // present but below the suspicious floor
        #expect(v?.score == nil)                      // no actionable verdict ⇒ no native confidence
    }

    // MARK: - Pure decoder: benign / empty

    @Test func decodeEmptyEdgesIsUnknown() {
        let v = OpenCTIProvider.decode(Self.emptyBody, indicator: "clean.example",
                                       kind: .domain, at: Self.now, baseURL: Self.base)
        #expect(v?.verdict == .unknown)
        #expect(v?.reference == nil)                  // nothing matched → no deep link
        #expect(v?.detail.contains("No OpenCTI observable matched") == true)
    }

    @Test func decodeMultiEdgeTakesHighestScore() {
        let v = OpenCTIProvider.decode(Self.multiEdgeBody, indicator: "x",
                                       kind: .hash, at: Self.now, baseURL: Self.base)
        #expect(v?.verdict == .malicious)             // 85 wins over 40
        #expect(v?.score == 0.85)
        #expect(v?.reference?.hasSuffix("/observables/obs--b") == true)  // the scored observable
    }

    @Test func decodeMalformedEnvelopeReturnsNil() {
        // Missing `data` ⇒ not a usable GraphQL envelope ⇒ nil (caller logs an error).
        let bad = Data(#"{ "errors": [ { "message": "boom" } ] }"#.utf8)
        #expect(OpenCTIProvider.decode(bad, indicator: "x", kind: .hash, at: Self.now) == nil)
        #expect(OpenCTIProvider.decode(Data("not json".utf8), indicator: "x", kind: .hash, at: Self.now) == nil)
    }

    @Test func decodeWithoutBaseURLHasNilReference() {
        // The decoder is fully usable with no baseURL; it just omits the deep link.
        let v = OpenCTIProvider.decode(Self.maliciousBody, indicator: "x", kind: .hash, at: Self.now)
        #expect(v?.verdict == .malicious)
        #expect(v?.reference == nil)
    }

    // MARK: - Opt-in: unconfigured ⇒ nil, no network

    @Test func unconfiguredProviderReturnsNilWithoutNetwork() async {
        // A transport that would fail the test if ever called.
        let tripwire: OpenCTIProvider.Transport = { _ in
            Issue.record("network must not be touched when unconfigured")
            return nil
        }
        // No baseURL.
        let noBase = OpenCTIProvider(baseURL: nil, token: "tok", fetch: tripwire, now: { Self.now })
        #expect(await noBase.lookup("44d88612fea8a8f36de82e1278abb02f", kind: .hash) == nil)

        // No token.
        let noToken = OpenCTIProvider(baseURL: Self.base, token: nil, fetch: tripwire, now: { Self.now })
        #expect(await noToken.lookup("44d88612fea8a8f36de82e1278abb02f", kind: .hash) == nil)

        // Whitespace-only token is treated as unconfigured.
        let blankToken = OpenCTIProvider(baseURL: Self.base, token: "   ", fetch: tripwire, now: { Self.now })
        #expect(await blankToken.lookup("44d88612fea8a8f36de82e1278abb02f", kind: .hash) == nil)
    }

    // MARK: - End-to-end via injected transport (no live HTTP)

    @Test func lookupViaInjectedTransportYieldsMalicious() async {
        // Capture the outgoing request to assert the Bearer header + /graphql path.
        actor Captured { var request: URLRequest?
            func set(_ r: URLRequest) { request = r } }
        let captured = Captured()

        let transport: OpenCTIProvider.Transport = { req in
            await captured.set(req)
            return (Self.maliciousBody, 200)
        }
        let provider = OpenCTIProvider(baseURL: Self.base, token: "secret-token",
                                       fetch: transport, now: { Self.now })
        let v = await provider.lookup("44d88612fea8a8f36de82e1278abb02f", kind: .hash)
        #expect(v?.verdict == .malicious)
        #expect(v?.source == "OpenCTI")

        let req = await captured.request
        #expect(req?.url?.absoluteString == "https://opencti.example.org/graphql")
        #expect(req?.httpMethod == "POST")
        #expect(req?.value(forHTTPHeaderField: "Authorization") == "Bearer secret-token")
    }

    @Test func lookupHTTPErrorYieldsErrorVerdict() async {
        let transport: OpenCTIProvider.Transport = { _ in (Data("nope".utf8), 503) }
        let provider = OpenCTIProvider(baseURL: Self.base, token: "tok",
                                       fetch: transport, now: { Self.now })
        let v = await provider.lookup("44d88612fea8a8f36de82e1278abb02f", kind: .hash)
        #expect(v?.verdict == .error)                 // non-definitive ⇒ cascade keeps going
        #expect(v?.verdict.isDefinitive == false)
    }

    @Test func lookupTransportFailureYieldsErrorVerdict() async {
        let transport: OpenCTIProvider.Transport = { _ in nil }   // connection failed
        let provider = OpenCTIProvider(baseURL: Self.base, token: "tok",
                                       fetch: transport, now: { Self.now })
        let v = await provider.lookup("evil.example", kind: .domain)
        #expect(v?.verdict == .error)
    }

    @Test func supportsAllNetworkKinds() {
        let p = OpenCTIProvider(baseURL: Self.base, token: "t")
        #expect(p.supports(.hash))
        #expect(p.supports(.ip))
        #expect(p.supports(.domain))
        #expect(p.supports(.url))
        #expect(p.tier == .threatIntel)
        #expect(p.name == "OpenCTI")
    }
}
