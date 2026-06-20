import Testing
import Foundation
@testable import Strata

/// Locks `VirusTotalProvider`: the pure JSON→verdict decoder (malicious +
/// clean/unknown), the opt-in (no-key) no-op, HTTP status mapping via an
/// injected transport (no live network), and URL shaping (esp. the
/// base64url-no-padding URL identifier).
struct VirusTotalProviderTests {
    private static let now = Date(timeIntervalSince1970: 1_700_000_000)

    // A realistic VT v3 /files response for a flagged sample (EICAR-style):
    // 60 of 76 engines call it malicious.
    private static let maliciousFilesJSON = """
    {
      "data": {
        "id": "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
        "type": "file",
        "links": { "self": "https://www.virustotal.com/api/v3/files/275a021b" },
        "attributes": {
          "type_description": "DOS executable",
          "meaningful_name": "eicar.com",
          "last_analysis_stats": {
            "harmless": 0,
            "type-unsupported": 4,
            "suspicious": 0,
            "confirmed-timeout": 0,
            "timeout": 1,
            "failure": 0,
            "malicious": 60,
            "undetected": 15
          }
        }
      }
    }
    """

    // A clean file: 70 engines, all harmless/undetected, none flagged.
    private static let cleanFilesJSON = """
    {
      "data": {
        "id": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "type": "file",
        "attributes": {
          "meaningful_name": "notepad.exe",
          "last_analysis_stats": {
            "harmless": 68,
            "suspicious": 0,
            "timeout": 0,
            "malicious": 0,
            "undetected": 2
          }
        }
      }
    }
    """

    // Suspicious-only (no malicious): VT maps to .suspicious.
    private static let suspiciousFilesJSON = """
    {
      "data": {
        "type": "file",
        "attributes": {
          "last_analysis_stats": {
            "harmless": 50, "suspicious": 3, "timeout": 0, "malicious": 0, "undetected": 17
          }
        }
      }
    }
    """

    // MARK: - Pure decoder

    @Test func decodeMaliciousFile() throws {
        let body = Data(Self.maliciousFilesJSON.utf8)
        let v = try #require(VirusTotalProvider.decode(
            body, indicator: "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
            kind: .hash, at: Self.now))
        #expect(v.verdict == .malicious)
        #expect(v.source == "VirusTotal")
        #expect(v.tier == .virusTotal)
        #expect(v.retrievedAt == Self.now)
        // 60 malicious of 76 total (60 + 0 + 0 + 15 + 1).
        let score = try #require(v.score)
        #expect(abs(score - 60.0 / 76.0) < 1e-9)
        #expect(v.detail.contains("60/76"))
        #expect(v.reference?.contains("/gui/file/") == true)
    }

    @Test func decodeCleanFileIsUnknownNotKnownGood() throws {
        // The crux: VT "clean" must NOT short-circuit the cascade as knownGood.
        let body = Data(Self.cleanFilesJSON.utf8)
        let v = try #require(VirusTotalProvider.decode(
            body, indicator: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            kind: .hash, at: Self.now))
        #expect(v.verdict == .unknown)
        #expect(v.verdict != .knownGood)
        #expect(v.verdict.isDefinitive == false)   // keeps the cascade honest
        #expect(v.score == nil)
        #expect(v.detail.contains("70"))           // 68 harmless + 2 undetected
    }

    @Test func decodeSuspiciousFile() throws {
        let body = Data(Self.suspiciousFilesJSON.utf8)
        let v = try #require(VirusTotalProvider.decode(
            body, indicator: "abc", kind: .hash, at: Self.now))
        #expect(v.verdict == .suspicious)
        let score = try #require(v.score)
        #expect(abs(score - 3.0 / 70.0) < 1e-9)
    }

    @Test func decodeRejectsMalformedBody() {
        #expect(VirusTotalProvider.decode(Data("not json".utf8), indicator: "x", kind: .hash, at: Self.now) == nil)
        #expect(VirusTotalProvider.decode(Data("{}".utf8), indicator: "x", kind: .hash, at: Self.now) == nil)
        // Right shape but no stats object.
        let noStats = #"{"data":{"attributes":{}}}"#
        #expect(VirusTotalProvider.decode(Data(noStats.utf8), indicator: "x", kind: .hash, at: Self.now) == nil)
    }

    // MARK: - Opt-in (no key ⇒ no network)

    @Test func unconfiguredKeyReturnsNilWithoutNetwork() async {
        var transportCalled = false
        let provider = VirusTotalProvider(apiKey: nil, now: { Self.now }) { _ in
            transportCalled = true
            return (Data(), 200)
        }
        let out = await provider.lookup("1.2.3.4", kind: .ip)
        #expect(out == nil)
        #expect(transportCalled == false)   // opt-in: never touched the network
    }

    @Test func emptyKeyReturnsNilWithoutNetwork() async {
        var transportCalled = false
        let provider = VirusTotalProvider(apiKey: "   ", now: { Self.now }) { _ in
            transportCalled = true
            return (Data(), 200)
        }
        #expect(await provider.lookup("evil.example", kind: .domain) == nil)
        #expect(transportCalled == false)
    }

    // MARK: - HTTP status mapping (injected transport)

    @Test func lookup200MaliciousEndToEnd() async throws {
        let provider = VirusTotalProvider(apiKey: "KEY", now: { Self.now }) { _ in
            (Data(Self.maliciousFilesJSON.utf8), 200)
        }
        let out = try #require(await provider.lookup(
            "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f", kind: .hash))
        #expect(out.verdict == .malicious)
    }

    @Test func lookup404IsUnknown() async throws {
        let provider = VirusTotalProvider(apiKey: "KEY", now: { Self.now }) { _ in
            (Data("not found".utf8), 404)
        }
        let out = try #require(await provider.lookup("deadbeef", kind: .hash))
        #expect(out.verdict == .unknown)
        #expect(out.verdict.isDefinitive == false)
    }

    @Test func lookup401IsError() async throws {
        let provider = VirusTotalProvider(apiKey: "KEY", now: { Self.now }) { _ in
            (Data(), 401)
        }
        let out = try #require(await provider.lookup("deadbeef", kind: .hash))
        #expect(out.verdict == .error)
        #expect(out.detail.contains("authentication"))
    }

    @Test func lookup429IsRateLimitError() async throws {
        let provider = VirusTotalProvider(apiKey: "KEY", now: { Self.now }) { _ in
            (Data(), 429)
        }
        let out = try #require(await provider.lookup("deadbeef", kind: .hash))
        #expect(out.verdict == .error)
        #expect(out.detail.contains("rate limit"))
    }

    @Test func transportFailureIsError() async throws {
        let provider = VirusTotalProvider(apiKey: "KEY", now: { Self.now }) { _ in nil }
        let out = try #require(await provider.lookup("deadbeef", kind: .hash))
        #expect(out.verdict == .error)
    }

    @Test func malformed200BodyIsError() async throws {
        let provider = VirusTotalProvider(apiKey: "KEY", now: { Self.now }) { _ in
            (Data("garbage".utf8), 200)
        }
        let out = try #require(await provider.lookup("deadbeef", kind: .hash))
        #expect(out.verdict == .error)
    }

    // MARK: - Request shaping

    @Test func requestCarriesApiKeyHeaderAndHashEndpoint() throws {
        let base = URL(string: "https://www.virustotal.com/api/v3")!
        let req = try #require(VirusTotalProvider.request(
            indicator: "ABCDEF", kind: .hash, baseURL: base, apiKey: "secret"))
        #expect(req.value(forHTTPHeaderField: "x-apikey") == "secret")
        #expect(req.httpMethod == "GET")
        // hashes lowercased into /files/{hash}
        #expect(req.url?.absoluteString == "https://www.virustotal.com/api/v3/files/abcdef")
    }

    @Test func endpointURLsPerKind() throws {
        let base = URL(string: "https://www.virustotal.com/api/v3")!
        let ip = try #require(VirusTotalProvider.endpointURL(indicator: "8.8.8.8", kind: .ip, baseURL: base))
        #expect(ip.absoluteString == "https://www.virustotal.com/api/v3/ip_addresses/8.8.8.8")

        let domain = try #require(VirusTotalProvider.endpointURL(indicator: "evil.example", kind: .domain, baseURL: base))
        #expect(domain.absoluteString == "https://www.virustotal.com/api/v3/domains/evil.example")
    }

    @Test func urlIndicatorUsesBase64URLNoPadding() throws {
        // VT's canonical example: the URL id for "http://www.virustotal.com/" is
        // the unpadded base64url of the raw URL.
        let raw = "http://www.virustotal.com/"
        let expectedID = Data(raw.utf8).base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
        #expect(VirusTotalProvider.base64URLNoPadding(raw) == expectedID)
        #expect(!expectedID.contains("="))      // padding stripped
        #expect(!expectedID.contains("/"))      // url-safe alphabet

        let base = URL(string: "https://www.virustotal.com/api/v3")!
        let url = try #require(VirusTotalProvider.endpointURL(indicator: raw, kind: .url, baseURL: base))
        #expect(url.absoluteString == "https://www.virustotal.com/api/v3/urls/\(expectedID)")
    }

    @Test func emptyIndicatorYieldsNoRequest() {
        let base = URL(string: "https://www.virustotal.com/api/v3")!
        #expect(VirusTotalProvider.request(indicator: "   ", kind: .hash, baseURL: base, apiKey: "k") == nil)
        #expect(VirusTotalProvider.endpointURL(indicator: "", kind: .domain, baseURL: base) == nil)
    }

    // MARK: - Conformance / metadata

    @Test func providerMetadata() {
        let p = VirusTotalProvider(apiKey: "k")
        #expect(p.name == "VirusTotal")
        #expect(p.tier == .virusTotal)
        #expect(p.supports(.hash))
        #expect(p.supports(.ip))
        #expect(p.supports(.domain))
        #expect(p.supports(.url))
    }
}
