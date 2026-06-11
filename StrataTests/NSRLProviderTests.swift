import Testing
import Foundation
@testable import Strata

/// Locks the NSRL tier: hash-only support, a `.knownGood` (definitive) verdict
/// for a known hash, `nil` (keep-cascading) for an unknown hash, the opt-in /
/// unconfigured no-op, and the newline-file loader (comments/blanks/case).
struct NSRLProviderTests {
    private static let now = Date(timeIntervalSince1970: 1_700_000_000)

    // A real SHA-256 (64 hex chars) — empty-string digest, a convenient fixture.
    private static let knownSHA256 =
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

    private func provider(_ hashes: Set<String>) -> NSRLProvider {
        NSRLProvider(hashes: hashes, now: { Self.now })
    }

    @Test func knownHashReturnsKnownGoodWithProvenance() async {
        let p = provider([Self.knownSHA256])
        let out = await p.lookup(Self.knownSHA256, kind: .hash)
        #expect(out != nil)
        #expect(out?.verdict == .knownGood)
        #expect(out?.verdict.isDefinitive == true)   // short-circuits the cascade
        #expect(out?.tier == .nsrl)
        #expect(out?.source == "NSRL")
        #expect(out?.detail == "In NSRL known-good set")
        #expect(out?.retrievedAt == Self.now)
        #expect(out?.indicator == Self.knownSHA256)
    }

    @Test func knownHashMatchesCaseInsensitively() async {
        // Set built from a lowercase hash; lookup arrives upper-cased + padded.
        let p = provider([Self.knownSHA256])
        let out = await p.lookup("  " + Self.knownSHA256.uppercased() + "  ", kind: .hash)
        #expect(out?.verdict == .knownGood)
    }

    @Test func unknownHashReturnsNilToKeepCascading() async {
        let p = provider([Self.knownSHA256])
        let out = await p.lookup(String(repeating: "a", count: 64), kind: .hash)
        #expect(out == nil)   // NOT a verdict — absence from NSRL is not a verdict
    }

    @Test func nonHashKindsAreUnsupportedAndReturnNil() async {
        let p = provider([Self.knownSHA256])
        #expect(p.supports(.hash))
        #expect(!p.supports(.domain))
        #expect(!p.supports(.ip))
        #expect(!p.supports(.url))
        // Even if a domain string happened to equal a set member, kind gates it.
        let out = await p.lookup(Self.knownSHA256, kind: .domain)
        #expect(out == nil)
    }

    @Test func emptySetIsAnUnconfiguredNoOp() async {
        let p = provider([])               // opt-in: nothing loaded
        let out = await p.lookup(Self.knownSHA256, kind: .hash)
        #expect(out == nil)                // no verdict, no network, silent skip
    }

    @Test func loadingFromFileParsesCommentsBlanksAndCase() throws {
        let md5  = "d41d8cd98f00b204e9800998ecf8427e"   // empty-string MD5
        let sha1 = "da39a3ee5e6b4b0d3255bfef95601890afd80709" // empty-string SHA-1
        let body = """
        # NSRL known-good export
        \(md5.uppercased())

           \(sha1)\t

        # trailing comment
        """
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent("nsrl-\(UUID().uuidString).txt")
        try body.write(to: url, atomically: true, encoding: .utf8)
        defer { try? FileManager.default.removeItem(at: url) }

        let p = NSRLProvider(loading: url, now: { Self.now })
        #expect(p.hashes == [md5, sha1])   // 2 hashes, comments/blanks dropped, lowercased
    }

    @Test func loadingMissingFileYieldsEmptyNoOpSet() async {
        let missing = FileManager.default.temporaryDirectory
            .appendingPathComponent("does-not-exist-\(UUID().uuidString).txt")
        let p = NSRLProvider(loading: missing, now: { Self.now })
        #expect(p.hashes.isEmpty)
        let out = await p.lookup(Self.knownSHA256, kind: .hash)
        #expect(out == nil)                // empty set ⇒ no-op
    }
}
