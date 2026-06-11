//
//  KnownBadHashTests.swift
//  StrataTests
//
//  Covers the KnownBadHashProvider (threat-intel tier, hash-only, emits
//  `.malicious` for an in-set hash, nil to keep cascading otherwise, the
//  newline-file loader, and the opt-in no-op) and the KnownBadHashAnalyzer
//  (seeded set matching a case IOC + an Amcache SHA-1; empty set ⇒ no-op).
//

import Testing
import Foundation
@testable import Strata

// MARK: - Provider

/// Locks the known-bad tier: hash-only support, a `.malicious` (definitive)
/// verdict for an in-set hash, `nil` (keep-cascading) for an out-of-set hash,
/// the `.threatIntel` tier placement, the opt-in/unconfigured no-op, and the
/// newline-file loader (comments/blanks/case).
struct KnownBadHashProviderTests {
    private static let now = Date(timeIntervalSince1970: 1_700_000_000)

    // A real SHA-256 (64 hex chars) — empty-string digest, a convenient fixture.
    private static let badSHA256 =
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

    private func provider(_ hashes: Set<String>) -> KnownBadHashProvider {
        KnownBadHashProvider(hashes: hashes, now: { Self.now })
    }

    @Test func inSetHashReturnsMaliciousWithProvenance() async {
        let p = provider([Self.badSHA256])
        let out = await p.lookup(Self.badSHA256, kind: .hash)
        #expect(out != nil)
        #expect(out?.verdict == .malicious)
        #expect(out?.verdict.isDefinitive == true)   // short-circuits the cascade
        #expect(out?.tier == .threatIntel)
        #expect(out?.source == "Known-Bad Hashes")
        #expect(out?.detail == "In known-bad hash set")
        #expect(out?.retrievedAt == Self.now)
        #expect(out?.indicator == Self.badSHA256)
    }

    @Test func inSetHashMatchesCaseInsensitively() async {
        // Set built from a lowercase hash; lookup arrives upper-cased + padded.
        let p = provider([Self.badSHA256])
        let out = await p.lookup("  " + Self.badSHA256.uppercased() + "  ", kind: .hash)
        #expect(out?.verdict == .malicious)
    }

    @Test func outOfSetHashReturnsNilToKeepCascading() async {
        let p = provider([Self.badSHA256])
        let out = await p.lookup(String(repeating: "b", count: 64), kind: .hash)
        #expect(out == nil)   // NOT a verdict — absence from the bad list is not goodness
    }

    @Test func nonHashKindsAreUnsupportedAndReturnNil() async {
        let p = provider([Self.badSHA256])
        #expect(p.supports(.hash))
        #expect(!p.supports(.domain))
        #expect(!p.supports(.ip))
        #expect(!p.supports(.url))
        // Even if a domain string happened to equal a set member, kind gates it.
        let out = await p.lookup(Self.badSHA256, kind: .domain)
        #expect(out == nil)
    }

    @Test func emptySetIsAnUnconfiguredNoOp() async {
        let p = provider([])               // opt-in: nothing loaded
        let out = await p.lookup(Self.badSHA256, kind: .hash)
        #expect(out == nil)                // no verdict, no network, silent skip
    }

    @Test func loadingFromFileParsesCommentsBlanksAndCase() throws {
        let md5  = "44d88612fea8a8f36de82e1278abb02f"   // EICAR-ish placeholder MD5
        let sha1 = "3395856ce81f2b7382dee72602f798b642f14140" // 40 hex
        let body = """
        # known-bad hash export
        \(md5.uppercased())

           \(sha1)\t

        # trailing comment
        """
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent("badhash-\(UUID().uuidString).txt")
        try body.write(to: url, atomically: true, encoding: .utf8)
        defer { try? FileManager.default.removeItem(at: url) }

        let p = KnownBadHashProvider(loading: url, now: { Self.now })
        #expect(p.hashes == [md5, sha1])   // 2 hashes, comments/blanks dropped, lowercased
    }

    @Test func loadingMissingFileYieldsEmptyNoOpSet() async {
        let missing = FileManager.default.temporaryDirectory
            .appendingPathComponent("does-not-exist-\(UUID().uuidString).txt")
        let p = KnownBadHashProvider(loading: missing, now: { Self.now })
        #expect(p.hashes.isEmpty)
        let out = await p.lookup(Self.badSHA256, kind: .hash)
        #expect(out == nil)                // empty set ⇒ no-op
    }
}

// MARK: - Analyzer

/// Locks the analyzer's match logic: a seeded set produces a finding for a
/// matching case IOC (hash) and a matching Amcache SHA-1; non-matching hashes
/// and an empty (default) set produce nothing.
struct KnownBadHashAnalyzerTests {
    private static let badSHA1   = String(repeating: "a", count: 40)   // matches the Amcache fixture
    private static let badSHA256 =
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

    /// An Amcache entry carrying `badSHA1` in its `sha1` field (the field
    /// AmcacheEntry exposes for the recovered SHA-1).
    private func amcacheEntry(sha1: String?) -> AmcacheEntry {
        AmcacheEntry(name: "evil.exe",
                     fullPath: #"c:\users\public\evil.exe"#,
                     sha1: sha1,
                     source: .inventoryApplicationFile,
                     sourceFile: #"/x/Amcache.hve"#)
    }

    private func context(amcache: [AmcacheEntry]) -> AnalysisContext {
        AnalysisContext(files: [], events: [], timeline: [], registryValues: [],
                        amcache: amcache)
    }

    @Test func matchesAmcacheSha1InSet() throws {
        let a = KnownBadHashAnalyzer(badHashes: [Self.badSHA1])
        let findings = a.analyze(context: context(amcache: [amcacheEntry(sha1: Self.badSHA1)]))
        #expect(findings.count == 1)
        let f = try #require(findings.first)
        #expect(f.severity == .critical)
        #expect(f.phase == .delivery)
        #expect(f.technique?.attackID == "T1204")
        #expect(f.title.contains("evil.exe"))
        #expect(f.detail.contains(Self.badSHA1))
        #expect(f.evidencePaths.contains(Self.badSHA1))
    }

    @Test func matchesCaseIOCHashInSet() throws {
        let ioc = IOC(kind: .hash, value: Self.badSHA256.uppercased(), note: "from report")
        let a = KnownBadHashAnalyzer(badHashes: [Self.badSHA256], iocs: [ioc])
        let findings = a.analyze(context: context(amcache: []))
        #expect(findings.count == 1)
        let f = try #require(findings.first)
        #expect(f.severity == .high)
        #expect(f.phase == .delivery)
        #expect(f.technique?.attackID == "T1588.001")
        #expect(f.detail.contains("from report"))   // IOC note carried into detail
    }

    @Test func nonHashIOCsAreIgnored() {
        let domainIOC = IOC(kind: .domain, value: Self.badSHA256, note: "")
        // Even though the domain's *value* equals a set member, kind gates it.
        let a = KnownBadHashAnalyzer(badHashes: [Self.badSHA256], iocs: [domainIOC])
        #expect(a.analyze(context: context(amcache: [])).isEmpty)
    }

    @Test func outOfSetAmcacheHashProducesNothing() {
        let a = KnownBadHashAnalyzer(badHashes: [Self.badSHA1])
        let clean = amcacheEntry(sha1: String(repeating: "c", count: 40))
        #expect(a.analyze(context: context(amcache: [clean])).isEmpty)
    }

    @Test func amcacheEntryWithoutSha1IsSkipped() {
        let a = KnownBadHashAnalyzer(badHashes: [Self.badSHA1])
        #expect(a.analyze(context: context(amcache: [amcacheEntry(sha1: nil)])).isEmpty)
    }

    @Test func emptyDefaultSetIsANoOp() {
        let a = KnownBadHashAnalyzer()   // default empty set + no IOCs
        let findings = a.analyze(context: context(amcache: [amcacheEntry(sha1: Self.badSHA1)]))
        #expect(findings.isEmpty)        // nothing configured ⇒ nothing emitted
    }
}
