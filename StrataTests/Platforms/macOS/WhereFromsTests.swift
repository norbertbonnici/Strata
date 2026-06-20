//
//  WhereFromsTests.swift
//  StrataTests
//
//  Covers the pure kMDItemWhereFroms decoder, MacWhereFrom host parsing, and the
//  MacWhereFromsAnalyzer raw-IP / paste-host detections. (The fsapfscat -x xattr
//  extraction that supplies the bytes is a vendored-C path validated separately
//  against a real APFS image — not exercised here.)
//

import Testing
import Foundation
@testable import Strata

struct WhereFromsTests {

    private func whereFromsPlist(_ urls: [String]) -> Data {
        try! PropertyListSerialization.data(fromPropertyList: urls, format: .binary, options: 0)
    }

    // MARK: - Parser

    @Test func decodesDownloadAndReferrer() {
        let data = whereFromsPlist(["https://example.com/tool.dmg", "https://example.com/page"])
        let wf = WhereFromsParser.parse(data, path: "/Users/jane/Downloads/tool.dmg", scope: "jane")
        #expect(wf != nil)
        #expect(wf?.downloadURL == "https://example.com/tool.dmg")
        #expect(wf?.referrerURL == "https://example.com/page")
        #expect(wf?.fileName == "tool.dmg")
        #expect(wf?.scope == "jane")
    }

    @Test func filtersEmptyStrings() {
        // A common shape is [url, ""] when there's no referrer.
        let data = whereFromsPlist(["https://example.com/x.zip", "  "])
        let wf = WhereFromsParser.parse(data, path: "/x.zip", scope: "s")
        #expect(wf?.urls == ["https://example.com/x.zip"])
        #expect(wf?.referrerURL == nil)
    }

    @Test func emptyArrayReturnsNil() {
        #expect(WhereFromsParser.parse(whereFromsPlist([]), path: "/x", scope: "s") == nil)
    }

    @Test func garbageReturnsNil() {
        #expect(WhereFromsParser.parse(Data("not a plist".utf8), path: "/x", scope: "s") == nil)
    }

    // MARK: - Host extraction

    @Test func hostParsing() {
        #expect(MacWhereFrom.host(of: "https://www.example.com/a/b?x=1") == "www.example.com")
        #expect(MacWhereFrom.host(of: "http://1.2.3.4:8080/p") == "1.2.3.4")
        #expect(MacWhereFrom.host(of: "https://user:pw@host.tld/p") == "host.tld")
        #expect(MacWhereFrom.host(of: "ftp://files.example.org") == "files.example.org")
        #expect(MacWhereFrom.host(of: nil) == nil)
        // '@' in the path/query must NOT be mistaken for userinfo.
        #expect(MacWhereFrom.host(of: "https://cdn.example.com/path/file@2x.png") == "cdn.example.com")
        #expect(MacWhereFrom.host(of: "https://dl.example.com/get?ref=a@b.com") == "dl.example.com")
        // Multiple '@' → last one delimits userinfo.
        #expect(MacWhereFrom.host(of: "https://user@host@real.tld/p") == "real.tld")
        // IPv6 literal unwrapped.
        #expect(MacWhereFrom.host(of: "https://[2606:4700::1]:8443/a") == "2606:4700::1")
    }

    @Test func rawIPDetection() {
        #expect(MacWhereFromsAnalyzer.isRawIPHost("203.0.113.7"))
        #expect(MacWhereFromsAnalyzer.isRawIPHost("10.0.0.1"))
        #expect(!MacWhereFromsAnalyzer.isRawIPHost("example.com"))
        #expect(!MacWhereFromsAnalyzer.isRawIPHost("1.2.3"))
        #expect(!MacWhereFromsAnalyzer.isRawIPHost("999.1.1.1"))
        #expect(!MacWhereFromsAnalyzer.isRawIPHost("1.2.3.4.5"))
    }

    // MARK: - Analyzer

    private func wf(_ url: String, path: String = "/Users/x/Downloads/f.dmg") -> MacWhereFrom {
        MacWhereFrom(path: path, urls: [url], scope: "x")
    }

    @Test func flagsRawIPDownloadHigh() {
        let f = MacWhereFromsAnalyzer().analyze([wf("https://203.0.113.7/payload.dmg")])
        #expect(f.count == 1)
        #expect(f[0].technique?.attackID == "T1105")
        #expect(f[0].severity == .high)
    }

    @Test func flagsPasteHostMedium() {
        let f = MacWhereFromsAnalyzer().analyze([wf("https://pastebin.com/raw/abc")])
        #expect(f.count == 1)
        #expect(f[0].technique?.attackID == "T1102")
        #expect(f[0].severity == .medium)
    }

    @Test func privateIPDowngradedToMedium() {
        // An internal/private IP (corp mirror) is medium, not high.
        let f = MacWhereFromsAnalyzer().analyze([wf("http://10.0.0.5/installer.pkg")])
        #expect(f.count == 1)
        #expect(f[0].severity == .medium)
        #expect(MacWhereFromsAnalyzer.isPrivateOrLocalIPv4("172.16.4.1"))
        #expect(MacWhereFromsAnalyzer.isPrivateOrLocalIPv4("192.168.1.9"))
        #expect(!MacWhereFromsAnalyzer.isPrivateOrLocalIPv4("203.0.113.7"))
    }

    @Test func suspiciousHostBoundaryMatch() {
        // Boundary match: file.io flags, profile.io does not.
        #expect(MacWhereFromsAnalyzer().analyze([wf("https://file.io/abc")]).count == 1)
        #expect(MacWhereFromsAnalyzer().analyze([wf("https://cdn.file.io/abc")]).count == 1)
        #expect(MacWhereFromsAnalyzer().analyze([wf("https://profile.io/abc")]).isEmpty)
    }

    @Test func ignoresBenignDownload() {
        let f = MacWhereFromsAnalyzer().analyze([
            wf("https://www.apple.com/macos/x.dmg"),
            wf("https://github.com/org/repo/releases/tool.zip"),
        ])
        #expect(f.isEmpty)
    }

    @Test func dedupesSameOrigin() {
        let f = MacWhereFromsAnalyzer().analyze([
            wf("https://203.0.113.7/a", path: "/p/same.dmg"),
            wf("https://203.0.113.7/a", path: "/p/same.dmg"),
        ])
        #expect(f.count == 1)
    }

    @Test func emptyNoFindings() {
        #expect(MacWhereFromsAnalyzer().analyze([]).isEmpty)
    }

    @Test func threadedThroughContext() {
        let ctx = AnalysisContext(files: [], events: [], timeline: [], registryValues: [],
                                  whereFroms: [wf("http://198.51.100.9/x.pkg")])
        let f = MacWhereFromsAnalyzer().analyze(context: ctx)
        #expect(f.count == 1)
        #expect(f[0].severity == .high)
    }
}
