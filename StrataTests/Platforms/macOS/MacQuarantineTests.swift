//
//  MacQuarantineTests.swift
//  StrataTests
//
//  Validates the macOS LaunchServices quarantine layer:
//   - QuarantineEvent: the pure CFAbsoluteTime->Date conversion and the
//     host/leaf display helpers (cross-platform, no I/O).
//   - QuarantineParser: an end-to-end read of a real LSQuarantineEvent SQLite
//     store built in-test with GRDB (macOS-only, mirrors BrowserHistoryParser:
//     SQLite-magic guard, copy-to-scratch, lenient by-name column mapping).
//   - MacQuarantineAnalyzer: the detection helper `analyze(_:)` against fixtures
//     (risky download from a suspicious origin, download by a non-browser agent).
//

import Testing
import Foundation
@testable import Strata

#if os(macOS)
import GRDB
#endif

// MARK: - Pure model decoders (cross-platform)

struct QuarantineEventDecoderTests {
    /// 2024-01-01 00:00:00 UTC in Unix seconds.
    private static let unix2024: Double = 1_704_067_200
    /// Seconds between 1970-01-01 and 2001-01-01.
    private static let cfOffset: Double = 978_307_200

    @Test func quarantineTimeConvertsCFAbsoluteEpoch() throws {
        // LSQuarantineTimeStamp is CFAbsoluteTime: seconds since 2001-01-01.
        let cf = Self.unix2024 - Self.cfOffset
        let date = try #require(QuarantineEvent.quarantineTime(cf))
        #expect(abs(date.timeIntervalSince1970 - Self.unix2024) < 1)
    }

    @Test func quarantineTimeMatchesKnownStamp() throws {
        // A real-world style stamp: 700000000 CFAbsoluteTime = 2023-03-10 ~UTC.
        let date = try #require(QuarantineEvent.quarantineTime(700_000_000))
        #expect(abs(date.timeIntervalSince1970 - (700_000_000 + Self.cfOffset)) < 1)
    }

    @Test func zeroAndNilTimestampsAreNil() {
        #expect(QuarantineEvent.quarantineTime(0) == nil)
        #expect(QuarantineEvent.quarantineTime(nil) == nil)
        #expect(QuarantineEvent.quarantineTime(-5) == nil)
    }

    @Test func hostExtraction() {
        #expect(QuarantineEvent.host(ofURL: "https://Evil.Example.com/path?q=1") == "evil.example.com")
        #expect(QuarantineEvent.host(ofURL: "http://1.2.3.4:8080/payload.dmg") == "1.2.3.4")
        #expect(QuarantineEvent.host(ofURL: "about:blank") == nil)
    }

    @Test func dataAndOriginHostHelpers() {
        let e = QuarantineEvent(agentName: "Safari",
                                dataURL: "https://cdn.example.org/x.dmg",
                                originURL: "https://lure.example.net/page",
                                sourceFile: "QuarantineEventsV2")
        #expect(e.dataHost == "cdn.example.org")
        #expect(e.originHost == "lure.example.net")
    }

    @Test func dataLeafExtractsFilename() {
        let e = QuarantineEvent(dataURL: "https://host.example/a/b/installer.pkg?token=1",
                                sourceFile: "QuarantineEventsV2")
        #expect(e.dataLeaf == "installer.pkg")
    }

    @Test func dataLeafNilWhenNoFilename() {
        let e = QuarantineEvent(dataURL: "https://host.example/", sourceFile: "Q")
        #expect(e.dataLeaf == nil)
    }

    @Test func displayTitlePrefersLeaf() {
        let e = QuarantineEvent(agentName: "curl",
                                dataURL: "https://h/p/tool.sh",
                                sourceFile: "Q")
        #expect(e.displayTitle == "tool.sh")
    }
}

// MARK: - Analyzer detection helper (cross-platform; tests analyze(_:))

struct MacQuarantineAnalyzerTests {
    private static let when = Date(timeIntervalSince1970: 1_700_000_000)

    private func event(agent: String? = "Safari", data: String? = nil,
                       origin: String? = nil) -> QuarantineEvent {
        QuarantineEvent(agentName: agent, dataURL: data, originURL: origin,
                        timestamp: Self.when, eventID: UUID().uuidString,
                        sourceFile: "QuarantineEventsV2")
    }

    @Test func flagsRiskyDownloadFromRawIPAsHighT1105() throws {
        let findings = MacQuarantineAnalyzer().analyze([
            event(agent: "Safari", data: "http://185.220.101.45/payload.dmg"),
        ])
        let f = try #require(findings.first { $0.technique?.attackID == "T1105" })
        #expect(f.severity == .high)
        #expect(f.phase == .delivery)
        #expect(f.title.contains("185.220.101.45"))
    }

    @Test func flagsRiskyDownloadFromPasteSite() throws {
        let findings = MacQuarantineAnalyzer().analyze([
            event(agent: "Google Chrome", data: "https://anonfiles.com/abc/stage2.zip"),
        ])
        let f = try #require(findings.first { $0.technique?.attackID == "T1105" })
        #expect(f.severity == .high)
        #expect(f.detail.localizedCaseInsensitiveContains("anonymous"))
    }

    @Test func flagsRiskyDownloadFromSuspiciousTLD() throws {
        let findings = MacQuarantineAnalyzer().analyze([
            event(agent: "Safari", data: "https://update-now.xyz/Installer.pkg"),
        ])
        #expect(findings.contains { $0.technique?.attackID == "T1105" })
    }

    @Test func flagsNonBrowserAgentDownloadT1204() throws {
        let findings = MacQuarantineAnalyzer().analyze([
            event(agent: "curl", data: "https://cdn.example.com/legit.pkg"),
        ])
        let f = try #require(findings.first { $0.technique?.attackID == "T1204" })
        #expect(f.severity == .high)
        #expect(f.phase == .delivery)
        #expect(f.title.localizedCaseInsensitiveContains("curl"))
    }

    @Test func flagsOsascriptAndWgetAgents() {
        let findings = MacQuarantineAnalyzer().analyze([
            event(agent: "osascript", data: "https://cdn.example.com/a.zip"),
            event(agent: "/usr/bin/wget", data: "https://cdn.example.com/b.tar.gz"),
        ])
        #expect(findings.filter { $0.technique?.attackID == "T1204" }.count == 2)
    }

    @Test func ignoresBenignBrowserDownloadFromKnownHost() {
        let findings = MacQuarantineAnalyzer().analyze([
            event(agent: "Safari", data: "https://cdn.apple.com/macos/update.pkg"),
            event(agent: "Google Chrome", data: "https://github.com/x/y/releases/tool.zip"),
        ])
        #expect(findings.isEmpty)
    }

    @Test func ignoresNonRiskyExtensionEvenFromSuspiciousHost() {
        // A PDF (not in riskyExtensions) from a paste site is not flagged by rule 1.
        let findings = MacQuarantineAnalyzer().analyze([
            event(agent: "Safari", data: "https://anonfiles.com/abc/report.pdf"),
        ])
        #expect(!findings.contains { $0.technique?.attackID == "T1105" })
    }

    @Test func emptyYieldsNothing() {
        #expect(MacQuarantineAnalyzer().analyze([]).isEmpty)
    }

    @Test func contextShimReturnsEmpty() {
        // AnalysisContext carries no quarantine field yet, so the protocol entry
        // point is a no-op placeholder for the integrator.
        let ctx = AnalysisContext(files: [], events: [], timeline: [], registryValues: [])
        #expect(MacQuarantineAnalyzer().analyze(context: ctx).isEmpty)
    }

    // Helper-level pinning.

    @Test func rawIPv4Detection() {
        #expect(MacQuarantineAnalyzer.isRawIPv4("10.0.0.1"))
        #expect(MacQuarantineAnalyzer.isRawIPv4("255.255.255.255"))
        #expect(!MacQuarantineAnalyzer.isRawIPv4("256.1.1.1"))
        #expect(!MacQuarantineAnalyzer.isRawIPv4("example.com"))
    }

    @Test func fileExtensionHelper() {
        #expect(MacQuarantineAnalyzer.fileExtension(of: "payload.dmg") == "dmg")
        #expect(MacQuarantineAnalyzer.fileExtension(of: "https://h/a/b/x.tar.gz?t=1") == "gz")
        #expect(MacQuarantineAnalyzer.fileExtension(of: "noext") == nil)
    }

    @Test func agentMatchGuardsAgainstSubstringFalsePositives() {
        #expect(MacQuarantineAnalyzer.agentMatches("curl", "curl"))
        #expect(MacQuarantineAnalyzer.agentMatches("/usr/bin/wget", "wget"))
        #expect(MacQuarantineAnalyzer.agentMatches("python3", "python3"))
        // "node" must not match inside an unrelated browser-ish name.
        #expect(!MacQuarantineAnalyzer.agentMatches("anode browser", "node"))
    }
}

// MARK: - Parser end-to-end (macOS-only; GRDB SQLite fixture)

#if os(macOS)

struct QuarantineParserTests {
    /// 2024-01-01 00:00:00 UTC.
    private static let unix2024: Double = 1_704_067_200
    private static let cfOffset: Double = 978_307_200

    /// Build a real QuarantineEventsV2 store on disk with the canonical
    /// LSQuarantineEvent schema and insert the given rows.
    private static func makeStore(
        rows: [(id: String, ts: Double, agent: String?, data: String?, origin: String?)]
    ) throws -> URL {
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent("quarantine-fixture-\(UUID().uuidString).db")
        let queue = try DatabaseQueue(path: url.path)
        try queue.write { db in
            try db.execute(sql: """
                CREATE TABLE LSQuarantineEvent (
                    LSQuarantineEventIdentifier TEXT PRIMARY KEY,
                    LSQuarantineTimeStamp REAL,
                    LSQuarantineAgentBundleIdentifier TEXT,
                    LSQuarantineAgentName TEXT,
                    LSQuarantineDataURLString TEXT,
                    LSQuarantineSenderName TEXT,
                    LSQuarantineSenderAddress TEXT,
                    LSQuarantineTypeNumber INTEGER,
                    LSQuarantineOriginTitle TEXT,
                    LSQuarantineOriginURLString TEXT,
                    LSQuarantineOriginAlias BLOB
                )
                """)
            for r in rows {
                try db.execute(sql: """
                    INSERT INTO LSQuarantineEvent
                        (LSQuarantineEventIdentifier, LSQuarantineTimeStamp,
                         LSQuarantineAgentName, LSQuarantineDataURLString,
                         LSQuarantineOriginURLString)
                    VALUES (?, ?, ?, ?, ?)
                    """, arguments: [r.id, r.ts, r.agent, r.data, r.origin])
            }
        }
        return url
    }

    @Test func parsesCanonicalQuarantineStore() throws {
        let cf = Self.unix2024 - Self.cfOffset
        let url = try Self.makeStore(rows: [
            (id: "11111111-1111-1111-1111-111111111111", ts: cf,
             agent: "Safari",
             data: "https://evil.example.com/payload.dmg",
             origin: "https://evil.example.com/landing"),
            (id: "22222222-2222-2222-2222-222222222222", ts: cf + 60,
             agent: "curl", data: "https://cdn.example.com/tool.pkg", origin: nil),
        ])
        defer { try? FileManager.default.removeItem(at: url) }

        let events = try QuarantineParser.parse(
            fileAt: url,
            sourceFile: "/Users/v/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2")
        #expect(events.count == 2)

        let safari = try #require(events.first { $0.agentName == "Safari" })
        #expect(safari.dataURL == "https://evil.example.com/payload.dmg")
        #expect(safari.originURL == "https://evil.example.com/landing")
        #expect(safari.eventID == "11111111-1111-1111-1111-111111111111")
        #expect(safari.dataLeaf == "payload.dmg")
        // The CFAbsoluteTime stamp decoded back to 2024-01-01.
        #expect(abs((safari.timestamp ?? .distantPast).timeIntervalSince1970 - Self.unix2024) < 1)

        let curl = try #require(events.first { $0.agentName == "curl" })
        #expect(curl.originURL == nil)
    }

    /// The store may be carried with an integer-stored timestamp; GRDB coerces
    /// it to Double and the conversion still lands.
    @Test func toleratesIntegerStoredTimestamp() throws {
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent("quarantine-int-\(UUID().uuidString).db")
        defer { try? FileManager.default.removeItem(at: url) }
        let queue = try DatabaseQueue(path: url.path)
        try queue.write { db in
            try db.execute(sql: """
                CREATE TABLE LSQuarantineEvent (
                    LSQuarantineEventIdentifier TEXT,
                    LSQuarantineTimeStamp INTEGER,
                    LSQuarantineAgentName TEXT,
                    LSQuarantineDataURLString TEXT,
                    LSQuarantineOriginURLString TEXT
                )
                """)
            let cf = Int64(Self.unix2024 - Self.cfOffset)
            try db.execute(sql: "INSERT INTO LSQuarantineEvent VALUES (?, ?, ?, ?, ?)",
                           arguments: ["e", cf, "Google Chrome",
                                       "https://h/x.zip", "https://h/page"])
        }
        let events = try QuarantineParser.parse(fileAt: url, sourceFile: "QuarantineEventsV2")
        let e = try #require(events.first)
        #expect(abs((e.timestamp ?? .distantPast).timeIntervalSince1970 - Self.unix2024) < 1)
    }

    @Test func nonSQLiteFileYieldsNothing() throws {
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent("not-a-db-\(UUID().uuidString)")
        try Data("this is not a sqlite database".utf8).write(to: url)
        defer { try? FileManager.default.removeItem(at: url) }
        let events = try QuarantineParser.parse(fileAt: url, sourceFile: "QuarantineEventsV2")
        #expect(events.isEmpty)
    }

    @Test func sqliteWithoutQuarantineTableYieldsNothing() throws {
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent("other-\(UUID().uuidString).db")
        defer { try? FileManager.default.removeItem(at: url) }
        let queue = try DatabaseQueue(path: url.path)
        try queue.write { db in
            try db.execute(sql: "CREATE TABLE notes (id INTEGER, body TEXT)")
            try db.execute(sql: "INSERT INTO notes VALUES (1, 'hi')")
        }
        let events = try QuarantineParser.parse(fileAt: url, sourceFile: "QuarantineEventsV2")
        #expect(events.isEmpty)
    }

    /// End-to-end: parse a real store, then run the analyzer on the result.
    @Test func parsedStoreFeedsAnalyzer() throws {
        let cf = Self.unix2024 - Self.cfOffset
        let url = try Self.makeStore(rows: [
            (id: "a", ts: cf, agent: "curl",
             data: "http://203.0.113.7/implant.dmg", origin: nil),
        ])
        defer { try? FileManager.default.removeItem(at: url) }
        let events = try QuarantineParser.parse(fileAt: url, sourceFile: "QuarantineEventsV2")
        let findings = MacQuarantineAnalyzer().analyze(events)
        // Both rules should fire: raw-IP risky download (T1105) AND curl agent (T1204).
        #expect(findings.contains { $0.technique?.attackID == "T1105" })
        #expect(findings.contains { $0.technique?.attackID == "T1204" })
    }
}

#endif
