//
//  BrowserHistoryTests.swift
//  StrataTests
//
//  Validates the pure, cross-platform browser-history helpers (timestamp
//  conversions, browser/profile/host parsing) and the BrowserHistoryAnalyzer
//  detection rules. The GRDB SQLite read itself (BrowserHistoryParser, macOS-
//  only) is exercised end-to-end against a real History DB out of band; here we
//  pin the decoding/detection logic that doesn't need a database.
//

import Testing
import Foundation
import SQLite3
@testable import Strata

struct BrowserHistoryDecoderTests {
    /// 2024-01-01 00:00:00 UTC in Unix seconds.
    private static let unix2024: Double = 1_704_067_200
    /// Seconds between 1601-01-01 and 1970-01-01.
    private static let webkitOffset: Double = 11_644_473_600

    @Test func chromeTimeConvertsWebkitEpoch() throws {
        // Chrome stores microseconds since 1601-01-01.
        let micros = Int64((Self.unix2024 + Self.webkitOffset) * 1_000_000)
        let date = try #require(BrowserHistoryEntry.chromeTime(micros))
        #expect(abs(date.timeIntervalSince1970 - Self.unix2024) < 1)
    }

    @Test func firefoxTimeConvertsUnixMicros() throws {
        let micros = Int64(Self.unix2024 * 1_000_000)
        let date = try #require(BrowserHistoryEntry.firefoxTime(micros))
        #expect(abs(date.timeIntervalSince1970 - Self.unix2024) < 1)
    }

    @Test func zeroAndNegativeTimestampsAreNil() {
        #expect(BrowserHistoryEntry.chromeTime(0) == nil)
        #expect(BrowserHistoryEntry.chromeTime(nil) == nil)
        #expect(BrowserHistoryEntry.firefoxTime(0) == nil)
        #expect(BrowserHistoryEntry.firefoxTime(-5) == nil)
    }

    @Test func browserClassificationFromPath() {
        #expect(BrowserHistoryEntry.browser(forPath: #"\Users\v\AppData\Local\Google\Chrome\User Data\Default\History"#) == .chrome)
        #expect(BrowserHistoryEntry.browser(forPath: #"\Users\v\AppData\Local\Microsoft\Edge\User Data\Default\History"#) == .edge)
        #expect(BrowserHistoryEntry.browser(forPath: #"\Users\v\AppData\Local\BraveSoftware\Brave-Browser\User Data\Default\History"#) == .brave)
        #expect(BrowserHistoryEntry.browser(forPath: #"\Users\v\AppData\Roaming\Mozilla\Firefox\Profiles\ab12.default-release\places.sqlite"#) == .firefox)
        #expect(BrowserHistoryEntry.browser(forPath: #"C:\where\History"#) == .unknown)
    }

    @Test func profileFromPath() {
        #expect(BrowserHistoryEntry.profile(forPath: #"\Google\Chrome\User Data\Profile 1\History"#) == "Profile 1")
        #expect(BrowserHistoryEntry.profile(forPath: #"/Mozilla/Firefox/Profiles/ab12.default-release/places.sqlite"#) == "ab12.default-release")
        #expect(BrowserHistoryEntry.profile(forPath: "History") == nil)
    }

    @Test func hostExtraction() {
        #expect(BrowserHistoryEntry.host(ofURL: "https://Evil.Example.com/path?q=1") == "evil.example.com")
        #expect(BrowserHistoryEntry.host(ofURL: "http://1.2.3.4:8080/panel") == "1.2.3.4")
        #expect(BrowserHistoryEntry.host(ofURL: "https://user:pw@cdn.discordapp.com/attachments/x") == "cdn.discordapp.com")
        #expect(BrowserHistoryEntry.host(ofURL: "about:blank") == nil)
    }

    @Test func downloadDetailSummaryUsesTargetLeaf() {
        let e = BrowserHistoryEntry(browser: .chrome, kind: .download,
                                    url: "http://x/y", timestamp: nil,
                                    targetPath: #"C:\Users\v\Downloads\payload.exe"#,
                                    receivedBytes: 2048, sourceFile: "History")
        #expect(e.targetLeaf == "payload.exe")
        #expect(e.detailSummary.contains("payload.exe"))
        #expect(e.detailSummary.contains("2.0 KB"))
    }
}

struct BrowserHistoryAnalyzerTests {
    private static let when = Date(timeIntervalSince1970: 1_700_000_000)

    private func visit(_ url: String, title: String? = nil, visits: Int = 1,
                       browser: BrowserHistoryEntry.Browser = .chrome) -> BrowserHistoryEntry {
        BrowserHistoryEntry(browser: browser, kind: .visit, url: url, title: title,
                            timestamp: Self.when, visitCount: visits, typedCount: 0,
                            sourceFile: "History")
    }

    private func download(_ url: String, target: String,
                          browser: BrowserHistoryEntry.Browser = .chrome) -> BrowserHistoryEntry {
        BrowserHistoryEntry(browser: browser, kind: .download, url: url,
                            timestamp: Self.when, targetPath: target,
                            receivedBytes: 4096, sourceFile: "History")
    }

    private func context(_ entries: [BrowserHistoryEntry]) -> AnalysisContext {
        AnalysisContext(files: [], events: [], timeline: [], registryValues: [],
                        browserHistory: entries)
    }

    @Test func flagsExecutableDownloadAsHighT1105() throws {
        let findings = BrowserHistoryAnalyzer().analyze(context: context([
            download("https://cdn.example.com/update", target: #"C:\Users\v\Downloads\update.exe"#),
        ]))
        let f = try #require(findings.first { $0.title.contains("Suspicious browser download") })
        #expect(f.severity == .high)
        #expect(f.phase == .delivery)
        #expect(f.technique?.attackID == "T1105")
    }

    @Test func archiveDownloadFromBenignHostIsMedium() throws {
        let findings = BrowserHistoryAnalyzer().analyze(context: context([
            download("https://cdn.example.com/pkg", target: #"C:\Users\v\Downloads\tools.zip"#),
        ]))
        let f = try #require(findings.first { $0.title.contains("Suspicious browser download") })
        #expect(f.severity == .medium)
    }

    @Test func flagsSuspiciousHostActivityT1102() throws {
        let findings = BrowserHistoryAnalyzer().analyze(context: context([
            visit("https://anonfiles.com/abc123/stage2"),
        ]))
        let f = try #require(findings.first { $0.title.contains("suspicious host") })
        #expect(f.phase == .commandAndControl)
        #expect(f.technique?.attackID == "T1102")
    }

    @Test func flagsRawIPActivity() throws {
        let findings = BrowserHistoryAnalyzer().analyze(context: context([
            visit("http://185.220.101.45/login"),
        ]))
        #expect(findings.contains { $0.title.contains("185.220.101.45") })
    }

    @Test func flagsOffensiveToolNameT1588() throws {
        let findings = BrowserHistoryAnalyzer().analyze(context: context([
            download("https://github.com/x/mimikatz/releases/mimikatz.exe",
                     target: #"C:\Users\v\Downloads\mimikatz.exe"#),
        ]))
        let f = try #require(findings.first { $0.technique?.attackID == "T1588.002" })
        #expect(f.severity == .high)
        #expect(f.phase == .weaponization)
        #expect(f.title.localizedCaseInsensitiveContains("mimikatz"))
    }

    @Test func ignoresBenignBrowsing() {
        let findings = BrowserHistoryAnalyzer().analyze(context: context([
            visit("https://www.google.com/search?q=swift", title: "Google"),
            visit("https://developer.apple.com/documentation", title: "Docs"),
            download("https://cdn.example.com/report", target: #"C:\Users\v\Downloads\report.pdf"#),
        ]))
        #expect(findings.isEmpty)
    }

    @Test func emptyYieldsNothing() {
        #expect(BrowserHistoryAnalyzer().analyze(context: context([])).isEmpty)
    }

    @Test func rawIPv4Detection() {
        #expect(BrowserHistoryAnalyzer.isRawIPv4("10.0.0.1"))
        #expect(BrowserHistoryAnalyzer.isRawIPv4("255.255.255.255"))
        #expect(!BrowserHistoryAnalyzer.isRawIPv4("256.1.1.1"))
        #expect(!BrowserHistoryAnalyzer.isRawIPv4("example.com"))
        #expect(!BrowserHistoryAnalyzer.isRawIPv4("1.2.3"))
    }

    @Test func fileExtensionHelper() {
        #expect(BrowserHistoryAnalyzer.fileExtension(of: "payload.exe") == "exe")
        #expect(BrowserHistoryAnalyzer.fileExtension(of: "archive.tar.gz") == "gz")
        #expect(BrowserHistoryAnalyzer.fileExtension(of: "noext") == nil)
        #expect(BrowserHistoryAnalyzer.fileExtension(of: ".bashrc") == nil)
    }
}

#if os(macOS)

/// End-to-end exercise of the macOS-only `BrowserHistoryParser` against real
/// SQLite databases built here with the system SQLite3 C API (no GRDB needed in
/// the test target). Validates schema detection + the column/timestamp wiring
/// that the pure-helper tests above can't reach.
struct BrowserHistoryParserTests {
    /// 2024-01-01 00:00:00 UTC.
    private static let unix2024 = 1_704_067_200
    private static let webkitOffset = 11_644_473_600

    private func writeDB(_ sql: String) throws -> URL {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("strata-bh-test-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        let dbURL = dir.appendingPathComponent("History")
        var handle: OpaquePointer?
        try #require(sqlite3_open(dbURL.path, &handle) == SQLITE_OK)
        var err: UnsafeMutablePointer<CChar>?
        let rc = sqlite3_exec(handle, sql, nil, nil, &err)
        if rc != SQLITE_OK {
            let msg = err.map { String(cString: $0) } ?? "unknown"
            sqlite3_free(err)
            sqlite3_close(handle)
            Issue.record("sqlite exec failed: \(msg)")
        }
        sqlite3_close(handle)
        return dbURL
    }

    @Test func parsesChromiumHistory() throws {
        let chrome2024 = (Self.unix2024 + Self.webkitOffset) * 1_000_000
        let dbURL = try writeDB("""
            CREATE TABLE urls (id INTEGER PRIMARY KEY, url TEXT, title TEXT,
                visit_count INTEGER, typed_count INTEGER, last_visit_time INTEGER, hidden INTEGER);
            CREATE TABLE downloads (id INTEGER PRIMARY KEY, current_path TEXT, target_path TEXT,
                start_time INTEGER, received_bytes INTEGER, total_bytes INTEGER, tab_url TEXT);
            INSERT INTO urls VALUES (1, 'https://evil.example.com/x', 'Evil Page', 5, 2, \(chrome2024), 0);
            INSERT INTO urls VALUES (2, 'https://bookmarked.example/never', 'Never', 0, 0, 0, 0);
            INSERT INTO downloads VALUES (1, 'C:\\Temp\\payload.exe.crdownload',
                'C:\\Users\\v\\Downloads\\payload.exe', \(chrome2024), 4096, 8192,
                'https://evil.example.com/dl');
            """)
        defer { try? FileManager.default.removeItem(at: dbURL.deletingLastPathComponent()) }

        let entries = try BrowserHistoryParser.parse(
            fileAt: dbURL,
            sourceFile: #"\Users\v\AppData\Local\Google\Chrome\User Data\Default\History"#)

        // The never-visited (last_visit_time = 0) URL is filtered out.
        let visits = entries.filter { $0.kind == .visit }
        #expect(visits.count == 1)
        let visit = try #require(visits.first)
        #expect(visit.browser == .chrome)
        #expect(visit.url == "https://evil.example.com/x")
        #expect(visit.title == "Evil Page")
        #expect(visit.visitCount == 5)
        #expect(visit.typedCount == 2)
        #expect(visit.userProfile == "Default")
        #expect(abs((visit.timestamp ?? .distantPast).timeIntervalSince1970 - Double(Self.unix2024)) < 1)

        let dl = try #require(entries.first { $0.kind == .download })
        #expect(dl.targetPath == #"C:\Users\v\Downloads\payload.exe"#)
        #expect(dl.targetLeaf == "payload.exe")
        #expect(dl.receivedBytes == 4096)
        #expect(dl.totalBytes == 8192)
        #expect(dl.referrer == "https://evil.example.com/dl")
        #expect(abs((dl.timestamp ?? .distantPast).timeIntervalSince1970 - Double(Self.unix2024)) < 1)
    }

    @Test func parsesFirefoxPlaces() throws {
        let firefox2024 = Self.unix2024 * 1_000_000
        let dbURL = try writeDB("""
            CREATE TABLE moz_places (id INTEGER PRIMARY KEY, url TEXT, title TEXT,
                visit_count INTEGER, typed INTEGER, last_visit_date INTEGER);
            INSERT INTO moz_places VALUES (1, 'https://anonfiles.com/abc/stage2', 'Drop', 3, 1, \(firefox2024));
            INSERT INTO moz_places VALUES (2, 'https://nevervisited.example', 'X', 0, 0, NULL);
            """)
        defer { try? FileManager.default.removeItem(at: dbURL.deletingLastPathComponent()) }

        let entries = try BrowserHistoryParser.parse(
            fileAt: dbURL,
            sourceFile: #"\Users\v\AppData\Roaming\Mozilla\Firefox\Profiles\ab12.default-release\places.sqlite"#)

        #expect(entries.count == 1)   // the NULL-last_visit_date row is filtered out
        let e = try #require(entries.first)
        #expect(e.browser == .firefox)
        #expect(e.kind == .visit)
        #expect(e.url == "https://anonfiles.com/abc/stage2")
        #expect(e.visitCount == 3)
        #expect(e.typedCount == 1)
        #expect(e.userProfile == "ab12.default-release")
        #expect(abs((e.timestamp ?? .distantPast).timeIntervalSince1970 - Double(Self.unix2024)) < 1)
    }

    @Test func nonBrowserSQLiteYieldsNothing() throws {
        let dbURL = try writeDB("CREATE TABLE notes (id INTEGER, body TEXT); INSERT INTO notes VALUES (1, 'hi');")
        defer { try? FileManager.default.removeItem(at: dbURL.deletingLastPathComponent()) }
        let entries = try BrowserHistoryParser.parse(fileAt: dbURL, sourceFile: "History")
        #expect(entries.isEmpty)
    }
}

#endif
