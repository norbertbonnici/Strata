//
//  PowerlogTests.swift
//  StrataTests
//
//  Covers the Powerlog (CurrentPowerlog.PLSQL) parser over a GRDB-built fixture
//  — the TIMEOFFSET clock correction, APPINFO bundle→name enrichment, network
//  byte summing, and schema-drift tolerance — plus the PowerlogAnalyzer
//  offensive-tool / RMM / osascript detections and the timeline projection.
//

import Testing
import Foundation
import GRDB
@testable import Strata

struct PowerlogTests {

    // Nov 2023 Unix-epoch base.
    private let base: Double = 1_700_000_000

    private func makePowerlogDB(_ build: (Database) throws -> Void) throws -> URL {
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent("powerlog-\(UUID().uuidString).PLSQL")
        let queue = try DatabaseQueue(path: url.path)
        try queue.write { db in
            try db.execute(sql: "CREATE TABLE PLSTORAGEOPERATOR_EVENTFORWARD_TIMEOFFSET (ID INTEGER PRIMARY KEY, timestamp REAL, system REAL)")
            try db.execute(sql: "CREATE TABLE PLPROCESSMONITORAGENT_EVENTFORWARD_PROCESSID (ID INTEGER PRIMARY KEY, timestamp REAL, PID INTEGER, ProcessName TEXT, BundleID TEXT)")
            try db.execute(sql: "CREATE TABLE PLAPPLICATIONAGENT_EVENTFORWARD_APPLIFECYCLE (ID INTEGER PRIMARY KEY, timestamp REAL, BundleID TEXT, EVENT TEXT, PID INTEGER)")
            try db.execute(sql: "CREATE TABLE PLAPPLICATIONAGENT_EVENTFORWARD_FRONTMOSTAPP (ID INTEGER PRIMARY KEY, timestamp REAL, BundleID TEXT)")
            try db.execute(sql: "CREATE TABLE PLPROCESSNETWORKAGENT_EVENTINTERVAL_USAGEDIFF (ID INTEGER PRIMARY KEY, timestamp REAL, timestampEnd REAL, BundleName TEXT, ProcessName TEXT, WiFiIn INTEGER, WiFiOut INTEGER, CellIn INTEGER, CellOut INTEGER)")
            try db.execute(sql: "CREATE TABLE PLAPPLICATIONAGENT_EVENTNONE_APPINFO (ID INTEGER PRIMARY KEY, timestamp REAL, BundleID TEXT, Name TEXT)")
            try build(db)
        }
        return url   // queue released → connection closed, file safe to copy
    }

    // MARK: - Parser

    @Test func parsesProcessWithOffsetAndEnrichment() throws {
        let url = try makePowerlogDB { db in
            // Offset of +5s applicable from `base`.
            try db.execute(sql: "INSERT INTO PLSTORAGEOPERATOR_EVENTFORWARD_TIMEOFFSET (ID, timestamp, system) VALUES (1, ?, 5.0)", arguments: [base])
            try db.execute(sql: "INSERT INTO PLAPPLICATIONAGENT_EVENTNONE_APPINFO (ID, BundleID, Name) VALUES (1, 'com.acme.tool', 'Acme Tool')")
            // ProcessName present → used directly.
            try db.execute(sql: "INSERT INTO PLPROCESSMONITORAGENT_EVENTFORWARD_PROCESSID (ID, timestamp, PID, ProcessName, BundleID) VALUES (1, ?, 501, 'osascript', 'com.apple.osascript')", arguments: [base + 100])
            // No ProcessName but a known BundleID → enriched from APPINFO.
            try db.execute(sql: "INSERT INTO PLPROCESSMONITORAGENT_EVENTFORWARD_PROCESSID (ID, timestamp, PID, ProcessName, BundleID) VALUES (2, ?, 502, NULL, 'com.acme.tool')", arguments: [base + 200])
        }
        defer { try? FileManager.default.removeItem(at: url) }

        let rows = try PowerlogParser.parse(fileAt: url, sourceFile: "/private/var/db/powerlog/.../CurrentPowerlog.PLSQL", scope: "system")
        let procs = rows.filter { $0.kind == .process }
        #expect(procs.count == 2)

        let p1 = procs.first { $0.pid == 501 }
        #expect(p1?.processName == "osascript")
        // Offset applied: base+100 raw → +5s.
        #expect(abs((p1?.date?.timeIntervalSince1970 ?? 0) - (base + 105)) < 0.5)

        let p2 = procs.first { $0.pid == 502 }
        #expect(p2?.processName == "Acme Tool")   // enriched from APPINFO
        #expect(p2?.bundleID == "com.acme.tool")
    }

    @Test func parsesNetworkSumsBytesAndInterval() throws {
        let url = try makePowerlogDB { db in
            try db.execute(sql: "INSERT INTO PLSTORAGEOPERATOR_EVENTFORWARD_TIMEOFFSET (ID, timestamp, system) VALUES (1, ?, 0.0)", arguments: [base])
            try db.execute(sql: """
                INSERT INTO PLPROCESSNETWORKAGENT_EVENTINTERVAL_USAGEDIFF
                (ID, timestamp, timestampEnd, BundleName, ProcessName, WiFiIn, WiFiOut, CellIn, CellOut)
                VALUES (1, ?, ?, 'com.acme.tool', 'exfil', 100, 200, 10, 20)
                """, arguments: [base + 300, base + 360])
        }
        defer { try? FileManager.default.removeItem(at: url) }

        let rows = try PowerlogParser.parse(fileAt: url, sourceFile: "/x/CurrentPowerlog.PLSQL", scope: "system")
        let net = rows.filter { $0.kind == .network }
        #expect(net.count == 1)
        #expect(net[0].bytesIn == 110)   // WiFiIn + CellIn
        #expect(net[0].bytesOut == 220)  // WiFiOut + CellOut
        #expect(net[0].processName == "exfil")
        #expect(net[0].endDate != nil)
    }

    @Test func appLifecycleAndFrontmostParsed() throws {
        let url = try makePowerlogDB { db in
            try db.execute(sql: "INSERT INTO PLAPPLICATIONAGENT_EVENTFORWARD_APPLIFECYCLE (ID, timestamp, BundleID, EVENT, PID) VALUES (1, ?, 'com.apple.Terminal', 'Foreground', 700)", arguments: [base + 10])
            try db.execute(sql: "INSERT INTO PLAPPLICATIONAGENT_EVENTFORWARD_FRONTMOSTAPP (ID, timestamp, BundleID) VALUES (1, ?, 'com.apple.Safari')", arguments: [base + 20])
        }
        defer { try? FileManager.default.removeItem(at: url) }

        let rows = try PowerlogParser.parse(fileAt: url, sourceFile: "/x/CurrentPowerlog.PLSQL", scope: "system")
        let life = rows.first { $0.kind == .appLifecycle }
        #expect(life?.bundleID == "com.apple.Terminal")
        #expect(life?.event == "Foreground")
        #expect(life?.pid == 700)
        // No TIMEOFFSET rows → offset 0, raw date passes through.
        #expect(abs((life?.date?.timeIntervalSince1970 ?? 0) - (base + 10)) < 0.5)
        #expect(rows.contains { $0.kind == .frontmost && $0.bundleID == "com.apple.Safari" })
    }

    @Test func tolerantOfMissingTables() throws {
        // Only the offset table + one event table exist; the parser must not
        // throw on the absent tables, just return what's present.
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent("powerlog-\(UUID().uuidString).PLSQL")
        do {
            let q = try DatabaseQueue(path: url.path)
            try q.write { db in
                try db.execute(sql: "CREATE TABLE PLPROCESSMONITORAGENT_EVENTFORWARD_PROCESSID (ID INTEGER PRIMARY KEY, timestamp REAL, PID INTEGER, ProcessName TEXT, BundleID TEXT)")
                try db.execute(sql: "INSERT INTO PLPROCESSMONITORAGENT_EVENTFORWARD_PROCESSID (ID, timestamp, PID, ProcessName, BundleID) VALUES (1, ?, 9, 'mimikatz', NULL)", arguments: [base + 1])
            }
        }
        defer { try? FileManager.default.removeItem(at: url) }

        let rows = try PowerlogParser.parse(fileAt: url, sourceFile: "/x/CurrentPowerlog.PLSQL", scope: "system")
        #expect(rows.count == 1)
        #expect(rows[0].processName == "mimikatz")
    }

    @Test func survivesColumnStorageClassDrift() throws {
        // BLOB-affinity columns keep each inserted value's original storage class,
        // so this stores timestamp/PID as TEXT and ProcessName as INTEGER — the
        // cross-version "TEXT↔INTEGER drift" the parser must tolerate. The old
        // `row[col] as T?` reads would TRAP (try! valueMismatch) here, not return
        // nil; the storage-class coercion must instead recover the values without
        // crashing.
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent("powerlog-\(UUID().uuidString).PLSQL")
        do {
            let q = try DatabaseQueue(path: url.path)
            try q.write { db in
                try db.execute(sql: "CREATE TABLE PLPROCESSMONITORAGENT_EVENTFORWARD_PROCESSID (ID INTEGER PRIMARY KEY, timestamp BLOB, PID BLOB, ProcessName BLOB, BundleID BLOB)")
                // timestamp + PID as TEXT, ProcessName as INTEGER (wrong slots).
                try db.execute(sql: "INSERT INTO PLPROCESSMONITORAGENT_EVENTFORWARD_PROCESSID (ID, timestamp, PID, ProcessName, BundleID) VALUES (1, '1700000500', '999', 12345, 'com.x')")
            }
        }
        defer { try? FileManager.default.removeItem(at: url) }

        let rows = try PowerlogParser.parse(fileAt: url, sourceFile: "/x/CurrentPowerlog.PLSQL", scope: "system")
        #expect(rows.count == 1)                                   // did not crash
        #expect(rows[0].pid == 999)                                // TEXT → Int64
        #expect(rows[0].processName == "12345")                    // INTEGER → String
        #expect(abs((rows[0].date?.timeIntervalSince1970 ?? 0) - 1_700_000_500) < 0.5)  // TEXT → Double
    }

    @Test func rejectsNonDatabase() throws {
        let url = FileManager.default.temporaryDirectory.appendingPathComponent("not-\(UUID().uuidString).PLSQL")
        try Data("not a database".utf8).write(to: url)
        defer { try? FileManager.default.removeItem(at: url) }
        #expect(try PowerlogParser.parse(fileAt: url, sourceFile: "/x", scope: "x").isEmpty)
    }

    // MARK: - Analyzer

    private func entry(_ kind: PowerlogEntry.Kind, name: String?, bundle: String? = nil) -> PowerlogEntry {
        PowerlogEntry(kind: kind, processName: name, bundleID: bundle,
                      date: Date(timeIntervalSince1970: base), scope: "system",
                      sourceFile: "/x/CurrentPowerlog.PLSQL")
    }

    @Test func flagsOffensiveToolHigh() {
        let f = PowerlogAnalyzer().analyze([entry(.process, name: "mimikatz")])
        #expect(f.count == 1)
        #expect(f[0].technique?.attackID == "T1059")
        #expect(f[0].severity == .high)
    }

    @Test func flagsExactExecOffensiveHigh() {
        // "nc" must match on basename equality, not substring (else it would
        // match every binary). A full-path ProcessName resolves to its basename.
        let f = PowerlogAnalyzer().analyze([entry(.process, name: "/usr/bin/nc")])
        #expect(f.count == 1)
        #expect(f[0].severity == .high)
    }

    @Test func flagsRemoteAccessHigh() {
        let f = PowerlogAnalyzer().analyze([entry(.frontmost, name: nil, bundle: "com.teamviewer.TeamViewer")])
        #expect(f.count == 1)
        #expect(f[0].technique?.attackID == "T1219")
        #expect(f[0].severity == .high)
    }

    @Test func flagsOsascriptMedium() {
        let f = PowerlogAnalyzer().analyze([entry(.process, name: "osascript")])
        #expect(f.count == 1)
        #expect(f[0].technique?.attackID == "T1059.002")
        #expect(f[0].severity == .medium)
    }

    @Test func ignoresBenign() {
        let f = PowerlogAnalyzer().analyze([
            entry(.frontmost, name: nil, bundle: "com.apple.Safari"),
            entry(.process, name: "Finder"),
        ])
        #expect(f.isEmpty)
    }

    @Test func doesNotFlagMDNSResponder() {
        // "responder" must match only on exact basename, never as a substring of
        // the core mDNSResponder daemon (a guaranteed FP on every macOS host).
        let f = PowerlogAnalyzer().analyze([
            entry(.process, name: "mDNSResponder", bundle: "com.apple.mDNSResponder"),
        ])
        #expect(f.isEmpty)
        // …but a real Responder binary (exact basename) is still flagged.
        let g = PowerlogAnalyzer().analyze([entry(.process, name: "/opt/responder")])
        #expect(g.count == 1)
        #expect(g[0].severity == .high)
    }

    @Test func emptyInputNoFindings() {
        #expect(PowerlogAnalyzer().analyze([]).isEmpty)
    }

    @Test func threadedThroughContext() {
        let ctx = AnalysisContext(files: [], events: [], timeline: [], registryValues: [],
                                  powerlog: [entry(.process, name: "cobaltstrike")])
        let f = PowerlogAnalyzer().analyze(context: ctx)
        #expect(f.count == 1)
        #expect(f[0].severity == .high)
    }

    // MARK: - Timeline

    @Test func timelineProjectsDatedRecords() {
        let dated = entry(.process, name: "osascript")
        let undated = PowerlogEntry(kind: .process, processName: "x", date: nil,
                                    scope: "system", sourceFile: "/x")
        let events = TimelineBuilder.build(from: [dated, undated])
        #expect(events.count == 1)   // undated dropped
        #expect(events[0].source == .powerlog)
        #expect(events[0].path.contains("osascript"))
    }
}
