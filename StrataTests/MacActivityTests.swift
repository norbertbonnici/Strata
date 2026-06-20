//
//  MacActivityTests.swift
//  StrataTests
//
//  Covers the QuickLook thumbnail-index parser (files + thumbnails side lookup,
//  CFAbsoluteTime decode, schema-drift resilience) and the trashed-payload
//  analyzer.
//

import Testing
import Foundation
import GRDB
@testable import Strata

struct MacActivityTests {

    private func makeIndex(_ build: (Database) throws -> Void) throws -> URL {
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent("qlindex-\(UUID().uuidString).sqlite")
        do {
            let q = try DatabaseQueue(path: url.path)
            try q.write { db in
                try db.execute(sql: "CREATE TABLE files (rowid INTEGER PRIMARY KEY, folder TEXT, file_name TEXT)")
                try db.execute(sql: "CREATE TABLE thumbnails (file_id INTEGER, last_hit_date REAL, hit_count INTEGER)")
                try build(db)
            }
        }
        return url
    }

    // CFAbsoluteTime for 2023-11-14T22:13:20Z ≈ 721_686_800.
    private let hit: Double = 721_686_800

    // MARK: - QuickLook parser

    @Test func parsesQuickLookIndex() throws {
        let url = try makeIndex { db in
            try db.execute(sql: "INSERT INTO files (rowid, folder, file_name) VALUES (1, '/Users/x/Downloads', 'invoice.pdf')")
            try db.execute(sql: "INSERT INTO thumbnails (file_id, last_hit_date, hit_count) VALUES (1, ?, 3)", arguments: [hit])
        }
        defer { try? FileManager.default.removeItem(at: url) }

        let out = try QuickLookParser.parse(fileAt: url,
            sourceFile: "/Users/x/Library/.../com.apple.QuickLook.thumbnailcache/index.sqlite", scope: "x")
        #expect(out.count == 1)
        #expect(out[0].kind == .quickLook)
        #expect(out[0].path == "/Users/x/Downloads/invoice.pdf")
        #expect(out[0].detail == "viewed 3×")
        // CFAbsoluteTime decodes to the right wall-clock time.
        #expect(out[0].timestamp == Date(timeIntervalSinceReferenceDate: hit))
    }

    @Test func recoversFilesEvenWhenThumbnailsSchemaDiffers() throws {
        // No `thumbnails` table at all — the file's presence is still evidence it
        // was previewed; the row must come back (timestamp nil).
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent("qlindex-\(UUID().uuidString).sqlite")
        do {
            let q = try DatabaseQueue(path: url.path)
            try q.write { db in
                try db.execute(sql: "CREATE TABLE files (rowid INTEGER PRIMARY KEY, folder TEXT, file_name TEXT)")
                try db.execute(sql: "INSERT INTO files (rowid, folder, file_name) VALUES (1, '/tmp', 'payload.sh')")
            }
        }
        defer { try? FileManager.default.removeItem(at: url) }
        let out = try QuickLookParser.parse(fileAt: url, sourceFile: "/x/index.sqlite", scope: "x")
        #expect(out.count == 1)
        #expect(out[0].path == "/tmp/payload.sh")
        #expect(out[0].timestamp == nil)
    }

    @Test func rejectsNonDatabase() throws {
        let url = FileManager.default.temporaryDirectory.appendingPathComponent("ql-\(UUID().uuidString)")
        try Data("nope".utf8).write(to: url)
        defer { try? FileManager.default.removeItem(at: url) }
        #expect(try QuickLookParser.parse(fileAt: url, sourceFile: "/x/index.sqlite", scope: "x").isEmpty)
    }

    // MARK: - Analyzer (trashed payloads)

    private func trash(_ path: String) -> MacActivityItem {
        MacActivityItem(kind: .trash, path: path, timestamp: Date(timeIntervalSince1970: 1_700_000_000),
                        scope: "x", sourceFile: path)
    }
    private func ql(_ path: String) -> MacActivityItem {
        MacActivityItem(kind: .quickLook, path: path, scope: "x", sourceFile: "/x/index.sqlite")
    }

    @Test func flagsTrashedPayload() {
        let findings = MacActivityAnalyzer().analyze([trash("/Users/x/.Trash/dropper.sh")])
        #expect(findings.count == 1)
        #expect(findings[0].technique?.attackID == "T1070.004")
        #expect(findings[0].severity == .medium)
        #expect(findings[0].title.contains("dropper.sh"))
    }

    @Test func ignoresBenignTrashAndAllQuickLook() {
        let findings = MacActivityAnalyzer().analyze([
            trash("/Users/x/.Trash/notes.txt"),          // benign extension
            ql("/Users/x/.Trash/evil.sh"),               // QuickLook is context, not a finding
            ql("/tmp/payload.dmg"),
        ])
        #expect(findings.isEmpty)
    }

    @Test func dedupesRepeatedTrashedPath() {
        let findings = MacActivityAnalyzer().analyze([
            trash("/Users/x/.Trash/a.app"), trash("/Users/x/.Trash/a.app"),
        ])
        #expect(findings.count == 1)
    }

    @Test func emptyInputNoFindings() {
        #expect(MacActivityAnalyzer().analyze([]).isEmpty)
    }

    @Test func threadedThroughContext() {
        let ctx = AnalysisContext(files: [], events: [], timeline: [], registryValues: [],
                                  userActivity: [trash("/Users/x/.Trash/x.pkg")])
        #expect(MacActivityAnalyzer().analyze(context: ctx).count == 1)
    }
}
