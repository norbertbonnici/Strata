//
//  DocumentRevisionsTests.swift
//  StrataTests
//
//  Covers the Versions-store parser (generations + files side lookup, epoch
//  decode, schema-drift resilience).
//

import Testing
import Foundation
import GRDB
@testable import Strata

struct DocumentRevisionsTests {

    private func makeDB(_ build: (Database) throws -> Void) throws -> URL {
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent("docrev-\(UUID().uuidString).sqlite")
        do {
            let q = try DatabaseQueue(path: url.path)
            try q.write { db in
                try db.execute(sql: "CREATE TABLE files (file_row_id INTEGER PRIMARY KEY, file_name TEXT, file_path TEXT, file_storage_id INTEGER)")
                try db.execute(sql: """
                    CREATE TABLE generations (generation_id INTEGER PRIMARY KEY, generation_storage_id INTEGER,
                        generation_add_time REAL, generation_size INTEGER, generation_path TEXT, generation_name TEXT)
                    """)
                try build(db)
            }
        }
        return url
    }

    private let t1: Double = 1_699_000_000
    private let t2: Double = 1_700_000_000

    @Test func parsesVersionsWithFileJoin() throws {
        let url = try makeDB { db in
            try db.execute(sql: "INSERT INTO files (file_row_id, file_name, file_path, file_storage_id) VALUES (1, 'report.pages', '/Users/x/Documents/report.pages', 100)")
            try db.execute(sql: "INSERT INTO generations (generation_id, generation_storage_id, generation_add_time, generation_size, generation_path, generation_name) VALUES (1, 100, ?, 2048, 'PerUID/501/.../v1', 'report.pages')", arguments: [t1])
            try db.execute(sql: "INSERT INTO generations (generation_id, generation_storage_id, generation_add_time, generation_size, generation_path, generation_name) VALUES (2, 100, ?, 4096, 'PerUID/501/.../v2', 'report.pages')", arguments: [t2])
        }
        defer { try? FileManager.default.removeItem(at: url) }

        let out = try DocumentRevisionsParser.parse(fileAt: url,
            sourceFile: "/.DocumentRevisions-V100/db-V1/db.sqlite", scope: "x")
        #expect(out.count == 2)
        #expect(out.allSatisfy { $0.filePath == "/Users/x/Documents/report.pages" })
        // Newest first (ORDER BY add_time DESC).
        #expect(out.first?.versionTime == Date(timeIntervalSince1970: t2))
        #expect(out.first?.size == 4096)
        #expect(out.first?.generationPath == "PerUID/501/.../v2")
    }

    @Test func recoversVersionsWhenFilesTableAbsent() throws {
        // No `files` table — the version rows must still come back, using
        // generation_name as the path fallback (recovery of an orphaned version).
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent("docrev-\(UUID().uuidString).sqlite")
        do {
            let q = try DatabaseQueue(path: url.path)
            try q.write { db in
                try db.execute(sql: "CREATE TABLE generations (generation_id INTEGER PRIMARY KEY, generation_storage_id INTEGER, generation_add_time REAL, generation_name TEXT)")
                try db.execute(sql: "INSERT INTO generations (generation_id, generation_storage_id, generation_add_time, generation_name) VALUES (1, 100, ?, 'secret.key')", arguments: [t1])
            }
        }
        defer { try? FileManager.default.removeItem(at: url) }
        let out = try DocumentRevisionsParser.parse(fileAt: url, sourceFile: "/x/db.sqlite", scope: "x")
        #expect(out.count == 1)
        #expect(out[0].filePath == "secret.key")
        #expect(out[0].versionTime == Date(timeIntervalSince1970: t1))
    }

    @Test func rejectsNonDatabase() throws {
        let url = FileManager.default.temporaryDirectory.appendingPathComponent("dr-\(UUID().uuidString)")
        try Data("nope".utf8).write(to: url)
        defer { try? FileManager.default.removeItem(at: url) }
        #expect(try DocumentRevisionsParser.parse(fileAt: url, sourceFile: "/x/db.sqlite", scope: "x").isEmpty)
    }

    @Test func emptyWhenNoGenerationsTable() throws {
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent("docrev-\(UUID().uuidString).sqlite")
        do {
            let q = try DatabaseQueue(path: url.path)
            try q.write { db in try db.execute(sql: "CREATE TABLE unrelated (x INTEGER)") }
        }
        defer { try? FileManager.default.removeItem(at: url) }
        #expect(try DocumentRevisionsParser.parse(fileAt: url, sourceFile: "/x/db.sqlite", scope: "x").isEmpty)
    }
}
