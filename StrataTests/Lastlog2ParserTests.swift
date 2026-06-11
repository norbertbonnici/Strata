//
//  Lastlog2ParserTests.swift
//  StrataTests
//
//  Validates Lastlog2Parser: the modern (glibc >= 2.40 / util-linux) lastlog2.db
//  SQLite "last login per user" store -> [LastlogEntry] (the same model the binary
//  LastlogParser yields, so both fold into one "last login" view).
//
//  The fixtures are real SQLite databases built in-test via GRDB (the same lib the
//  parser reads with), so the GRDB read path - copy-to-scratch, table discovery,
//  lenient case-insensitive column mapping - is exercised end-to-end on macOS.
//

import Testing
import Foundation
import GRDB
@testable import Strata

#if os(macOS)

struct Lastlog2ParserTests {

    /// Build a real lastlog2.db on disk: create a table and insert the given rows.
    /// `columns` lets a test pick the column casing/names so the lenient,
    /// case-insensitive reader is exercised against schema drift.
    private static func makeDB(table: String = "Lastlog2",
                               columns: (name: String, time: String, tty: String, host: String) =
                                   ("Name", "Time", "TTY", "RemoteHost"),
                               rows: [(name: String, time: Int64, tty: String, host: String)]) throws -> URL {
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent("lastlog2-fixture-\(UUID().uuidString).db")
        let queue = try DatabaseQueue(path: url.path)
        try queue.write { db in
            try db.execute(sql: """
                CREATE TABLE "\(table)" (
                    "\(columns.name)" TEXT PRIMARY KEY,
                    "\(columns.time)" INTEGER,
                    "\(columns.tty)" TEXT,
                    "\(columns.host)" TEXT
                )
                """)
            for r in rows {
                try db.execute(
                    sql: "INSERT INTO \"\(table)\" VALUES (?, ?, ?, ?)",
                    arguments: [r.name, r.time, r.tty, r.host])
            }
        }
        return url
    }

    @Test func parsesCanonicalSchema() throws {
        let url = try Self.makeDB(rows: [
            (name: "root", time: 1_700_000_000, tty: "pts/0", host: "10.0.0.5"),
            (name: "jane", time: 1_698_712_159, tty: "tty1",  host: ""),
        ])
        defer { try? FileManager.default.removeItem(at: url) }

        let entries = try Lastlog2Parser.parse(fileAt: url, sourceFile: "/var/log/lastlog2.db",
                                               nameToUID: ["root": 0, "jane": 1000])
        #expect(entries.count == 2)

        let root = try #require(entries.first { $0.user == "root" })
        #expect(root.uid == 0)                                         // resolved from passwd map
        #expect(root.line == "pts/0")
        #expect(root.host == "10.0.0.5")
        #expect(root.timestamp == Date(timeIntervalSince1970: 1_700_000_000))
        #expect(root.sourceFile == "/var/log/lastlog2.db")

        let jane = try #require(entries.first { $0.user == "jane" })
        #expect(jane.uid == 1000)
        #expect(jane.line == "tty1")
        #expect(jane.host == "")                                       // local login
    }

    @Test func sentinelUIDWhenNoPasswdMap() throws {
        let url = try Self.makeDB(rows: [
            (name: "attacker", time: 1_700_000_000, tty: "pts/1", host: "203.0.113.9"),
        ])
        defer { try? FileManager.default.removeItem(at: url) }

        let entries = try Lastlog2Parser.parse(fileAt: url)             // no nameToUID
        let e = try #require(entries.first)
        #expect(e.user == "attacker")
        #expect(e.uid == -1)                                           // sentinel: lastlog2 is name-keyed
        #expect(e.account == "attacker")                              // username still shown, not the sentinel
    }

    @Test func zeroTimeMapsToNilTimestamp() throws {
        // Time == 0 means "never logged in" (mirrors the binary parser's rule).
        let url = try Self.makeDB(rows: [
            (name: "neverlogged", time: 0, tty: "", host: ""),
        ])
        defer { try? FileManager.default.removeItem(at: url) }

        let e = try #require(try Lastlog2Parser.parse(fileAt: url).first)
        #expect(e.user == "neverlogged")
        #expect(e.timestamp == nil)
    }

    @Test func lenientLowercaseAndDriftedColumnNames() throws {
        // A drifted release: lowercase table + ll_*-style column names. The
        // case-insensitive, multi-alias reader must still map every field.
        let url = try Self.makeDB(table: "lastlog2",
                                  columns: ("name", "ll_time", "ll_line", "ll_host"),
                                  rows: [(name: "svc", time: 1_699_000_000, tty: "ssh", host: "192.168.1.2")])
        defer { try? FileManager.default.removeItem(at: url) }

        let e = try #require(try Lastlog2Parser.parse(fileAt: url).first)
        #expect(e.user == "svc")
        #expect(e.line == "ssh")
        #expect(e.host == "192.168.1.2")
        #expect(e.timestamp == Date(timeIntervalSince1970: 1_699_000_000))
    }

    @Test func nonSQLiteFileIsSkipped() throws {
        // A name collision (an unrelated file called lastlog2.db) is silently
        // skipped via the SQLite-magic guard, not surfaced as an error.
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent("not-a-db-\(UUID().uuidString).db")
        try Data("just some text, not a database\n".utf8).write(to: url)
        defer { try? FileManager.default.removeItem(at: url) }

        #expect(try Lastlog2Parser.parse(fileAt: url).isEmpty)
    }
}

#endif
