//
//  MacNotificationTests.swift
//  StrataTests
//
//  Covers the Notification Center (`db2/db`) parser over a GRDB-built fixture —
//  app-bundle side lookup, title/body recovery from the per-record `data`
//  bplist, the CFAbsoluteTime decoder — plus the timeline projection.
//

import Testing
import Foundation
import GRDB
@testable import Strata

struct MacNotificationTests {

    private func makeNotedDB(_ build: (Database) throws -> Void) throws -> URL {
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent("noted-\(UUID().uuidString).db")
        let queue = try DatabaseQueue(path: url.path)
        try queue.write { db in
            try db.execute(sql: "CREATE TABLE app (app_id INTEGER PRIMARY KEY, identifier TEXT)")
            try db.execute(sql: """
                CREATE TABLE record (rec_id INTEGER PRIMARY KEY, app_id INTEGER,
                    delivered_date REAL, request_date REAL, data BLOB)
                """)
            try build(db)
        }
        return url   // queue released → connection closed, file safe to copy
    }

    /// A notification `data` bplist: `{ req: { titl: ..., body: ... } }`.
    private func notifData(title: String, body: String) throws -> Data {
        let plist: [String: Any] = ["req": ["titl": title, "body": body]]
        return try PropertyListSerialization.data(fromPropertyList: plist, format: .binary, options: 0)
    }

    private let cf1: Double = 715_000_000   // CFAbsoluteTime (≈ 2023), < 1e9

    // MARK: - Parser

    @Test func parsesNotificationsWithAppAndBody() throws {
        let blob = try notifData(title: "Your code is 123456", body: "Tap to verify your login")
        let url = try makeNotedDB { db in
            try db.execute(sql: "INSERT INTO app (app_id, identifier) VALUES (1, 'com.apple.MobileSMS')")
            try db.execute(sql: """
                INSERT INTO record (rec_id, app_id, delivered_date, request_date, data)
                VALUES (1, 1, ?, NULL, ?)
                """, arguments: [cf1, blob])
        }
        defer { try? FileManager.default.removeItem(at: url) }

        let rows = try NotificationParser.parse(
            fileAt: url, sourceFile: "/Users/x/Library/.../db2/db", scope: "x")
        #expect(rows.count == 1)
        let n = rows[0]
        #expect(n.appID == "com.apple.MobileSMS")
        #expect(n.title == "Your code is 123456")
        #expect(n.body == "Tap to verify your login")
        #expect(n.deliveredDate != nil)
        // CFAbsoluteTime → wall clock (2001 epoch).
        #expect(abs(n.deliveredDate!.timeIntervalSinceReferenceDate - cf1) < 1)
    }

    @Test func recoversWhenAppTableMissingRow() throws {
        // A record whose app_id has no matching `app` row: the notification must
        // still come back, just with appID == nil.
        let blob = try notifData(title: "Build complete", body: "Archive succeeded")
        let url = try makeNotedDB { db in
            try db.execute(sql: """
                INSERT INTO record (rec_id, app_id, delivered_date, request_date, data)
                VALUES (1, 99, ?, NULL, ?)
                """, arguments: [cf1, blob])
        }
        defer { try? FileManager.default.removeItem(at: url) }

        let rows = try NotificationParser.parse(fileAt: url, sourceFile: "/x/db", scope: "x")
        #expect(rows.count == 1)
        #expect(rows[0].appID == nil)
        #expect(rows[0].title == "Build complete")
    }

    @Test func fallsBackToRequestDate() throws {
        let url = try makeNotedDB { db in
            try db.execute(sql: """
                INSERT INTO record (rec_id, app_id, delivered_date, request_date, data)
                VALUES (1, NULL, NULL, ?, NULL)
                """, arguments: [cf1])
        }
        defer { try? FileManager.default.removeItem(at: url) }

        let rows = try NotificationParser.parse(fileAt: url, sourceFile: "/x/db", scope: "x")
        #expect(rows.count == 1)
        #expect(rows[0].deliveredDate != nil)
    }

    @Test func rejectsNonDatabase() throws {
        let url = FileManager.default.temporaryDirectory.appendingPathComponent("not-\(UUID().uuidString).db")
        try Data("not a database".utf8).write(to: url)
        defer { try? FileManager.default.removeItem(at: url) }
        #expect(try NotificationParser.parse(fileAt: url, sourceFile: "/x/db", scope: "x").isEmpty)
    }

    @Test func decodeFindsTitleAndBodyAcrossKeys() throws {
        let blob = try notifData(title: "Hello", body: "World")
        let (t, b) = NotificationParser.decode(blob)
        #expect(t == "Hello")
        #expect(b == "World")
        #expect(NotificationParser.decode(nil) == (nil, nil))
    }

    // MARK: - Timeline

    @Test func timelineProjectsOneEventPerDeliveredDate() {
        let n1 = MacNotification(appID: "com.app", title: "T", body: "B",
                                 deliveredDate: Date(timeIntervalSinceReferenceDate: cf1),
                                 scope: "x", sourceFile: "/x/db")
        let n2 = MacNotification(appID: "com.app", title: "T2", body: nil,
                                 deliveredDate: nil, scope: "x", sourceFile: "/x/db")
        let events = TimelineBuilder.build(from: [n1, n2])
        #expect(events.count == 1)   // n2 has no date → dropped
        #expect(events[0].source == .notifications)
        #expect(events[0].path.contains("com.app"))
    }
}
