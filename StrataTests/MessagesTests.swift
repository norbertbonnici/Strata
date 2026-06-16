//
//  MessagesTests.swift
//  StrataTests
//
//  Covers the Messages (chat.db) parser over a GRDB-built fixture — including
//  attributedBody text recovery and the apple-epoch decoder — plus the
//  suspicious-link analyzer.
//

import Testing
import Foundation
import GRDB
@testable import Strata

struct MessagesTests {

    private func makeChatDB(_ build: (Database) throws -> Void) throws -> URL {
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent("chat-\(UUID().uuidString).db")
        let queue = try DatabaseQueue(path: url.path)
        try queue.write { db in
            try db.execute(sql: "CREATE TABLE handle (ROWID INTEGER PRIMARY KEY, id TEXT)")
            try db.execute(sql: "CREATE TABLE chat (ROWID INTEGER PRIMARY KEY, display_name TEXT)")
            try db.execute(sql: """
                CREATE TABLE message (ROWID INTEGER PRIMARY KEY, guid TEXT, text TEXT, service TEXT,
                    handle_id INTEGER, date INTEGER, is_from_me INTEGER,
                    cache_has_attachments INTEGER, attributedBody BLOB)
                """)
            try db.execute(sql: "CREATE TABLE chat_message_join (chat_id INTEGER, message_id INTEGER)")
            try build(db)
        }
        return url   // queue released here → connection closed, file safe to copy
    }

    private let d1: Int64 = 715_000_000_000_000_000   // ns since 2001
    private let d2: Int64 = 716_000_000_000_000_000

    // MARK: - Parser

    @Test func parsesMessagesIncludingAttributedBody() throws {
        let body = try NSKeyedArchiver.archivedData(
            withRootObject: NSAttributedString(string: "secret body text"), requiringSecureCoding: false)
        let url = try makeChatDB { db in
            try db.execute(sql: "INSERT INTO handle (ROWID, id) VALUES (1, '+15551234567')")
            try db.execute(sql: "INSERT INTO chat (ROWID, display_name) VALUES (1, 'Team Chat')")
            try db.execute(sql: """
                INSERT INTO message (ROWID, guid, text, service, handle_id, date, is_from_me, cache_has_attachments, attributedBody)
                VALUES (1, 'g1', 'hey check http://1.2.3.4/x', 'iMessage', 1, ?, 0, 0, NULL)
                """, arguments: [d1])
            try db.execute(sql: """
                INSERT INTO message (ROWID, guid, text, service, handle_id, date, is_from_me, cache_has_attachments, attributedBody)
                VALUES (2, 'g2', NULL, 'iMessage', 1, ?, 1, 0, ?)
                """, arguments: [d2, body])
            try db.execute(sql: "INSERT INTO chat_message_join (chat_id, message_id) VALUES (1, 1)")
        }
        defer { try? FileManager.default.removeItem(at: url) }

        let msgs = try MessagesParser.parse(fileAt: url, sourceFile: "/Users/x/Library/Messages/chat.db", scope: "x")
        #expect(msgs.count == 2)
        let g1 = msgs.first { $0.guid == "g1" }
        #expect(g1?.isFromMe == false)
        #expect(g1?.handle == "+15551234567")
        #expect(g1?.text?.contains("1.2.3.4") == true)
        #expect(g1?.chatName == "Team Chat")
        #expect(g1?.timestamp != nil)
        let g2 = msgs.first { $0.guid == "g2" }
        #expect(g2?.isFromMe == true)
        #expect(g2?.text == "secret body text")   // recovered from attributedBody
    }

    @Test func rejectsNonChatDB() throws {
        let url = FileManager.default.temporaryDirectory.appendingPathComponent("not-\(UUID().uuidString).db")
        try Data("not a database".utf8).write(to: url)
        defer { try? FileManager.default.removeItem(at: url) }
        #expect(try MessagesParser.parse(fileAt: url, sourceFile: "/x/chat.db", scope: "x").isEmpty)
    }

    @Test func attributedBodyTextPicksLongestPlainString() throws {
        let body = try NSKeyedArchiver.archivedData(
            withRootObject: NSAttributedString(string: "the message body"), requiringSecureCoding: false)
        #expect(MessagesParser.attributedBodyText(body) == "the message body")
    }

    @Test func appleTimeHandlesNanosAndSeconds() {
        // Nanoseconds (modern) and seconds (legacy) should land at the same Date.
        let secs: Int64 = 715_000_000
        let nanos = secs * 1_000_000_000
        let a = MessageEntry.appleTime(nanos)
        let b = MessageEntry.appleTime(secs)
        #expect(a != nil && b != nil)
        #expect(abs(a!.timeIntervalSince1970 - b!.timeIntervalSince1970) < 1)
        #expect(MessageEntry.appleTime(0) == nil)
    }

    // MARK: - Analyzer

    private func msg(_ text: String?, fromMe: Bool) -> MessageEntry {
        MessageEntry(isFromMe: fromMe, text: text, timestamp: Date(timeIntervalSince1970: 1_700_000_000),
                     scope: "x", sourceFile: "/Users/x/Library/Messages/chat.db")
    }

    @Test func flagsReceivedRawIPLinkHigh() {
        let findings = MacMessagesAnalyzer().analyze([msg("open http://203.0.113.7/p now", fromMe: false)])
        #expect(findings.count == 1)
        #expect(findings[0].technique?.attackID == "T1566.002")
        #expect(findings[0].severity == .high)
    }

    @Test func flagsSentPasteLinkMedium() {
        let findings = MacMessagesAnalyzer().analyze([msg("here https://pastebin.com/abc123", fromMe: true)])
        #expect(findings.count == 1)
        #expect(findings[0].technique?.attackID == "T1204.001")
        #expect(findings[0].severity == .medium)
    }

    @Test func ignoresBenignMessages() {
        let findings = MacMessagesAnalyzer().analyze([
            msg("lunch at noon?", fromMe: false),
            msg("see you at https://www.apple.com/maps", fromMe: false),
        ])
        #expect(findings.isEmpty)
    }

    @Test func emptyInputNoFindings() {
        #expect(MacMessagesAnalyzer().analyze([]).isEmpty)
    }

    @Test func threadedThroughContext() {
        let ctx = AnalysisContext(files: [], events: [], timeline: [], registryValues: [],
                                  messages: [msg("grab http://1.2.3.4/x", fromMe: false)])
        let findings = MacMessagesAnalyzer().analyze(context: ctx)
        #expect(findings.count == 1)
        #expect(findings[0].severity == .high)
    }
}
