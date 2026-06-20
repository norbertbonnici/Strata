//
//  MailTests.swift
//  StrataTests
//
//  Covers the Mail Envelope Index parser over a GRDB-built fixture (sender /
//  subject / mailbox joins, recipient aggregation, Unix-epoch dates) and the
//  conservative inbound-phishing analyzer.
//

import Testing
import Foundation
import GRDB
@testable import Strata

struct MailTests {

    private func makeEnvelopeIndex(_ build: (Database) throws -> Void) throws -> URL {
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent("envidx-\(UUID().uuidString).sqlite")
        let queue = try DatabaseQueue(path: url.path)
        try queue.write { db in
            try db.execute(sql: "CREATE TABLE subjects (ROWID INTEGER PRIMARY KEY, subject TEXT)")
            try db.execute(sql: "CREATE TABLE addresses (ROWID INTEGER PRIMARY KEY, address TEXT, comment TEXT)")
            try db.execute(sql: "CREATE TABLE mailboxes (ROWID INTEGER PRIMARY KEY, url TEXT)")
            try db.execute(sql: """
                CREATE TABLE messages (ROWID INTEGER PRIMARY KEY, date_sent INTEGER, date_received INTEGER,
                    subject INTEGER, sender INTEGER, mailbox INTEGER)
                """)
            try db.execute(sql: "CREATE TABLE recipients (ROWID INTEGER PRIMARY KEY, message_key INTEGER, address_id INTEGER, type INTEGER)")
            try build(db)
        }
        return url
    }

    private let recv: Int64 = 1_700_000_000   // Unix seconds
    private let sent: Int64 = 1_700_000_500

    // MARK: - Parser

    @Test func parsesEnvelopeIndex() throws {
        let url = try makeEnvelopeIndex { db in
            try db.execute(sql: "INSERT INTO addresses (ROWID, address, comment) VALUES (1, 'attacker@evil.example', 'Eve'), (2, 'me@corp.com', 'Me'), (3, 'bob@corp.com', 'Bob')")
            try db.execute(sql: "INSERT INTO subjects (ROWID, subject) VALUES (1, 'Invoice overdue'), (2, 'Re: lunch')")
            try db.execute(sql: "INSERT INTO mailboxes (ROWID, url) VALUES (1, 'imap://me@corp.com/INBOX'), (2, 'imap://me@corp.com/Sent Messages')")
            // Received message from attacker → INBOX.
            try db.execute(sql: "INSERT INTO messages (ROWID, date_sent, date_received, subject, sender, mailbox) VALUES (10, ?, ?, 1, 1, 1)", arguments: [sent, recv])
            // Sent message from me → Sent, to bob.
            try db.execute(sql: "INSERT INTO messages (ROWID, date_sent, date_received, subject, sender, mailbox) VALUES (11, ?, ?, 2, 2, 2)", arguments: [sent, recv])
            try db.execute(sql: "INSERT INTO recipients (ROWID, message_key, address_id, type) VALUES (1, 10, 2, 0), (2, 11, 3, 0)")
        }
        defer { try? FileManager.default.removeItem(at: url) }

        let mail = try MailParser.parse(fileAt: url, sourceFile: "/Users/me/Library/Mail/V10/MailData/Envelope Index", scope: "me")
        #expect(mail.count == 2)
        let inbound = mail.first { $0.subject == "Invoice overdue" }
        #expect(inbound?.sender == "attacker@evil.example")
        #expect(inbound?.senderDisplay == "Eve")
        #expect(inbound?.recipients == "me@corp.com")
        #expect(inbound?.mailbox == "imap://me@corp.com/INBOX")
        #expect(inbound?.isSent == false)
        #expect(inbound?.dateReceived != nil)
        let outbound = mail.first { $0.subject == "Re: lunch" }
        #expect(outbound?.isSent == true)               // "Sent Messages" mailbox
        #expect(outbound?.recipients == "bob@corp.com")
    }

    @Test func rejectsNonDatabase() throws {
        let url = FileManager.default.temporaryDirectory.appendingPathComponent("ei-\(UUID().uuidString)")
        try Data("nope".utf8).write(to: url)
        defer { try? FileManager.default.removeItem(at: url) }
        #expect(try MailParser.parse(fileAt: url, sourceFile: "/x/Envelope Index", scope: "x").isEmpty)
    }

    @Test func mailTimeDecodesUnixSeconds() {
        let d = MailMessageEntry.mailTime(1_700_000_000)
        #expect(d == Date(timeIntervalSince1970: 1_700_000_000))
        #expect(MailMessageEntry.mailTime(0) == nil)
        #expect(MailMessageEntry.mailTime(nil) == nil)
    }

    // MARK: - Analyzer

    private func msg(subject: String? = nil, sender: String?, mailbox: String) -> MailMessageEntry {
        MailMessageEntry(subject: subject, sender: sender, dateReceived: Date(timeIntervalSince1970: 1_700_000_000),
                         mailbox: mailbox, scope: "x", sourceFile: "/Users/x/Library/Mail/V10/MailData/Envelope Index")
    }

    @Test func flagsRawIPSender() {
        let findings = MacMailAnalyzer().analyze([
            msg(subject: "hi", sender: "x@203.0.113.9", mailbox: "imap://me/INBOX"),
        ])
        #expect(findings.count == 1)
        #expect(findings[0].technique?.attackID == "T1566.002")
        #expect(findings[0].severity == .high)
    }

    @Test func flagsSuspiciousLinkInSubject() {
        let findings = MacMailAnalyzer().analyze([
            msg(subject: "see https://pastebin.com/abc", sender: "x@vendor.com", mailbox: "imap://me/INBOX"),
        ])
        #expect(findings.contains { $0.technique?.attackID == "T1566.002" && $0.severity == .medium })
    }

    @Test func ignoresBenignAndSentMail() {
        let findings = MacMailAnalyzer().analyze([
            msg(subject: "quarterly report", sender: "cfo@corp.com", mailbox: "imap://me/INBOX"),
            // Sent mail to a raw IP is not inbound delivery → ignored.
            msg(subject: "ping", sender: "x@203.0.113.9", mailbox: "imap://me/Sent Messages"),
        ])
        #expect(findings.isEmpty)
    }

    @Test func emptyInputNoFindings() {
        #expect(MacMailAnalyzer().analyze([]).isEmpty)
    }

    @Test func threadedThroughContext() {
        let ctx = AnalysisContext(files: [], events: [], timeline: [], registryValues: [],
                                  mail: [msg(sender: "x@1.2.3.4", mailbox: "imap://me/INBOX")])
        #expect(MacMailAnalyzer().analyze(context: ctx).count == 1)
    }
}
