//
//  SudoLogParserTests.swift
//  StrataTests
//
//  Covers SudoLogParser: sudo's own logfile format (/var/log/sudo and
//  rotations), written when `Defaults logfile=...` is configured - distinct
//  from the syslog line sudo also emits to auth.log. Parses into AuthLogEntry
//  rows with kind == .sudo so they fold into the existing Auth & Logins tab.
//

import Testing
import Foundation
@testable import Strata

struct SudoLogParserTests {

    /// Anchor (file mtime) supplying the year for the classic syslog prefix.
    private var anchor: Date {
        var cal = Calendar(identifier: .gregorian)
        cal.timeZone = TimeZone(identifier: "UTC")!
        return cal.date(from: DateComponents(year: 2026, month: 6, day: 11,
                                             hour: 0, minute: 0, second: 0))!
    }

    @Test func parsesSuccessAndDeniedLines() throws {
        // A successful sudo (hostless prefix) + a denied sudo (hostname prefix).
        let log = """
        Jun 10 12:00:00 : alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/id
        Jun 10 12:00:05 myhost : bob : command not allowed ; TTY=pts/1 ; PWD=/tmp ; USER=root ; COMMAND=/bin/rm -rf /
        """
        let entries = SudoLogParser.parse(text: log, sourceFile: "/var/log/sudo", anchor: anchor)
        #expect(entries.count == 2)

        // --- Success line ---
        let ok = entries[0]
        #expect(ok.kind == .sudo)
        #expect(ok.process == "sudo")
        #expect(ok.user == "alice")               // name after the timestamp colon
        #expect(ok.host == "")                     // hostless variant
        #expect(ok.command == "/usr/bin/id")       // after COMMAND=
        #expect(ok.method == nil)
        #expect(ok.sourceIP == nil)
        #expect(ok.sourceFile == "/var/log/sudo")
        // Target user + PWD carried in the message (no dedicated model slot).
        #expect(ok.message.contains("USER=root"))
        #expect(ok.message.contains("PWD=/home/alice"))
        #expect(ok.message.contains("COMMAND=/usr/bin/id"))
        // Timestamp: Jun 10 12:00:00 against a 2026 mtime -> 2026-06-10 UTC.
        let expected = Calendar(identifier: .gregorian).date(from: {
            var c = DateComponents()
            c.timeZone = TimeZone(identifier: "UTC")
            c.year = 2026; c.month = 6; c.day = 10
            c.hour = 12; c.minute = 0; c.second = 0
            return c
        }())
        #expect(ok.timestamp == expected)

        // --- Denied line ---
        let denied = entries[1]
        #expect(denied.kind == .sudo)
        #expect(denied.user == "bob")
        #expect(denied.host == "myhost")           // hostname variant
        #expect(denied.command == "/bin/rm -rf /") // attempted command preserved
        // Failure reason + target user surfaced in the message.
        #expect(denied.message.contains("command not allowed"))
        #expect(denied.message.contains("USER=root"))
    }

    @Test func parsesRFC3339Prefix() throws {
        // Modern rsyslog forwarding can wrap the sudo logfile line in RFC 3339.
        let log = "2026-06-10T12:00:00+00:00 : carol : TTY=pts/2 ; PWD=/srv ; USER=root ; COMMAND=/usr/bin/whoami"
        let entries = SudoLogParser.parse(text: log, sourceFile: "/var/log/sudo")
        #expect(entries.count == 1)
        let e = entries[0]
        #expect(e.kind == .sudo)
        #expect(e.user == "carol")
        #expect(e.command == "/usr/bin/whoami")
        #expect(e.timestamp == Date(timeIntervalSince1970: 1781092800))  // 2026-06-10T12:00:00Z
    }

    @Test func ignoresNonSudoNoise() throws {
        // A line with no timestamp prefix isn't a sudo logfile entry.
        let entries = SudoLogParser.parse(text: "not a log line at all",
                                          sourceFile: "/var/log/sudo")
        #expect(entries.isEmpty)
    }
}
