//
//  AppServerLogParserTests.swift
//  StrataTests
//
//  Covers AppServerLogParser - the two non-CLF app-server log shapes the
//  CLF/Combined WebLogParser misses: Rails/Rack `Started`↔`Completed` line
//  pairs, and Puma/Node Combined-format lines prefixed with a `[pid]` worker
//  token. Both fold into the existing WebAccessLogEntry model (server .unknown).
//

import Testing
import Foundation
@testable import Strata

struct AppServerLogParserTests {

    // MARK: - (a) Rails / Rack Started↔Completed pair

    @Test func correlatesRailsStartedAndCompletedPair() throws {
        let log = """
        Started GET "/tickets?status=open" for 203.0.113.9 at 2026-06-10 12:00:00 +0000
        Processing by TicketsController#index as HTML
          Parameters: {"status"=>"open"}
        Completed 200 OK in 5ms (Views: 3.0ms | ActiveRecord: 1.0ms)
        """
        let entries = AppServerLogParser.parse(text: log, sourceFile: "/var/log/rails/development.log")
        #expect(entries.count == 1)
        let e = try #require(entries.first)
        #expect(e.method == "GET")
        #expect(e.path == "/tickets")
        #expect(e.query == "status=open")
        #expect(e.clientIP == "203.0.113.9")
        #expect(e.status == 200)
        #expect(e.server == .unknown)
        #expect(e.sourceFile == "/var/log/rails/development.log")
        // "2026-06-10 12:00:00 +0000" with explicit offset → exact epoch.
        #expect(e.timestamp == Date(timeIntervalSince1970: 1_781_092_800))
    }

    @Test func emitsStartedWithoutCompletedAsStatusZero() throws {
        // A request that started but whose Completed never landed (truncated log).
        let log = """
        Started POST "/login" for 10.0.0.5 at 2026-06-10 12:01:00 +0000
        """
        let entries = AppServerLogParser.parse(text: log, sourceFile: "dev.log")
        let e = try #require(entries.first)
        #expect(e.method == "POST")
        #expect(e.path == "/login")
        #expect(e.query == nil)
        #expect(e.clientIP == "10.0.0.5")
        #expect(e.status == 0)            // no Completed seen
    }

    @Test func newStartedFlushesPreviousUnmatchedStarted() throws {
        // Two Starteds, only the second Completes: first emits status 0.
        let log = """
        Started GET "/a" for 1.1.1.1 at 2026-06-10 12:00:00 +0000
        Started GET "/b" for 2.2.2.2 at 2026-06-10 12:00:01 +0000
        Completed 404 Not Found in 2ms
        """
        let entries = AppServerLogParser.parse(text: log, sourceFile: "dev.log")
        #expect(entries.count == 2)
        #expect(entries[0].path == "/a")
        #expect(entries[0].status == 0)   // flushed when /b started
        #expect(entries[1].path == "/b")
        #expect(entries[1].clientIP == "2.2.2.2")
        #expect(entries[1].status == 404)
    }

    // MARK: - (b) Puma / Node Combined with [pid] prefix

    @Test func parsesPumaPIDPrefixedCombinedLine() throws {
        let line = #"[12345] 198.51.100.7 - - [10/Jun/2026:12:00:00 +0000] "GET /api/health HTTP/1.1" 200 1234 "https://ref/" "curl/8.0""#
        let entries = AppServerLogParser.parse(text: line, sourceFile: "/var/log/puma.log")
        let e = try #require(entries.first)
        #expect(e.clientIP == "198.51.100.7")
        #expect(e.method == "GET")
        #expect(e.path == "/api/health")
        #expect(e.httpVersion == "HTTP/1.1")
        #expect(e.status == 200)
        #expect(e.bytes == 1234)
        #expect(e.referer == "https://ref/")
        #expect(e.userAgent == "curl/8.0")
        #expect(e.server == .unknown)     // app server, not nginx/apache
        #expect(e.timestamp == Date(timeIntervalSince1970: 1_781_092_800))
    }

    @Test func parsesCombinedWithoutPIDPrefixToo() throws {
        // No worker token - still a valid combined line.
        let line = #"198.51.100.8 - - [10/Jun/2026:12:00:05 +0000] "POST /upload HTTP/1.1" 500 0 "-" "Go-http-client/2.0""#
        let entries = AppServerLogParser.parse(text: line, sourceFile: "node.log")
        let e = try #require(entries.first)
        #expect(e.clientIP == "198.51.100.8")
        #expect(e.method == "POST")
        #expect(e.status == 500)
    }

    @Test func stripPIDPrefixOnlyStripsPureDigitToken() {
        // PID token is stripped...
        #expect(AppServerLogParser.stripPIDPrefix("[999] rest") == "rest")
        // ...but a CLF date (never leads a combined line) is left intact, and a
        // non-numeric bracket token is preserved.
        #expect(AppServerLogParser.stripPIDPrefix("[10/Jun/2026:12:00:00 +0000] x")
                == "[10/Jun/2026:12:00:00 +0000] x")
        #expect(AppServerLogParser.stripPIDPrefix("1.2.3.4 - - [..]") == "1.2.3.4 - - [..]")
    }
}
