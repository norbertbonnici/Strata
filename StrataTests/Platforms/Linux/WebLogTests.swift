//
//  WebLogTests.swift
//  StrataTests
//
//  Covers the web-access-log bundle: the CLF/Combined parser (incl. the
//  timezone-explicit bracketed date and quoted-field tokenizing), the timeline
//  projection, and the exploitation/webshell/scanner analyzer.
//

import Testing
import Foundation
@testable import Strata

struct WebLogParserTests {

    @Test func parsesCombinedLogFormat() throws {
        let line = #"203.0.113.9 - - [10/Oct/2026:13:55:36 +0000] "GET /admin?id=1 HTTP/1.1" 200 2326 "http://ref/" "Mozilla/5.0 (X11)""#
        let e = try #require(WebLogParser.parseLine(line, sourceFile: "/var/log/nginx/access.log", server: .nginx))
        #expect(e.clientIP == "203.0.113.9")
        #expect(e.method == "GET")
        #expect(e.path == "/admin")
        #expect(e.query == "id=1")
        #expect(e.httpVersion == "HTTP/1.1")
        #expect(e.status == 200)
        #expect(e.bytes == 2326)
        #expect(e.referer == "http://ref/")
        #expect(e.userAgent == "Mozilla/5.0 (X11)")   // spaces inside quotes preserved
        #expect(e.server == .nginx)
        // Bracketed date carries an explicit timezone -> accurate.
        #expect(e.timestamp == Date(timeIntervalSince1970: 1_791_640_536))
    }

    @Test func parsesCommonLogFormatNoReferer() throws {
        let line = #"10.0.0.5 - frank [10/Oct/2026:13:55:36 +0200] "POST /upload.php HTTP/1.0" 404 -"#
        let e = try #require(WebLogParser.parseLine(line, sourceFile: "/var/log/apache2/access.log", server: .apache))
        #expect(e.method == "POST")
        #expect(e.path == "/upload.php")
        #expect(e.query == nil)
        #expect(e.status == 404)
        #expect(e.bytes == 0)        // '-' bytes
        #expect(e.referer == nil)
        #expect(e.userAgent == nil)
    }

    @Test func skipsMalformedLines() {
        #expect(WebLogParser.parseLine("garbage", sourceFile: "/x", server: .unknown) == nil)
        #expect(WebLogParser.parseLine("", sourceFile: "/x", server: .unknown) == nil)
    }

    @Test func projectsTimestampedRequestsOntoTimeline() {
        let rows = [
            WebAccessLogEntry(timestamp: Date(timeIntervalSince1970: 100), clientIP: "1.2.3.4",
                              method: "GET", path: "/", status: 200, bytes: 10, server: .nginx,
                              sourceFile: "/var/log/nginx/access.log"),
            WebAccessLogEntry(timestamp: nil, clientIP: "1.2.3.4", method: "GET", path: "/x",
                              status: 200, bytes: 0, server: .nginx, sourceFile: "/x"),
        ]
        let events = TimelineBuilder.build(from: rows)
        #expect(events.count == 1)   // undated row dropped
        #expect(events[0].source == .weblog)
        #expect(events[0].path.contains("1.2.3.4"))
    }
}

struct WebLogAnalyzerTests {

    private func req(_ ip: String, _ method: String, _ path: String, query: String? = nil,
                     status: Int = 200, ua: String? = nil) -> WebAccessLogEntry {
        WebAccessLogEntry(timestamp: Date(timeIntervalSince1970: 1000), clientIP: ip,
                          method: method, path: path, query: query, status: status,
                          bytes: 100, userAgent: ua, server: .nginx,
                          sourceFile: "/var/log/nginx/access.log")
    }

    private func analyze(_ rows: [WebAccessLogEntry]) -> [Finding] {
        WebLogAnalyzer().analyze(context: AnalysisContext(
            files: [], events: [], timeline: [], registryValues: [], webAccess: rows))
    }

    @Test func flagsSQLiAndTraversalWithStatusEscalation() {
        let f = analyze([
            req("203.0.113.9", "GET", "/item", query: "id=1 UNION SELECT password FROM users", status: 200),
            req("203.0.113.9", "GET", "/download", query: "f=../../../../etc/passwd", status: 403),
        ])
        let sqli = f.first { $0.title.contains("SQL injection") }
        #expect(sqli != nil)
        #expect(sqli?.severity == .high)             // 200 -> high
        #expect(sqli?.technique?.attackID == "T1190")
        let trav = f.first { $0.title.contains("Path traversal") }
        #expect(trav?.severity == .medium)           // 403 -> medium
    }

    @Test func flagsWebshellCriticalOn200() {
        let f = analyze([req("10.0.0.9", "POST", "/uploads/shell.php", status: 200)])
        let shell = f.first { $0.title.contains("webshell") }
        #expect(shell?.severity == .critical)
        #expect(shell?.technique?.attackID == "T1505.003")
    }

    @Test func flagsScannerUserAgent() {
        let f = analyze([
            req("198.51.100.7", "GET", "/", ua: "sqlmap/1.7#stable (http://sqlmap.org)"),
            req("198.51.100.7", "GET", "/x", ua: "sqlmap/1.7#stable"),
        ])
        let scan = f.first { $0.title.contains("sqlmap") }
        #expect(scan != nil)
        #expect(scan?.technique?.attackID == "T1595.002")
        #expect(scan?.detail.contains("2 ") == true)   // aggregated count
    }

    @Test func flagsDirBruteForceOn404Burst() {
        let rows = (0..<120).map { req("203.0.113.50", "GET", "/p\($0)", status: 404) }
        let f = analyze(rows)
        #expect(f.contains { $0.title.contains("Directory brute-force") })
    }

    @Test func cleanTrafficYieldsNothing() {
        let f = analyze([
            req("10.0.0.5", "GET", "/", status: 200),
            req("10.0.0.5", "GET", "/style.css", status: 200),
            req("10.0.0.5", "POST", "/api/login", status: 401),
        ])
        #expect(f.isEmpty)
    }
}
