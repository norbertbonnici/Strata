import Foundation

/// Parses HTTP request logs from **application servers** that sit behind no
/// reverse proxy and so log in non-CLF shapes the `WebLogParser` (nginx/apache
/// CLF + Combined) misses entirely. This was a real triage gap: a Node
/// ticketing app's traffic was invisible because nothing in front of it wrote a
/// Combined-format access log.
///
/// Two high-value shapes are recovered into the existing `WebAccessLogEntry`
/// model (server tagged `.unknown` - "web"), so they fold into the same Web
/// Access tab / timeline / `WebLogAnalyzer` with no new UI:
///
///  (a) **Rails / Rack development log** - a request spans two lines:
///
///        Started GET "/path" for 1.2.3.4 at 2026-06-10 12:00:00 +0000
///        ...
///        Completed 200 OK in 5ms (Views: 3.0ms | ActiveRecord: 1.0ms)
///
///      The `Started` line carries method / target / client IP / timestamp;
///      the matching `Completed` line (the next one seen) carries the status.
///      We correlate the most-recent unmatched `Started` with the next
///      `Completed`. A `Started` with no following `Completed` is still emitted
///      with `status == 0` (request seen, response unknown).
///
///  (b) **Puma / Node "common"** - Combined Log Format optionally prefixed by a
///      worker/PID token in brackets:
///
///        [12345] 1.2.3.4 - - [10/Jun/2026:12:00:00 +0000] "GET /p HTTP/1.1" 200 1234 "ref" "ua"
///
///      We strip an optional leading `[digits] ` and hand the remainder to the
///      shared `WebLogParser` combined parser.
///
/// Pure - text in, `[WebAccessLogEntry]` out - so it unit-tests without disk
/// fixtures and runs off the main actor.
public nonisolated enum AppServerLogParser {

    /// Server tag for everything this parser emits - an app server with no
    /// fronting nginx/apache, so neither `.nginx` nor `.apache` is accurate.
    private static let server: WebAccessLogEntry.Server = .unknown

    public static func parse(text: String, sourceFile: String) -> [WebAccessLogEntry] {
        var entries: [WebAccessLogEntry] = []
        // The most-recent `Started` awaiting its `Completed` (Rails interleaves
        // at most one in-flight request per worker in the dev log).
        var pendingStart: StartedRequest?

        func flushPending() {
            if let s = pendingStart {
                entries.append(s.entry(status: 0, sourceFile: sourceFile))
                pendingStart = nil
            }
        }

        for rawLine in text.split(separator: "\n", omittingEmptySubsequences: true) {
            let line = String(rawLine)

            // (b) Puma / Node combined, optional [pid] prefix. Try this first:
            // a combined line never begins with `Started `/`Completed `.
            if let combined = parseCombinedWithOptionalPID(line, sourceFile: sourceFile) {
                entries.append(combined)
                continue
            }

            // (a) Rails / Rack pair.
            if let started = parseStarted(line) {
                // A new Started before the previous one Completed: emit the
                // previous with unknown status, then hold the new one.
                flushPending()
                pendingStart = started
            } else if let status = parseCompletedStatus(line), let s = pendingStart {
                entries.append(s.entry(status: status, sourceFile: sourceFile))
                pendingStart = nil
            }
            // Any other line (ActiveRecord SQL, params, blank) is ignored and
            // does not break the Started↔Completed correlation.
        }
        flushPending()   // trailing Started with no Completed
        return entries
    }

    // MARK: - Rails / Rack pair

    /// A parsed `Started` line, holding everything except the response status.
    struct StartedRequest {
        let timestamp: Date?
        let method: String
        let path: String
        let query: String?
        let clientIP: String

        func entry(status: Int, sourceFile: String) -> WebAccessLogEntry {
            WebAccessLogEntry(timestamp: timestamp, clientIP: clientIP, method: method,
                              path: path, query: query, httpVersion: nil,
                              status: status, bytes: 0, referer: nil, userAgent: nil,
                              server: AppServerLogParser.server, sourceFile: sourceFile)
        }
    }

    /// `Started GET "/path?q=1" for 1.2.3.4 at 2026-06-10 12:00:00 +0000`
    /// → method / path / query / client IP / timestamp. nil if not a Started line.
    static func parseStarted(_ line: String) -> StartedRequest? {
        let trimmed = line.trimmingCharacters(in: .whitespaces)
        guard trimmed.hasPrefix("Started ") else { return nil }
        let rest = trimmed.dropFirst("Started ".count)   // `GET "/path" for IP at DATE`

        // Method = first token.
        guard let methodEnd = rest.firstIndex(of: " ") else { return nil }
        let method = String(rest[rest.startIndex..<methodEnd])
        guard !method.isEmpty else { return nil }

        // Target = the quoted `"..."` immediately after the method.
        let afterMethod = rest[rest.index(after: methodEnd)...]
        guard let openQuote = afterMethod.firstIndex(of: "\"") else { return nil }
        let afterOpen = afterMethod.index(after: openQuote)
        guard let closeQuote = afterMethod[afterOpen...].firstIndex(of: "\"") else { return nil }
        let rawTarget = String(afterMethod[afterOpen..<closeQuote])
        let (path, query) = splitTarget(rawTarget)

        // After the closing quote: ` for <ip> at <date with spaces>`.
        let tail = String(afterMethod[afterMethod.index(after: closeQuote)...])
        let clientIP = token(after: " for ", in: tail) ?? ""
        guard !clientIP.isEmpty, clientIP != "-" else { return nil }

        let timestamp: Date?
        if let atRange = tail.range(of: " at ") {
            timestamp = parseRailsDate(String(tail[atRange.upperBound...])
                .trimmingCharacters(in: .whitespaces))
        } else {
            timestamp = nil
        }

        return StartedRequest(timestamp: timestamp, method: method,
                              path: path, query: query, clientIP: clientIP)
    }

    /// `Completed 200 OK in 5ms (...)` → 200. nil if not a Completed line.
    static func parseCompletedStatus(_ line: String) -> Int? {
        let trimmed = line.trimmingCharacters(in: .whitespaces)
        guard trimmed.hasPrefix("Completed ") else { return nil }
        let rest = trimmed.dropFirst("Completed ".count)
        let firstToken = rest.split(separator: " ", omittingEmptySubsequences: true).first
        return firstToken.flatMap { Int($0) }
    }

    // MARK: - Puma / Node combined (optional [pid] prefix)

    /// Strip an optional leading `[digits] ` worker/PID token, then parse the
    /// remainder as Combined Log Format via the shared `WebLogParser`. nil if
    /// the line isn't a combined line (so the Rails branch can have a look).
    static func parseCombinedWithOptionalPID(_ line: String,
                                             sourceFile: String) -> WebAccessLogEntry? {
        let stripped = stripPIDPrefix(line).trimmingCharacters(in: .whitespaces)
        // A Rails `Started ... for <ip> at <date>` line happens to tokenize to
        // CLF's >=7 fields (it has a space-padded `"..."` quoted token), so
        // `WebLogParser` would mis-accept it. Hand off only lines that don't
        // begin with the Rails markers - a real combined line never does.
        guard !stripped.hasPrefix("Started "),
              !stripped.hasPrefix("Completed ") else { return nil }
        // WebLogParser.parseLine returns nil for anything that doesn't tokenize
        // to >=7 CLF fields with a non-"-" client IP - the real guard.
        return WebLogParser.parseLine(stripped, sourceFile: sourceFile, server: server)
    }

    /// `[12345] rest...` → `rest...`. Only a *pure-digit* bracketed leading
    /// token is treated as a PID prefix - the CLF date `[10/Jun/...]` (which
    /// never sits at the very start of a combined line) is never stripped.
    static func stripPIDPrefix(_ line: String) -> String {
        guard line.first == "[", let close = line.firstIndex(of: "]") else { return line }
        let inside = line[line.index(after: line.startIndex)..<close]
        guard !inside.isEmpty, inside.allSatisfy(\.isNumber) else { return line }
        var idx = line.index(after: close)
        while idx < line.endIndex, line[idx] == " " { idx = line.index(after: idx) }
        return String(line[idx...])
    }

    // MARK: - Helpers

    /// `"/path?q=1"` → ("/path", "q=1"); no '?' → (target, nil).
    private static func splitTarget(_ target: String) -> (String, String?) {
        if let q = target.firstIndex(of: "?") {
            return (String(target[..<q]), String(target[target.index(after: q)...]))
        }
        return (target, nil)
    }

    /// First whitespace-delimited token after `marker` in `text`.
    private static func token(after marker: String, in text: String) -> String? {
        guard let range = text.range(of: marker) else { return nil }
        return text[range.upperBound...].split(separator: " ").first.map(String.init)
    }

    /// Rails dev-log timestamp: `2026-06-10 12:00:00 +0000` (space-separated,
    /// explicit offset). Parsed with a fixed POSIX formatter.
    private static let railsDateFormatter: DateFormatter = {
        let f = DateFormatter()
        f.locale = Locale(identifier: "en_US_POSIX")
        f.timeZone = TimeZone(identifier: "UTC")
        f.dateFormat = "yyyy-MM-dd HH:mm:ss Z"
        return f
    }()

    static func parseRailsDate(_ field: String) -> Date? {
        railsDateFormatter.date(from: field)
    }
}
