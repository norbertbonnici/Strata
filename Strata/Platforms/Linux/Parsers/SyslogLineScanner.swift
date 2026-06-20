import Foundation

/// Shared scanner for the classic-syslog / rsyslog line shape used by
/// `auth.log`, `secure`, `syslog`, and `messages`:
///
///     <prefix> host process[pid]: message
///
/// where `<prefix>` is either classic syslog (`Mar 12 13:01:02`, no year/TZ -
/// the year is inferred from the file mtime, the clock treated as UTC) or
/// rsyslog RFC 3339 (`2026-06-10T12:00:00.123456+02:00`, exact). Factored out
/// of `AuthLogParser` so `SyslogParser` reuses the identical, well-tested
/// prefix/tag parse and only the body classifier differs.
public nonisolated enum SyslogLineScanner {

    /// One scanned line, before any program-specific classification.
    public struct Line {
        public let timestamp: Date?
        public let host: String
        public let process: String
        public let pid: Int?
        public let message: String
    }

    /// Scan a full line into its parts, or nil when it isn't syslog-shaped.
    /// `anchor` (the file's mtime) supplies the year for classic timestamps.
    public static func scan(_ line: String, anchor: Date?) -> Line? {
        var rest = Substring(line)
        let timestamp: Date?
        if let (date, remainder) = parseRFC3339Prefix(rest) {
            timestamp = date; rest = remainder
        } else if let (date, remainder) = parseClassicPrefix(rest, anchor: anchor) {
            timestamp = date; rest = remainder
        } else {
            return nil
        }

        // "host process[pid]: message"  (pid optional; "process:" also legal).
        let parts = rest.split(separator: " ", maxSplits: 1, omittingEmptySubsequences: true)
        guard parts.count == 2 else { return nil }
        let host = String(parts[0])
        var tail = parts[1]

        guard let colon = tail.firstIndex(of: ":") else { return nil }
        var process = String(tail[..<colon])
        var pid: Int? = nil
        if let bracket = process.firstIndex(of: "[") {
            let pidText = process[process.index(after: bracket)...].dropLast(process.hasSuffix("]") ? 1 : 0)
            pid = Int(pidText)
            process = String(process[..<bracket])
        }
        tail = tail[tail.index(after: colon)...]
        let message = String(tail).trimmingCharacters(in: .whitespaces)
        guard !process.isEmpty, !message.isEmpty else { return nil }
        return Line(timestamp: timestamp, host: host, process: process, pid: pid, message: message)
    }

    // MARK: - Timestamp prefixes

    static let monthNumbers: [String: Int] = [
        "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
        "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
    ]

    static var utcCalendar: Calendar {
        var cal = Calendar(identifier: .gregorian)
        cal.timeZone = TimeZone(identifier: "UTC")!
        return cal
    }

    /// `Mar 12 13:01:02 ` (day may be space-padded: `Mar  2`).
    static func parseClassicPrefix(_ text: Substring, anchor: Date?) -> (Date?, Substring)? {
        let tokens = text.split(separator: " ", maxSplits: 3, omittingEmptySubsequences: true)
        guard tokens.count == 4,
              let month = monthNumbers[String(tokens[0])],
              let day = Int(tokens[1]), (1...31).contains(day)
        else { return nil }
        let clock = tokens[2].split(separator: ":")
        guard clock.count == 3,
              let hour = Int(clock[0]), let minute = Int(clock[1]), let second = Int(clock[2])
        else { return nil }

        let calendar = utcCalendar
        let anchorDate = anchor ?? Date(timeIntervalSinceReferenceDate: 0)
        let anchorYear = calendar.component(.year, from: anchorDate)
        func date(year: Int) -> Date? {
            calendar.date(from: DateComponents(year: year, month: month, day: day,
                                               hour: hour, minute: minute, second: second))
        }
        var stamp = date(year: anchorYear)
        // A December entry read against a January mtime belongs to last year.
        if let s = stamp, let anchor, s > anchor.addingTimeInterval(2 * 86_400) {
            stamp = date(year: anchorYear - 1)
        }
        return (stamp, tokens[3])
    }

    /// `2026-06-10T12:00:00.123456+02:00 ` - rsyslog's RFC 3339 format.
    static func parseRFC3339Prefix(_ text: Substring) -> (Date?, Substring)? {
        guard let space = text.firstIndex(of: " ") else { return nil }
        let stamp = String(text[..<space])
        guard stamp.count >= 19, stamp[stamp.index(stamp.startIndex, offsetBy: 10)] == "T"
        else { return nil }
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = stamp.contains(".")
            ? [.withInternetDateTime, .withFractionalSeconds]
            : [.withInternetDateTime]
        guard let date = formatter.date(from: stamp) else { return nil }
        return (date, text[text.index(after: space)...])
    }
}
