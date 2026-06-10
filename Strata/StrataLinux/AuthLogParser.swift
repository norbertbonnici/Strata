import Foundation

/// Parses syslog-format authentication logs (`/var/log/auth.log`, `/var/log/
/// secure`) into classified `AuthLogEntry` rows. Pure - text in, values out -
/// so it unit-tests without fixtures on disk and runs off the main actor.
///
/// Two line formats are handled:
///  - classic syslog:  `Mar 12 13:01:02 host sshd[123]: message`
///    (no year, no timezone - see `anchor` below)
///  - RFC 3339 (modern rsyslog / journald forwarding):
///    `2026-06-10T12:00:00.123456+02:00 host sshd[123]: message`
///
/// Classic syslog timestamps carry **no year**: the year is inferred from the
/// log file's own last-modified time (entries can't postdate the file's
/// mtime), rolling back one year for entries that would land in the future -
/// the standard log2timeline approach. They also carry no timezone; they're
/// interpreted as UTC, which keeps them stable and explicit even though the
/// host may have logged local time (documented limitation).
public nonisolated enum AuthLogParser {

    /// `anchor` = the log file's last-modified date (year inference).
    public static func parse(text: String, sourceFile: String,
                             anchor: Date? = nil) -> [AuthLogEntry] {
        var entries: [AuthLogEntry] = []
        for rawLine in text.split(separator: "\n", omittingEmptySubsequences: true) {
            let line = String(rawLine)
            guard let entry = parseLine(line, sourceFile: sourceFile, anchor: anchor) else { continue }
            entries.append(entry)
        }
        return entries
    }

    /// Parse one line; nil when the line doesn't look like syslog at all.
    static func parseLine(_ line: String, sourceFile: String,
                          anchor: Date? = nil) -> AuthLogEntry? {
        var rest = Substring(line)
        let timestamp: Date?

        if let (date, remainder) = parseRFC3339Prefix(rest) {
            timestamp = date
            rest = remainder
        } else if let (date, remainder) = parseClassicPrefix(rest, anchor: anchor) {
            timestamp = date
            rest = remainder
        } else {
            return nil
        }

        // "host process[pid]: message"  (pid optional; "process:" also legal)
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

        let classified = classify(process: process, message: message)
        return AuthLogEntry(timestamp: timestamp, host: host, process: process,
                            pid: pid, kind: classified.kind, user: classified.user,
                            sourceIP: classified.ip, port: classified.port,
                            method: classified.method, command: classified.command,
                            message: message, sourceFile: sourceFile)
    }

    // MARK: - Timestamp prefixes

    private static let monthNumbers: [String: Int] = [
        "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
        "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
    ]

    private static var utcCalendar: Calendar {
        var cal = Calendar(identifier: .gregorian)
        cal.timeZone = TimeZone(identifier: "UTC")!
        return cal
    }

    /// `Mar 12 13:01:02 ` (day may be space-padded: `Mar  2`).
    private static func parseClassicPrefix(_ text: Substring,
                                           anchor: Date?) -> (Date?, Substring)? {
        let tokens = text.split(separator: " ", maxSplits: 3, omittingEmptySubsequences: true)
        guard tokens.count == 4,
              let month = monthNumbers[String(tokens[0])],
              let day = Int(tokens[1]) , (1...31).contains(day)
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
        // Entries can't postdate the file's mtime (+2 days of clock slack):
        // a December entry read against a January mtime belongs to last year.
        if let s = stamp, let anchor, s > anchor.addingTimeInterval(2 * 86_400) {
            stamp = date(year: anchorYear - 1)
        }
        return (stamp, tokens[3])
    }

    /// `2026-06-10T12:00:00.123456+02:00 ` - rsyslog's RFC 3339 format.
    private static func parseRFC3339Prefix(_ text: Substring) -> (Date?, Substring)? {
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

    // MARK: - Classification

    private struct Classified {
        var kind: AuthLogEntry.Kind = .other
        var user: String?
        var ip: String?
        var port: Int?
        var method: String?
        var command: String?
    }

    private static func classify(process: String, message: String) -> Classified {
        var out = Classified()

        func token(after marker: String) -> String? {
            guard let range = message.range(of: marker) else { return nil }
            let tail = message[range.upperBound...]
            return tail.split(separator: " ").first.map(String.init)
        }

        switch process {
        case "sshd":
            if message.hasPrefix("Accepted ") {
                out.kind = .sshAccepted
                out.method = token(after: "Accepted ")
                out.user = token(after: " for ")
                out.ip = token(after: " from ")
                out.port = token(after: " port ").flatMap(Int.init)
            } else if message.hasPrefix("Failed ") {
                out.kind = .sshFailed
                out.user = message.contains(" for invalid user ")
                    ? token(after: " for invalid user ")
                    : token(after: " for ")
                out.ip = token(after: " from ")
                out.port = token(after: " port ").flatMap(Int.init)
            } else if message.hasPrefix("Invalid user ") {
                out.kind = .sshInvalidUser
                out.user = token(after: "Invalid user ")
                out.ip = token(after: " from ")
            } else if message.contains("session opened for user") {
                out.kind = .sessionOpened
                out.user = sessionUser(in: message)
            } else if message.contains("session closed for user") {
                out.kind = .sessionClosed
                out.user = sessionUser(in: message)
            }
        case "sudo":
            // "  jane : TTY=pts/0 ; PWD=/home/jane ; USER=root ; COMMAND=/usr/bin/id"
            if message.contains("COMMAND=") {
                out.kind = .sudo
                out.user = message.split(separator: ":").first?
                    .trimmingCharacters(in: .whitespaces)
                if let range = message.range(of: "COMMAND=") {
                    out.command = String(message[range.upperBound...])
                        .trimmingCharacters(in: .whitespaces)
                }
            } else if message.contains("session opened for user") {
                out.kind = .sessionOpened
                out.user = sessionUser(in: message)
            }
        case "useradd", "adduser", "groupadd":
            if message.hasPrefix("new user:") || message.hasPrefix("new group:") {
                out.kind = .userAdded
                out.user = token(after: "name=")?
                    .trimmingCharacters(in: CharacterSet(charactersIn: ","))
            }
        case "usermod", "passwd", "chpasswd", "chage", "chfn", "chsh":
            out.kind = .userModified
            out.user = sessionUser(in: message) ?? token(after: " for ")
        default:
            if message.contains("session opened for user") {
                out.kind = .sessionOpened
                out.user = sessionUser(in: message)
            } else if message.contains("session closed for user") {
                out.kind = .sessionClosed
                out.user = sessionUser(in: message)
            }
        }
        return out
    }

    /// "session opened for user root(uid=0) by jane(uid=1000)" -> "root".
    private static func sessionUser(in message: String) -> String? {
        guard let range = message.range(of: "for user ") else { return nil }
        let tail = message[range.upperBound...]
        let raw = tail.split(separator: " ").first.map(String.init) ?? ""
        let name = raw.split(separator: "(").first.map(String.init) ?? raw
        return name.isEmpty ? nil : name
    }
}
