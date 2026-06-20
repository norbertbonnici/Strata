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
        // Prefix + host/process[pid]/message split is shared with SyslogParser.
        guard let scanned = SyslogLineScanner.scan(line, anchor: anchor) else { return nil }
        let classified = classify(process: scanned.process, message: scanned.message)
        return AuthLogEntry(timestamp: scanned.timestamp, host: scanned.host,
                            process: scanned.process, pid: scanned.pid,
                            kind: classified.kind, user: classified.user,
                            sourceIP: classified.ip, port: classified.port,
                            method: classified.method, command: classified.command,
                            message: scanned.message, sourceFile: sourceFile)
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
