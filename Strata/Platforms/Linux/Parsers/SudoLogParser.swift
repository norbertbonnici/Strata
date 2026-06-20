import Foundation

/// Parses sudo's own log file (`/var/log/sudo` and rotations) into classified
/// `AuthLogEntry` rows with `kind == .sudo`, so they fold straight into the
/// existing "Auth & Logins" tab and the AuthLog analyzers alongside the sudo
/// lines that `AuthLogParser` recovers from `auth.log`/`secure`.
///
/// When `Defaults logfile=/var/log/sudo` is configured, sudo writes its **own**
/// format - distinct from the syslog line it also emits to auth.log. Each entry
/// is a classic-syslog timestamp prefix followed by ` : <user> : <fields>`:
///
///     Jun 10 12:00:00 : alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/id
///     Jun 10 12:00:05 myhost : bob : command not allowed ; TTY=pts/1 ; PWD=/tmp ; USER=root ; COMMAND=/bin/rm -rf /
///
/// Two prefix shapes occur: with or without a leading hostname between the
/// timestamp and the first ` : `. The fields are `;`-separated `KEY=value`
/// pairs (TTY/PWD/USER/COMMAND), and a failure is signalled by a free-text
/// segment such as `command not allowed` or `user NOT in sudoers` where the
/// first field would otherwise be `TTY=`.
///
/// The timestamp prefix reuses `SyslogLineScanner` (classic `Mon DD HH:MM:SS`
/// with the file-mtime `anchor` supplying the year, or rsyslog RFC 3339) so the
/// year-inference / timezone handling is identical to `AuthLogParser`. The body
/// shape differs from the `host process[pid]: message` syslog tag, so the body
/// is parsed here rather than via `SyslogLineScanner.scan`.
public nonisolated enum SudoLogParser {

    /// `anchor` = the log file's last-modified date (year inference for the
    /// classic `Mon DD HH:MM:SS` prefix, which carries no year).
    public static func parse(text: String, sourceFile: String,
                             anchor: Date? = nil) -> [AuthLogEntry] {
        var entries: [AuthLogEntry] = []
        for rawLine in text.split(separator: "\n", omittingEmptySubsequences: true) {
            if let entry = parseLine(String(rawLine), sourceFile: sourceFile, anchor: anchor) {
                entries.append(entry)
            }
        }
        return entries
    }

    /// Parse one sudo-logfile line; nil when it doesn't carry a timestamp +
    /// ` : user : ` shape (e.g. a continuation line or a foreign format).
    static func parseLine(_ line: String, sourceFile: String,
                          anchor: Date? = nil) -> AuthLogEntry? {
        // 1) Timestamp prefix - reuse the shared scanner's two prefix parsers.
        let prefix = Substring(line)
        let timestamp: Date?
        var rest: Substring
        if let (date, remainder) = SyslogLineScanner.parseRFC3339Prefix(prefix) {
            timestamp = date; rest = remainder
        } else if let (date, remainder) = SyslogLineScanner.parseClassicPrefix(prefix, anchor: anchor) {
            timestamp = date; rest = remainder
        } else {
            return nil
        }

        // 2) Optional hostname, then ` : user : <fields>`.
        //    After the timestamp split, `rest` is either:
        //        "host : user : <fields>"   (hostname variant)
        //        ": user : <fields>"        (hostless - leading colon)
        //    The classic-prefix scanner consumes the space after the time, so a
        //    hostless line starts with a bare ":". Normalise that to an empty
        //    host segment so both variants split uniformly on " : ".
        var body = String(rest)
        if body.hasPrefix(":") {
            // Hostless: turn ": user : ..." into " : user : ..." so the split
            // yields ["", "user", "<fields>"] (empty host).
            body = " " + body
        }
        let segments = splitOnColonSeparator(body)
        // Need at least: [hostOrEmpty, user, fields...].
        guard segments.count >= 3 else { return nil }

        var index = 0
        // The piece before the first " : " is the hostname, possibly empty.
        let host = segments[index].trimmingCharacters(in: .whitespaces)
        index += 1

        let user = segments[index].trimmingCharacters(in: .whitespaces)
        index += 1
        guard !user.isEmpty else { return nil }

        // 3) The remaining text is the field block: re-join (the `;`-separated
        //    `KEY=value` block may itself have contained " : " inside a value,
        //    though that's rare; join preserves it) and pull the structured bits.
        let fieldBlock = segments[index...].joined(separator: " : ")
        let fields = parseFields(fieldBlock)

        let command = fields["COMMAND"]
        let targetUser = fields["USER"]
        let pwd = fields["PWD"]
        let tty = fields["TTY"]

        // 4) Failure detection: a leading free-text segment (no `KEY=` before
        //    the first `;`) such as "command not allowed" / "user NOT in
        //    sudoers". COMMAND= may still be present (the attempted command).
        let failureReason = leadingFailureReason(in: fieldBlock)

        // 5) Build a human message that carries the target user + pwd + tty +
        //    any failure reason (the model has no dedicated slot for these).
        var parts: [String] = []
        if let failureReason { parts.append(failureReason) }
        if let targetUser { parts.append("USER=\(targetUser)") }
        if let pwd { parts.append("PWD=\(pwd)") }
        if let tty { parts.append("TTY=\(tty)") }
        if let command { parts.append("COMMAND=\(command)") }
        let message = parts.isEmpty ? fieldBlock.trimmingCharacters(in: .whitespaces)
                                    : parts.joined(separator: " ; ")

        return AuthLogEntry(timestamp: timestamp, host: host, process: "sudo",
                            pid: nil, kind: .sudo, user: user, sourceIP: nil,
                            port: nil, method: nil, command: command,
                            message: message, sourceFile: sourceFile)
    }

    // MARK: - Field block parsing

    /// Split a string on the literal separator " : ", keeping empty leading
    /// pieces (so a hostless line ` : alice : ...` yields ["", "alice", ...]).
    private static func splitOnColonSeparator(_ text: String) -> [String] {
        text.components(separatedBy: " : ")
    }

    /// Parse the `;`-separated `KEY=value` field block into a dictionary. The
    /// value runs to the next `;` (or end), preserving internal spaces (a
    /// COMMAND= value is the rest of its segment). Free-text segments without a
    /// `=` are ignored here (handled by `leadingFailureReason`).
    private static func parseFields(_ block: String) -> [String: String] {
        var out: [String: String] = [:]
        for segment in block.split(separator: ";") {
            let piece = segment.trimmingCharacters(in: .whitespaces)
            guard let eq = piece.firstIndex(of: "=") else { continue }
            let key = String(piece[..<eq]).trimmingCharacters(in: .whitespaces)
            let value = String(piece[piece.index(after: eq)...]).trimmingCharacters(in: .whitespaces)
            guard !key.isEmpty else { continue }
            // Don't clobber a real first occurrence (KEY=value is unique here).
            if out[key] == nil { out[key] = value }
        }
        return out
    }

    /// A leading `;`-delimited free-text segment (no `=`) is sudo's failure
    /// reason, e.g. "command not allowed" or "user NOT in sudoers". nil when the
    /// first field is a normal `KEY=value` (a successful run).
    private static func leadingFailureReason(in block: String) -> String? {
        guard let first = block.split(separator: ";").first else { return nil }
        let piece = first.trimmingCharacters(in: .whitespaces)
        if piece.isEmpty || piece.contains("=") { return nil }
        return piece
    }
}
