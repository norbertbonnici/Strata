import Foundation

/// Parses the general system logs `/var/log/syslog` (Debian) and
/// `/var/log/messages` (RHEL) into classified `SyslogEntry` rows, reusing
/// `SyslogLineScanner` for the prefix/tag split. Only the *non-auth* telemetry
/// is the point here - kernel USB/OOM/segfault/disk lines, systemd unit
/// lifecycle, and cron execution - so auth-class programs (sshd/sudo/su/login/
/// session) are skipped (the auth-log path already covers them).
public nonisolated enum SyslogParser {

    /// Programs whose lines are auth events handled by `AuthLogParser`; skip
    /// them here to avoid double-counting (`su` is kept - it's logged here, not
    /// always in auth.log, and carries elevation context).
    private static let authPrograms: Set<String> = [
        "sshd", "sudo", "login", "systemd-logind", "polkitd", "gdm-password",
        "CRON" /* auth-class PAM session lines, not the CMD lines */,
    ]

    public static func parse(text: String, sourceFile: String, anchor: Date?) -> [SyslogEntry] {
        var entries: [SyslogEntry] = []
        for rawLine in text.split(separator: "\n", omittingEmptySubsequences: true) {
            guard let line = SyslogLineScanner.scan(String(rawLine), anchor: anchor) else { continue }
            guard let entry = classify(line, sourceFile: sourceFile) else { continue }
            entries.append(entry)
        }
        return entries
    }

    private static func classify(_ line: SyslogLineScanner.Line, sourceFile: String) -> SyslogEntry? {
        let program = line.process
        let lower = line.message.lowercased()

        // Cron *execution* (CRON[pid]: (user) CMD (command)) is high-value and
        // distinct from cron's PAM session lines.
        if (program == "CRON" || program == "CROND" || program == "cron"),
           let cmdRange = line.message.range(of: "CMD (") {
            let after = line.message[cmdRange.upperBound...]
            let command = after.hasSuffix(")") ? String(after.dropLast()) : String(after)
            let user = userInParens(line.message)
            return make(line, .cronExec, user: user, command: command, sourceFile: sourceFile)
        }
        // Other auth-class programs are handled by the auth-log path.
        if Self.authPrograms.contains(program) { return nil }

        if program == "su" {
            return make(line, .suSession, user: suTarget(line.message), sourceFile: sourceFile)
        }

        if program == "kernel" {
            if lower.contains("usb-storage") || lower.contains("usb mass storage")
                || lower.contains("attached scsi removable disk") {
                return make(line, .massStorage, sourceFile: sourceFile)
            }
            if lower.contains("new ") && lower.contains("usb device") {
                return make(line, .usbDevice, sourceFile: sourceFile)
            }
            if lower.contains("out of memory") || lower.contains("oom-killer") {
                return make(line, .outOfMemory, sourceFile: sourceFile)
            }
            if lower.contains("segfault") || lower.contains("general protection")
                || lower.contains("trap invalid opcode") || lower.hasPrefix("traps:") {
                return make(line, .segfault, sourceFile: sourceFile)
            }
            if lower.contains("killed process") {
                return make(line, .processKilled, sourceFile: sourceFile)
            }
            if lower.contains("i/o error") || lower.contains("ext4-fs error")
                || lower.contains("medium error") || lower.contains("ata error") {
                return make(line, .diskError, sourceFile: sourceFile)
            }
            if lower.contains("link is down") || lower.contains("link down") {
                return make(line, .networkError, sourceFile: sourceFile)
            }
            return nil   // ordinary kernel chatter - not surfaced
        }

        if program == "systemd" || program == "init" {
            let unit = systemdUnit(line.message)
            if lower.contains("scheduled restart job") || lower.contains("start request repeated too quickly")
                || (lower.contains("restart counter is") ) {
                return make(line, .crashLoop, unit: unit, sourceFile: sourceFile)
            }
            if lower.contains("failed with result") || lower.contains("main process exited")
                || lower.contains("dumped core") {
                return make(line, .serviceFailed, unit: unit, sourceFile: sourceFile)
            }
            if lower.hasPrefix("started ") { return make(line, .serviceStarted, unit: unit, sourceFile: sourceFile) }
            if lower.hasPrefix("stopped ") { return make(line, .serviceStopped, unit: unit, sourceFile: sourceFile) }
            return nil
        }

        return nil   // unclassified program - drop (kept out of the noise)
    }

    private static func make(_ line: SyslogLineScanner.Line, _ category: SyslogEntry.Category,
                             user: String? = nil, command: String? = nil, unit: String? = nil,
                             sourceFile: String) -> SyslogEntry {
        SyslogEntry(timestamp: line.timestamp, host: line.host, process: line.process,
                    pid: line.pid, category: category, message: line.message,
                    user: user, command: command, unit: unit, sourceFile: sourceFile)
    }

    /// First `(user)` group in a cron line.
    private static func userInParens(_ message: String) -> String? {
        guard let open = message.firstIndex(of: "("),
              let close = message[open...].firstIndex(of: ")") else { return nil }
        let inner = message[message.index(after: open)..<close]
        return inner.isEmpty ? nil : String(inner)
    }

    /// `su: (to root) jane on pts/0` -> "root".
    private static func suTarget(_ message: String) -> String? {
        guard let range = message.range(of: "(to ") else { return nil }
        return message[range.upperBound...].prefix { $0 != ")" && $0 != " " }.isEmpty
            ? nil : String(message[range.upperBound...].prefix { $0 != ")" && $0 != " " })
    }

    /// First `*.service`/`.timer`/`.mount` token in a systemd line.
    private static func systemdUnit(_ message: String) -> String? {
        for token in message.split(whereSeparator: { $0 == " " || $0 == ":" }) {
            if token.hasSuffix(".service") || token.hasSuffix(".timer")
                || token.hasSuffix(".mount") || token.hasSuffix(".socket") {
                return String(token)
            }
        }
        return nil
    }
}
