import Foundation

/// Parses Linux persistence sources into `LinuxPersistenceEntry` rows. Pure.
///
/// - **cron**: `/etc/crontab` and `/etc/cron.d/*` (6+ fields - schedule then a
///   *user* column then the command) and user spool crontabs under
///   `/var/spool/cron[/crontabs]/<user>` (5 fields + command, the user being
///   the file name). `@reboot`-style nicknames are honored - `@reboot` is the
///   classic cron persistence trigger.
/// - **systemd service units**: `*.service` INI files - the unit name,
///   `Description=`, `User=`, and the first `ExecStart=` (exec prefixes like
///   `-`/`@` stripped).
public nonisolated enum LinuxPersistenceParser {

    // MARK: - cron

    /// `hasUserField`: true for `/etc/crontab` + `/etc/cron.d/*`;
    /// false for user spool crontabs (pass the owner as `defaultUser`).
    public static func parseCrontab(text: String, sourceFile: String,
                                    hasUserField: Bool,
                                    defaultUser: String? = nil) -> [LinuxPersistenceEntry] {
        var entries: [LinuxPersistenceEntry] = []
        for rawLine in text.split(separator: "\n", omittingEmptySubsequences: true) {
            let line = rawLine.trimmingCharacters(in: .whitespaces)
            if line.isEmpty || line.hasPrefix("#") { continue }
            // Environment assignments (SHELL=, PATH=, MAILTO=...) aren't jobs.
            if isEnvironmentAssignment(line) { continue }

            var fields = line.split(separator: " ", omittingEmptySubsequences: true)
                .map(String.init)
            let schedule: String
            if line.hasPrefix("@") {
                schedule = fields.removeFirst()           // @reboot / @daily / ...
            } else {
                guard fields.count >= 5 else { continue }
                schedule = fields.prefix(5).joined(separator: " ")
                fields.removeFirst(5)
            }

            var user = defaultUser
            if hasUserField, !fields.isEmpty {
                user = fields.removeFirst()
            }
            guard !fields.isEmpty else { continue }
            let command = fields.joined(separator: " ")
            entries.append(LinuxPersistenceEntry(kind: .cron, schedule: schedule,
                                                 user: user, command: command,
                                                 sourceFile: sourceFile))
        }
        return entries
    }

    /// `FOO=bar` at the head of a crontab line (no spaces before `=` and the
    /// name looks like an identifier).
    private static func isEnvironmentAssignment(_ line: String) -> Bool {
        guard let eq = line.firstIndex(of: "=") else { return false }
        let name = line[..<eq]
        guard !name.isEmpty, !name.contains(" "), !name.contains("\t") else { return false }
        return name.allSatisfy { $0.isLetter || $0.isNumber || $0 == "_" }
    }

    // MARK: - systemd

    /// Returns nil when the unit has no `ExecStart` (template/alias units).
    public static func parseSystemdUnit(text: String,
                                        sourceFile: String) -> LinuxPersistenceEntry? {
        var section = ""
        var execStart: String?
        var description: String?
        var user: String?

        for rawLine in text.split(separator: "\n", omittingEmptySubsequences: true) {
            let line = rawLine.trimmingCharacters(in: .whitespaces)
            if line.isEmpty || line.hasPrefix("#") || line.hasPrefix(";") { continue }
            if line.hasPrefix("["), line.hasSuffix("]") {
                section = line.dropFirst().dropLast().lowercased()
                continue
            }
            guard let eq = line.firstIndex(of: "=") else { continue }
            let key = line[..<eq].trimmingCharacters(in: .whitespaces).lowercased()
            let value = line[line.index(after: eq)...].trimmingCharacters(in: .whitespaces)

            switch (section, key) {
            case ("unit", "description"):
                if description == nil { description = value }
            case ("service", "execstart"):
                if execStart == nil, !value.isEmpty {
                    // Strip systemd exec prefixes (- @ : + ! !!).
                    execStart = String(value.drop { "-@:+!".contains($0) })
                }
            case ("service", "user"):
                if user == nil { user = value }
            default:
                break
            }
        }

        guard let command = execStart else { return nil }
        let unitName = sourceFile
            .split(whereSeparator: { $0 == "/" || $0 == "\\" })
            .last.map(String.init) ?? sourceFile
        return LinuxPersistenceEntry(kind: .systemdService, user: user,
                                     command: command, unitName: unitName,
                                     detail: description, sourceFile: sourceFile)
    }

    /// A `*.timer` unit - the modern systemd cron replacement. Captures the
    /// `OnCalendar=`/`OnBootSec=`/`OnUnitActiveSec=` schedule and the `Unit=`
    /// it triggers (defaulting to the same basename `.service`).
    public static func parseSystemdTimer(text: String,
                                         sourceFile: String) -> LinuxPersistenceEntry? {
        var section = ""
        var schedule: [String] = []
        var triggers: String?
        var description: String?
        for rawLine in text.split(separator: "\n", omittingEmptySubsequences: true) {
            let line = rawLine.trimmingCharacters(in: .whitespaces)
            if line.isEmpty || line.hasPrefix("#") || line.hasPrefix(";") { continue }
            if line.hasPrefix("["), line.hasSuffix("]") {
                section = line.dropFirst().dropLast().lowercased(); continue
            }
            guard let eq = line.firstIndex(of: "=") else { continue }
            let key = line[..<eq].trimmingCharacters(in: .whitespaces).lowercased()
            let value = line[line.index(after: eq)...].trimmingCharacters(in: .whitespaces)
            switch (section, key) {
            case ("unit", "description"): if description == nil { description = value }
            case ("timer", "oncalendar"), ("timer", "onbootsec"),
                 ("timer", "onunitactivesec"), ("timer", "onstartupsec"):
                schedule.append(value)
            case ("timer", "unit"): triggers = value
            default: break
            }
        }
        let unitName = sourceFile.split(whereSeparator: { $0 == "/" }).last.map(String.init) ?? sourceFile
        let triggered = triggers ?? unitName.replacingOccurrences(of: ".timer", with: ".service")
        return LinuxPersistenceEntry(kind: .systemdTimer,
                                     schedule: schedule.isEmpty ? nil : schedule.joined(separator: ", "),
                                     command: triggered, unitName: unitName,
                                     detail: description, sourceFile: sourceFile)
    }

    /// `/etc/ld.so.preload` - whitespace/newline-separated library paths (`#`
    /// comments). Any entry here is injected into *every* dynamically-linked
    /// process, so the bar for suspicion is low. Parsed line-by-line so a
    /// comment line isn't tokenised into stray "words".
    public static func parseLdPreload(text: String, sourceFile: String) -> [LinuxPersistenceEntry] {
        var entries: [LinuxPersistenceEntry] = []
        for rawLine in text.split(separator: "\n", omittingEmptySubsequences: true) {
            let line = rawLine.trimmingCharacters(in: .whitespaces)
            if line.isEmpty || line.hasPrefix("#") { continue }
            for token in line.split(separator: " ", omittingEmptySubsequences: true) {
                if token.hasPrefix("#") { break }   // trailing comment
                entries.append(LinuxPersistenceEntry(kind: .ldPreload,
                                                     command: String(token), sourceFile: sourceFile))
            }
        }
        return entries
    }

    /// An XDG `*.desktop` autostart entry - GUI-session persistence. Captures
    /// `Exec=` and `Name=`.
    public static func parseAutostart(text: String, sourceFile: String) -> LinuxPersistenceEntry? {
        var exec: String?, name: String?
        for rawLine in text.split(separator: "\n", omittingEmptySubsequences: true) {
            let line = rawLine.trimmingCharacters(in: .whitespaces)
            if line.hasPrefix("Exec="), exec == nil { exec = String(line.dropFirst(5)) }
            else if line.hasPrefix("Name="), name == nil { name = String(line.dropFirst(5)) }
        }
        guard let command = exec, !command.isEmpty else { return nil }
        let unitName = sourceFile.split(whereSeparator: { $0 == "/" }).last.map(String.init) ?? sourceFile
        return LinuxPersistenceEntry(kind: .xdgAutostart, command: command,
                                     unitName: unitName, detail: name, sourceFile: sourceFile)
    }

    /// A shell script that auto-runs (`/etc/rc.local`, `/etc/init.d/*`,
    /// `/etc/cron.{hourly,daily,…}/*`) or a shell-init file (`~/.bashrc`,
    /// `/etc/profile.d/*`). Emits one entry per meaningful command line.
    ///
    /// `suspiciousOnly` filters to lines carrying an execution/download tell -
    /// used for shell-init files, where the whole point is to surface a planted
    /// `curl … | sh` without flooding on an ordinary `.bashrc`. Boot/periodic
    /// scripts pass `false` (every command line is inherently auto-run).
    public static func parseScript(text: String, kind: LinuxPersistenceEntry.Kind,
                                   sourceFile: String, user: String? = nil,
                                   suspiciousOnly: Bool, limit: Int = 100) -> [LinuxPersistenceEntry] {
        var entries: [LinuxPersistenceEntry] = []
        for rawLine in text.split(separator: "\n", omittingEmptySubsequences: true) {
            if entries.count >= limit { break }
            let line = rawLine.trimmingCharacters(in: .whitespaces)
            if line.isEmpty || line.hasPrefix("#") || line == "exit 0" { continue }
            // Skip shebangs, pure variable assignments, and shell scaffolding.
            if line.hasPrefix("#!") || isShellScaffolding(line) { continue }
            if isPureAssignment(line) { continue }
            if suspiciousOnly && !hasExecutionTell(line) { continue }
            entries.append(LinuxPersistenceEntry(kind: kind, user: user,
                                                 command: line, sourceFile: sourceFile))
        }
        return entries
    }

    private static func isPureAssignment(_ line: String) -> Bool {
        guard let eq = line.firstIndex(of: "="), !line.contains(" ") || line.firstIndex(of: " ")! > eq else {
            return false
        }
        let name = line[..<eq]
        let trimmed = name.hasPrefix("export ") ? name.dropFirst(7) : Substring(name)
        return !trimmed.isEmpty && trimmed.allSatisfy { $0.isLetter || $0.isNumber || $0 == "_" }
    }

    private static func isShellScaffolding(_ line: String) -> Bool {
        let s = line.lowercased()
        let keywords = ["fi", "done", "esac", "else", "then", "do", "}", "{", "if [", "case ", "for ", "while "]
        return keywords.contains(where: { s == $0 || s.hasPrefix($0) })
    }

    private static func hasExecutionTell(_ line: String) -> Bool {
        let s = line.lowercased()
        let tells = ["curl ", "wget ", "/dev/tcp/", "nc ", "ncat ", "base64", "eval ",
                     "python -c", "python3 -c", "perl -e", "| sh", "|sh", "| bash", "|bash",
                     "/tmp/", "/dev/shm/", "/var/tmp/", "bash -i", "exec "]
        return tells.contains(where: s.contains)
    }
}
