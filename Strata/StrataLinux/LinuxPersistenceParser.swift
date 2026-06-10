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
}
