import Foundation

/// Linux anti-forensics / indicator-removal detection (T1070 and sub-techniques).
///
/// This deliberately **complements** the three existing analyzers rather than
/// duplicating them:
///
///  - `ShellHistoryAnalyzer` already carries a "Shell history tampering" rule
///    over a small fixed set (`history -c`, `history -w`, `unset histfile`,
///    `histsize=0`, `rm ~/.bash_history`, `ln -sf /dev/null`). To avoid
///    double-reporting, every history-clearing signal here is one that rule does
///    **not** already match — `set +o history`, `export histfile=/dev/null`,
///    `histfilesize=0`, and removal of `.zsh_history` / `/root/.zsh_history`.
///  - `LogClearedAnalyzer` is **Windows-only** (Security 1102 / System 104).
///    Linux log/journal clearing is uncovered ground.
///  - `AuthLogAnalyzer` handles brute force / root login / account creation —
///    no anti-forensics overlap.
///
/// Beyond shell history, this analyzer also reaches into the *system* log
/// (`syslog`), the binary `journald` journal, and the kernel `audit` trail —
/// the very logs an attacker tampers with — to catch the EXECVE / message
/// evidence of the wipe even when the shell history itself was cleared.
///
/// Severity discipline: a confirmed **wipe** of a log or history file (`> log`,
/// `rm`, `truncate -s 0`, `journalctl --vacuum*`) is `.high`; merely **disabling**
/// future logging (`unset HISTFILE`, `auditctl -e 0`, `setenforce 0`,
/// stopping a logging daemon) is `.medium` — suggestive, but recoverable and
/// occasionally legitimate during maintenance. Timestomping a file in a staging
/// path is `.high`; elsewhere `.medium`.
///
/// Kill-chain phase: Exploitation (defense evasion). Every finding tags a real
/// T1070 sub-technique.
public nonisolated struct LinuxAntiForensicsAnalyzer: Analyzer {
    public let name = "Linux Anti-Forensics"
    public init() {}

    // MARK: - Rule shape

    /// A command-line rule. `indicators` are lowercased substrings; ANY match
    /// fires (subject to `requiresAll`, used when one token alone is too broad).
    private struct Rule {
        let indicators: [String]
        /// When non-empty, every one of these must ALSO appear — used to gate a
        /// broad verb (e.g. `touch `) behind a specific flag (`-t`, `-r`, `-d`).
        var requiresAll: [String] = []
        let title: String
        let severity: Severity
        let technique: AttackTechnique
    }

    private static func technique(_ id: String, _ name: String) -> AttackTechnique {
        AttackTechnique(attackID: id, name: name)
    }

    // MARK: - History clearing / disabling (T1070.003)
    //
    // Scoped to signals ShellHistoryAnalyzer's tamper rule does NOT cover, so the
    // two never both fire on the same command. A wipe of the file is .high; an
    // in-session disable of future logging is .medium.

    private static let historyRules: [Rule] = [
        // Wipes — file removal NOT already caught by ShellHistoryAnalyzer's
        // tamper rule. That rule owns `rm ~/.bash_history` and
        // `rm /root/.bash_history`, so we deliberately do NOT list `.bash_history`
        // here (it would double-report). We cover only the files that rule misses:
        // `.zsh_history` (zsh, any home — its rule is bash-only) and `.bash_logout`
        // (a logout-time wipe vector it doesn't list), both gated behind `rm `.
        Rule(indicators: [".zsh_history", ".bash_logout"],
             requiresAll: ["rm "],
             title: "Shell history file removed",
             severity: .high,
             technique: technique("T1070.003", "Indicator Removal: Clear Command History")),
        // Disables — redirect the history file to the bit bucket (not the
        // `ln -sf /dev/null` form the other rule has).
        Rule(indicators: ["export histfile=/dev/null", "histfile=/dev/null",
                          "set +o history", "unset histsize", "histfilesize=0"],
             title: "Shell history logging disabled",
             severity: .medium,
             technique: technique("T1070.003", "Indicator Removal: Clear Command History")),
    ]

    // MARK: - Log clearing (T1070.002)
    //
    // Truncation/removal of system logs and journal vacuuming. Gated on the log
    // *path* so `echo foo > script.sh` doesn't fire. A wipe is .high.

    /// Canonical Linux log paths/files an attacker scrubs. Lowercased; matched as
    /// substrings so a full path (`/var/log/auth.log`) or a bare name works.
    private static let logTargets = [
        "/var/log/auth.log", "/var/log/secure", "/var/log/syslog",
        "/var/log/messages", "/var/log/wtmp", "/var/log/btmp",
        "/var/log/lastlog", "/var/log/faillog", "/var/log/audit/audit.log",
        "/var/log/maillog", "/var/log/kern.log", "/var/log/cron",
        "/var/log/apache2", "/var/log/nginx", "/var/log/httpd",
    ]

    /// Vacuum/rotate verbs on the systemd journal — these *delete* journal data.
    private static let journalWipeTokens = [
        "journalctl --rotate", "journalctl --vacuum-time",
        "journalctl --vacuum-size", "journalctl --vacuum-files",
        "rm -rf /var/log/journal", "rm -r /var/log/journal",
        "rm /var/log/journal",
    ]

    // MARK: - Audit / logging-daemon tampering (T1070, T1562.001/.006)
    //
    // Stopping or flushing the very subsystems that produce the evidence. .medium
    // (disabling, not yet a destructive wipe) — but a strong evasion signal.

    private static let auditTamperRules: [Rule] = [
        Rule(indicators: ["auditctl -d", "auditctl --delete-all"],
             title: "Audit rules flushed (auditctl -D)",
             severity: .medium,
             technique: technique("T1562.001", "Impair Defenses: Disable or Modify Tools")),
        Rule(indicators: ["auditctl -e 0"],
             title: "Audit subsystem disabled (auditctl -e 0)",
             severity: .medium,
             technique: technique("T1562.001", "Impair Defenses: Disable or Modify Tools")),
        Rule(indicators: ["systemctl stop auditd", "service auditd stop",
                          "systemctl disable auditd", "pkill -9 auditd",
                          "kill auditd", "/etc/init.d/auditd stop"],
             title: "Audit daemon stopped",
             severity: .medium,
             technique: technique("T1562.001", "Impair Defenses: Disable or Modify Tools")),
        Rule(indicators: ["systemctl stop rsyslog", "service rsyslog stop",
                          "systemctl disable rsyslog", "systemctl stop syslog",
                          "/etc/init.d/rsyslog stop", "systemctl stop systemd-journald"],
             title: "System logging daemon stopped",
             severity: .medium,
             technique: technique("T1562.006", "Impair Defenses: Indicator Blocking")),
        Rule(indicators: ["setenforce 0"],
             title: "SELinux set to permissive (setenforce 0)",
             severity: .medium,
             technique: technique("T1562.001", "Impair Defenses: Disable or Modify Tools")),
    ]

    // MARK: - Timestomp (T1070.006)
    //
    // `touch` with a timestamp-overriding flag (-t / -d / --date / -r) targeting a
    // file in a staging directory. The flag gate keeps benign `touch newfile`
    // (which only creates an empty file at *now*) from firing. MftAnalyzer owns
    // NTFS $SI-vs-$FN timestomp; this is the command-line Linux counterpart.

    private static let touchFlags = ["-t ", "-d ", "--date", "-r "]

    /// Directories that make a timestomp suspicious rather than routine (a
    /// developer running `touch -r` in their project tree is noise).
    private static let stagingPaths = [
        "/tmp/", "/var/tmp/", "/dev/shm/", "/run/shm/",
        "/var/www/", "/usr/bin/", "/usr/sbin/", "/bin/", "/sbin/",
        "/etc/cron", "/etc/systemd/", "/.ssh/", "/usr/local/bin/",
    ]

    // MARK: - analyze

    public func analyze(context: AnalysisContext) -> [Finding] {
        var findings: [Finding] = []

        // ---- Shell history: dedupe one finding per (user, command). ----
        // ShellHistoryEntry has no `kind`, so we walk the raw command text.
        if !context.shellHistory.isEmpty {
            var seen = Set<String>()
            for entry in context.shellHistory {
                let cmd = entry.command.lowercased()
                if let f = historyFinding(cmd, entry: entry, dedupe: &seen) { findings.append(f) }
                if let f = logClearFinding(cmd, sourceFile: entry.sourceFile,
                                           timestamp: entry.timestamp,
                                           context: "\(entry.user)'s \(entry.shell.label) history",
                                           dedupe: &seen) { findings.append(f) }
                if let f = auditTamperFinding(cmd, sourceFile: entry.sourceFile,
                                              timestamp: entry.timestamp,
                                              context: "\(entry.user)'s \(entry.shell.label) history",
                                              dedupe: &seen) { findings.append(f) }
                if let f = timestompFinding(cmd, sourceFile: entry.sourceFile,
                                            timestamp: entry.timestamp,
                                            context: "\(entry.user)'s \(entry.shell.label) history",
                                            dedupe: &seen) { findings.append(f) }
            }
        }

        // ---- audit EXECVE: the wipe command as the kernel recorded it. ----
        // audit survives a history wipe, so this is the higher-confidence path.
        var auditSeen = Set<String>()
        for ev in context.audit {
            guard let cmd = ev.commandLine?.lowercased(), !cmd.isEmpty else { continue }
            let src = "auditd EXECVE\(ev.auid.map { " (auid \($0))" } ?? "")"
            if let f = logClearFinding(cmd, sourceFile: ev.sourceFile, timestamp: ev.timestamp,
                                       context: src, dedupe: &auditSeen) { findings.append(f) }
            if let f = auditTamperFinding(cmd, sourceFile: ev.sourceFile, timestamp: ev.timestamp,
                                          context: src, dedupe: &auditSeen) { findings.append(f) }
            if let f = timestompFinding(cmd, sourceFile: ev.sourceFile, timestamp: ev.timestamp,
                                        context: src, dedupe: &auditSeen) { findings.append(f) }
        }

        // ---- syslog + journald: the daemons logging their own shutdown, plus
        // CRON-launched wipe commands. We scan the message/command text. ----
        var sysSeen = Set<String>()
        for s in context.syslog {
            let hay = (s.command ?? s.message).lowercased()
            guard !hay.isEmpty else { continue }
            let src = "syslog (\(s.process))"
            if let f = logClearFinding(hay, sourceFile: s.sourceFile, timestamp: s.timestamp,
                                       context: src, dedupe: &sysSeen) { findings.append(f) }
            if let f = auditTamperFinding(hay, sourceFile: s.sourceFile, timestamp: s.timestamp,
                                          context: src, dedupe: &sysSeen) { findings.append(f) }
        }
        for j in context.journald {
            let hay = j.message.lowercased()
            guard !hay.isEmpty else { continue }
            let src = "journald\(j.program.map { " (\($0))" } ?? "")"
            if let f = logClearFinding(hay, sourceFile: j.sourceFile, timestamp: j.timestamp,
                                       context: src, dedupe: &sysSeen) { findings.append(f) }
            if let f = auditTamperFinding(hay, sourceFile: j.sourceFile, timestamp: j.timestamp,
                                          context: src, dedupe: &sysSeen) { findings.append(f) }
        }

        return findings
    }

    // MARK: - Matchers (each returns at most one finding, deduped by content)

    private func ruleMatches(_ rule: Rule, _ cmd: String) -> Bool {
        guard rule.indicators.contains(where: cmd.contains) else { return false }
        return rule.requiresAll.allSatisfy(cmd.contains)
    }

    /// True when the `rm`/`shred` verb is acting on the *log path itself* — i.e.
    /// the destructive verb governs the same command segment the target lives in.
    /// We split on shell command separators (`&&`, `||`, `;`, `|`, `&`) and only
    /// consider the segment that contains the target, so
    /// `rm /tmp/x && cat /var/log/auth.log` (rm on /tmp, log merely read) stays
    /// quiet while `rm -f /var/log/auth.log` fires.
    private func removesOrShreds(_ cmd: String, target: String) -> Bool {
        // Normalise the separators to a single delimiter, then scan segments.
        var work = cmd
        for sep in ["&&", "||", ";", "|", "&"] {
            work = work.replacingOccurrences(of: sep, with: "\u{1}")
        }
        for segment in work.split(separator: "\u{1}") {
            guard segment.contains(target) else { continue }
            for verb in ["rm ", "rm\t", "shred "] where segment.contains(verb) {
                return true
            }
        }
        return false
    }

    private func historyFinding(_ cmd: String, entry: ShellHistoryEntry,
                                dedupe seen: inout Set<String>) -> Finding? {
        for rule in Self.historyRules where ruleMatches(rule, cmd) {
            let key = "hist|\(rule.title)|\(entry.user)|\(cmd)"
            guard seen.insert(key).inserted else { return nil }
            return Finding(
                title: "\(rule.title) (\(entry.user))",
                detail: "\(entry.user)'s \(entry.shell.label) history recorded a command that "
                    + (rule.severity == .high ? "destroys" : "disables future")
                    + " shell-history evidence:\n\(entry.command)",
                severity: rule.severity,
                phase: .exploitation,
                technique: rule.technique,
                timestamp: entry.timestamp,
                evidencePaths: [entry.sourceFile])
        }
        return nil
    }

    private func logClearFinding(_ cmd: String, sourceFile: String, timestamp: Date?,
                                 context: String, dedupe seen: inout Set<String>) -> Finding? {
        // Journal vacuum/rotate — self-evidently a journal wipe, no path gate.
        if let tok = Self.journalWipeTokens.first(where: cmd.contains) {
            let key = "journal|\(tok)|\(cmd)"
            guard seen.insert(key).inserted else { return nil }
            return Finding(
                title: "systemd journal cleared",
                detail: "\(context): a journal vacuum/rotate command was run, deleting journald "
                    + "history:\n\(cmd)\nToken: \(tok)",
                severity: .high,
                phase: .exploitation,
                technique: Self.technique("T1070.002", "Indicator Removal: Clear Linux or Mac System Logs"),
                timestamp: timestamp,
                evidencePaths: [sourceFile])
        }

        // Truncate/redirect/remove of a known log path. Gate on the destructive
        // verb so a plain `cat /var/log/syslog` (read, not write) is ignored.
        guard let target = Self.logTargets.first(where: cmd.contains) else { return nil }
        let isTruncate = cmd.contains("truncate -s 0") || cmd.contains("truncate --size=0")
        // A redirect that writes INTO *this* log path (`> /var/log/auth.log`,
        // `>/var/log/auth.log`, `:> /var/log/...`). We require the matched log
        // path to immediately follow the redirect operator so an unrelated
        // colon-redirect elsewhere in the line (or a write to a *different*
        // /var/log file we don't track) can't fire on a coincidental path match.
        let isRedirect = cmd.contains("> \(target)") || cmd.contains(">\(target)")
                      || cmd.contains(":> \(target)") || cmd.contains(": > \(target)")
        // `rm`/`shred` of the log path. Require the destructive verb to actually
        // precede the matched target in the string (verb…target ordering) so
        // `rm /tmp/x && cat /var/log/auth.log` (rm targets /tmp, log only read)
        // does not fire.
        let isRemove = removesOrShreds(cmd, target: target)
        let isCpDevNull = cmd.contains("cp /dev/null") || cmd.contains("cat /dev/null >")
        guard isTruncate || isRedirect || isRemove || isCpDevNull else { return nil }

        let key = "logclear|\(target)|\(cmd)"
        guard seen.insert(key).inserted else { return nil }
        let verb = isRemove ? "deleted" : "truncated"
        return Finding(
            title: "System log \(verb): \(target)",
            detail: "\(context): a command \(verb) the log \(target), destroying its contents:\n"
                + "\(cmd)",
            severity: .high,
            phase: .exploitation,
            technique: Self.technique("T1070.002", "Indicator Removal: Clear Linux or Mac System Logs"),
            timestamp: timestamp,
            evidencePaths: [sourceFile])
    }

    private func auditTamperFinding(_ cmd: String, sourceFile: String, timestamp: Date?,
                                    context: String, dedupe seen: inout Set<String>) -> Finding? {
        for rule in Self.auditTamperRules where ruleMatches(rule, cmd) {
            let key = "tamper|\(rule.title)|\(cmd)"
            guard seen.insert(key).inserted else { return nil }
            return Finding(
                title: rule.title,
                detail: "\(context): \(rule.title.lowercased()) — an attacker disabling the "
                    + "subsystem that produces forensic evidence:\n\(cmd)",
                severity: rule.severity,
                phase: .exploitation,
                technique: rule.technique,
                timestamp: timestamp,
                evidencePaths: [sourceFile])
        }
        return nil
    }

    private func timestompFinding(_ cmd: String, sourceFile: String, timestamp: Date?,
                                  context: String, dedupe seen: inout Set<String>) -> Finding? {
        // Must be a `touch` carrying a timestamp-override flag — a bare `touch f`
        // only stamps "now" on an empty file and isn't anti-forensic.
        guard cmd.contains("touch ") else { return nil }
        guard Self.touchFlags.contains(where: cmd.contains) else { return nil }

        let staging = Self.stagingPaths.first(where: cmd.contains)
        let key = "timestomp|\(cmd)"
        guard seen.insert(key).inserted else { return nil }
        let severity: Severity = staging != nil ? .high : .medium
        return Finding(
            title: "File timestomping via touch"
                + (staging.map { " in \($0.trimmingCharacters(in: CharacterSet(charactersIn: "/")))" } ?? ""),
            detail: "\(context): a `touch` command back-dated a file's timestamps"
                + (staging.map { " in the staging path \($0)" } ?? "")
                + ", a hallmark of timestomping to evade timeline analysis:\n\(cmd)",
            severity: severity,
            phase: .exploitation,
            technique: Self.technique("T1070.006", "Indicator Removal: Timestomp"),
            timestamp: timestamp,
            evidencePaths: [sourceFile])
    }
}
