import Foundation

/// Persistence detection across the full sweep of Linux auto-run locations -
/// cron, systemd services + timers, init scripts, shell-init files, XDG
/// autostart, and `ld.so.preload` - the Linux counterpart of the Run-key /
/// scheduled-task / service-install analyzers on the Windows side.
///
/// Rules:
///  1. **`ld.so.preload`** — *any* entry is flagged (it injects a library into
///     every process; on a stock host the file is absent or empty).
///  2. **Suspicious content** — a job/unit/script command that runs from a
///     staging path (`/tmp`, `/dev/shm`, `/var/tmp`, a home dir) or embeds
///     download/decode/netcat tooling. High severity.
///  3. **`@reboot` cron** — boot-persistent cron, the classic low-effort
///     persistence; flagged even with an innocuous command.
///
/// Shell-init entries are pre-filtered at parse time to execution-bearing lines
/// only, so they're surfaced here regardless of the fragment list (a planted
/// line in `.bashrc` is suspicious by virtue of being there).
public nonisolated struct LinuxPersistenceAnalyzer: Analyzer {
    public let name = "Linux Persistence"
    public init() {}

    /// Lowercase fragments that make a persisted command suspicious.
    private static let suspiciousFragments = [
        "/tmp/", "/dev/shm/", "/var/tmp/", "/home/",
        "curl ", "wget ", "base64", "nc -", "ncat ", "/dev/tcp/",
        "python -c", "python3 -c", "perl -e", "| sh", "| bash", "|sh", "|bash",
        "bash -i", "eval ", "msfvenom", "socat ",
    ]

    public func analyze(context: AnalysisContext) -> [Finding] {
        guard !context.linuxPersistence.isEmpty else { return [] }
        var findings: [Finding] = []

        for entry in context.linuxPersistence {
            let command = entry.command.lowercased()
            let suspicious = Self.suspiciousFragments.first(where: command.contains)
            let isRebootCron = entry.kind == .cron && entry.schedule?.lowercased() == "@reboot"
            // ld.so.preload and shell-init (already exec-filtered) are always
            // worth surfacing; everything else needs a tell.
            let alwaysFlag = entry.kind == .ldPreload || entry.kind == .shellInit
            guard alwaysFlag || suspicious != nil || isRebootCron else { continue }

            var reasons: [String] = []
            if entry.kind == .ldPreload { reasons.append("injected into every process via ld.so.preload") }
            if entry.kind == .shellInit { reasons.append("runs on every shell login") }
            if let fragment = suspicious {
                reasons.append("command contains \"\(fragment.trimmingCharacters(in: .whitespaces))\"")
            }
            if isRebootCron { reasons.append("runs at boot (@reboot)") }

            let severity: Severity = (entry.kind == .ldPreload || suspicious != nil) ? .high : .medium
            findings.append(Finding(
                title: "\(entry.kind.label) persistence: \(entry.title)",
                detail: "\(describe(entry)) — \(reasons.joined(separator: "; ")).\n\(entry.command)",
                severity: severity,
                phase: .installation,
                technique: Self.technique(for: entry.kind),
                evidencePaths: [entry.sourceFile]))
        }

        return findings
    }

    private func describe(_ entry: LinuxPersistenceEntry) -> String {
        switch entry.kind {
        case .cron:
            return "Cron job (\(entry.schedule ?? "?"))" + (entry.user.map { " as \($0)" } ?? "")
        case .systemdService:
            return "systemd service \(entry.unitName ?? "?")" + (entry.user.map { " (User=\($0))" } ?? "")
        case .systemdTimer:
            return "systemd timer \(entry.unitName ?? "?") (\(entry.schedule ?? "?"))"
        case .initScript:
            return "Init/boot script"
        case .shellInit:
            return "Shell-init file" + (entry.user.map { " (\($0))" } ?? "")
        case .xdgAutostart:
            return "XDG autostart \(entry.unitName ?? "?")"
        case .ldPreload:
            return "ld.so.preload library"
        case .atJob:
            return "at job"
        }
    }

    private static func technique(for kind: LinuxPersistenceEntry.Kind) -> AttackTechnique {
        switch kind {
        case .cron, .atJob:
            return AttackTechnique(attackID: "T1053.003", name: "Scheduled Task/Job: Cron")
        case .systemdService, .systemdTimer:
            return AttackTechnique(attackID: "T1543.002",
                                   name: "Create or Modify System Process: Systemd Service")
        case .initScript:
            return AttackTechnique(attackID: "T1037.004",
                                   name: "Boot or Logon Initialization Scripts: RC Scripts")
        case .shellInit:
            return AttackTechnique(attackID: "T1546.004",
                                   name: "Event Triggered Execution: Unix Shell Configuration Modification")
        case .xdgAutostart:
            return AttackTechnique(attackID: "T1547.013",
                                   name: "Boot or Logon Autostart Execution: XDG Autostart Entries")
        case .ldPreload:
            return AttackTechnique(attackID: "T1574.006",
                                   name: "Hijack Execution Flow: Dynamic Linker Hijacking")
        }
    }
}
