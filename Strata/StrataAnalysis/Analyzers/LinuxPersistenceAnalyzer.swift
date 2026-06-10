import Foundation

/// Persistence detection over parsed cron jobs and systemd service units -
/// the Linux counterpart of the Run-key / scheduled-task / service-install
/// analyzers on the Windows side.
///
/// Rules:
///  1. **Suspicious content** - a job/unit whose command runs from a staging
///     path (`/tmp`, `/dev/shm`, `/var/tmp`, a home directory) or embeds
///     download/decode/netcat tooling. High severity.
///  2. **`@reboot` cron** - boot-persistent cron is the classic low-effort
///     Linux persistence; flagged medium even with an innocuous-looking
///     command (high when rule 1 also matches).
public nonisolated struct LinuxPersistenceAnalyzer: Analyzer {
    public let name = "Linux Persistence"
    public init() {}

    /// Lowercase fragments that make a persisted command suspicious.
    private static let suspiciousFragments = [
        "/tmp/", "/dev/shm/", "/var/tmp/", "/home/",
        "curl ", "wget ", "base64", "nc -", "ncat ", "/dev/tcp/",
        "python -c", "perl -e", "| sh", "| bash", "|sh", "|bash",
    ]

    public func analyze(context: AnalysisContext) -> [Finding] {
        guard !context.linuxPersistence.isEmpty else { return [] }
        var findings: [Finding] = []

        for entry in context.linuxPersistence {
            let command = entry.command.lowercased()
            let suspicious = Self.suspiciousFragments.first(where: command.contains)
            let isRebootCron = entry.kind == .cron && entry.schedule?.lowercased() == "@reboot"
            guard suspicious != nil || isRebootCron else { continue }

            let severity: Severity = suspicious != nil ? .high : .medium
            let technique: AttackTechnique = entry.kind == .cron
                ? AttackTechnique(attackID: "T1053.003", name: "Scheduled Task/Job: Cron")
                : AttackTechnique(attackID: "T1543.002",
                                  name: "Create or Modify System Process: Systemd Service")

            var reasons: [String] = []
            if let fragment = suspicious { reasons.append("command contains \"\(fragment.trimmingCharacters(in: .whitespaces))\"") }
            if isRebootCron { reasons.append("runs at boot (@reboot)") }

            let what: String
            switch entry.kind {
            case .cron:
                what = "Cron job (\(entry.schedule ?? "?"))"
                    + (entry.user.map { " as \($0)" } ?? "")
            case .systemdService:
                what = "systemd service \(entry.unitName ?? "?")"
                    + (entry.user.map { " (User=\($0))" } ?? "")
            }

            findings.append(Finding(
                title: "\(entry.kind.label) persistence: \(entry.title)",
                detail: "\(what) — \(reasons.joined(separator: "; ")).\n\(entry.command)",
                severity: severity,
                phase: .installation,
                technique: technique,
                evidencePaths: [entry.sourceFile]))
        }

        return findings
    }
}
