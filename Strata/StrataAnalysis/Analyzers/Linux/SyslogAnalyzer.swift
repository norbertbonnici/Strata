import Foundation

/// Detection over general syslog/messages telemetry - the kernel/systemd/cron
/// events that aren't auth-related and live only in these logs.
public nonisolated struct SyslogAnalyzer: Analyzer {
    public let name = "System Log"
    public init() {}

    private static let networkDaemons = ["sshd", "nginx", "apache2", "httpd", "php-fpm",
                                         "sudo", "dbus", "smbd", "named", "exim", "postfix", "vsftpd"]
    private static let downloadTells = ["curl ", "wget ", "| sh", "|sh", "| bash", "|bash",
                                        "/dev/tcp/", "base64", "nc ", "ncat ", "/tmp/", "/dev/shm/"]

    public func analyze(context: AnalysisContext) -> [Finding] {
        guard !context.syslog.isEmpty else { return [] }
        var findings: [Finding] = []

        // USB mass-storage insertion (one finding per insert episode; collapse
        // a run of usb/mass-storage lines within a short window).
        let usb = context.syslog.filter { $0.category == .massStorage || $0.category == .usbDevice }
        if let first = usb.first(where: { $0.category == .massStorage }) ?? usb.first {
            findings.append(Finding(
                title: "USB storage device attached",
                detail: "Kernel recorded USB / removable-storage attachment (\(usb.count) related line(s)). "
                    + "Presence, not malice - correlate with file activity for data-staging/exfil or malware delivery.\n\(first.message)",
                severity: .info, phase: .delivery,
                technique: AttackTechnique(attackID: "T1091", name: "Replication Through Removable Media"),
                timestamp: usb.compactMap(\.timestamp).max(), evidencePaths: [first.sourceFile]))
        }

        // Segfault burst on a network-facing daemon (exploitation tell).
        var segByComm: [String: [SyslogEntry]] = [:]
        for e in context.syslog where e.category == .segfault {
            let comm = e.message.split(separator: "[").first.map { String($0).lowercased() } ?? e.process
            segByComm[comm, default: []].append(e)
        }
        for (comm, group) in segByComm {
            let isDaemon = Self.networkDaemons.contains { comm.contains($0) }
            if isDaemon || group.count >= 3 {
                findings.append(Finding(
                    title: "Segfault\(group.count > 1 ? " burst (\(group.count))" : "") on \(comm)",
                    detail: "\(comm) crashed with a segmentation/protection fault"
                        + (group.count >= 3 ? " \(group.count) times" : "")
                        + (isDaemon ? " - a network-facing daemon crashing is a strong in-progress memory-corruption exploit tell." : ".")
                        + "\n\(group.first!.message)",
                    severity: isDaemon ? .medium : .low, phase: .exploitation,
                    technique: AttackTechnique(attackID: "T1203", name: "Exploitation for Client Execution"),
                    timestamp: group.compactMap(\.timestamp).max(), evidencePaths: [group.first!.sourceFile]))
            }
        }

        // systemd crash loop (per unit), cross-referenced with persistence.
        let knownUnits = Set(context.linuxPersistence.compactMap { $0.unitName })
        var loopByUnit: [String: [SyslogEntry]] = [:]
        for e in context.syslog where e.category == .crashLoop {
            loopByUnit[e.unit ?? e.message, default: []].append(e)
        }
        for (unit, group) in loopByUnit where group.count >= 3 {
            let unknown = !unit.isEmpty && !knownUnits.contains(unit)
                && !unit.hasPrefix("systemd") && !unit.hasPrefix("network")
            findings.append(Finding(
                title: "Service crash loop: \(unit)",
                detail: "\(unit) restarted repeatedly (\(group.count) restart events)"
                    + (unknown ? " - an unrecognized unit crash-looping is a common failed-implant tell." : "."),
                severity: unknown ? .high : .medium, phase: .installation,
                technique: AttackTechnique(attackID: "T1543.002",
                                           name: "Create or Modify System Process: Systemd Service"),
                timestamp: group.compactMap(\.timestamp).max(), evidencePaths: [group.first!.sourceFile]))
        }

        // Suspicious cron execution (download-pipe / staging command).
        for e in context.syslog where e.category == .cronExec {
            let cmd = (e.command ?? e.message).lowercased()
            guard Self.downloadTells.contains(where: cmd.contains) else { continue }
            findings.append(Finding(
                title: "Suspicious cron execution\(e.user.map { " (\($0))" } ?? "")",
                detail: "Cron ran a command with download/staging characteristics: \(e.command ?? e.message)",
                severity: .high, phase: .exploitation,
                technique: AttackTechnique(attackID: "T1053.003", name: "Scheduled Task/Job: Cron"),
                timestamp: e.timestamp, evidencePaths: [e.sourceFile]))
        }

        return findings
    }
}
