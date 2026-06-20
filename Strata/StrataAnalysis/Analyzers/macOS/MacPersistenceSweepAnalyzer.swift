import Foundation

/// Detection over the non-launchd macOS persistence sweep
/// (`[MacPersistenceItem]`) - cron, `periodic`, `emond`, login/logout hooks,
/// `rc` scripts. The companion to `MacPersistenceAnalyzer` (which covers
/// launchd). High-signal by construction: several of these mechanisms
/// (`emond`, login hooks, `rc.local`) are deprecated or non-stock on macOS, so
/// their mere presence is suspicious; cron and periodic are gated on a
/// suspicious command so a benign maintenance job stays quiet.
public nonisolated struct MacPersistenceSweepAnalyzer: Analyzer {
    public let name = "macOS Persistence Sweep"
    public init() {}

    /// Path fragments marking an executable as living in a non-standard staging
    /// location (mirrors `MacPersistenceAnalyzer`).
    private static let stagingPaths = [
        "/tmp/", "/private/tmp/", "/var/tmp/", "/private/var/tmp/",
        "/users/shared/", "/library/caches/", "/.",
    ]

    /// Interpreters + downloaders whose presence in a scheduled command implies
    /// a scripted payload rather than a maintenance task.
    private static let scriptOrDownloader = [
        "bash", "sh", "zsh", "ksh", "python", "python3", "perl", "ruby",
        "osascript", "curl", "wget", "nc", "ncat", "node", "base64",
    ]

    public func analyze(context: AnalysisContext) -> [Finding] {
        analyze(context.macPersistence)
    }

    /// Core detection over the parsed sweep. Pure; unit-tested.
    public func analyze(_ items: [MacPersistenceItem]) -> [Finding] {
        var findings: [Finding] = []
        for item in items {
            switch item.kind {
            case .emond:
                findings.append(emondFinding(item))
            case .loginHook, .logoutHook:
                findings.append(hookFinding(item))
            case .cron:
                if let f = cronFinding(item) { findings.append(f) }
            case .periodic:
                findings.append(periodicFinding(item))
            case .rcScript:
                if let f = rcFinding(item) { findings.append(f) }
            case .configProfile:
                continue   // surfaced in the tab; too benign on managed fleets to flag
            }
        }
        return findings
    }

    // MARK: - Per-kind rules

    private func emondFinding(_ item: MacPersistenceItem) -> Finding {
        var detail = "An emond rule runs a command. emond is a deprecated, undocumented event monitor almost exclusively abused for persistence (T1546.014)."
        if let events = item.detail, !events.isEmpty { detail += "\nTriggers on: \(events)." }
        if !item.command.isEmpty { detail += "\nCommand: \(item.command)" }
        return Finding(
            title: "emond persistence rule: \(item.title)",
            detail: detail,
            severity: .high,
            phase: .installation,
            technique: AttackTechnique(attackID: "T1546.014", name: "Event Triggered Execution: Emond"),
            timestamp: nil,
            evidencePaths: [item.sourceFile])
    }

    private func hookFinding(_ item: MacPersistenceItem) -> Finding {
        let which = item.kind == .loginHook ? "login" : "logout"
        let detail = "A \(which) hook runs a script at \(which) (as root for the system plist). Login/logout hooks are a deprecated mechanism Apple replaced with launchd; their presence is a strong persistence tell (T1037.002).\nScript: \(item.command)"
        return Finding(
            title: "macOS \(which) hook: \(item.command)",
            detail: detail,
            severity: .high,
            phase: .installation,
            technique: AttackTechnique(attackID: "T1037.002", name: "Boot or Logon Initialization Scripts: Login Hook"),
            timestamp: nil,
            evidencePaths: [item.sourceFile])
    }

    private func cronFinding(_ item: MacPersistenceItem) -> Finding? {
        var reasons: [String] = []
        let atReboot = (item.schedule?.lowercased() == "@reboot")
        if atReboot { reasons.append("runs at every boot (@reboot)") }
        if Self.isStagingPath(item.command.lowercased()) {
            reasons.append("command runs from a non-standard path")
        }
        if Self.usesScriptOrDownloader(item.command) {
            reasons.append("invokes a shell / scripting interpreter or downloader")
        }
        guard !reasons.isEmpty else { return nil }
        var detail = "A cron job looks like persistence — \(reasons.joined(separator: "; ")) (T1053.003)."
        if let schedule = item.schedule { detail += "\nSchedule: \(schedule)" }
        if let user = item.user { detail += "\nRuns as: \(user)" }
        detail += "\nCommand: \(item.command)"
        return Finding(
            title: "Suspicious cron job: \(item.title)",
            detail: detail,
            severity: .high,
            phase: .installation,
            technique: AttackTechnique(attackID: "T1053.003", name: "Scheduled Task/Job: Cron"),
            timestamp: nil,
            evidencePaths: [item.sourceFile])
    }

    private func periodicFinding(_ item: MacPersistenceItem) -> Finding {
        let cadence = item.schedule.map { " (\($0))" } ?? ""
        let detail = "A custom script is installed in the macOS periodic system\(cadence). Apple ships a fixed set; an added script runs on the periodic cadence as a persistence foothold (T1053).\nScript: \(item.command)"
        return Finding(
            title: "Custom periodic script: \(item.title)",
            detail: detail,
            severity: .medium,
            phase: .installation,
            technique: AttackTechnique(attackID: "T1053", name: "Scheduled Task/Job"),
            timestamp: nil,
            evidencePaths: [item.sourceFile])
    }

    private func rcFinding(_ item: MacPersistenceItem) -> Finding? {
        // rc.common is stock; only rc.local (which macOS does not ship) is a tell.
        guard (item.name ?? "").lowercased() == "rc.local" else { return nil }
        let detail = "An /etc/rc.local boot script is present. macOS does not ship rc.local, so it was added — it runs at boot as root (T1037.004).\nCommands: \(item.command.isEmpty ? "(see file)" : item.command)"
        return Finding(
            title: "macOS rc.local boot script",
            detail: detail,
            severity: .high,
            phase: .installation,
            technique: AttackTechnique(attackID: "T1037.004", name: "Boot or Logon Initialization Scripts: RC Scripts"),
            timestamp: nil,
            evidencePaths: [item.sourceFile])
    }

    // MARK: - Helpers

    private static func isStagingPath(_ commandLower: String) -> Bool {
        guard !commandLower.isEmpty else { return false }
        if commandLower.contains("/.") { return true }
        return stagingPaths.contains { commandLower.contains($0) }
    }

    private static func usesScriptOrDownloader(_ command: String) -> Bool {
        let tokens = command.lowercased().split(whereSeparator: { $0 == " " || $0 == "/" }).map(String.init)
        return tokens.contains { scriptOrDownloader.contains($0) }
    }
}
