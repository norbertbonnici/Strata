import Foundation

/// Detection over the macOS **software-install** history. Most installs are
/// benign, so this stays low-noise with two high-precision rules keyed on what
/// the install records actually expose:
///
///  - **Abnormal installer process** — a package whose recorded install process
///    is a scripting interpreter / network tool rather than the install daemons.
///    Standard installs record the daemon (installer / softwareupdated /
///    storedownloadd), so this is opportunistic-but-high-precision: its *absence*
///    does not prove an install wasn't script-driven (the daemon name is what the
///    receipt stores, not the invoking shell).
///  - **Suspicious package identity** — an installed package whose name / bundle
///    id matches a known offensive tool (T1588.002) or remote-access / RMM
///    product (T1219). RMM and dual-use tools are routinely shipped as `.pkg`, so
///    this is the higher-recall rule.
///
/// Note: the *origin* a package was staged/downloaded from is **not** recorded in
/// install history (`PackageFileName` is a bare basename, `InstallPrefixPath` is
/// the install *destination*) — that provenance lives in the quarantine store /
/// FSEvents, which have their own analyzers.
public nonisolated struct MacInstallAnalyzer: Analyzer {
    public let name = "macOS Installs"
    public init() {}

    /// Process basenames that are never a legitimate package installer.
    static let abnormalInstallers: Set<String> = [
        "bash", "zsh", "sh", "ksh", "python", "python3", "ruby", "perl",
        "osascript", "curl", "wget", "nc", "ncat", "node", "php",
    ]

    public func analyze(context: AnalysisContext) -> [Finding] {
        analyze(context.installHistory)
    }

    /// Pure entry point (unit-tested with fixtures).
    public func analyze(_ entries: [MacInstallEntry]) -> [Finding] {
        guard !entries.isEmpty else { return [] }
        var findings: [Finding] = []
        var seen = Set<String>()

        for e in entries {
            // Stable identity so two records for the same package (InstallHistory
            // + its receipt) dedupe, while distinct *unnamed* installs don't merge.
            let id = e.packageIdentifiers.first ?? e.displayName ?? ""
            let when = e.date.map { String(Int($0.timeIntervalSince1970)) } ?? ""
            let ident = id.isEmpty ? "\(when)|\(e.version ?? "")" : "\(id)|\(e.version ?? "")"
            let evidence = [(e.sourceFile as NSString).lastPathComponent]

            // Rule A — abnormal installer process.
            if let proc = e.processName?.lowercased() {
                let base = (proc as NSString).lastPathComponent
                if Self.abnormalInstallers.contains(base), seen.insert("A|\(ident)|\(base)").inserted {
                    findings.append(Finding(
                        title: "Package installed by a non-installer process: \(e.displayTitle)",
                        detail: "'\(e.displayTitle)'\(e.version.map { " \($0)" } ?? "") was installed by '\(base)', "
                            + "a scripting interpreter / network tool rather than the install daemons "
                            + "(installer / softwareupdated / storedownloadd) — i.e. a package was installed "
                            + "programmatically / out of band. Confirm the command that ran.",
                        severity: .high, phase: .installation,
                        technique: AttackTechnique(attackID: "T1059", name: "Command and Scripting Interpreter"),
                        timestamp: e.date, evidencePaths: evidence))
                }
            }

            // Rule B — suspicious package identity (name / bundle id / file basename).
            let hay = ([e.displayName] + e.packageIdentifiers + [(e.packageFile as NSString?)?.lastPathComponent])
                .compactMap { $0?.lowercased() }
            if let hit = PowerlogAnalyzer.offensiveTokens.first(where: { t in hay.contains { $0.contains(t) } }),
               seen.insert("O|\(ident)|\(hit)").inserted {
                findings.append(Finding(
                    title: "Offensive tool installed: \(e.displayTitle)",
                    detail: "The installed package '\(e.displayTitle)' matches a known offensive / dual-use "
                        + "tool name ('\(hit)'). Confirm why this was installed on the host.",
                    severity: .high, phase: .installation,
                    technique: AttackTechnique(attackID: "T1588.002", name: "Obtain Capabilities: Tool"),
                    timestamp: e.date, evidencePaths: evidence))
            } else if let hit = KnowledgeCAnalyzer.remoteAccessHints.first(where: { h in hay.contains { $0.contains(h) } }),
                      seen.insert("R|\(ident)|\(hit)").inserted {
                findings.append(Finding(
                    title: "Remote-access tool installed: \(e.displayTitle)",
                    detail: "The installed package '\(e.displayTitle)' is remote-control / RMM software "
                        + "('\(hit)'). Confirm whether this remote-access capability was expected.",
                    severity: .high, phase: .commandAndControl,
                    technique: AttackTechnique(attackID: "T1219", name: "Remote Access Software"),
                    timestamp: e.date, evidencePaths: evidence))
            }
        }
        return findings.sorted { ($0.timestamp ?? .distantPast) > ($1.timestamp ?? .distantPast) }
    }
}
