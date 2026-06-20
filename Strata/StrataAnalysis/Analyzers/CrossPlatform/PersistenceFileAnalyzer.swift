import Foundation

/// File-system-only persistence detection. Anything dropped into the Startup
/// folders or the Scheduled Tasks directory is, by definition, "this will
/// execute on boot / logon" - the registry Run keys are a separate detection
/// (registry parsing is phase-3). We surface non-Microsoft executables and
/// scripts and trust the user to triage from there.
///
/// ATT&CK T1547.001 Boot or Logon Autostart: Registry Run Keys / Startup
/// Folder (for Startup) and T1053.005 Scheduled Task (for Tasks).
/// Kill-chain phase: Installation.
public nonisolated struct PersistenceFileAnalyzer: Analyzer {
    public let name = "File Persistence"
    public init() {}

    /// Lowercased path fragments that indicate auto-start locations. We match
    /// substrings rather than full paths so per-user variants ("\Users\X\")
    /// match the same rule.
    private static let startupFragments = [
        "/programdata/microsoft/windows/start menu/programs/startup/",
        "/appdata/roaming/microsoft/windows/start menu/programs/startup/",
    ]
    private static let taskFragments = [
        "/windows/system32/tasks/",
        "/windows/syswow64/tasks/",
    ]
    /// Extensions worth surfacing inside Startup. The Tasks folder is XML and
    /// every entry is interesting, so this list only filters Startup.
    private static let startupExtensions: Set<String> = [
        "exe", "dll", "ps1", "vbs", "vbe", "js", "jse", "wsf", "bat", "cmd",
        "hta", "lnk", "scr",
    ]

    public func analyze(context: AnalysisContext) -> [Finding] {
        context.files.compactMap { entry -> Finding? in
            guard !entry.isDirectory, !entry.isDeleted, entry.size > 0 else { return nil }
            let path = entry.fullPath.lowercased()

            if Self.startupFragments.contains(where: { path.contains($0) }),
               Self.startupExtensions.contains(entry.fileExtension) {
                return Finding(
                    title: "Startup-folder item: \(entry.name)",
                    detail: "\(entry.fullPath)\nSize: \(entry.size) bytes. Anything in a Startup folder runs at user logon - confirm provenance.",
                    severity: .medium,
                    phase: .installation,
                    technique: AttackTechnique(attackID: "T1547.001",
                                                name: "Registry Run Keys / Startup Folder"),
                    timestamp: entry.modified ?? entry.created,
                    evidencePaths: [entry.fullPath])
            }

            if Self.taskFragments.contains(where: { path.contains($0) }) {
                // Scheduled tasks live as XML files in System32\Tasks. Every
                // file is a scheduled task definition; severity stays medium
                // because most are legitimate Microsoft-provided ones.
                return Finding(
                    title: "Scheduled task definition: \(entry.name)",
                    detail: "\(entry.fullPath)\nSize: \(entry.size) bytes. Inspect the XML for the action / trigger / principal to assess.",
                    severity: .info,
                    phase: .installation,
                    technique: AttackTechnique(attackID: "T1053.005",
                                                name: "Scheduled Task/Job: Scheduled Task"),
                    timestamp: entry.modified ?? entry.created,
                    evidencePaths: [entry.fullPath])
            }

            return nil
        }
    }
}
