import Foundation

/// Security 4688 and Microsoft-Windows-Sysmon/Operational 1 both record
/// process creation; we normalise both into (image, parentImage, cmdline) and
/// flag well-known "this should never happen on a normal user's box" parent
/// -> child pairs - the canonical example being WINWORD.EXE spawning
/// PowerShell, the macro-borne RAT pattern.
///
/// ATT&CK T1059 Command and Scripting Interpreter; the parent-child
/// relationship is the actual signal.
/// Kill-chain phase: Exploitation.
public nonisolated struct ProcessCreationAnalyzer: Analyzer {
    public let name = "Anomalous Process Creation"
    public init() {}

    /// Image basenames (lowercased) that should never legitimately spawn a
    /// shell / scripting host / lolbin.
    private static let officeParents: Set<String> = [
        "winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe",
        "msaccess.exe", "visio.exe", "onenote.exe",
    ]
    private static let browserParents: Set<String> = [
        "chrome.exe", "msedge.exe", "firefox.exe", "iexplore.exe", "brave.exe",
    ]
    /// Children that are interesting when spawned by office / browsers.
    private static let suspiciousChildren: Set<String> = [
        "powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe",
        "mshta.exe", "rundll32.exe", "regsvr32.exe", "certutil.exe",
        "bitsadmin.exe", "installutil.exe", "msbuild.exe", "wmic.exe",
    ]

    public func analyze(context: AnalysisContext) -> [Finding] {
        context.events.compactMap { event -> Finding? in
            guard let row = extract(from: event) else { return nil }
            let parent = (row.parent as NSString).lastPathComponent.lowercased()
            let child  = (row.image  as NSString).lastPathComponent.lowercased()

            let isOfficeChild  = Self.officeParents.contains(parent)
                && Self.suspiciousChildren.contains(child)
            let isBrowserChild = Self.browserParents.contains(parent)
                && Self.suspiciousChildren.contains(child)
            guard isOfficeChild || isBrowserChild else { return nil }

            let severity: Severity = isOfficeChild ? .critical : .high
            let label = isOfficeChild ? "Office app" : "Browser"
            let cmdline = row.cmdline.isEmpty ? "" : "\nCommand line: \(row.cmdline)"
            return Finding(
                title: "\(label) spawned \(child): \(parent) -> \(child)",
                detail: "Process creation: \(row.parent) -> \(row.image).\(cmdline)\n\nObserved on \(event.computer) at \(event.writtenAt.formatted()). This parent-child pair is the canonical macro / drive-by execution pattern.",
                severity: severity,
                phase: .exploitation,
                technique: AttackTechnique(attackID: "T1059",
                                            name: "Command and Scripting Interpreter"),
                timestamp: event.writtenAt,
                evidencePaths: [event.sourceFile])
        }
    }

    private struct Row {
        let image: String
        let parent: String
        let cmdline: String
    }

    /// Normalise 4688 (NewProcessName / ParentProcessName) and Sysmon 1
    /// (Image / ParentImage) into one tuple. Sysmon's payload also gives us
    /// a richer CommandLine that 4688 may not.
    private func extract(from event: EventLogRecord) -> Row? {
        if event.eventID == 4688 {
            guard let image = event.data("NewProcessName"),
                  let parent = event.data("ParentProcessName")
            else { return nil }
            return Row(image: image, parent: parent,
                       cmdline: event.data("CommandLine") ?? event.data("ProcessCommandLine") ?? "")
        }
        if event.eventID == 1,
           event.channel.localizedCaseInsensitiveContains("Sysmon") {
            guard let image = event.data("Image"),
                  let parent = event.data("ParentImage")
            else { return nil }
            return Row(image: image, parent: parent,
                       cmdline: event.data("CommandLine") ?? "")
        }
        return nil
    }
}
