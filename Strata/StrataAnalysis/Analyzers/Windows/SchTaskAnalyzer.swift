import Foundation

/// Security 4698 = a scheduled task was created. The payload includes the
/// task's full XML, so we can score by what the task actually *does*:
/// scripted / encoded commands and lolbins drive severity up, vanilla
/// `taskeng.exe`-style Microsoft entries stay low.
///
/// ATT&CK T1053.005 Scheduled Task/Job: Scheduled Task.
/// Kill-chain phase: Installation.
public nonisolated struct SchTaskAnalyzer: Analyzer {
    public let name = "Scheduled Task Created"
    public init() {}

    private static let suspiciousTokens = [
        "powershell", "-enc", "-encodedcommand", "frombase64string",
        "downloadstring", "iex ", "invoke-expression",
        "cmd.exe /c", "cmd /c", "rundll32", "regsvr32", "mshta", "wmic",
        "\\users\\", "\\appdata\\", "\\temp\\", "\\public\\", "\\programdata\\",
    ]

    public func analyze(context: AnalysisContext) -> [Finding] {
        context.events.compactMap { event -> Finding? in
            guard event.eventID == 4698 else { return nil }

            let taskName = event.data("TaskName") ?? "(unknown)"
            let taskXML  = event.data("TaskContent") ?? ""
            let actor    = event.data("SubjectUserName") ?? "unknown"
            let blob = (taskName + " " + taskXML).lowercased()
            let hits = Self.suspiciousTokens.filter { blob.contains($0) }

            let severity: Severity
            switch hits.count {
            case 0:    severity = .info       // vanilla Microsoft tasks - still log
            case 1:    severity = .medium
            case 2:    severity = .high
            default:   severity = .critical
            }

            var bullets: [String] = ["Task: \(taskName)", "Created by: \(actor)"]
            if !hits.isEmpty {
                bullets.append("Suspicious tokens: \(hits.joined(separator: ", "))")
            }
            return Finding(
                title: "Scheduled task created: \(taskName)",
                detail: bullets.joined(separator: "\n") + "\n\nObserved on \(event.computer) at \(event.writtenAt.formatted()).",
                severity: severity,
                phase: .installation,
                technique: AttackTechnique(attackID: "T1053.005",
                                            name: "Scheduled Task/Job: Scheduled Task"),
                timestamp: event.writtenAt,
                evidencePaths: [event.sourceFile])
        }
    }
}
