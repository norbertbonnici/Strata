import Foundation

/// Detection over macOS **unified-log** entries. The unified log is the richest
/// single macOS telemetry source, but also the highest-volume — so this runs a
/// few **high-precision** checks rather than broad keyword sweeps: privilege
/// escalation via `sudo`, AppleScript/`osascript` execution, and remote SSH
/// logins. Keys off the resolved process name + message text (subsystem
/// attribution is a later refinement).
public nonisolated struct UnifiedLogAnalyzer: Analyzer {
    public let name = "Unified Log"
    public init() {}

    public func analyze(context: AnalysisContext) -> [Finding] {
        guard !context.unifiedLog.isEmpty else { return [] }
        var findings: [Finding] = []

        // Aggregate sudo command invocations rather than one finding per line.
        var sudoCommands = Set<String>()
        var sudoSample = ""
        var sudoLast: Date?
        var osascriptSeen = false
        var osascriptSample = ""
        var osascriptLast: Date?

        for entry in context.unifiedLog {
            let proc = (entry.process ?? "").lowercased()
            let msg = entry.message

            // sudo: "<user> : TTY=… ; … ; COMMAND=/path".
            if proc == "sudo", let range = msg.range(of: "COMMAND=") {
                let cmd = String(msg[range.upperBound...]).trimmingCharacters(in: .whitespaces)
                if !cmd.isEmpty { sudoCommands.insert(cmd) }
                if sudoSample.isEmpty { sudoSample = msg }
                if let t = entry.timestamp, sudoLast == nil || t > sudoLast! { sudoLast = t }
            }

            // osascript / AppleScript execution — a common macOS LOLBin for
            // phishing payloads and persistence.
            if proc == "osascript" || msg.lowercased().contains("osascript") {
                osascriptSeen = true
                if osascriptSample.isEmpty { osascriptSample = msg.isEmpty ? "osascript executed" : msg }
                if let t = entry.timestamp, osascriptLast == nil || t > osascriptLast! { osascriptLast = t }
            }

            // Remote SSH login accepted.
            if proc == "sshd", msg.hasPrefix("Accepted ") {
                findings.append(Finding(
                    title: "SSH login accepted (unified log)",
                    detail: msg, severity: .medium, phase: .exploitation,
                    technique: AttackTechnique(attackID: "T1021.004", name: "Remote Services: SSH"),
                    timestamp: entry.timestamp, evidencePaths: [entry.sourceFile]))
            }
        }

        if !sudoCommands.isEmpty {
            findings.append(Finding(
                title: "sudo privilege escalation — \(sudoCommands.count) command(s)",
                detail: "Commands run via sudo include: "
                    + sudoCommands.sorted().prefix(8).joined(separator: ", ")
                    + (sudoCommands.count > 8 ? " …" : "") + "\n\nExample: \(sudoSample)",
                severity: .medium, phase: .exploitation,
                technique: AttackTechnique(attackID: "T1548.003",
                                           name: "Abuse Elevation Control Mechanism: Sudo and Sudo Caching"),
                timestamp: sudoLast, evidencePaths: ["unified log"]))
        }
        if osascriptSeen {
            findings.append(Finding(
                title: "AppleScript / osascript execution",
                detail: osascriptSample, severity: .medium, phase: .exploitation,
                technique: AttackTechnique(attackID: "T1059.002",
                                           name: "Command and Scripting Interpreter: AppleScript"),
                timestamp: osascriptLast, evidencePaths: ["unified log"]))
        }
        return findings
    }
}
