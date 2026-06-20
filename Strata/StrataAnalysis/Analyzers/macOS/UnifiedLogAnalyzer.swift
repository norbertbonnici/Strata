import Foundation

/// Detection over macOS **unified-log** entries. The unified log is the richest
/// single macOS telemetry source, but also the highest-volume — so this runs a
/// set of **high-precision** checks rather than broad keyword sweeps. Keys off
/// the resolved process name + message text (subsystem attribution is a later
/// refinement):
///
///  - **sudo** privilege escalation (T1548.003) and **osascript** / AppleScript
///    execution (T1059.002), aggregated.
///  - **SSH** logins accepted (T1021.004) and **failed**-password bursts that
///    look like brute forcing (T1110.001), aggregated per source.
///  - **Screen Sharing / VNC** authentication succeeded — a remote interactive
///    session (T1021.001).
///  - **Local account creation** via `sysadminctl` / `dscl` (T1136.001).
public nonisolated struct UnifiedLogAnalyzer: Analyzer {
    public let name = "Unified Log"
    public init() {}

    /// Failed SSH attempts at/above this count are treated as brute forcing.
    static let bruteForceThreshold = 5

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
        // SSH failed-login burst (brute force).
        var sshFailCount = 0
        var sshFailSample = ""
        var sshFailLast: Date?
        var sshFailSources = Set<String>()
        // Screen Sharing / VNC authentication.
        var screenShareSeen = false
        var screenShareSample = ""
        var screenShareLast: Date?
        // Local account creation.
        var accountCreations: [(message: String, date: Date?)] = []

        for entry in context.unifiedLog {
            let proc = (entry.process ?? "").lowercased()
            let msg = entry.message
            let lower = msg.lowercased()

            // sudo: "<user> : TTY=… ; … ; COMMAND=/path".
            if proc == "sudo", let range = msg.range(of: "COMMAND=") {
                let cmd = String(msg[range.upperBound...]).trimmingCharacters(in: .whitespaces)
                if !cmd.isEmpty { sudoCommands.insert(cmd) }
                if sudoSample.isEmpty { sudoSample = msg }
                if let t = entry.timestamp, sudoLast == nil || t > sudoLast! { sudoLast = t }
            }

            // osascript / AppleScript execution — a common macOS LOLBin for
            // phishing payloads and persistence.
            if proc == "osascript" || lower.contains("osascript") {
                osascriptSeen = true
                if osascriptSample.isEmpty { osascriptSample = msg.isEmpty ? "osascript executed" : msg }
                if let t = entry.timestamp, osascriptLast == nil || t > osascriptLast! { osascriptLast = t }
            }

            if proc == "sshd" {
                // Remote SSH login accepted.
                if msg.hasPrefix("Accepted ") {
                    findings.append(Finding(
                        title: "SSH login accepted (unified log)",
                        detail: msg, severity: .medium, phase: .exploitation,
                        technique: AttackTechnique(attackID: "T1021.004", name: "Remote Services: SSH"),
                        timestamp: entry.timestamp, evidencePaths: [entry.sourceFile]))
                }
                // Failed authentication — counted toward a brute-force burst.
                if msg.hasPrefix("Failed password") || msg.hasPrefix("Invalid user")
                    || lower.contains("authentication failure") || lower.contains("failed keyboard-interactive") {
                    sshFailCount += 1
                    if sshFailSample.isEmpty { sshFailSample = msg }
                    if let ip = Self.sourceIP(in: msg) { sshFailSources.insert(ip) }
                    if let t = entry.timestamp, sshFailLast == nil || t > sshFailLast! { sshFailLast = t }
                }
            }

            // Screen Sharing / VNC interactive session authenticated.
            if (proc == "screensharingd" || proc == "screensharingagent" || proc.contains("ardagent")),
               lower.contains("authentication") && (lower.contains("succeed") || lower.contains("success")) {
                screenShareSeen = true
                if screenShareSample.isEmpty { screenShareSample = msg.isEmpty ? "Screen Sharing authenticated" : msg }
                if let t = entry.timestamp, screenShareLast == nil || t > screenShareLast! { screenShareLast = t }
            }

            // Local account creation via the admin CLIs.
            if (proc == "sysadminctl" && (lower.contains("adduser") || lower.contains("-adduser")))
                || (proc == "dscl" && lower.contains("create") && msg.contains("/Users/"))
                || lower.contains("created user account") {
                accountCreations.append((msg.isEmpty ? "account created (\(proc))" : msg, entry.timestamp))
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
        if sshFailCount > 0 {
            let bruteForce = sshFailCount >= Self.bruteForceThreshold
            let sources = sshFailSources.isEmpty ? "" :
                "\nSource(s): " + sshFailSources.sorted().prefix(8).joined(separator: ", ")
            findings.append(Finding(
                title: bruteForce
                    ? "SSH brute-force burst — \(sshFailCount) failed logins"
                    : "SSH authentication failures — \(sshFailCount)",
                detail: "The unified log recorded \(sshFailCount) failed SSH authentication attempt(s)."
                    + sources + "\n\nExample: \(sshFailSample)"
                    + (bruteForce ? "\n\nA burst of failures is consistent with password guessing; "
                        + "check for a subsequent accepted login from the same source." : ""),
                severity: bruteForce ? .high : .medium, phase: .exploitation,
                technique: AttackTechnique(attackID: "T1110.001", name: "Brute Force: Password Guessing"),
                timestamp: sshFailLast, evidencePaths: ["unified log"]))
        }
        if screenShareSeen {
            findings.append(Finding(
                title: "Screen Sharing / VNC session authenticated",
                detail: screenShareSample
                    + "\n\nAn authenticated Screen Sharing / VNC session places a remote operator on the "
                    + "desktop; correlate with the login and network timelines.",
                severity: .high, phase: .exploitation,
                technique: AttackTechnique(attackID: "T1021.001", name: "Remote Services: Remote Desktop Protocol"),
                timestamp: screenShareLast, evidencePaths: ["unified log"]))
        }
        if !accountCreations.isEmpty {
            let last = accountCreations.compactMap(\.date).max()
            findings.append(Finding(
                title: "Local account created — \(accountCreations.count) event(s)",
                detail: "A local account was created via sysadminctl / dscl:\n"
                    + accountCreations.prefix(5).map { "• \($0.message)" }.joined(separator: "\n")
                    + "\n\nNew local accounts are a common persistence / privilege mechanism; "
                    + "confirm the account is authorised.",
                severity: .high, phase: .installation,
                technique: AttackTechnique(attackID: "T1136.001", name: "Create Account: Local Account"),
                timestamp: last, evidencePaths: ["unified log"]))
        }
        return findings
    }

    /// Pull the source IP out of an sshd message ("… from 10.0.0.5 port 22 …").
    static func sourceIP(in message: String) -> String? {
        guard let range = message.range(of: " from ") else { return nil }
        let after = message[range.upperBound...]
        let token = after.prefix { $0 != " " }
        return token.isEmpty ? nil : String(token)
    }
}
