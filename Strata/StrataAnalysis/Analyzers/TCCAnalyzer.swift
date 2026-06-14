import Foundation

/// Detection over the macOS **TCC** privacy database. A grant of a high-impact
/// capability — Accessibility (keystroke injection / UI control), Screen
/// Recording, Input Monitoring, Full Disk Access, Camera/Microphone, Automation
/// — to a **non-Apple** client is a strong signal: it's how stalkerware,
/// info-stealers, and RMM/backdoor tooling persist their reach. Apple-signed
/// system clients are expected to hold these and are not flagged.
public nonisolated struct TCCAnalyzer: Analyzer {
    public let name = "TCC Privacy"
    public init() {}

    public func analyze(context: AnalysisContext) -> [Finding] {
        guard !context.tcc.isEmpty else { return [] }
        var findings: [Finding] = []
        var seen = Set<String>()

        for grant in context.tcc {
            guard grant.isSensitive, grant.authValue == .allowed,
                  !Self.isAppleClient(grant) else { continue }
            let key = "\(grant.service)|\(grant.client)|\(grant.scope)"
            guard seen.insert(key).inserted else { continue }

            let (technique, phase) = Self.attack(for: grant.service)
            findings.append(Finding(
                title: "\(grant.serviceLabel) granted to non-Apple app: \(grant.clientLabel)",
                detail: "TCC (\(grant.scope)) authorised \(grant.serviceLabel) for "
                    + "\(grant.client). This capability can be abused for surveillance or "
                    + "control; verify the application is expected.",
                severity: .high, phase: phase, technique: technique,
                timestamp: grant.lastModified, evidencePaths: [grant.sourceFile]))
        }
        return findings
    }

    /// Apple-signed system clients legitimately hold these grants.
    static func isAppleClient(_ g: TCCAccess) -> Bool {
        if g.clientType == 0 { return g.client.hasPrefix("com.apple.") }
        let p = g.client.lowercased()
        return p.hasPrefix("/system/") || p.hasPrefix("/usr/libexec/")
            || p.hasPrefix("/usr/sbin/") || p.hasPrefix("/usr/bin/")
    }

    static func attack(for service: String) -> (AttackTechnique, KillChainPhase) {
        switch service {
        case "kTCCServiceScreenCapture":
            return (AttackTechnique(attackID: "T1113", name: "Screen Capture"), .actionsOnObjectives)
        case "kTCCServiceCamera":
            return (AttackTechnique(attackID: "T1125", name: "Video Capture"), .actionsOnObjectives)
        case "kTCCServiceMicrophone":
            return (AttackTechnique(attackID: "T1123", name: "Audio Capture"), .actionsOnObjectives)
        case "kTCCServiceAccessibility", "kTCCServicePostEvent", "kTCCServiceListenEvent":
            return (AttackTechnique(attackID: "T1056.001", name: "Input Capture: Keylogging"), .actionsOnObjectives)
        case "kTCCServiceSystemPolicyAllFiles", "kTCCServiceSystemPolicySysAdminFiles":
            return (AttackTechnique(attackID: "T1005", name: "Data from Local System"), .actionsOnObjectives)
        case "kTCCServiceAppleEvents":
            return (AttackTechnique(attackID: "T1059.002", name: "Command and Scripting Interpreter: AppleScript"), .exploitation)
        default:
            return (AttackTechnique(attackID: "T1548", name: "Abuse Elevation Control Mechanism"), .exploitation)
        }
    }
}
