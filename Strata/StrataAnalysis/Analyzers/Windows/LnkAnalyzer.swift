import Foundation

/// Detection over parsed Windows shortcuts (`.lnk`).
///
/// Two high-signal patterns:
///  1. A shortcut that carries **command-line arguments**. Ordinary document
///     shortcuts have none, so any are notable; arguments containing an
///     interpreter / encoded blob / download verb are a classic phishing lure
///     (an innocent icon hiding `powershell -enc ...`).
///  2. A shortcut whose **target** lives in an attacker-staging directory
///     (Temp, Recycle Bin, Public, Downloads) - file-access evidence from a
///     location a normal document wouldn't sit in.
///
/// Kill-chain phase: Exploitation (the lure executes; ordinary access shortcuts
/// stay lower severity). Low-noise: only shortcuts matching one of the patterns
/// produce a finding.
public nonisolated struct LnkAnalyzer: Analyzer {
    public let name = "Shortcut (LNK)"
    public init() {}

    /// Lowercased substrings in arguments that escalate to high severity.
    private static let suspiciousArgTokens = [
        "powershell", "pwsh", "-enc", "-e ", "-ec ", "iex", "invoke-expression",
        "frombase64string", "downloadstring", "downloadfile", "http://", "https://",
        "cmd /c", "cmd.exe", "/c ", "rundll32", "mshta", "regsvr32", "certutil",
        "bitsadmin", "wscript", "cscript", "-w hidden", "-windowstyle hidden",
        "-nop", "-noprofile", "bypass", "\\temp\\", "%temp%", "vbscript:",
    ]
    private static let highRiskTargetFragments = [
        #"\temp\"#, #"\$recycle.bin\"#, #"\users\public\"#, #"\perflogs\"#,
    ]
    private static let mediumRiskTargetFragments = [
        #"\downloads\"#, #"\appdata\local\temp\"#, #"\programdata\"#,
    ]

    public func analyze(context: AnalysisContext) -> [Finding] {
        context.lnk.compactMap { entry -> Finding? in
            // Rule 1: shortcut with command-line arguments.
            if let args = entry.arguments, !args.isEmpty {
                let lower = args.lowercased()
                let suspicious = Self.suspiciousArgTokens.contains { lower.contains($0) }
                var detail = "Target: \(entry.targetPath ?? "(none)")\nArguments: \(args)"
                if let machine = entry.machineIdentifier { detail += "\nCreated on host: \(machine)" }
                detail += "\nShortcut: \(entry.sourceFile)"
                detail += suspicious
                    ? "\nArguments contain interpreter / download / encoding tokens - classic malicious-LNK lure."
                    : "\nDocument shortcuts don't normally carry arguments - review."
                return Finding(
                    title: "Shortcut with command-line arguments: \(entry.name)",
                    detail: detail,
                    severity: suspicious ? .high : .medium,
                    phase: .exploitation,
                    technique: AttackTechnique(attackID: "T1204.002", name: "User Execution: Malicious File"),
                    timestamp: entry.targetModified ?? entry.targetAccessed,
                    evidencePaths: [entry.sourceFile] + (entry.targetPath.map { [$0] } ?? []))
            }

            // Rule 2: shortcut target in a suspicious location.
            if let target = entry.targetPath?.lowercased() {
                let severity: Severity
                if Self.highRiskTargetFragments.contains(where: { target.contains($0) }) {
                    severity = .high
                } else if Self.mediumRiskTargetFragments.contains(where: { target.contains($0) }) {
                    severity = .medium
                } else {
                    return nil
                }
                return Finding(
                    title: "Shortcut to suspicious path: \(entry.name)",
                    detail: "Target: \(entry.targetPath ?? "")\nShortcut: \(entry.sourceFile)\nFile-access evidence from a location attackers use to stage payloads.",
                    severity: severity,
                    phase: .exploitation,
                    technique: AttackTechnique(attackID: "T1204.002", name: "User Execution: Malicious File"),
                    timestamp: entry.targetModified ?? entry.targetAccessed,
                    evidencePaths: [entry.sourceFile, entry.targetPath ?? ""])
            }

            return nil
        }
    }
}
