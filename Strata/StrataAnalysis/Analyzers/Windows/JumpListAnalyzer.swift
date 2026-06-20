import Foundation

/// Detection over parsed JumpLists.
///
/// Two rules:
///  1. A destination whose target lives in an attacker-staging directory (Temp,
///     Recycle Bin, Public, Downloads) - file-access evidence with a real
///     last-opened time from the DestList.
///  2. An entry in the **Remote Desktop (`mstsc`) jumplist** - each is a host the
///     user RDP'd to, which directly attributes **lateral movement** to specific
///     remote machines (with the access timestamp).
///
/// Low-noise: only matching entries produce findings.
public nonisolated struct JumpListAnalyzer: Analyzer {
    public let name = "JumpList"
    public init() {}

    private static let highRiskFragments = [
        #"\temp\"#, #"\$recycle.bin\"#, #"\users\public\"#, #"\perflogs\"#,
    ]
    private static let mediumRiskFragments = [
        #"\downloads\"#, #"\appdata\local\temp\"#, #"\programdata\"#,
    ]

    public func analyze(context: AnalysisContext) -> [Finding] {
        context.jumpList.compactMap { entry -> Finding? in
            // Rule 2: Remote Desktop jumplist == lateral-movement destination.
            if entry.appID.caseInsensitiveCompare(JumpListAppID.remoteDesktop) == .orderedSame,
               let target = entry.targetPath, !target.isEmpty {
                var detail = "RDP destination: \(target)"
                if let host = entry.hostname { detail += "\nRecorded on host: \(host)" }
                if let when = entry.lastAccessed { detail += "\nLast connected: \(when.ISO8601Format())" }
                detail += "\nFrom the Remote Desktop (mstsc) jumplist - evidence this host connected out to the destination."
                return Finding(
                    title: "RDP destination (JumpList): \(target)",
                    detail: detail,
                    severity: .medium,
                    phase: .actionsOnObjectives,
                    technique: AttackTechnique(attackID: "T1021.001", name: "Remote Services: Remote Desktop Protocol"),
                    timestamp: entry.lastAccessed,
                    evidencePaths: [entry.sourceFile, target])
            }

            // Rule 1: target in a suspicious location.
            guard let target = entry.targetPath?.lowercased() else { return nil }
            let severity: Severity
            if Self.highRiskFragments.contains(where: { target.contains($0) }) {
                severity = .high
            } else if Self.mediumRiskFragments.contains(where: { target.contains($0) }) {
                severity = .medium
            } else {
                return nil
            }
            var detail = "Target: \(entry.targetPath ?? "")"
            if let app = entry.application { detail += "\nApplication: \(app)" }
            if let when = entry.lastAccessed { detail += "\nLast opened: \(when.ISO8601Format())" }
            detail += "\nFile-access evidence from a JumpList (\(entry.listType == .automatic ? "automatic" : "custom")) for a location attackers use to stage payloads."
            return Finding(
                title: "JumpList target in suspicious path: \(entry.name)",
                detail: detail,
                severity: severity,
                phase: .exploitation,
                technique: AttackTechnique(attackID: "T1204.002", name: "User Execution: Malicious File"),
                timestamp: entry.lastAccessed,
                evidencePaths: [entry.sourceFile, entry.targetPath ?? ""])
        }
    }
}
