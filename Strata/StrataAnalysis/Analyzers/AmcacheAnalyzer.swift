import Foundation

/// Program-presence detection over reconstructed Amcache entries.
///
/// Amcache records that a binary was *present / registered* on the host (with
/// its path, size, PE link date, and a SHA-1) — it does NOT prove execution.
/// So this analyzer surfaces binaries Amcache saw in locations attackers favour
/// for staging payloads, and carries the recovered SHA-1 in the finding so the
/// analyst can pivot to hash lookups. All wording says "present", never "ran".
///
/// Kept low-volume by gating on suspicious paths (a normal host's Amcache lists
/// thousands of legitimate programs); kill-chain phase: Installation.
public nonisolated struct AmcacheAnalyzer: Analyzer {
    public let name = "Amcache Presence"
    public init() {}

    /// Lowercased path fragments that shouldn't normally host an executable.
    /// Amcache paths use backslashes and are already lowercased on modern builds.
    private static let highRiskFragments = [
        #"\temp\"#,           // \Windows\Temp, \AppData\Local\Temp, any \Temp\
        #"\$recycle.bin\"#,
        #"\users\public\"#,
        #"\perflogs\"#,
        #"\programdata\"#,
    ]
    private static let mediumRiskFragments = [
        #"\downloads\"#,
        #"\appdata\roaming\"#,
    ]

    public func analyze(context: AnalysisContext) -> [Finding] {
        context.amcache.compactMap { entry -> Finding? in
            guard let path = entry.fullPath?.lowercased() else { return nil }
            let severity: Severity
            if Self.highRiskFragments.contains(where: { path.contains($0) }) {
                severity = .high
            } else if Self.mediumRiskFragments.contains(where: { path.contains($0) }) {
                severity = .medium
            } else {
                return nil
            }
            var detail = entry.fullPath ?? entry.name
            if let sha1 = entry.sha1 { detail += "\nSHA-1: \(sha1)" }
            if let size = entry.size { detail += "\nSize: \(size) bytes" }
            if let registered = entry.registeredAt {
                detail += "\nRegistered in Amcache: \(registered.ISO8601Format())"
            }
            detail += "\nAmcache records presence/registration, not execution - corroborate with Prefetch / event logs."
            return Finding(
                title: "Suspicious binary present (Amcache): \(entry.name)",
                detail: detail,
                severity: severity,
                phase: .installation,
                technique: AttackTechnique(attackID: "T1204.002", name: "User Execution: Malicious File"),
                timestamp: entry.registeredAt,
                evidencePaths: [entry.fullPath ?? entry.name] + (entry.sha1.map { [$0] } ?? []))
        }
    }
}
