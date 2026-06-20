import Foundation

/// Presence detection over the AppCompatCache (Shimcache).
///
/// Shimcache proves a file's path was **known to the application-compatibility
/// subsystem** — i.e. it was present on the host — NOT that it executed (there
/// is no reliable execution flag, and none at all on Win10/11). So this analyzer
/// surfaces cached paths in attacker-staging locations and the wording always
/// says "present in AppCompatCache", never "ran". Corroborate with Prefetch /
/// Amcache / event logs for execution.
///
/// AppCompatCache holds up to ~1024 mostly-benign system paths, so this is
/// gated on suspicious directories to stay low-noise (one finding per hit, not
/// per entry). Kill-chain phase: Installation.
public nonisolated struct ShimcacheAnalyzer: Analyzer {
    public let name = "Shimcache Presence"
    public init() {}

    private static let highRiskFragments = [
        #"\temp\"#, #"\$recycle.bin\"#, #"\users\public\"#, #"\perflogs\"#, #"\programdata\"#,
    ]
    private static let mediumRiskFragments = [
        #"\downloads\"#, #"\appdata\roaming\"#,
    ]

    public func analyze(context: AnalysisContext) -> [Finding] {
        context.shimcache.compactMap { entry -> Finding? in
            let path = entry.path.lowercased()
            let severity: Severity
            if Self.highRiskFragments.contains(where: { path.contains($0) }) {
                severity = .high
            } else if Self.mediumRiskFragments.contains(where: { path.contains($0) }) {
                severity = .medium
            } else {
                return nil
            }
            var detail = entry.path
            detail += "\nAppCompatCache position: \(entry.insertionOrder) (0 = most recent)"
            if let modified = entry.lastModified {
                detail += "\nFile modified (at cache time): \(modified.ISO8601Format())"
            }
            detail += "\nPresent in AppCompatCache - proves the file was known to the system, NOT that it executed."
            return Finding(
                title: "Suspicious path present (Shimcache): \(entry.name)",
                detail: detail,
                severity: severity,
                phase: .installation,
                technique: AttackTechnique(attackID: "T1204.002", name: "User Execution: Malicious File"),
                timestamp: entry.lastModified,
                evidencePaths: [entry.path])
        }
    }
}
