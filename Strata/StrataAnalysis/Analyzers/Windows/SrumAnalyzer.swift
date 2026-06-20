import Foundation

/// Detection over the Windows SRUM database (`SRUDB.dat`).
///
/// SRUM's distinct triage value over Prefetch/Amcache is that it ties an
/// application (by full path) to **network byte volume** and to execution, in
/// time buckets, surviving independently of the other execution artifacts. Kept
/// low-noise by gating on user-writable staging locations and aggregating per
/// application (one finding per binary, not one per hourly bucket):
///  1. **Execution from a suspicious path** (Application Resource Usage) — a
///     binary that ran from Temp / Public / Recycle Bin / PerfLogs / Downloads.
///  2. **Outbound network volume from a suspicious-path app** (Network Data
///     Usage) — an executable in a staging location with bytes sent, a C2 /
///     exfiltration lead (SRUM gives volume, not destination).
public nonisolated struct SrumAnalyzer: Analyzer {
    public let name = "SRUM Activity"
    public init() {}

    /// Lowercased path fragments that shouldn't normally host an executable.
    /// Mirrors PrefetchAnalyzer so the two execution artifacts agree.
    private static let highRiskFragments = [
        #"\temp\"#, #"\$recycle.bin\"#, #"\users\public\"#, #"\perflogs\"#,
    ]
    private static let mediumRiskFragments = [#"\downloads\"#]

    /// Above this aggregate outbound volume a suspicious-path egress is .high.
    private static let highEgressBytes: Int64 = 10 * 1024 * 1024   // 10 MB

    public func analyze(context: AnalysisContext) -> [Finding] {
        guard !context.srum.isEmpty else { return [] }
        var findings: [Finding] = []
        findings += executionFindings(context.srum)
        findings += egressFindings(context.srum)
        return findings
    }

    // MARK: - Rule 1: execution from a suspicious path

    private struct ExecAgg { var count = 0; var last: Date?; var path = ""; var source = "" }

    private func executionFindings(_ srum: [SrumEntry]) -> [Finding] {
        var byApp: [String: ExecAgg] = [:]
        for e in srum where e.kind == .appResourceUsage {
            guard let path = e.application, !path.isEmpty else { continue }
            var agg = byApp[path.lowercased()] ?? ExecAgg()
            agg.count += 1
            agg.path = path
            agg.source = e.sourceFile
            if let t = e.timestamp, t > (agg.last ?? .distantPast) { agg.last = t }
            byApp[path.lowercased()] = agg
        }
        return byApp.compactMap { (lower, agg) in
            let severity: Severity
            let fragment: String
            if let f = Self.highRiskFragments.first(where: { lower.contains($0) }) {
                severity = .high; fragment = f
            } else if let f = Self.mediumRiskFragments.first(where: { lower.contains($0) }) {
                severity = .medium; fragment = f
            } else {
                return nil
            }
            return Finding(
                title: "SRUM execution from suspicious path: \(Self.leaf(agg.path))",
                detail: "\(agg.path)\nSeen in \(agg.count) SRUM resource-usage bucket\(agg.count == 1 ? "" : "s")"
                    + (agg.last.map { "; last \($0.ISO8601Format())" } ?? "") + "."
                    + "\nRan from \(fragment.replacingOccurrences(of: "\\", with: "/")) - a location commonly used to stage dropped payloads.",
                severity: severity,
                phase: .exploitation,
                technique: AttackTechnique(attackID: "T1204.002", name: "User Execution: Malicious File"),
                timestamp: agg.last,
                evidencePaths: [agg.path, agg.source].filter { !$0.isEmpty })
        }
    }

    // MARK: - Rule 2: outbound network volume from a suspicious-path app

    private struct NetAgg { var sent: Int64 = 0; var received: Int64 = 0; var last: Date?; var path = ""; var source = "" }

    private func egressFindings(_ srum: [SrumEntry]) -> [Finding] {
        var byApp: [String: NetAgg] = [:]
        for e in srum where e.kind == .networkData {
            guard let path = e.application, !path.isEmpty else { continue }
            var agg = byApp[path.lowercased()] ?? NetAgg()
            agg.sent += e.bytesSent ?? 0
            agg.received += e.bytesReceived ?? 0
            agg.path = path
            agg.source = e.sourceFile
            if let t = e.timestamp, t > (agg.last ?? .distantPast) { agg.last = t }
            byApp[path.lowercased()] = agg
        }
        return byApp.compactMap { (lower, agg) in
            guard agg.sent > 0 else { return nil }
            let suspicious = Self.highRiskFragments.contains { lower.contains($0) }
                || Self.mediumRiskFragments.contains { lower.contains($0) }
            guard suspicious else { return nil }
            let severity: Severity = agg.sent >= Self.highEgressBytes ? .high : .medium
            return Finding(
                title: "SRUM network egress from suspicious path: \(Self.leaf(agg.path))",
                detail: "\(agg.path)\nSent \(SrumEntry.humanBytes(agg.sent)), received \(SrumEntry.humanBytes(agg.received)) (SRUM totals)"
                    + (agg.last.map { "; last \($0.ISO8601Format())" } ?? "") + "."
                    + "\nAn executable in a staging location with outbound network traffic - a possible C2 or exfiltration channel (SRUM records volume, not destination).",
                severity: severity,
                phase: .actionsOnObjectives,
                technique: AttackTechnique(attackID: "T1048", name: "Exfiltration Over Alternative Protocol"),
                timestamp: agg.last,
                evidencePaths: [agg.path, agg.source].filter { !$0.isEmpty })
        }
    }

    private static func leaf(_ path: String) -> String {
        let parts = path.split(whereSeparator: { $0 == "\\" || $0 == "/" })
        return parts.last.map(String.init) ?? path
    }
}
