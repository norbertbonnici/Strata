import Foundation

/// Security 4625 = failed logon. Clustering 5+ failures targeting the same
/// account within a 10-minute window is a strong brute-force / password-spray
/// signal, even before you look at the source IP.
///
/// ATT&CK T1110 Brute Force. Kill-chain phase: Reconnaissance (treating early
/// credential probing as recon - if it eventually succeeds it becomes Initial
/// Access, which a separate 4624 analyzer can light up.)
public nonisolated struct FailedLogonAnalyzer: Analyzer {
    public let name = "Failed Logon Burst"
    public init() {}

    private static let window: TimeInterval = 600
    private static let threshold = 5

    public func analyze(context: AnalysisContext) -> [Finding] {
        let failures = context.events
            .filter { $0.eventID == 4625 }
            .sorted { $0.writtenAt < $1.writtenAt }
        guard !failures.isEmpty else { return [] }

        // Group by target account; within a group, slide a 10-minute window.
        let grouped = Dictionary(grouping: failures) { event in
            event.data("TargetUserName")?.lowercased() ?? "<unknown>"
        }

        var findings: [Finding] = []
        for (user, hits) in grouped where hits.count >= Self.threshold {
            var start = 0
            for end in 0..<hits.count {
                while hits[end].writtenAt.timeIntervalSince(hits[start].writtenAt) > Self.window {
                    start += 1
                }
                let burst = hits[start...end]
                if burst.count >= Self.threshold {
                    let sources = Set(burst.compactMap { $0.data("IpAddress") }
                        .filter { $0 != "-" && !$0.isEmpty })
                    let severity: Severity = burst.count >= 20 ? .high : .medium
                    findings.append(Finding(
                        title: "Failed-logon burst against \(user) (\(burst.count) in 10m)",
                        detail: makeDetail(user: user, burst: burst, sources: sources),
                        severity: severity,
                        phase: .reconnaissance,
                        technique: AttackTechnique(attackID: "T1110", name: "Brute Force"),
                        timestamp: burst.first?.writtenAt,
                        evidencePaths: Array(Set(burst.map { $0.sourceFile }))))
                    break // one finding per user is enough
                }
            }
        }
        return findings
    }

    private func makeDetail(user: String, burst: ArraySlice<EventLogRecord>,
                            sources: Set<String>) -> String {
        let first = burst.first?.writtenAt.formatted() ?? "?"
        let last  = burst.last?.writtenAt.formatted() ?? "?"
        let from = sources.isEmpty ? "unknown source(s)"
            : sources.sorted().prefix(3).joined(separator: ", ")
        return "\(burst.count) failed logon attempts targeting '\(user)' between \(first) and \(last), from \(from)."
    }
}
