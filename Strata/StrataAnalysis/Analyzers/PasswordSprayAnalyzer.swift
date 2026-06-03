import Foundation

/// Password spray (the inverse of brute force): one password tried against
/// many accounts from a single source, designed to stay under per-account
/// lockout thresholds. We cluster Security 4625 failures by source IP /
/// WorkstationName and flag when one source hit >= 10 distinct accounts
/// within an hour with an average of <= 3 attempts per account.
///
/// Sibling to FailedLogonAnalyzer (T1110.001) which handles the inverse
/// pattern (many attempts against one account).
///
/// ATT&CK T1110.003 Brute Force: Password Spraying.
/// Kill-chain phase: Reconnaissance.
public nonisolated struct PasswordSprayAnalyzer: Analyzer {
    public let name = "Password Spray"
    public init() {}

    private static let window: TimeInterval = 3600
    private static let minDistinctAccounts = 10
    private static let maxAttemptsPerAccount = 3

    public func analyze(context: AnalysisContext) -> [Finding] {
        let failures = context.events
            .filter { $0.eventID == 4625 }
            .sorted { $0.writtenAt < $1.writtenAt }
        guard failures.count >= Self.minDistinctAccounts else { return [] }

        let grouped = Dictionary(grouping: failures) { source(for: $0) }
        var findings: [Finding] = []
        for (src, hits) in grouped
        where src != "<unknown>" && hits.count >= Self.minDistinctAccounts
        {
            guard let burst = firstSprayWindow(in: hits) else { continue }
            let users = Set(burst.compactMap { $0.data("TargetUserName")?.lowercased() })
            let perUser = Double(burst.count) / Double(max(1, users.count))
            let sample = users.sorted().prefix(8).joined(separator: ", ")
            findings.append(Finding(
                title: "Password spray from \(src): \(users.count) accounts, \(burst.count) attempts",
                detail: """
                Single source \(src) failed against \(users.count) distinct accounts within \(Int(Self.window/60))m \
                (avg \(String(format: "%.1f", perUser)) attempts/account).
                Window: \(burst.first!.writtenAt.formatted()) -> \(burst.last!.writtenAt.formatted()).
                Sample targets: \(sample)\(users.count > 8 ? ", ..." : "")
                """,
                severity: users.count >= 25 ? .high : .medium,
                phase: .reconnaissance,
                technique: AttackTechnique(attackID: "T1110.003",
                                            name: "Brute Force: Password Spraying"),
                timestamp: burst.first?.writtenAt,
                evidencePaths: Array(Set(burst.map { $0.sourceFile }))))
        }
        return findings
    }

    /// Slide a 60-minute window over per-source failures; return the first
    /// slice that meets distinct-accounts + low-per-user thresholds.
    private func firstSprayWindow(in hits: [EventLogRecord]) -> [EventLogRecord]? {
        var start = 0
        for end in 0..<hits.count {
            while hits[end].writtenAt.timeIntervalSince(hits[start].writtenAt) > Self.window {
                start += 1
            }
            let slice = Array(hits[start...end])
            let users = Set(slice.compactMap { $0.data("TargetUserName")?.lowercased() })
            let perUser = Double(slice.count) / Double(max(1, users.count))
            if users.count >= Self.minDistinctAccounts,
               perUser <= Double(Self.maxAttemptsPerAccount) {
                return slice
            }
        }
        return nil
    }

    private func source(for event: EventLogRecord) -> String {
        let ip = (event.data("IpAddress") ?? "").trimmingCharacters(in: .whitespaces)
        if !ip.isEmpty, ip != "-", ip != "::1", ip != "127.0.0.1" { return ip }
        let ws = (event.data("WorkstationName") ?? "").trimmingCharacters(in: .whitespaces)
        if !ws.isEmpty, ws != "-" { return ws }
        return "<unknown>"
    }
}
