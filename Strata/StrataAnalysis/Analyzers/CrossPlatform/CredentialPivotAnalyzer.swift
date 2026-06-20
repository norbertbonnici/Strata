import Foundation

/// Pairs a failed-logon burst against an account with a subsequent successful
/// remote logon for the same account - evidence that guessed / sprayed
/// credentials were then used to pivot. Required signals:
///   - >= 5 Security 4625 failures against TargetUserName U within 1h (the
///     "guessing" phase), and
///   - a Security 4624 success for U with remote LogonType (3 or 10) within
///     24h after that burst, ideally from the same source IP / workstation.
///
/// When the source matches the burst, severity is critical (the same
/// attacker IP that was guessing is now inside). When only the account
/// matches, severity is high - could be the legitimate user retrying.
///
/// ATT&CK T1078 Valid Accounts + T1021 Remote Services.
/// Kill-chain phase: Actions on Objectives.
public nonisolated struct CredentialPivotAnalyzer: Analyzer {
    public let name = "Credential Compromise & Lateral Pivot"
    public init() {}

    private static let burstWindow: TimeInterval = 3600
    private static let pivotWindow: TimeInterval = 24 * 3600
    private static let burstMin = 5
    private static let remoteLogonTypes: Set<String> = ["3", "10"]

    public func analyze(context: AnalysisContext) -> [Finding] {
        let failures = context.events
            .filter { $0.eventID == 4625 }
            .sorted { $0.writtenAt < $1.writtenAt }
        let successes = context.events
            .filter { $0.eventID == 4624 }
            .filter { Self.remoteLogonTypes.contains($0.data("LogonType") ?? "") }
            .sorted { $0.writtenAt < $1.writtenAt }
        guard !failures.isEmpty, !successes.isEmpty else { return [] }

        let failuresByUser = Dictionary(grouping: failures) {
            ($0.data("TargetUserName") ?? "").lowercased()
        }
        let successesByUser = Dictionary(grouping: successes) {
            ($0.data("TargetUserName") ?? "").lowercased()
        }

        var findings: [Finding] = []
        for (user, fails) in failuresByUser
        where !user.isEmpty && fails.count >= Self.burstMin
        {
            guard let burst = firstBurst(in: fails),
                  let pivots = successesByUser[user] else { continue }

            let burstSources = Set(burst.compactMap { source(for: $0) }
                                        .filter { !$0.isEmpty })
            let burstStart = burst.first!.writtenAt
            let burstEnd   = burst.last!.writtenAt
            guard let success = pivots.first(where: { event in
                let dt = event.writtenAt.timeIntervalSince(burstEnd)
                return dt >= 0 && dt <= Self.pivotWindow
            }) else { continue }
            let successSource = source(for: success)
            let sameSource = !successSource.isEmpty && burstSources.contains(successSource)

            let title = sameSource
                ? "Account \(user) likely compromised: \(burst.count) failures then success from \(successSource)"
                : "Account \(user): burst failures, then remote logon (different source)"
            findings.append(Finding(
                title: title,
                detail: """
                Failures: \(burst.count) failed logons for '\(user)' between \(burstStart.formatted()) and \(burstEnd.formatted()) \
                from \(burstSources.sorted().prefix(3).joined(separator: ", ")).
                Pivot: 4624 type \(success.data("LogonType") ?? "?") at \(success.writtenAt.formatted()) on \(success.computer) \
                from \(successSource.isEmpty ? "(unknown)" : successSource).
                Source match: \(sameSource ? "YES (same IP / workstation)" : "no").
                """,
                severity: sameSource ? .critical : .high,
                phase: .actionsOnObjectives,
                technique: AttackTechnique(attackID: "T1078",
                                            name: "Valid Accounts"),
                timestamp: success.writtenAt,
                evidencePaths: Array(Set(burst.map { $0.sourceFile } + [success.sourceFile]))))
        }
        return findings
    }

    private func firstBurst(in hits: [EventLogRecord]) -> [EventLogRecord]? {
        var start = 0
        for end in 0..<hits.count {
            while hits[end].writtenAt.timeIntervalSince(hits[start].writtenAt) > Self.burstWindow {
                start += 1
            }
            if end - start + 1 >= Self.burstMin {
                return Array(hits[start...end])
            }
        }
        return nil
    }

    private func source(for event: EventLogRecord) -> String {
        let ip = (event.data("IpAddress") ?? "").trimmingCharacters(in: .whitespaces)
        if !ip.isEmpty, ip != "-", ip != "::1", ip != "127.0.0.1" { return ip }
        let ws = (event.data("WorkstationName") ?? "").trimmingCharacters(in: .whitespaces)
        if !ws.isEmpty, ws != "-" { return ws }
        return ""
    }
}
