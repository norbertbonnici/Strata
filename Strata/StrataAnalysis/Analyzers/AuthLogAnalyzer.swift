import Foundation

/// Authentication-evidence detection over parsed Linux auth logs and btmp
/// failed-login records - the Linux counterpart of the failed-logon /
/// password-spray analyzers on the Windows side.
///
/// Rules:
///  1. **Brute force** - bursts of failed SSH logins per source IP (auth.log
///     `Failed password` / `Invalid user`, plus btmp records when the log has
///     rotated away). One aggregated finding per attacking IP.
///  2. **Login after repeated failures** - an accepted SSH login from an IP
///     that also produced a failure burst: the brute force likely *worked*.
///  3. **Root SSH login** - direct root logins are a triage flag on any
///     hardened host, and the standard post-compromise foothold.
///  4. **Account creation** - useradd/groupadd events from the auth log.
public nonisolated struct AuthLogAnalyzer: Analyzer {
    public let name = "Linux Auth Log"
    public init() {}

    /// Failures from one source needed to call it a brute-force burst.
    static let bruteForceThreshold = 10

    public func analyze(context: AnalysisContext) -> [Finding] {
        guard !context.authLog.isEmpty || !context.logins.isEmpty else { return [] }
        var findings: [Finding] = []

        // Failures per source IP: auth.log failed/invalid + btmp records.
        struct FailureAgg {
            var count = 0
            var users = Set<String>()
            var first: Date?
            var last: Date?
            var sources = Set<String>()
        }
        var failures: [String: FailureAgg] = [:]

        func recordFailure(ip: String, user: String?, date: Date?, source: String) {
            guard !ip.isEmpty else { return }
            var agg = failures[ip] ?? FailureAgg()
            agg.count += 1
            if let user, !user.isEmpty { agg.users.insert(user) }
            if let date {
                if agg.first == nil || date < agg.first! { agg.first = date }
                if agg.last == nil || date > agg.last! { agg.last = date }
            }
            agg.sources.insert(source)
            failures[ip] = agg
        }

        for entry in context.authLog
        where entry.kind == .sshFailed || entry.kind == .sshInvalidUser {
            recordFailure(ip: entry.sourceIP ?? "", user: entry.user,
                          date: entry.timestamp, source: entry.sourceFile)
        }
        for record in context.logins where record.isFailedLogin {
            recordFailure(ip: record.host, user: record.user,
                          date: record.timestamp, source: record.sourceFile)
        }

        // Accepted logins per IP (rule 2 join) + root logins (rule 3).
        var acceptedByIP: [String: [AuthLogEntry]] = [:]
        for entry in context.authLog where entry.kind == .sshAccepted {
            if let ip = entry.sourceIP { acceptedByIP[ip, default: []].append(entry) }
            if entry.user == "root" {
                findings.append(Finding(
                    title: "Direct root SSH login from \(entry.sourceIP ?? "unknown")",
                    detail: "sshd accepted a \(entry.method ?? "?") login for root"
                        + (entry.sourceIP.map { " from \($0)" } ?? "")
                        + ". Direct root logins are disabled on hardened hosts and are "
                        + "the standard post-compromise foothold.",
                    severity: entry.method == "password" ? .high : .medium,
                    phase: .exploitation,
                    technique: AttackTechnique(attackID: "T1021.004", name: "Remote Services: SSH"),
                    timestamp: entry.timestamp,
                    evidencePaths: [entry.sourceFile]))
            }
        }

        for (ip, agg) in failures where agg.count >= Self.bruteForceThreshold {
            let succeeded = acceptedByIP[ip]
            let userSample = agg.users.sorted().prefix(8).joined(separator: ", ")
            if let success = succeeded?.first {
                findings.append(Finding(
                    title: "SSH brute force from \(ip) SUCCEEDED",
                    detail: "\(agg.count) failed logins from \(ip) (\(agg.users.count) "
                        + "account name(s): \(userSample)) followed by an accepted "
                        + "\(success.method ?? "?") login for \(success.user ?? "?"). "
                        + "Treat the account as compromised.",
                    severity: .critical,
                    phase: .exploitation,
                    technique: AttackTechnique(attackID: "T1110", name: "Brute Force"),
                    timestamp: success.timestamp ?? agg.last,
                    evidencePaths: Array(agg.sources).sorted()))
            } else {
                findings.append(Finding(
                    title: "SSH brute force from \(ip)",
                    detail: "\(agg.count) failed logins from \(ip) targeting "
                        + "\(agg.users.count) account name(s) (\(userSample))"
                        + (agg.first != nil && agg.last != nil
                            ? ", between \(agg.first!.ISO8601Format()) and \(agg.last!.ISO8601Format())"
                            : "")
                        + ". No accepted login from this source was recorded.",
                    severity: agg.users.count > 3 ? .high : .medium,
                    phase: .exploitation,
                    technique: AttackTechnique(
                        attackID: agg.users.count > 3 ? "T1110.003" : "T1110.001",
                        name: agg.users.count > 3 ? "Brute Force: Password Spraying"
                                                  : "Brute Force: Password Guessing"),
                    timestamp: agg.last,
                    evidencePaths: Array(agg.sources).sorted()))
            }
        }

        // Rule 4: account creation.
        for entry in context.authLog where entry.kind == .userAdded {
            findings.append(Finding(
                title: "Account created: \(entry.user ?? "?")",
                detail: "\(entry.process): \(entry.message)",
                severity: .medium,
                phase: .installation,
                technique: AttackTechnique(attackID: "T1136.001",
                                           name: "Create Account: Local Account"),
                timestamp: entry.timestamp,
                evidencePaths: [entry.sourceFile]))
        }

        return findings
    }
}
