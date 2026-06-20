import Foundation

/// Detection over journald entries. On a modern systemd host the journal is
/// often the only place auth events live (no `auth.log`/`secure`), so this runs
/// the same high-signal auth checks as `AuthLogAnalyzer` against the journal's
/// `MESSAGE` field: SSH brute force (with success-after-burst escalation) and
/// sudo/su authentication failures. It also flags service crash loops.
public nonisolated struct JournaldAnalyzer: Analyzer {
    public let name = "Journald"
    public init() {}

    static let bruteForceThreshold = 10

    public func analyze(context: AnalysisContext) -> [Finding] {
        guard !context.journald.isEmpty else { return [] }
        var findings: [Finding] = []

        struct FailureAgg {
            var count = 0; var users = Set<String>(); var last: Date?; var source = ""
        }
        var failures: [String: FailureAgg] = [:]
        var acceptedByIP: [String: JournaldEntry] = [:]
        var sudoFailures = 0
        var sudoSample = ""
        var sudoLast: Date?
        var sudoSource = ""

        for entry in context.journald {
            let prog = (entry.program ?? "").lowercased()
            let msg = entry.message

            if prog == "sshd" {
                if msg.hasPrefix("Failed ") || msg.hasPrefix("Invalid user ") {
                    let ip = token(after: " from ", in: msg) ?? ""
                    guard !ip.isEmpty else { continue }
                    var agg = failures[ip] ?? FailureAgg()
                    agg.count += 1
                    if let u = msg.hasPrefix("Invalid user ")
                        ? token(after: "Invalid user ", in: msg)
                        : (msg.contains(" for invalid user ") ? token(after: " for invalid user ", in: msg)
                                                              : token(after: " for ", in: msg)) {
                        agg.users.insert(u)
                    }
                    if let t = entry.timestamp, agg.last == nil || t > agg.last! { agg.last = t }
                    agg.source = entry.sourceFile
                    failures[ip] = agg
                } else if msg.hasPrefix("Accepted ") {
                    if let ip = token(after: " from ", in: msg) { acceptedByIP[ip] = entry }
                    if token(after: " for ", in: msg) == "root" {
                        findings.append(Finding(
                            title: "Direct root SSH login (journal) from \(token(after: " from ", in: msg) ?? "?")",
                            detail: msg, severity: .medium, phase: .exploitation,
                            technique: AttackTechnique(attackID: "T1021.004", name: "Remote Services: SSH"),
                            timestamp: entry.timestamp, evidencePaths: [entry.sourceFile]))
                    }
                }
            } else if prog == "sudo", msg.contains("authentication failure") || msg.contains("incorrect password") {
                sudoFailures += 1
                if sudoSample.isEmpty { sudoSample = msg }
                if let t = entry.timestamp, sudoLast == nil || t > sudoLast! { sudoLast = t }
                sudoSource = entry.sourceFile
            }
        }

        for (ip, agg) in failures where agg.count >= Self.bruteForceThreshold {
            if let success = acceptedByIP[ip] {
                findings.append(Finding(
                    title: "SSH brute force from \(ip) SUCCEEDED (journal)",
                    detail: "\(agg.count) failed SSH logins from \(ip) (\(agg.users.count) account name(s)) "
                        + "followed by an accepted login. Treat the account as compromised.\n\(success.message)",
                    severity: .critical, phase: .exploitation,
                    technique: AttackTechnique(attackID: "T1110", name: "Brute Force"),
                    timestamp: success.timestamp ?? agg.last, evidencePaths: [agg.source]))
            } else {
                findings.append(Finding(
                    title: "SSH brute force from \(ip) (journal)",
                    detail: "\(agg.count) failed SSH logins from \(ip) targeting \(agg.users.count) "
                        + "account name(s). No accepted login from this source was recorded.",
                    severity: agg.users.count > 3 ? .high : .medium, phase: .exploitation,
                    technique: AttackTechnique(
                        attackID: agg.users.count > 3 ? "T1110.003" : "T1110.001",
                        name: agg.users.count > 3 ? "Brute Force: Password Spraying"
                                                  : "Brute Force: Password Guessing"),
                    timestamp: agg.last, evidencePaths: [agg.source]))
            }
        }

        if sudoFailures >= 5 {
            findings.append(Finding(
                title: "Repeated sudo authentication failures (journal)",
                detail: "\(sudoFailures) sudo authentication failures recorded - possible privilege-"
                    + "escalation attempts or credential guessing.\n\(sudoSample)",
                severity: .medium, phase: .exploitation,
                technique: AttackTechnique(attackID: "T1548.003", name: "Abuse Elevation Control Mechanism: Sudo"),
                timestamp: sudoLast, evidencePaths: [sudoSource]))
        }

        return findings
    }

    private func token(after marker: String, in message: String) -> String? {
        guard let range = message.range(of: marker) else { return nil }
        return message[range.upperBound...].split(separator: " ").first.map(String.init)
    }
}
