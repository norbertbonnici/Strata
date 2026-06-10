import Foundation

/// Attacker-tradecraft detection over parsed shell history. History survives
/// surprisingly often, and a one-liner in `.bash_history` is frequently the
/// most direct record of hands-on-keyboard activity on a Linux host.
///
/// One finding per distinct (user, command) pair - re-running the same
/// command doesn't multiply findings; the count rides in the detail.
public nonisolated struct ShellHistoryAnalyzer: Analyzer {
    public let name = "Shell History"
    public init() {}

    private struct Rule {
        let indicators: [String]   // lowercase substrings; any match fires
        let title: String
        let severity: Severity
        let phase: KillChainPhase
        let technique: AttackTechnique
    }

    private static let rules: [Rule] = [
        Rule(indicators: ["/dev/tcp/", "nc -e", "ncat -e", "nc.traditional -e",
                          "bash -i >&", "pty.spawn", "socat tcp", "socat exec"],
             title: "Reverse/bind shell command",
             severity: .high,
             phase: .commandAndControl,
             technique: AttackTechnique(attackID: "T1059.004",
                                        name: "Command and Scripting Interpreter: Unix Shell")),
        Rule(indicators: ["curl ", "wget "],
             title: "Download-and-execute pipeline",
             severity: .high,
             phase: .delivery,
             technique: AttackTechnique(attackID: "T1105", name: "Ingress Tool Transfer")),
        Rule(indicators: ["history -c", "history -w", "unset histfile",
                          "histsize=0", "rm ~/.bash_history", "rm /root/.bash_history",
                          "ln -sf /dev/null"],
             title: "Shell history tampering",
             severity: .high,
             phase: .actionsOnObjectives,
             technique: AttackTechnique(attackID: "T1070.003",
                                        name: "Indicator Removal: Clear Command History")),
        Rule(indicators: ["chmod +x /tmp/", "chmod +x /dev/shm/", "chmod +x /var/tmp/",
                          "chmod 777 /tmp/", "chmod u+s "],
             title: "Staging-directory executable preparation",
             severity: .medium,
             phase: .installation,
             technique: AttackTechnique(attackID: "T1222.002",
                 name: "File and Directory Permissions Modification: Linux and Mac")),
        Rule(indicators: ["base64 -d", "base64 --decode"],
             title: "Base64 decode on the command line",
             severity: .medium,
             phase: .exploitation,
             technique: AttackTechnique(attackID: "T1140",
                                        name: "Deobfuscate/Decode Files or Information")),
    ]

    public func analyze(context: AnalysisContext) -> [Finding] {
        guard !context.shellHistory.isEmpty else { return [] }

        // The download rule only counts when the fetch is piped into a shell
        // or chmod'd - bare curl/wget is everyday admin work.
        func matches(_ rule: Rule, command: String) -> Bool {
            guard rule.indicators.contains(where: command.contains) else { return false }
            if rule.technique.attackID == "T1105" {
                return command.contains("| sh") || command.contains("|sh")
                    || command.contains("| bash") || command.contains("|bash")
                    || command.contains("&& chmod") || command.contains("; chmod")
            }
            return true
        }

        struct Agg {
            var count = 0
            var first: ShellHistoryEntry?
            var lastDate: Date?
        }
        // Key: rule index | user | command.
        var hits: [String: (Rule, ShellHistoryEntry, Agg)] = [:]

        for entry in context.shellHistory {
            let command = entry.command.lowercased()
            for (index, rule) in Self.rules.enumerated() where matches(rule, command: command) {
                let key = "\(index)|\(entry.user)|\(command)"
                var (_, _, agg) = hits[key] ?? (rule, entry, Agg())
                agg.count += 1
                if agg.first == nil { agg.first = entry }
                if let stamp = entry.timestamp,
                   agg.lastDate == nil || stamp > agg.lastDate! { agg.lastDate = stamp }
                hits[key] = (rule, entry, agg)
                break   // first matching rule wins; the others would double-report
            }
        }

        return hits.values.map { rule, entry, agg in
            Finding(
                title: "\(rule.title) (\(entry.user))",
                detail: "\(entry.user)'s \(entry.shell.label) history"
                    + (agg.count > 1 ? " (\(agg.count)×)" : "")
                    + ":\n\(entry.command)",
                severity: rule.severity,
                phase: rule.phase,
                technique: rule.technique,
                timestamp: agg.lastDate ?? entry.timestamp,
                evidencePaths: [entry.sourceFile])
        }
    }
}
