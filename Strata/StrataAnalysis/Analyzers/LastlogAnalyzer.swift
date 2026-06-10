import Foundation

/// Detection over `/var/log/lastlog` - the last login per account. Surfaces two
/// durable-foothold tells that this one snapshot uniquely shows (independent of
/// wtmp/auth.log rotation): a non-interactive service account that has logged
/// in at all, and a privileged account whose last login came from a public/
/// unexpected host.
public nonisolated struct LastlogAnalyzer: Analyzer {
    public let name = "Last Login"
    public init() {}

    /// Service/system account names that should never have an interactive login.
    private static let serviceNames: Set<String> = [
        "bin", "daemon", "sys", "sync", "games", "man", "lp", "mail", "news",
        "uucp", "proxy", "www-data", "backup", "list", "irc", "gnats", "nobody",
        "systemd-network", "systemd-resolve", "messagebus", "postgres", "mysql",
        "redis", "named", "bind", "ftp", "sshd", "_apt", "tss", "uuidd",
    ]

    public func analyze(context: AnalysisContext) -> [Finding] {
        guard !context.lastlog.isEmpty else { return [] }
        var findings: [Finding] = []

        // Shells + privileged-group membership for context.
        let shellByName = Dictionary((context.linuxInfo?.users ?? []).map { ($0.name, $0.shell) },
                                     uniquingKeysWith: { first, _ in first })
        let privileged: Set<String> = {
            var set: Set<String> = ["root"]
            for group in (context.linuxAccess?.groups ?? [])
            where ["sudo", "wheel", "admin", "docker", "lxd"].contains(group.name.lowercased()) {
                set.formUnion(group.members)
            }
            return set
        }()

        for record in context.lastlog {
            let userName = record.user
            // Rule 1: service/system account with a recorded login.
            let shell = userName.flatMap { shellByName[$0] }
            let nonLoginShell = shell.map { $0.hasSuffix("nologin") || $0.hasSuffix("/false") } ?? false
            let isService = (userName.map { Self.serviceNames.contains($0) } ?? false)
                || nonLoginShell
                || (userName == nil && record.uid < 1000 && record.uid != 0)
            if isService {
                findings.append(Finding(
                    title: "Service account login recorded: \(record.account)",
                    detail: "lastlog shows \(record.account) (uid \(record.uid)"
                        + (shell.map { ", shell \($0)" } ?? "") + ") last logged in on "
                        + "\(record.line)\(record.host.isEmpty ? "" : " from \(record.host)"). "
                        + "Non-interactive accounts should never log in - strong compromise signal.",
                    severity: .high, phase: .exploitation,
                    technique: AttackTechnique(attackID: "T1078.003", name: "Valid Accounts: Local Accounts"),
                    timestamp: record.timestamp, evidencePaths: [record.sourceFile]))
                continue
            }

            // Rule 2: privileged account last login from a public/external host.
            if let userName, privileged.contains(userName), !record.host.isEmpty,
               isPublicHost(record.host) {
                findings.append(Finding(
                    title: "Privileged login from external host: \(userName)",
                    detail: "lastlog shows \(userName) last logged in from \(record.host) over "
                        + "\(record.line) - a sudo/root account's last login originated from a public/"
                        + "non-RFC1918 address. Correlate with the accepted-login window to confirm.",
                    severity: .medium, phase: .exploitation,
                    technique: AttackTechnique(attackID: "T1078", name: "Valid Accounts"),
                    timestamp: record.timestamp, evidencePaths: [record.sourceFile]))
            }
        }
        return findings
    }

    /// True for a routable/public host (not RFC1918, loopback, link-local, or
    /// an empty/local tty marker).
    private func isPublicHost(_ host: String) -> Bool {
        if host.isEmpty || host == ":0" || host == "localhost" { return false }
        // Only judge things that look like an IPv4 address; leave hostnames be
        // (a bare hostname isn't necessarily external).
        let parts = host.split(separator: ".")
        guard parts.count == 4, let a = Int(parts[0]), let b = Int(parts[1]),
              parts.allSatisfy({ Int($0) != nil }) else { return false }
        if a == 10 || a == 127 { return false }
        if a == 192 && b == 168 { return false }
        if a == 172 && (16...31).contains(b) { return false }
        if a == 169 && b == 254 { return false }
        if a == 0 { return false }
        return true
    }
}
