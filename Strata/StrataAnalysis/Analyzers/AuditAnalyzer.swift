import Foundation

/// Detection over folded auditd events. The kernel audit trail uniquely records
/// *what executed*, *who* (the immutable login uid), and *which sensitive files
/// were touched* - evidence no other Linux source carries, and which survives
/// even when auth.log was wiped.
public nonisolated struct AuditAnalyzer: Analyzer {
    public let name = "Linux Audit"
    public init() {}

    private static let serviceAccounts: Set<String> = [
        "www-data", "apache", "nginx", "httpd", "tomcat", "postgres", "mysql",
        "redis", "daemon", "nobody", "mail", "ftp", "named", "bind",
    ]
    private static let stagingPaths = ["/tmp/", "/var/tmp/", "/dev/shm/", "/run/shm/"]
    private static let interpreters = ["/bin/sh", "/bin/bash", "/bin/dash", "/usr/bin/python",
                                       "/usr/bin/perl", "/usr/bin/php", "/usr/bin/ruby",
                                       "nc", "ncat", "socat", "whoami", "/usr/bin/id", "wget", "curl"]
    private static let sensitiveFiles = ["/etc/passwd", "/etc/shadow", "/etc/sudoers",
                                         "/.ssh/authorized_keys", "/etc/ssh/sshd_config",
                                         "/etc/ld.so.preload", "/etc/crontab"]

    public func analyze(context: AnalysisContext) -> [Finding] {
        guard !context.audit.isEmpty else { return [] }
        var findings: [Finding] = []

        // Account name lookup for uid/auid attribution.
        let userByUid = Dictionary((context.linuxInfo?.users ?? []).map { ($0.uid, $0.name) },
                                   uniquingKeysWith: { first, _ in first })
        func name(_ uid: Int?) -> String? { uid.flatMap { userByUid[$0] } }

        // USER_AUTH/USER_ACCT failed bursts (non-SSH local PAM surfaces).
        struct AuthAgg { var count = 0; var accts = Set<String>(); var last: Date?; var source = "" }
        var authFails: [String: AuthAgg] = [:]   // keyed by terminal/source

        for event in context.audit {
            // Rule 1+2: suspicious execve (service/web UID, staging path, interpreter).
            if event.recordType == "EXECVE" || event.syscall == "execve" || event.syscall == "execveat" {
                let cmd = (event.commandLine ?? event.exe ?? "").lowercased()
                let runner = name(event.auid) ?? name(event.uid) ?? ""
                let underService = Self.serviceAccounts.contains(runner)
                    || Self.serviceAccounts.contains((event.comm ?? "").lowercased())
                let fromStaging = Self.stagingPaths.contains { (event.exe ?? event.path ?? "").contains($0) }
                let isInterp = Self.interpreters.contains { cmd.contains($0) }
                if (underService && isInterp) || fromStaging {
                    findings.append(Finding(
                        title: fromStaging ? "Execution from staging path (audit): \(event.comm ?? "?")"
                                           : "Shell/interpreter under service account \(runner) (audit)",
                        detail: "auditd recorded execve of \(event.commandLine ?? event.exe ?? "?")"
                            + (event.auid != nil ? " (auid \(name(event.auid) ?? String(event.auid!)))" : "")
                            + ". \(fromStaging ? "Binary runs from a world-writable staging directory." : "An interactive shell/recon tool spawned under a non-interactive service account is the web-shell-to-command pivot.")",
                        severity: .high, phase: .exploitation,
                        technique: AttackTechnique(attackID: "T1059.004",
                                                   name: "Command and Scripting Interpreter: Unix Shell"),
                        timestamp: event.timestamp, evidencePaths: [event.sourceFile]))
                }
            }

            // Rule 3: account / group creation.
            if event.recordType.hasPrefix("ADD_USER") || event.recordType == "ADD_GROUP"
                || event.recordType == "USER_MGMT" || event.recordType.hasPrefix("GRP_") {
                if event.result != "failed" {
                    findings.append(Finding(
                        title: "Account/group change (audit): \(event.account ?? "?")",
                        detail: "auditd \(event.recordType) for \(event.account ?? "?")"
                            + (event.auid != nil ? " by auid \(name(event.auid) ?? String(event.auid!))" : "")
                            + (event.auid == nil ? " by a non-interactive context (auid unset)" : "") + ".",
                        severity: event.auid == nil ? .high : .medium, phase: .installation,
                        technique: AttackTechnique(attackID: "T1136.001", name: "Create Account: Local Account"),
                        timestamp: event.timestamp, evidencePaths: [event.sourceFile]))
                }
            }

            // Rule 4: USER_AUTH/USER_ACCT failures (aggregate).
            if (event.recordType == "USER_AUTH" || event.recordType == "USER_ACCT"),
               event.result == "failed", (event.comm ?? "") != "sshd",
               !(event.exe ?? "").contains("sshd") {
                let keyT = event.tty ?? event.sourceIP ?? "local"
                var agg = authFails[keyT] ?? AuthAgg()
                agg.count += 1
                if let a = event.account { agg.accts.insert(a) }
                if let t = event.timestamp, agg.last == nil || t > agg.last! { agg.last = t }
                agg.source = event.sourceFile
                authFails[keyT] = agg
            }

            // Rule 6: write to a watched sensitive file (audit rule key fired).
            if let path = event.path, event.key != nil || event.recordType == "SYSCALL",
               Self.sensitiveFiles.contains(where: path.contains),
               (event.syscall == nil || ["openat", "open", "rename", "unlinkat", "unlink", "chmod", "fchmodat"].contains(event.syscall!)),
               event.success != false {
                let technique: AttackTechnique = path.contains("authorized_keys")
                    ? AttackTechnique(attackID: "T1098.004", name: "Account Manipulation: SSH Authorized Keys")
                    : (path.contains("sudoers")
                       ? AttackTechnique(attackID: "T1548.003", name: "Abuse Elevation Control Mechanism: Sudo")
                       : AttackTechnique(attackID: "T1565.001", name: "Data Manipulation: Stored Data Manipulation"))
                findings.append(Finding(
                    title: "Sensitive file modified (audit): \(path)",
                    detail: "auditd recorded a write/modify to \(path)"
                        + (event.auid != nil ? " by auid \(name(event.auid) ?? String(event.auid!))" : "")
                        + (event.key != nil ? " (rule key: \(event.key!))" : "") + ".",
                    severity: event.auid == nil ? .high : .medium, phase: .installation,
                    technique: technique, timestamp: event.timestamp, evidencePaths: [event.sourceFile]))
            }

            // Rule 7: SELinux/AppArmor denial (single high-value ones).
            if event.recordType == "AVC" || event.recordType == "USER_AVC" {
                // Surfaced individually only for execmem/execstack-class denials
                // (memory-corruption tell); others would be policy noise.
                let m = event.summary.lowercased()
                if m.contains("execmem") || m.contains("execstack") || m.contains("execheap") {
                    findings.append(Finding(
                        title: "SELinux execmem/execstack denial (audit)",
                        detail: "A confined domain was denied executable-memory permission - a "
                            + "memory-corruption / shellcode-execution tell.\n\(event.summary)",
                        severity: .medium, phase: .exploitation,
                        technique: AttackTechnique(attackID: "T1211", name: "Exploitation for Defense Evasion"),
                        timestamp: event.timestamp, evidencePaths: [event.sourceFile]))
                }
            }
        }

        for (term, agg) in authFails where agg.count >= 10 {
            findings.append(Finding(
                title: "Local PAM auth-failure burst (audit) on \(term)",
                detail: "\(agg.count) failed USER_AUTH/USER_ACCT events on \(term) across "
                    + "\(agg.accts.count) account(s) - non-SSH credential guessing (su/login/console/cron PAM).",
                severity: agg.accts.count > 3 ? .high : .medium, phase: .exploitation,
                technique: AttackTechnique(
                    attackID: agg.accts.count > 3 ? "T1110.003" : "T1110.001",
                    name: agg.accts.count > 3 ? "Brute Force: Password Spraying"
                                              : "Brute Force: Password Guessing"),
                timestamp: agg.last, evidencePaths: [agg.source]))
        }

        return findings
    }
}
