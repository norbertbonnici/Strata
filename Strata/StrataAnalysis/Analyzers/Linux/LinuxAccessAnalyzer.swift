import Foundation

/// Access & privilege detection over the Linux SSH-trust and account artifacts -
/// the Linux analogue of the Windows account / logon-rights checks. Surfaces the
/// classic "how do they get back in, and as whom" findings: backdoor SSH keys,
/// dangerous sshd settings, passwordless and rogue-root accounts, over-broad
/// sudo, and root-equivalent group membership.
public nonisolated struct LinuxAccessAnalyzer: Analyzer {
    public let name = "Linux Access & Privilege"
    public init() {}

    public func analyze(context: AnalysisContext) -> [Finding] {
        guard let access = context.linuxAccess else { return [] }
        var findings: [Finding] = []

        // MARK: SSH authorized_keys
        for key in access.authorizedKeys {
            let who = key.user ?? "?"
            let forced = key.options.first { $0.lowercased().hasPrefix("command=") }
            if let forced {
                findings.append(Finding(
                    title: "Forced-command SSH key for \(who)",
                    detail: "An authorized_keys entry runs a fixed command on login "
                        + "(\(forced)). Legitimate for automation, but also a common "
                        + "backdoor shape - confirm the command and the key's owner.\n"
                        + "\(key.algorithm) \(key.comment)",
                    severity: .medium,
                    phase: .installation,
                    technique: AttackTechnique(attackID: "T1098.004",
                                               name: "Account Manipulation: SSH Authorized Keys"),
                    evidencePaths: [key.sourceFile]))
            } else if who == "root" {
                findings.append(Finding(
                    title: "SSH key authorized for root",
                    detail: "root's authorized_keys grants key-based login directly to "
                        + "root (\(key.algorithm)\(key.comment.isEmpty ? "" : " \(key.comment)")). "
                        + "Verify the key is expected - a planted key is durable remote access.",
                    severity: .high,
                    phase: .installation,
                    technique: AttackTechnique(attackID: "T1098.004",
                                               name: "Account Manipulation: SSH Authorized Keys"),
                    evidencePaths: [key.sourceFile]))
            }
        }

        // MARK: sshd_config
        let sshd = access.sshdSettings
        let sshdPath = access.sshdSourceFile ?? "/etc/ssh/sshd_config"
        if let v = sshd["permitemptypasswords"], v.lowercased() == "yes" {
            findings.append(Finding(
                title: "sshd permits empty passwords",
                detail: "PermitEmptyPasswords yes - accounts with a blank password can log in over SSH.",
                severity: .critical, phase: .exploitation,
                technique: AttackTechnique(attackID: "T1021.004", name: "Remote Services: SSH"),
                evidencePaths: [sshdPath]))
        }
        if let v = sshd["permitrootlogin"], ["yes", "without-password", "prohibit-password"].contains(v.lowercased()) {
            findings.append(Finding(
                title: "sshd permits root login (PermitRootLogin \(v))",
                detail: "Direct root SSH login is enabled. Hardened hosts set this to 'no'; "
                    + "with it on, a guessed/planted root credential is immediate full access.",
                severity: v.lowercased() == "yes" ? .high : .medium,
                phase: .exploitation,
                technique: AttackTechnique(attackID: "T1021.004", name: "Remote Services: SSH"),
                evidencePaths: [sshdPath]))
        }

        // MARK: passwd / shadow
        // Non-root account with UID 0 = a hidden root-equivalent backdoor.
        if let users = context.linuxInfo?.users {
            for user in users where user.uid == 0 && user.name != "root" {
                findings.append(Finding(
                    title: "Non-root account with UID 0: \(user.name)",
                    detail: "\(user.name) has UID 0, making it root-equivalent - a classic "
                        + "stealth-root backdoor. Home \(user.home), shell \(user.shell).",
                    severity: .critical, phase: .installation,
                    technique: AttackTechnique(attackID: "T1136.001", name: "Create Account: Local Account"),
                    evidencePaths: ["/etc/passwd"]))
            }
        }
        for (account, status) in access.shadow where status == .empty {
            findings.append(Finding(
                title: "Passwordless account: \(account)",
                detail: "\(account) has an empty password hash in /etc/shadow - it can "
                    + "authenticate with no password.",
                severity: .high, phase: .installation,
                technique: AttackTechnique(attackID: "T1098", name: "Account Manipulation"),
                evidencePaths: ["/etc/shadow"]))
        }

        // MARK: sudoers
        for rule in access.sudoRules where rule.noPasswd && rule.grantsAll
            && !rule.principal.hasPrefix("%") && rule.principal.lowercased() != "root" {
            findings.append(Finding(
                title: "Passwordless full sudo for \(rule.principal)",
                detail: "\(rule.principal) may run ALL commands via sudo with NOPASSWD "
                    + "(runas \(rule.runAs ?? "ALL")) - password-free privilege escalation to root.",
                severity: .high, phase: .exploitation,
                technique: AttackTechnique(attackID: "T1548.003", name: "Abuse Elevation Control Mechanism: Sudo"),
                evidencePaths: [rule.sourceFile]))
        }

        // MARK: privileged group membership
        // docker membership is effectively root (mount host fs in a container).
        for group in access.groups where ["docker", "lxd"].contains(group.name.lowercased()) {
            let nonRoot = group.members.filter { $0 != "root" }
            if !nonRoot.isEmpty {
                findings.append(Finding(
                    title: "Root-equivalent group '\(group.name)': \(nonRoot.joined(separator: ", "))",
                    detail: "Members of the \(group.name) group can trivially obtain root "
                        + "(e.g. mount the host filesystem from a container). Confirm these accounts are expected.",
                    severity: .medium, phase: .exploitation,
                    technique: AttackTechnique(attackID: "T1548", name: "Abuse Elevation Control Mechanism"),
                    evidencePaths: ["/etc/group"]))
            }
        }

        return findings
    }
}
