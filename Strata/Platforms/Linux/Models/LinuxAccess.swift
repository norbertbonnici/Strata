import Foundation

// Linux access & privilege artifacts: SSH trust (authorized_keys / known_hosts
// / sshd_config) and account privilege (shadow / sudoers / group). These answer
// "who can get in, and as whom" - the Linux analogue of the Windows account /
// logon-rights picture. All value types, persisted per host as `linuxaccess
// .json`, surfaced in the Accounts & SSH tab + a dedicated analyzer.

// MARK: - SSH trust

/// One SSH public key from an `authorized_keys` file (a key that may log into
/// the owning account) or a `known_hosts` file (a host this account has
/// connected to - a lateral-movement breadcrumb). A backdoor `authorized_keys`
/// entry is one of the most common Linux persistence/access mechanisms.
public nonisolated struct SSHKey: Identifiable, Hashable, Sendable, Codable {
    public enum Kind: String, Codable, Sendable {
        case authorized   // grants login TO this account
        case knownHost    // a host this account connected to

        public var label: String {
            switch self {
            case .authorized: return "Authorized key"
            case .knownHost:  return "Known host"
            }
        }
    }

    public let id: UUID
    public let kind: Kind
    /// Owning account (from the home directory path) for an authorized key.
    public let user: String?
    /// Key algorithm, e.g. `ssh-ed25519`, `ssh-rsa`, `ecdsa-sha2-nistp256`.
    public let algorithm: String
    /// Trailing free-text comment (often `user@host` or a tool name).
    public let comment: String
    /// `authorized_keys` options preceding the key (`command="..."`,
    /// `from="..."`, `no-pty`, …) - a `command=` forced command is a classic
    /// backdoor shape.
    public let options: [String]
    /// `known_hosts` host field (hostname/IP, possibly hashed).
    public let host: String?
    public let sourceFile: String

    public init(id: UUID = UUID(), kind: Kind, user: String? = nil, algorithm: String,
                comment: String = "", options: [String] = [], host: String? = nil,
                sourceFile: String) {
        self.id = id
        self.kind = kind
        self.user = user
        self.algorithm = algorithm
        self.comment = comment
        self.options = options
        self.host = host
        self.sourceFile = sourceFile
    }
}

// MARK: - Privilege

/// One `sudoers` (or `sudoers.d/*`) rule - who may run what as whom. `NOPASSWD`
/// and broad `ALL` grants are the high-signal cases.
public nonisolated struct SudoRule: Identifiable, Hashable, Sendable, Codable {
    public let id: UUID
    /// The principal: a user, or `%group` for a group rule.
    public let principal: String
    /// `(runAs)` spec, e.g. `ALL`, `root`. nil when unspecified.
    public let runAs: String?
    /// Whether the rule carries the `NOPASSWD:` tag.
    public let noPasswd: Bool
    /// The command spec, e.g. `ALL`, `/usr/bin/systemctl restart x`.
    public let command: String
    public let sourceFile: String

    public init(id: UUID = UUID(), principal: String, runAs: String? = nil,
                noPasswd: Bool, command: String, sourceFile: String) {
        self.id = id
        self.principal = principal
        self.runAs = runAs
        self.noPasswd = noPasswd
        self.command = command
        self.sourceFile = sourceFile
    }

    /// True for a principal granted `ALL` commands - full root-equivalent sudo.
    public var grantsAll: Bool {
        command.uppercased() == "ALL"
    }
}

/// One `/etc/group` row (name, gid, members). The analyzer cares about
/// membership of the privileged groups (`sudo`, `wheel`, `root`, `docker` -
/// docker membership is effectively root, `adm` reads logs).
public nonisolated struct LinuxGroup: Hashable, Sendable, Codable {
    public let name: String
    public let gid: Int
    public let members: [String]

    public init(name: String, gid: Int, members: [String]) {
        self.name = name
        self.gid = gid
        self.members = members
    }
}

/// Password state for an account, decoded from the `/etc/shadow` hash field.
public nonisolated enum ShadowStatus: String, Codable, Sendable, Hashable {
    case usable    // a real password hash is set
    case locked    // hash starts with `!` or `*` - login via password disabled
    case empty     // empty hash field - PASSWORDLESS login (alarm)
    case noLogin   // `*` / `!!` placeholder for a system/never-set account

    public var label: String {
        switch self {
        case .usable:  return "Password set"
        case .locked:  return "Locked"
        case .empty:   return "EMPTY (passwordless)"
        case .noLogin: return "No password set"
        }
    }
}

// MARK: - Aggregate

/// All access/privilege artifacts for one host, gathered in `parseLinux`.
/// Carried as a single value (rather than several arrays) since they're read
/// together by the Accounts & SSH view and the access analyzer.
public nonisolated struct LinuxAccessInfo: Hashable, Sendable, Codable {
    public var sshKeys: [SSHKey] = []
    /// Parsed `sshd_config` (lowercased keyword → value; last value wins).
    public var sshdSettings: [String: String] = [:]
    public var sshdSourceFile: String?
    public var sudoRules: [SudoRule] = []
    public var groups: [LinuxGroup] = []
    /// Account name → password state, from `/etc/shadow`.
    public var shadow: [String: ShadowStatus] = [:]

    public init() {}

    public var isEmpty: Bool {
        sshKeys.isEmpty && sshdSettings.isEmpty && sudoRules.isEmpty
            && groups.isEmpty && shadow.isEmpty
    }

    /// Convenience: authorized keys only (the login-granting ones).
    public var authorizedKeys: [SSHKey] { sshKeys.filter { $0.kind == .authorized } }
}
