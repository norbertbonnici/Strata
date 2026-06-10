import Foundation

// Linux triage artifacts. All value types, `nonisolated` + `Sendable` +
// `Codable`, mirroring the Windows artifact models: parsed once (pure-Swift,
// no vendored tools - these are text or fixed-layout binary formats),
// persisted per host in the case bundle, spliced onto the super-timeline.

// MARK: - Auth log (syslog-format authentication events)

/// One event from `/var/log/auth.log` (Debian) or `/var/log/secure` (RHEL) -
/// SSH logins, sudo invocations, session lifecycle, account changes. The
/// single highest-signal Linux triage source: it attributes *who* came from
/// *where* and what they elevated to.
public nonisolated struct AuthLogEntry: Identifiable, Hashable, Sendable, Codable {
    /// Classified event kind, so analyzers/views don't re-grep the message.
    public enum Kind: String, Sendable, Codable, CaseIterable {
        case sshAccepted     // "Accepted password/publickey for X from IP"
        case sshFailed       // "Failed password for [invalid user] X from IP"
        case sshInvalidUser  // "Invalid user X from IP"
        case sudo            // "USER : TTY=... ; COMMAND=..."
        case sessionOpened
        case sessionClosed
        case userAdded       // useradd/adduser: new user/group
        case userModified    // usermod/passwd/chage changes
        case other

        public var label: String {
            switch self {
            case .sshAccepted:    return "SSH accepted"
            case .sshFailed:      return "SSH failed"
            case .sshInvalidUser: return "Invalid user"
            case .sudo:           return "sudo"
            case .sessionOpened:  return "Session opened"
            case .sessionClosed:  return "Session closed"
            case .userAdded:      return "User added"
            case .userModified:   return "User modified"
            case .other:          return "Other"
            }
        }
    }

    public let id: UUID
    public let timestamp: Date?
    public let host: String            // syslog hostname field
    public let process: String         // "sshd", "sudo", "useradd", ...
    public let pid: Int?
    public let kind: Kind
    public let user: String?           // the account involved, when parsed
    public let sourceIP: String?       // remote address, when parsed
    public let port: Int?
    public let method: String?         // "password" / "publickey" (ssh)
    public let command: String?        // sudo COMMAND=
    public let message: String         // full message body after "process[pid]:"
    public let sourceFile: String

    public init(id: UUID = UUID(), timestamp: Date?, host: String, process: String,
                pid: Int? = nil, kind: Kind, user: String? = nil, sourceIP: String? = nil,
                port: Int? = nil, method: String? = nil, command: String? = nil,
                message: String, sourceFile: String) {
        self.id = id
        self.timestamp = timestamp
        self.host = host
        self.process = process
        self.pid = pid
        self.kind = kind
        self.user = user
        self.sourceIP = sourceIP
        self.port = port
        self.method = method
        self.command = command
        self.message = message
        self.sourceFile = sourceFile
    }
}

// MARK: - utmp login records (wtmp / btmp)

/// One fixed-size record from `/var/log/wtmp` (logins/reboots) or
/// `/var/log/btmp` (failed logins). Binary, but a stable 384-byte struct -
/// parsed pure-Swift. btmp is often the only brute-force evidence left when
/// auth.log has rotated away.
public nonisolated struct UtmpRecord: Identifiable, Hashable, Sendable, Codable {
    /// `ut_type` values we care about (linux/utmp.h).
    public enum RecordType: Int32, Sendable, Codable {
        case bootTime = 2        // BOOT_TIME
        case newTime = 3
        case oldTime = 4
        case initProcess = 5
        case loginProcess = 6    // LOGIN_PROCESS (getty waiting)
        case userProcess = 7     // USER_PROCESS (a real login)
        case deadProcess = 8     // DEAD_PROCESS (logout)
        case other = 0

        public var label: String {
            switch self {
            case .bootTime:     return "Boot"
            case .userProcess:  return "Login"
            case .deadProcess:  return "Logout"
            case .loginProcess: return "Login prompt"
            case .initProcess:  return "Init"
            case .newTime, .oldTime: return "Clock change"
            case .other:        return "Other"
            }
        }
    }

    public let id: UUID
    public let type: RecordType
    public let pid: Int32
    public let line: String        // tty / "ssh" pseudo-line
    public let user: String
    public let host: String        // remote hostname/IP as recorded
    public let timestamp: Date?
    /// True when the record came from btmp - i.e. a FAILED login attempt.
    public let isFailedLogin: Bool
    public let sourceFile: String

    public init(id: UUID = UUID(), type: RecordType, pid: Int32, line: String,
                user: String, host: String, timestamp: Date?,
                isFailedLogin: Bool, sourceFile: String) {
        self.id = id
        self.type = type
        self.pid = pid
        self.line = line
        self.user = user
        self.host = host
        self.timestamp = timestamp
        self.isFailedLogin = isFailedLogin
        self.sourceFile = sourceFile
    }
}

// MARK: - Shell history

/// One command from a user's shell history file. zsh extended history carries
/// a real epoch timestamp; bash does too when `HISTTIMEFORMAT` was set
/// (written as `#<epoch>` comment lines) - otherwise order is all we have.
public nonisolated struct ShellHistoryEntry: Identifiable, Hashable, Sendable, Codable {
    public enum Shell: String, Sendable, Codable {
        case bash, zsh

        public var label: String { rawValue }
    }

    public let id: UUID
    public let user: String          // derived from the home directory path
    public let shell: Shell
    public let command: String
    public let timestamp: Date?      // zsh extended / bash HISTTIMEFORMAT only
    public let lineNumber: Int       // 1-based position in the file (ordering)
    public let sourceFile: String

    public init(id: UUID = UUID(), user: String, shell: Shell, command: String,
                timestamp: Date? = nil, lineNumber: Int, sourceFile: String) {
        self.id = id
        self.user = user
        self.shell = shell
        self.command = command
        self.timestamp = timestamp
        self.lineNumber = lineNumber
        self.sourceFile = sourceFile
    }
}

// MARK: - Persistence (cron + systemd)

/// One Linux persistence mechanism: a cron job (system crontab, `/etc/cron.d`,
/// or a user spool crontab) or a systemd service unit. The Linux analogue of
/// the Run-key / scheduled-task / service detections on Windows.
public nonisolated struct LinuxPersistenceEntry: Identifiable, Hashable, Sendable, Codable {
    public enum Kind: String, Sendable, Codable {
        case cron
        case systemdService

        public var label: String {
            switch self {
            case .cron:           return "Cron"
            case .systemdService: return "systemd service"
            }
        }
    }

    public let id: UUID
    public let kind: Kind
    /// Cron: the schedule expression ("* * * * *", "@reboot"). nil for systemd.
    public let schedule: String?
    /// Cron: the user the job runs as (column 6 of system crontabs; the spool
    /// file's owner for user crontabs). systemd: the unit's User=, if set.
    public let user: String?
    /// The command line (cron command / systemd ExecStart).
    public let command: String
    /// systemd: the unit name ("backdoor.service"). nil for cron.
    public let unitName: String?
    /// systemd: Description=, if present.
    public let detail: String?
    public let sourceFile: String

    public init(id: UUID = UUID(), kind: Kind, schedule: String? = nil,
                user: String? = nil, command: String, unitName: String? = nil,
                detail: String? = nil, sourceFile: String) {
        self.id = id
        self.kind = kind
        self.schedule = schedule
        self.user = user
        self.command = command
        self.unitName = unitName
        self.detail = detail
        self.sourceFile = sourceFile
    }

    /// Display name: unit name for systemd, schedule + command head for cron.
    public var title: String {
        if let unitName { return unitName }
        let head = command.split(separator: " ").first.map(String.init) ?? command
        return "\(schedule ?? "?")  \(head)"
    }
}

// MARK: - Linux host info (the Linux host profile source)

/// One row of `/etc/passwd`.
public nonisolated struct LinuxUser: Hashable, Sendable, Codable {
    public let name: String
    public let uid: Int
    public let gid: Int
    public let home: String
    public let shell: String

    public init(name: String, uid: Int, gid: Int, home: String, shell: String) {
        self.name = name
        self.uid = uid
        self.gid = gid
        self.home = home
        self.shell = shell
    }

    /// A shell that lets the account actually log in (vs nologin/false).
    public var hasLoginShell: Bool {
        !(shell.hasSuffix("nologin") || shell.hasSuffix("/false") || shell.isEmpty)
    }
}

/// What `/etc/os-release` + `/etc/hostname` + `/etc/passwd` + `/etc/timezone`
/// tell us about a Linux host - the source for its `HostProfile` (the Linux
/// counterpart of the Windows registry derivation).
public nonisolated struct LinuxHostInfo: Hashable, Sendable, Codable {
    public var prettyName: String?     // "Ubuntu 22.04.4 LTS"
    public var osID: String?           // "ubuntu"
    public var versionID: String?      // "22.04"
    public var hostname: String?
    public var timeZone: String?
    public var users: [LinuxUser] = []

    public init() {}

    public var isEmpty: Bool {
        prettyName == nil && osID == nil && hostname == nil
            && timeZone == nil && users.isEmpty
    }
}
