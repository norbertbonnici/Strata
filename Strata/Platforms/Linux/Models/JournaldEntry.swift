import Foundation

/// One log entry from a systemd **journald** binary journal
/// (`/var/log/journal/<machine-id>/*.journal`). On a modern systemd host the
/// journal is often the *only* place auth/service/kernel events live -
/// `auth.log`/`secure` may not exist at all - so this closes the biggest Linux
/// log-coverage gap. Decoded by the pure-Swift `JournaldParser` (no vendored
/// tool); persisted per host as `journald.json`, spliced onto the timeline.
public nonisolated struct JournaldEntry: Identifiable, Hashable, Sendable, Codable {
    public let id: UUID
    /// `__REALTIME_TIMESTAMP` - microseconds since the Unix epoch (UTC, exact).
    public let timestamp: Date?
    /// `MESSAGE` (empty when it was compressed with an unsupported codec).
    public let message: String
    /// `PRIORITY` - syslog severity 0 (emerg) … 7 (debug).
    public let priority: Int?
    /// `_COMM` - the process name.
    public let comm: String?
    /// `_PID`.
    public let pid: Int?
    /// `_SYSTEMD_UNIT` - the owning unit, e.g. `ssh.service`.
    public let unit: String?
    /// `SYSLOG_IDENTIFIER` - the logging program, e.g. `sshd`, `sudo`.
    public let identifier: String?
    /// `_HOSTNAME`.
    public let hostname: String?
    /// `_UID`.
    public let uid: Int?
    /// `_BOOT_ID` (hex) - groups entries by boot session.
    public let bootID: String?
    public let sourceFile: String

    public init(id: UUID = UUID(), timestamp: Date?, message: String, priority: Int? = nil,
                comm: String? = nil, pid: Int? = nil, unit: String? = nil,
                identifier: String? = nil, hostname: String? = nil, uid: Int? = nil,
                bootID: String? = nil, sourceFile: String) {
        self.id = id
        self.timestamp = timestamp
        self.message = message
        self.priority = priority
        self.comm = comm
        self.pid = pid
        self.unit = unit
        self.identifier = identifier
        self.hostname = hostname
        self.uid = uid
        self.bootID = bootID
        self.sourceFile = sourceFile
    }

    /// The program that emitted the line: SYSLOG_IDENTIFIER, else _COMM.
    public var program: String? { identifier ?? comm }

    /// syslog severity label for the priority value.
    public var priorityLabel: String? {
        guard let priority else { return nil }
        switch priority {
        case 0: return "emerg"
        case 1: return "alert"
        case 2: return "crit"
        case 3: return "err"
        case 4: return "warning"
        case 5: return "notice"
        case 6: return "info"
        case 7: return "debug"
        default: return String(priority)
        }
    }
}
