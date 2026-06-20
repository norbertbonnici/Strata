import Foundation

/// One classified line from the general system log (`/var/log/syslog` on
/// Debian, `/var/log/messages` on RHEL). Shares the syslog line shape with
/// `auth.log`, but carries the *non-auth* telemetry: kernel USB insertions,
/// OOM kills, segfaults, disk errors, systemd unit lifecycle / crash loops, and
/// cron execution. Auth-class lines (sshd/sudo/su/sessions) are left to the
/// auth-log path and de-duplicated out here.
public nonisolated struct SyslogEntry: Identifiable, Hashable, Sendable, Codable {
    /// High-signal category derived from (program, message). Drives the view
    /// filter + analyzers without re-grepping.
    public enum Category: String, Codable, Sendable, CaseIterable {
        case usbDevice          // kernel: new USB device
        case massStorage        // usb-storage / sd node attached
        case outOfMemory        // OOM killer
        case segfault           // segfault / GP fault / invalid opcode
        case processKilled      // "Killed process N"
        case diskError          // I/O error, EXT4-fs error, medium error
        case networkError       // link down, fw drop
        case serviceStarted
        case serviceStopped
        case serviceFailed      // unit Failed with result
        case crashLoop          // restart counter / start request repeated
        case cronExec           // CRON (user) CMD (...)
        case suSession          // su elevation
        case other

        public var label: String {
            switch self {
            case .usbDevice:      return "USB device"
            case .massStorage:    return "Mass storage"
            case .outOfMemory:    return "Out of memory"
            case .segfault:       return "Segfault"
            case .processKilled:  return "Process killed"
            case .diskError:      return "Disk error"
            case .networkError:   return "Network error"
            case .serviceStarted: return "Service started"
            case .serviceStopped: return "Service stopped"
            case .serviceFailed:  return "Service failed"
            case .crashLoop:      return "Crash loop"
            case .cronExec:       return "Cron exec"
            case .suSession:      return "su"
            case .other:          return "Other"
            }
        }

        /// Low-value / high-volume categories hidden by default in the view and
        /// kept off the timeline splice.
        public var isNoise: Bool {
            self == .serviceStarted || self == .serviceStopped || self == .other
        }
    }

    public let id: UUID
    public let timestamp: Date?
    public let host: String
    public let process: String
    public let pid: Int?
    public let category: Category
    public let message: String
    /// cron user / su target, when applicable.
    public let user: String?
    /// cron command / su shell, when applicable.
    public let command: String?
    /// systemd unit name, when applicable.
    public let unit: String?
    public let sourceFile: String

    public init(id: UUID = UUID(), timestamp: Date?, host: String, process: String,
                pid: Int? = nil, category: Category, message: String, user: String? = nil,
                command: String? = nil, unit: String? = nil, sourceFile: String) {
        self.id = id
        self.timestamp = timestamp
        self.host = host
        self.process = process
        self.pid = pid
        self.category = category
        self.message = message
        self.user = user
        self.command = command
        self.unit = unit
        self.sourceFile = sourceFile
    }
}

/// One populated record from `/var/log/lastlog` - the last login for one
/// account. The file is a UID-indexed array of fixed 292-byte records; the
/// account is the record's *position*, never stored. Gives a one-snapshot "last
/// login per user" view that survives `wtmp` rotation.
public nonisolated struct LastlogEntry: Identifiable, Hashable, Sendable, Codable {
    public let id: UUID
    /// UID = the record's index in the file.
    public let uid: Int
    /// Resolved username (from /etc/passwd), when available.
    public let user: String?
    public let timestamp: Date?     // ll_time (epoch). Records with 0 are dropped.
    public let line: String         // ll_line: tty / pts / "ssh"
    public let host: String         // ll_host: remote source (empty for local)
    public let sourceFile: String

    public init(id: UUID = UUID(), uid: Int, user: String? = nil, timestamp: Date?,
                line: String, host: String, sourceFile: String) {
        self.id = id
        self.uid = uid
        self.user = user
        self.timestamp = timestamp
        self.line = line
        self.host = host
        self.sourceFile = sourceFile
    }

    public var account: String { user ?? "uid \(uid)" }
}
