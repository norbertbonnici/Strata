import Foundation

/// One logical event from the Linux audit daemon log (`/var/log/audit/
/// audit.log`). auditd emits several records per event (SYSCALL + EXECVE +
/// PROCTITLE + CWD + PATH, or a USER_* record), all sharing the same
/// `audit(epoch:serial)` id; `AuditParser` folds that group into this single
/// triage row. The kernel's audit trail uniquely records *what executed*, *who*
/// (the immutable login uid), and *what files were touched* - evidence no other
/// Linux source carries, and which survives even when auth.log was wiped.
public nonisolated struct AuditEvent: Identifiable, Hashable, Sendable, Codable {
    public let id: UUID
    public let timestamp: Date?
    /// The `audit(epoch:SERIAL)` serial - the event id the records grouped on.
    public let serial: Int
    /// Primary record type that drove the fold (SYSCALL / EXECVE / USER_AUTH /
    /// ADD_USER / AVC / …).
    public let recordType: String
    /// Resolved syscall name (e.g. "execve"), when a SYSCALL record was present.
    public let syscall: String?
    public let success: Bool?
    public let exit: Int?
    /// Executable image path (`exe=`).
    public let exe: String?
    /// Short process name (`comm=`).
    public let comm: String?
    /// Full command line, reconstructed from the EXECVE args (falling back to
    /// the decoded PROCTITLE).
    public let commandLine: String?
    /// Working dir (`cwd=`) + first touched path (`PATH name=`).
    public let path: String?
    /// Login uid - the original user, immutable across su/sudo. nil = unset.
    public let auid: Int?
    public let uid: Int?
    /// Audit session id; nil = unset.
    public let ses: Int?
    public let tty: String?
    /// Firing audit rule key (`key=`), when set.
    public let key: String?
    /// USER_* records: the account (`acct=`), verdict (`res=`), source.
    public let account: String?
    public let result: String?      // "success" / "failed"
    public let sourceIP: String?    // USER_* addr=
    public let sourceFile: String

    public init(id: UUID = UUID(), timestamp: Date?, serial: Int, recordType: String,
                syscall: String? = nil, success: Bool? = nil, exit: Int? = nil,
                exe: String? = nil, comm: String? = nil, commandLine: String? = nil,
                path: String? = nil, auid: Int? = nil, uid: Int? = nil, ses: Int? = nil,
                tty: String? = nil, key: String? = nil, account: String? = nil,
                result: String? = nil, sourceIP: String? = nil, sourceFile: String) {
        self.id = id
        self.timestamp = timestamp
        self.serial = serial
        self.recordType = recordType
        self.syscall = syscall
        self.success = success
        self.exit = exit
        self.exe = exe
        self.comm = comm
        self.commandLine = commandLine
        self.path = path
        self.auid = auid
        self.uid = uid
        self.ses = ses
        self.tty = tty
        self.key = key
        self.account = account
        self.result = result
        self.sourceIP = sourceIP
        self.sourceFile = sourceFile
    }

    /// One-line display of the most salient content.
    public var summary: String {
        if let commandLine { return commandLine }
        if let exe { return exe }
        if let account { return "\(recordType): \(account)\(result.map { " (\($0))" } ?? "")" }
        return recordType
    }
}
