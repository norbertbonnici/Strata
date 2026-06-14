import Foundation

/// Inputs that any analyzer can see. Adding a new evidence source (registry
/// hives, MFT $J, prefetch, etc.) means extending this struct, not changing
/// every existing analyzer.
public nonisolated struct AnalysisContext: Sendable {
    public let files: [FileEntry]
    public let events: [EventLogRecord]
    public let timeline: [TimelineEvent]
    public let registryValues: [RegistryValue]
    public let prefetch: [PrefetchEntry]
    public let amcache: [AmcacheEntry]
    public let shimcache: [ShimcacheEntry]
    public let lnk: [LnkEntry]
    public let jumpList: [JumpListEntry]
    public let usn: [UsnRecord]
    public let recycleBin: [RecycleBinEntry]
    public let srum: [SrumEntry]
    public let browserHistory: [BrowserHistoryEntry]
    public let mft: [MftEntry]
    public let wmi: [WmiPersistenceEntry]
    // Linux artifacts (empty on Windows evidence).
    public let authLog: [AuthLogEntry]
    public let logins: [UtmpRecord]
    public let shellHistory: [ShellHistoryEntry]
    public let linuxPersistence: [LinuxPersistenceEntry]
    public let linuxInfo: LinuxHostInfo?
    public let linuxAccess: LinuxAccessInfo?
    public let webAccess: [WebAccessLogEntry]
    public let packages: [PackageEvent]
    public let journald: [JournaldEntry]
    public let audit: [AuditEvent]
    public let syslog: [SyslogEntry]
    public let lastlog: [LastlogEntry]
    // macOS artifacts (empty on Windows/Linux evidence).
    public let launchItems: [LaunchItemEntry]
    public let quarantine: [QuarantineEvent]
    public let macPersistence: [MacPersistenceItem]
    public let fsEvents: [FSEventRecord]
    public let unifiedLog: [UnifiedLogEntry]
    public let tcc: [TCCAccess]

    public init(files: [FileEntry], events: [EventLogRecord],
                timeline: [TimelineEvent], registryValues: [RegistryValue],
                prefetch: [PrefetchEntry] = [], amcache: [AmcacheEntry] = [],
                shimcache: [ShimcacheEntry] = [], lnk: [LnkEntry] = [],
                jumpList: [JumpListEntry] = [], usn: [UsnRecord] = [],
                recycleBin: [RecycleBinEntry] = [],
                srum: [SrumEntry] = [], browserHistory: [BrowserHistoryEntry] = [],
                mft: [MftEntry] = [], wmi: [WmiPersistenceEntry] = [],
                authLog: [AuthLogEntry] = [], logins: [UtmpRecord] = [],
                shellHistory: [ShellHistoryEntry] = [],
                linuxPersistence: [LinuxPersistenceEntry] = [],
                linuxInfo: LinuxHostInfo? = nil, linuxAccess: LinuxAccessInfo? = nil,
                webAccess: [WebAccessLogEntry] = [], packages: [PackageEvent] = [],
                journald: [JournaldEntry] = [], audit: [AuditEvent] = [],
                syslog: [SyslogEntry] = [], lastlog: [LastlogEntry] = [],
                launchItems: [LaunchItemEntry] = [], quarantine: [QuarantineEvent] = [],
                macPersistence: [MacPersistenceItem] = [], fsEvents: [FSEventRecord] = [],
                unifiedLog: [UnifiedLogEntry] = [], tcc: [TCCAccess] = []) {
        self.files = files
        self.events = events
        self.timeline = timeline
        self.registryValues = registryValues
        self.prefetch = prefetch
        self.amcache = amcache
        self.shimcache = shimcache
        self.lnk = lnk
        self.jumpList = jumpList
        self.usn = usn
        self.recycleBin = recycleBin
        self.srum = srum
        self.browserHistory = browserHistory
        self.mft = mft
        self.wmi = wmi
        self.authLog = authLog
        self.logins = logins
        self.shellHistory = shellHistory
        self.linuxPersistence = linuxPersistence
        self.linuxInfo = linuxInfo
        self.linuxAccess = linuxAccess
        self.webAccess = webAccess
        self.packages = packages
        self.journald = journald
        self.audit = audit
        self.syslog = syslog
        self.lastlog = lastlog
        self.launchItems = launchItems
        self.quarantine = quarantine
        self.macPersistence = macPersistence
        self.fsEvents = fsEvents
        self.unifiedLog = unifiedLog
        self.tcc = tcc
    }
}

/// A detection rule. Pure function from evidence to findings - no I/O, no
/// state, so we can run analyzers in parallel and reorder them freely.
public protocol Analyzer: Sendable {
    nonisolated var name: String { get }
    nonisolated func analyze(context: AnalysisContext) -> [Finding]
}
