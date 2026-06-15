import Foundation

/// One of the four NTFS Standard-Information timestamps, in `mactime` order.
public enum MACBKind: String, CaseIterable, Sendable, Codable {
    case modified = "M"
    case accessed = "A"
    case changed  = "C"   // MFT entry modified
    case born     = "B"   // created

    public nonisolated var label: String {
        switch self {
        case .modified: return "Modified"
        case .accessed: return "Accessed"
        case .changed:  return "MFT changed"
        case .born:     return "Created"
        }
    }
}

/// Origin of a timeline event. Filesystem rows come from TSK MACB expansion;
/// evtx rows come from parsed Windows event log records. The axis lets the
/// analyst sessionize over just the meaningful telemetry (evtx) instead of
/// drowning in million-row MACB noise.
public enum TimelineSource: String, CaseIterable, Sendable, Codable {
    case filesystem = "FS"
    case evtx       = "EVTX"
    case registry   = "REG"
    case prefetch   = "PF"
    case shimcache  = "SHIM"
    case amcache    = "AMC"
    case lnk        = "LNK"
    case jumplist   = "JUMP"
    case usn        = "USN"
    case srum       = "SRUM"
    case browser    = "BROWSER"
    case mft        = "MFT"
    case authlog    = "AUTH"
    case logins     = "LOGIN"
    case shellHistory = "SHELL"
    case weblog     = "WEB"
    case package    = "PKG"
    case journald   = "JRNL"
    case auditd     = "AUDIT"
    case syslog     = "SYS"
    case lastlog    = "LAST"
    case unifiedLog = "ULOG"
    case tcc        = "TCC"
    case knowledgeC = "KNOW"
    case macRecent  = "MREC"
    case macSecurity = "MSEC"

    public nonisolated var label: String {
        switch self {
        case .filesystem: return "Filesystem"
        case .evtx:       return "Event Log"
        case .registry:   return "Registry"
        case .prefetch:   return "Prefetch"
        case .shimcache:  return "Shimcache"
        case .amcache:    return "Amcache"
        case .lnk:        return "LNK"
        case .jumplist:   return "JumpLists"
        case .usn:        return "USN Journal"
        case .srum:       return "SRUM"
        case .browser:    return "Browser History"
        case .mft:        return "MFT"
        case .authlog:    return "Auth Log"
        case .logins:     return "Logins"
        case .shellHistory: return "Shell History"
        case .weblog:     return "Web Logs"
        case .package:    return "Packages"
        case .journald:   return "Journal"
        case .auditd:     return "Audit"
        case .syslog:     return "System Log"
        case .lastlog:    return "Last Login"
        case .unifiedLog: return "Unified Log"
        case .tcc:        return "TCC (Privacy)"
        case .knowledgeC: return "KnowledgeC"
        case .macRecent:  return "macOS Recent Items"
        case .macSecurity: return "macOS Security"
        }
    }
}

/// A single point on the timeline: one timestamp of one file.
/// Each FileEntry expands into up to four of these (the mactime model).
///
/// `nonisolated` so the (pure) value type and its memberwise init can be
/// constructed off the main actor - `TimelineBuilder.build` runs nonisolated
/// during off-main case load.
public nonisolated struct TimelineEvent: Identifiable, Hashable, Sendable {
    public let id: UUID
    public let date: Date
    public let kind: MACBKind
    public let source: TimelineSource
    public let fileID: Int64
    public let path: String
    public let size: Int64
    public let isDeleted: Bool
    /// Set only for `.evtx` rows. Carries the Windows event ID so the
    /// table can render it in place of the MACB badge without re-parsing
    /// the path.
    public let eventID: UInt32?

    public init(date: Date, kind: MACBKind, source: TimelineSource = .filesystem,
                fileID: Int64, path: String, size: Int64, isDeleted: Bool,
                eventID: UInt32? = nil) {
        self.id = UUID()
        self.date = date; self.kind = kind; self.source = source; self.fileID = fileID
        self.path = path; self.size = size; self.isDeleted = isDeleted
        self.eventID = eventID
    }

    /// Content-derived identity that survives reloads. `id` is a fresh UUID per
    /// parse (the timeline is rebuilt from artifacts on every case open), so
    /// anything persisted *about* an event - an analyst bookmark - keys off
    /// this instead. The date uses the raw bit pattern: artifact decoding is
    /// deterministic, and formatting a Double would risk locale/rounding drift.
    public var stableKey: String {
        "\(source.rawValue)|\(kind.rawValue)|\(date.timeIntervalSinceReferenceDate.bitPattern)|\(eventID ?? 0)|\(path)"
    }
}
