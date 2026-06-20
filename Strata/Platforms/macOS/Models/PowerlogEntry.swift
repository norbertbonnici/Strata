import Foundation

/// One macOS **Powerlog** activity record (the powerd analytics SQLite store,
/// `CurrentPowerlog.PLSQL`). Powerlog is one of the few macOS artifacts that
/// records true **process-execution** timing — process names + bundle ids +
/// PIDs powerd observed, app launch/exit lifecycle, the frontmost app, and
/// per-process network volume — surviving independently of the unified log.
///
/// Pure / `Sendable` / no I/O — the macOS-only `PowerlogParser` reads the SQLite
/// store via GRDB and applies the `TIMEOFFSET` clock correction.
public nonisolated struct PowerlogEntry: Identifiable, Hashable, Sendable, Codable {
    /// Which Powerlog table the record came from.
    public enum Kind: String, Sendable, Codable, CaseIterable {
        case process       // PLPROCESSMONITORAGENT_EVENTFORWARD_PROCESSID
        case appLifecycle  // PLAPPLICATIONAGENT_EVENTFORWARD_APPLIFECYCLE
        case frontmost     // PLAPPLICATIONAGENT_EVENTFORWARD_FRONTMOSTAPP
        case network       // PLPROCESSNETWORKAGENT_EVENTINTERVAL_USAGEDIFF

        public nonisolated var label: String {
            switch self {
            case .process:      return "Process"
            case .appLifecycle: return "App lifecycle"
            case .frontmost:    return "Frontmost"
            case .network:      return "Network"
            }
        }
    }

    public let id: UUID
    public let kind: Kind
    public let processName: String?
    public let bundleID: String?
    public let pid: Int64?
    /// Raw lifecycle EVENT text (e.g. "Foreground"/"Background"), when present.
    public let event: String?
    /// The offset-corrected wall-clock timestamp (interval start for `.network`).
    public let date: Date?
    /// Interval end, set only for `.network` records.
    public let endDate: Date?
    public let bytesIn: Int64?
    public let bytesOut: Int64?
    public let scope: String
    public let sourceFile: String

    public init(id: UUID = UUID(), kind: Kind, processName: String? = nil,
                bundleID: String? = nil, pid: Int64? = nil, event: String? = nil,
                date: Date? = nil, endDate: Date? = nil,
                bytesIn: Int64? = nil, bytesOut: Int64? = nil,
                scope: String, sourceFile: String) {
        self.id = id
        self.kind = kind
        self.processName = processName
        self.bundleID = bundleID
        self.pid = pid
        self.event = event
        self.date = date
        self.endDate = endDate
        self.bytesIn = bytesIn
        self.bytesOut = bytesOut
        self.scope = scope
        self.sourceFile = sourceFile
    }

    public var timestamp: Date? { date }

    public var displayName: String {
        if let p = processName, !p.isEmpty { return p }
        if let b = bundleID, !b.isEmpty { return b }
        return "(unknown)"
    }

    public var timelineSummary: String {
        let who = displayName
        switch kind {
        case .process:
            return "[Powerlog] process: \(who)" + (pid.map { " (pid \($0))" } ?? "")
        case .appLifecycle:
            return "[Powerlog] app \(event ?? "lifecycle"): \(who)"
        case .frontmost:
            return "[Powerlog] frontmost app: \(who)"
        case .network:
            return "[Powerlog] network: \(who) (in \(bytesIn ?? 0) / out \(bytesOut ?? 0) bytes)"
        }
    }
}
