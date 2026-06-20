import Foundation

/// One decoded record from the macOS **unified log** (`*.tracev3` under
/// `/var/db/diagnostics/` + `/var/db/uuidtext/`). The unified log is the modern
/// macOS system log (it replaced ASL / `/var/log/system.log`), and is the
/// richest single source of process execution, auth, TCC, and network activity
/// on a Mac.
///
/// **Build status.** Decoding `.tracev3` is multi-layered: a chunked binary
/// container (this is parsed in Phase 1 — see `TraceV3Parser`), whose firehose
/// tracepoints reference format strings stored *out of file* in `.uuidtext` /
/// the `dsc` shared cache, with timestamps in mach-continuous time that a
/// `timesync` boot record converts to wall clock. This value type is the target
/// shape those later phases populate; the container parser does not yet emit it.
///
/// Pure / `Sendable` / no I/O so it's testable off-main and usable on iOS.
public nonisolated struct UnifiedLogEntry: Identifiable, Hashable, Sendable, Codable {
    /// The unified-log activity kind a tracepoint records.
    public enum EventType: String, Sendable, Codable {
        case log, activity, trace, signpost, statedump, simpledump, loss, unknown
        public var label: String { rawValue.capitalized }
    }

    /// Log message level (`OS_LOG_TYPE_*`).
    public enum Level: String, Sendable, Codable {
        case `default`, info, debug, error, fault, unknown
        public var label: String { rawValue.capitalized }
    }

    public let id: UUID
    /// Wall-clock time (mach-continuous time resolved through the timesync boot
    /// record). nil until the timesync/firehose phase populates it.
    public let timestamp: Date?
    public let eventType: EventType
    public let level: Level
    public let pid: Int?
    /// Emitting process image path (or its leaf), resolved from the catalog.
    public let process: String?
    /// `subsystem` / `category` from the format-string metadata, when present.
    public let subsystem: String?
    public let category: String?
    /// The rendered log message (format string + arguments). Empty until the
    /// `.uuidtext` / `dsc` resolution phase fills it in.
    public let message: String
    /// The source `.tracev3` file the record came from.
    public let sourceFile: String

    public init(id: UUID = UUID(), timestamp: Date? = nil,
                eventType: EventType = .unknown, level: Level = .default,
                pid: Int? = nil, process: String? = nil,
                subsystem: String? = nil, category: String? = nil,
                message: String = "", sourceFile: String) {
        self.id = id
        self.timestamp = timestamp
        self.eventType = eventType
        self.level = level
        self.pid = pid
        self.process = process
        self.subsystem = subsystem
        self.category = category
        self.message = message
        self.sourceFile = sourceFile
    }
}
