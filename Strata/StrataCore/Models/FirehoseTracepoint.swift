import Foundation

/// One decoded **firehose tracepoint** — a single log record inside a firehose
/// chunk (`0x6001`), before its message is resolved. Carries the fixed 24-byte
/// tracepoint header fields, the absolute mach-continuous time (base + delta),
/// the emitting process resolved from the catalog, and the raw data slice that
/// M5 will parse against the `.uuidtext`/`dsc` format string to render the
/// message. This is an in-memory intermediate (not persisted); the persisted /
/// displayed shape is `UnifiedLogEntry`.
public nonisolated struct FirehoseTracepoint: Sendable, Hashable {
    /// Firehose activity type (`0x02` activity, `0x03` trace, `0x04` log,
    /// `0x06` signpost, `0x07` loss).
    public let activityType: UInt8
    /// Log type / level for a log tracepoint (`0x00` default … `0x11` fault).
    public let logType: UInt8
    public let flags: UInt16
    /// Offset of the format string in the `.uuidtext`/`dsc` (resolved in M5).
    public let formatStringLocation: UInt32
    public let threadID: UInt64
    /// Absolute mach-continuous time (firehose base + tracepoint delta).
    public let continuousTime: UInt64
    /// Emitting process, from the catalog `(first,second)` proc-id pair.
    public let pid: UInt32
    public let euid: UInt32
    public let firstProcID: UInt64
    public let secondProcID: UInt32
    /// The tracepoint's data-item bytes (`data_size` long) — M5 input.
    public let data: [UInt8]

    public init(activityType: UInt8, logType: UInt8, flags: UInt16,
                formatStringLocation: UInt32, threadID: UInt64, continuousTime: UInt64,
                pid: UInt32, euid: UInt32, firstProcID: UInt64, secondProcID: UInt32,
                data: [UInt8]) {
        self.activityType = activityType; self.logType = logType; self.flags = flags
        self.formatStringLocation = formatStringLocation; self.threadID = threadID
        self.continuousTime = continuousTime; self.pid = pid; self.euid = euid
        self.firstProcID = firstProcID; self.secondProcID = secondProcID; self.data = data
    }

    /// Firehose activity type → `UnifiedLogEntry.EventType`.
    public var eventType: UnifiedLogEntry.EventType {
        switch activityType {
        case 0x02: return .activity
        case 0x03: return .trace
        case 0x04: return .log
        case 0x06: return .signpost
        case 0x07: return .loss
        default:   return .unknown
        }
    }

    /// Log type → `UnifiedLogEntry.Level` (meaningful for `.log` tracepoints).
    public var level: UnifiedLogEntry.Level {
        switch logType {
        case 0x00: return .default
        case 0x01: return .info
        case 0x02: return .debug
        case 0x10: return .error
        case 0x11: return .fault
        default:   return .default
        }
    }

    /// Project to a partial `UnifiedLogEntry`. `timestamp` is resolved through
    /// the boot's timesync anchors; `process`/`subsystem`/`category`/`message`
    /// stay empty until M5 resolves the `.uuidtext`/`dsc` strings.
    public func partialEntry(timesync: TimesyncBoot?, sourceFile: String) -> UnifiedLogEntry {
        UnifiedLogEntry(timestamp: timesync?.walltime(forContinuousTime: continuousTime),
                        eventType: eventType, level: level, pid: Int(pid),
                        message: "", sourceFile: sourceFile)
    }
}
