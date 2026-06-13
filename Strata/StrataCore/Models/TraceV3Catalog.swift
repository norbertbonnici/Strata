import Foundation

/// The `.tracev3` **file header** (chunk tag `0x1000`) — boot session metadata.
/// Decoded from the fixed header fields plus its tagged sub-records
/// (`0x6100` continuous-time, `0x6101` system info, `0x6102` boot UUID,
/// `0x6103` timezone). The **boot UUID** ties a file to its timesync boot
/// session (`TimesyncBoot`), and the mach timebase + continuous-time base feed
/// the firehose timestamp math.
public nonisolated struct TraceV3Header: Sendable, Hashable, Codable {
    public let bootUUID: String
    public let timebaseNumerator: UInt32
    public let timebaseDenominator: UInt32
    /// Boot continuous-time base (== catalog `earliestFirehoseTimestamp`).
    public let continuousTime: UInt64
    /// Wall-clock of the header record, seconds since 1970.
    public let startWalltimeSeconds: UInt64
    /// Timezone bias in minutes (e.g. -120 for UTC+2).
    public let timezoneBiasMinutes: Int32
    public let osBuild: String
    public let hardwareModel: String
    public let timezonePath: String

    public init(bootUUID: String, timebaseNumerator: UInt32, timebaseDenominator: UInt32,
                continuousTime: UInt64, startWalltimeSeconds: UInt64,
                timezoneBiasMinutes: Int32, osBuild: String, hardwareModel: String,
                timezonePath: String) {
        self.bootUUID = bootUUID
        self.timebaseNumerator = max(timebaseNumerator, 1)
        self.timebaseDenominator = max(timebaseDenominator, 1)
        self.continuousTime = continuousTime
        self.startWalltimeSeconds = startWalltimeSeconds
        self.timezoneBiasMinutes = timezoneBiasMinutes
        self.osBuild = osBuild
        self.hardwareModel = hardwareModel
        self.timezonePath = timezonePath
    }
}

/// The `(first, second)` process-id pair that a firehose chunk carries and a
/// catalog `ProcessInfo` entry is keyed by — the join between a tracepoint and
/// the process that emitted it.
public nonisolated struct ProcIDKey: Hashable, Sendable, Codable {
    public let first: UInt64
    public let second: UInt32
    public init(first: UInt64, second: UInt32) { self.first = first; self.second = second }
}

/// One catalog **ProcessInfo** entry: the process behind a `(first,second)`
/// proc-id pair, its PID/EUID, the catalog-UUID indices of its main executable
/// and shared-cache (`dsc`), the per-process loaded-image table (for M5 absolute
/// address → image resolution), and the subsystem/category string map a
/// firehose tracepoint's subsystem identifier resolves through.
public nonisolated struct CatalogProcessInfo: Sendable, Hashable, Codable {
    public let firstProcID: UInt64
    public let secondProcID: UInt32
    public let pid: UInt32
    public let euid: UInt32
    public let mainUUIDIndex: Int
    public let dscUUIDIndex: Int
    public let uuidEntries: [UUIDEntry]
    public let subsystems: [Subsystem]

    /// A loaded-image range used to resolve an absolute program counter to a
    /// UUID (M5). `size` is the image's text size; `uuidIndex` indexes the
    /// catalog UUID array.
    public struct UUIDEntry: Sendable, Hashable, Codable {
        public let size: UInt32
        public let uuidIndex: Int
        public init(size: UInt32, uuidIndex: Int) { self.size = size; self.uuidIndex = uuidIndex }
    }

    /// A subsystem/category pair keyed by the per-process identifier a firehose
    /// tracepoint references.
    public struct Subsystem: Sendable, Hashable, Codable {
        public let identifier: UInt16
        public let subsystem: String
        public let category: String
        public init(identifier: UInt16, subsystem: String, category: String) {
            self.identifier = identifier; self.subsystem = subsystem; self.category = category
        }
    }

    public init(firstProcID: UInt64, secondProcID: UInt32, pid: UInt32, euid: UInt32,
                mainUUIDIndex: Int, dscUUIDIndex: Int, uuidEntries: [UUIDEntry],
                subsystems: [Subsystem]) {
        self.firstProcID = firstProcID; self.secondProcID = secondProcID
        self.pid = pid; self.euid = euid
        self.mainUUIDIndex = mainUUIDIndex; self.dscUUIDIndex = dscUUIDIndex
        self.uuidEntries = uuidEntries; self.subsystems = subsystems
    }

    public var key: ProcIDKey { ProcIDKey(first: firstProcID, second: secondProcID) }

    /// Resolve a firehose subsystem identifier to its subsystem/category strings.
    public func subsystem(for identifier: UInt16) -> Subsystem? {
        subsystems.first { $0.identifier == identifier }
    }
}

/// A catalog **subchunk**: the continuous-time window covered by one compressed
/// chunkset and its uncompressed size. The `[start,end]` range lets a decoded
/// firehose chunk be attributed to a boot session and bounded in time.
public nonisolated struct CatalogSubchunk: Sendable, Hashable, Codable {
    public let startContinuousTime: UInt64
    public let endContinuousTime: UInt64
    public let uncompressedSize: UInt32
    public let compressionAlgorithm: UInt32
    public init(startContinuousTime: UInt64, endContinuousTime: UInt64,
                uncompressedSize: UInt32, compressionAlgorithm: UInt32) {
        self.startContinuousTime = startContinuousTime
        self.endContinuousTime = endContinuousTime
        self.uncompressedSize = uncompressedSize
        self.compressionAlgorithm = compressionAlgorithm
    }
}

/// A decoded `.tracev3` **catalog** chunk (`0x600B`): the UUID array (referenced
/// by index from process-info entries), the process-info entries (keyed by
/// proc-id pair), and the subchunk time windows.
public nonisolated struct TraceV3Catalog: Sendable, Hashable, Codable {
    public let uuids: [String]
    public let processInfos: [CatalogProcessInfo]
    public let subchunks: [CatalogSubchunk]
    public let earliestFirehoseTimestamp: UInt64

    public init(uuids: [String], processInfos: [CatalogProcessInfo],
                subchunks: [CatalogSubchunk], earliestFirehoseTimestamp: UInt64) {
        self.uuids = uuids; self.processInfos = processInfos
        self.subchunks = subchunks; self.earliestFirehoseTimestamp = earliestFirehoseTimestamp
    }

    /// The process behind a firehose `(first,second)` proc-id pair.
    public func processInfo(first: UInt64, second: UInt32) -> CatalogProcessInfo? {
        processInfos.first { $0.firstProcID == first && $0.secondProcID == second }
    }

    /// The catalog UUID at an index (nil if out of range).
    public func uuid(at index: Int) -> String? {
        (index >= 0 && index < uuids.count) ? uuids[index] : nil
    }
}
