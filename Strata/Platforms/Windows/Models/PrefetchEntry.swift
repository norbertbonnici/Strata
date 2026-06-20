import Foundation

/// A parsed Windows Prefetch (`.pf`) file - evidence of program execution.
///
/// Windows writes one `.pf` per executable launched from
/// `C:\Windows\Prefetch\`, recording how many times it ran, the timestamps of
/// its most recent runs (up to 8 on Win8+, a single one on Win7), and the
/// volumes + files it touched while starting. That makes prefetch one of the
/// highest-signal execution artifacts in a triage: it survives the binary's
/// deletion and pins a program to a wall-clock run time.
///
/// Produced by `PrefetchParser` (libscca's `sccainfo`); persisted per host as
/// `prefetch.json` inside the case bundle.
public nonisolated struct PrefetchEntry: Identifiable, Hashable, Sendable, Codable {
    public let id: UUID
    /// Executable name as recorded in the prefetch header, e.g. "CMD.EXE".
    public let executableName: String
    /// Best-effort full NT path of the executable, recovered from the file
    /// metrics array, e.g. "\\VOLUME{...}\\WINDOWS\\SYSTEM32\\CMD.EXE". nil when
    /// it couldn't be matched (rare). The analyzer keys path-based detections
    /// off this.
    public let executablePath: String?
    /// Total launches Windows has counted. Can exceed `lastRunTimes.count`
    /// because only the most recent runs keep a timestamp.
    public let runCount: UInt32
    /// Recorded run timestamps, most-recent first. 1 entry on Win7, up to 8 on
    /// Win8+. Empty only for a malformed/empty file.
    public let lastRunTimes: [Date]
    /// Number of files the program referenced while starting (DLLs, data, etc.).
    public let fileCount: Int
    /// Number of distinct volumes referenced.
    public let volumeCount: Int
    /// Prefetch format version (17 = Win7, 23 = Win8, 30/31 = Win10/11). nil if
    /// the tool didn't report it.
    public let formatVersion: Int?
    /// Source `.pf` path the entry was parsed from.
    public let sourceFile: String

    public init(id: UUID = UUID(), executableName: String, executablePath: String? = nil,
                runCount: UInt32, lastRunTimes: [Date], fileCount: Int = 0,
                volumeCount: Int = 0, formatVersion: Int? = nil, sourceFile: String) {
        self.id = id
        self.executableName = executableName
        self.executablePath = executablePath
        self.runCount = runCount
        self.lastRunTimes = lastRunTimes
        self.fileCount = fileCount
        self.volumeCount = volumeCount
        self.formatVersion = formatVersion
        self.sourceFile = sourceFile
    }

    /// Most recent execution, if any timestamp survived.
    public var lastRun: Date? { lastRunTimes.first }
    /// Oldest of the *recorded* runs (not necessarily the program's first ever
    /// run, since only the last 8 keep timestamps).
    public var oldestRecordedRun: Date? { lastRunTimes.last }
}
