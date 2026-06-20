import Foundation

/// One boot record from a macOS unified-log **timesync** database
/// (`/var/db/diagnostics/timesync/*.timesync`), with its mach-continuous-time →
/// wall-clock anchors. The unified log stores tracepoint times as
/// mach-continuous time (a monotonic tick count since boot); the timesync DB is
/// what converts those to real dates, accounting for clock adjustments.
///
/// A `.timesync` file holds one or more boot records (each begins with the
/// `0xBBB0` signature), and each boot record is followed by periodic sync
/// records (`"Ts "` / `0x00207354`) that re-anchor continuous time to wall time.
public nonisolated struct TimesyncBoot: Identifiable, Hashable, Sendable, Codable {
    public var id: String { bootUUID }
    /// The boot session UUID (matches the `.tracev3` header's boot UUID).
    public let bootUUID: String
    /// Mach timebase: continuous-time ticks → nanoseconds = ticks · num / denom.
    /// On Apple Silicon this is typically 125/3; on Intel 1/1.
    public let timebaseNumerator: UInt32
    public let timebaseDenominator: UInt32
    /// Wall-clock of boot (continuous time 0), nanoseconds since 1970.
    public let bootTimeNs: UInt64
    /// (continuous_time, walltime_ns) re-anchor points, ascending by ct. The
    /// boot itself is the implicit first anchor (0, bootTimeNs).
    public let anchors: [Anchor]

    public struct Anchor: Hashable, Sendable, Codable {
        public let continuousTime: UInt64
        public let wallTimeNs: UInt64
        public init(continuousTime: UInt64, wallTimeNs: UInt64) {
            self.continuousTime = continuousTime
            self.wallTimeNs = wallTimeNs
        }
    }

    public init(bootUUID: String, timebaseNumerator: UInt32, timebaseDenominator: UInt32,
                bootTimeNs: UInt64, anchors: [Anchor]) {
        self.bootUUID = bootUUID
        self.timebaseNumerator = max(timebaseNumerator, 1)
        self.timebaseDenominator = max(timebaseDenominator, 1)
        self.bootTimeNs = bootTimeNs
        self.anchors = anchors
    }

    /// Convert a mach-continuous time within this boot to a wall-clock `Date`.
    /// Uses the latest anchor at or before `continuousTime`, then adds the
    /// timebase-scaled delta.
    public func walltime(forContinuousTime ct: UInt64) -> Date {
        // Anchors include the implicit boot anchor (0, bootTimeNs) prepended by
        // the parser, so `anchors` is non-empty and ascending.
        let base = anchors.last { $0.continuousTime <= ct } ?? anchors.first
            ?? Anchor(continuousTime: 0, wallTimeNs: bootTimeNs)
        let deltaTicks = ct >= base.continuousTime ? ct - base.continuousTime : 0
        let deltaNs = deltaTicks &* UInt64(timebaseNumerator) / UInt64(timebaseDenominator)
        let wallNs = base.wallTimeNs &+ deltaNs
        return Date(timeIntervalSince1970: Double(wallNs) / 1_000_000_000)
    }
}
