import Foundation

/// Windows `FILETIME` helpers. FILETIME counts **100-nanosecond ticks since
/// 1601-01-01 UTC** — a 7-decimal sub-second resolution that a `Date` (a `Double`
/// of seconds) physically cannot hold at modern instants (the value exceeds the
/// 52-bit mantissa). So timestamps that need full forensic precision are stored
/// raw (`UInt64`) and rendered losslessly here.
public nonisolated enum FileTime {
    /// 100-ns ticks between the FILETIME epoch (1601) and the Unix epoch (1970).
    static let unixEpochTicks: Int64 = 11_644_473_600 * 10_000_000   // 116444736000000000
    private static let ticksPerSecond: Int64 = 10_000_000

    /// Lossy `Date` (Double seconds) — fine for the timeline, sorting, and
    /// coarse (≥1 s) comparisons. nil for 0 (unset) or implausible values
    /// (outside ~1601–2200) so a garbage record doesn't pollute the timeline.
    public static func date(_ ft: UInt64) -> Date? {
        guard ft != 0 else { return nil }
        let secs = Double(ft) / Double(ticksPerSecond) - 11_644_473_600
        guard secs > -11_644_473_600, secs < 7_258_118_400 else { return nil }
        return Date(timeIntervalSince1970: secs)
    }

    /// Lossless UTC string with the full 100-ns precision, e.g.
    /// `2019-11-22 12:29:11.9188377`. nil for 0 (unset).
    public static func precise(_ ft: UInt64) -> String? {
        guard ft != 0 else { return nil }
        // Overflow-safe: a hostile FILETIME with the top bit set underflows Int64
        // here (the bare `-` would trap); treat such a value as unrenderable.
        let (unixTicks, overflow) = Int64(bitPattern: ft).subtractingReportingOverflow(unixEpochTicks)
        guard !overflow else { return nil }   // can be negative (pre-1970)
        var seconds = unixTicks / ticksPerSecond
        var sub = unixTicks % ticksPerSecond
        if sub < 0 { sub += ticksPerSecond; seconds -= 1 }       // floor toward the past
        let whole = formatter.string(from: Date(timeIntervalSince1970: Double(seconds)))
        return whole + String(format: ".%07d", sub)
    }

    /// True when the tick value is whole-second (zero 100-ns sub-second) — the
    /// timestomp-tool fingerprint. Exact (no float rounding), unlike a `Date`.
    public static func isWholeSecond(_ ft: UInt64) -> Bool {
        ft != 0 && ft % UInt64(ticksPerSecond) == 0
    }

    private static let formatter: DateFormatter = {
        let f = DateFormatter()
        f.dateFormat = "yyyy-MM-dd HH:mm:ss"
        f.locale = Locale(identifier: "en_US_POSIX")
        f.timeZone = TimeZone(identifier: "UTC")
        return f
    }()
}
