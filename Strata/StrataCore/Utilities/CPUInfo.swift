import Foundation

/// CPU-topology helpers for sizing CPU-bound parallel work.
///
/// On Apple Silicon `ProcessInfo.activeProcessorCount` counts **all** cores —
/// performance (P) *and* efficiency (E). For throughput work (carving, bulk
/// decode) we'd rather fan out only to the P-cores and let a high-QoS scheduler
/// keep the work there, instead of oversubscribing onto the slower E-cores and
/// contending for memory bandwidth.
///
/// macOS has **no public hard core-affinity / pinning API** — the old
/// `THREAD_AFFINITY_POLICY` is a no-op on Apple Silicon — so the realistic way to
/// "run on the performance cores" is: size the fan-out to `performanceCoreCount`
/// and run at `.userInitiated` (or higher) QoS, which the scheduler biases onto
/// P-cores.
public nonisolated enum CPUInfo {
    /// Logical performance-core count: `hw.perflevel0.logicalcpu` on a
    /// heterogeneous machine (Apple Silicon, `hw.nperflevels > 1`), or the full
    /// active processor count on a uniform machine (Intel / older). Always ≥ 1.
    public static var performanceCoreCount: Int {
        let active = max(1, ProcessInfo.processInfo.activeProcessorCount)
        // perflevel0 is the fastest level (P-cores); only meaningful when the
        // machine actually has more than one performance level.
        guard let levels = sysctlInt("hw.nperflevels"), levels > 1,
              let perf = sysctlInt("hw.perflevel0.logicalcpu"), perf > 0 else {
            return active
        }
        return min(perf, active)
    }

    /// Read an integer `sysctl` by name. These hw.* values are 32-bit ints; a
    /// zero-initialised `Int` read on little-endian Apple hardware captures them
    /// correctly regardless of the 4- vs 8-byte width sysctl reports back.
    private static func sysctlInt(_ name: String) -> Int? {
        var value = 0
        var size = MemoryLayout<Int>.size
        return sysctlbyname(name, &value, &size, nil, 0) == 0 ? value : nil
    }
}
