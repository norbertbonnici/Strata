import Foundation

/// **M4** of the macOS unified-log decoder: decode a firehose chunk's
/// tracepoints. A firehose chunk (`0x6001`, inside a decompressed chunkset)
/// begins with a preamble — the emitting process's `(first,second)` proc-id
/// pair, the public-data size, and a base mach-continuous time — followed by a
/// run of fixed-24-byte tracepoint headers each trailed by `data_size` data
/// bytes (8-byte aligned).
///
/// Layout confirmed against the real macOS-12 image and Mandiant's
/// `macos-UnifiedLogs`. The tracepoint **message** is not resolved here (that is
/// M5, needing the `.uuidtext`/`dsc` strings); M4 produces `FirehoseTracepoint`s
/// with timestamp, process, type and level, plus the raw data slice for M5.
public nonisolated enum FirehoseDecoder {

    /// Firehose preamble field offsets within the chunk *data* (after the
    /// 16-byte chunk tag/subtag/size preamble).
    private enum P {
        static let firstProcID = 0      // u64
        static let secondProcID = 8     // u32
        static let publicDataSize = 16  // u16
        static let baseContinuousTime = 24  // u64
        static let tracepointsStart = 32
    }
    /// Fixed tracepoint header size; message data follows, then 8-byte padding.
    private static let tracepointHeaderSize = 24

    /// Decode one firehose chunk's *data* payload into tracepoints, resolving the
    /// emitting process via `catalog`.
    public static func tracepoints(chunkData f: [UInt8], catalog: TraceV3Catalog?) -> [FirehoseTracepoint] {
        let n = f.count
        guard n >= P.tracepointsStart else { return [] }
        func u16(_ o: Int) -> Int { (o + 1 < n) ? Int(f[o]) | (Int(f[o + 1]) << 8) : 0 }
        func u32(_ o: Int) -> UInt32 {
            (o + 3 < n) ? UInt32(f[o]) | (UInt32(f[o + 1]) << 8) | (UInt32(f[o + 2]) << 16) | (UInt32(f[o + 3]) << 24) : 0
        }
        func u64(_ o: Int) -> UInt64 {
            guard o + 7 < n else { return 0 }
            var v: UInt64 = 0; for k in 0..<8 { v |= UInt64(f[o + k]) << (8 * k) }; return v
        }

        let firstProc = u64(P.firstProcID)
        let secondProc = u32(P.secondProcID)
        let publicDataSize = u16(P.publicDataSize)
        let base = u64(P.baseContinuousTime)
        // The public-data size is measured from offset 16 (the size field), so
        // the tracepoint region ends at 16 + publicDataSize — clamped to the
        // chunk. (Validated: this lands exactly on the chunk end.)
        let regionEnd = min(n, P.publicDataSize + publicDataSize)

        let proc = catalog?.processInfo(first: firstProc, second: secondProc)
        let pid = proc?.pid ?? 0
        let euid = proc?.euid ?? 0

        var out: [FirehoseTracepoint] = []
        var p = P.tracepointsStart
        while p + tracepointHeaderSize <= regionEnd {
            let activityType = f[p]
            // An all-zero run is trailing padding, not a tracepoint.
            if activityType == 0 { break }
            let logType = f[p + 1]
            let flags = UInt16(truncatingIfNeeded: u16(p + 2))
            let fmtLoc = u32(p + 4)
            let tid = u64(p + 8)
            let deltaLower = u32(p + 16)
            let deltaUpper = UInt64(u16(p + 20))
            let dataSize = u16(p + 22)
            let dataStart = p + tracepointHeaderSize
            let dataEnd = dataStart + dataSize
            guard dataEnd <= regionEnd else { break }

            let continuousTime = base &+ ((deltaUpper << 32) | UInt64(deltaLower))
            out.append(FirehoseTracepoint(
                activityType: activityType, logType: logType, flags: flags,
                formatStringLocation: fmtLoc, threadID: tid, continuousTime: continuousTime,
                pid: pid, euid: euid, firstProcID: firstProc, secondProcID: secondProc,
                data: Array(f[dataStart..<dataEnd])))

            // Advance past the data, then pad the position to an 8-byte boundary.
            var next = dataEnd
            if next % 8 != 0 { next += 8 - (next % 8) }
            p = next
        }
        return out
    }
}
