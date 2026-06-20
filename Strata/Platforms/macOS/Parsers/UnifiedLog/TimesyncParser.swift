import Foundation

/// Pure-Swift parser for the macOS unified-log **timesync** database
/// (`/var/db/diagnostics/timesync/*.timesync`). Its sole job is to recover the
/// mach-continuous-time → wall-clock anchors so the firehose tracepoint times
/// (continuous-time deltas) can be rendered as real dates. No vendored tool.
///
/// File layout (little-endian), confirmed against a real macOS-12 `.timesync`:
///   one or more **boot records**, each followed by its **sync records** —
///
///   Boot record (48 bytes):
///     0x00  u16  signature  = 0xBBB0
///     0x02  u16  header size = 0x0030
///     0x04  u32  (unknown / padding)
///     0x08  16   boot UUID
///     0x18  u32  mach timebase numerator
///     0x1C  u32  mach timebase denominator
///     0x20  u64  boot walltime, nanoseconds since 1970 (== continuous time 0)
///     0x28  u32  timezone offset   (unused here)
///     0x2C  u32  daylight-saving   (unused here)
///
///   Sync record (32 bytes):
///     0x00  u32  signature  = 0x00207354 ("Ts ")
///     0x04  u32  (flags / index)
///     0x08  u64  mach continuous time
///     0x10  u64  walltime, nanoseconds since 1970
///     0x18  u32  timezone offset   (unused here)
///     0x1C  u32  daylight-saving   (unused here)
public enum TimesyncParser {
    private static let bootSignature: UInt16 = 0xBBB0
    private static let syncSignature: UInt32 = 0x0020_7354   // "Ts "
    private static let bootRecordSize = 48
    private static let syncRecordSize = 32

    /// Parse a single `.timesync` file into its boot records (each with anchors).
    public static func parse(_ data: Data) -> [TimesyncBoot] {
        var boots: [TimesyncBoot] = []
        let bytes = [UInt8](data)
        let count = bytes.count
        var i = 0

        // Open builder state for the boot record currently being filled.
        var curUUID: String?
        var curNum: UInt32 = 1
        var curDen: UInt32 = 1
        var curBootNs: UInt64 = 0
        var curAnchors: [TimesyncBoot.Anchor] = []

        func flush() {
            guard let uuid = curUUID else { return }
            // Prepend the implicit boot anchor (continuous time 0 → boot wall),
            // then keep anchors ascending by continuous time.
            var anchors = curAnchors
            anchors.insert(.init(continuousTime: 0, wallTimeNs: curBootNs), at: 0)
            anchors.sort { $0.continuousTime < $1.continuousTime }
            boots.append(TimesyncBoot(bootUUID: uuid, timebaseNumerator: curNum,
                                      timebaseDenominator: curDen, bootTimeNs: curBootNs,
                                      anchors: anchors))
            curUUID = nil
            curAnchors = []
        }

        while i + 4 <= count {
            // A boot record starts with the 0xBBB0 u16 signature.
            if i + bootRecordSize <= count && u16(bytes, i) == bootSignature {
                flush()
                curUUID = uuid(bytes, i + 0x08)
                curNum = max(u32(bytes, i + 0x18), 1)
                curDen = max(u32(bytes, i + 0x1C), 1)
                curBootNs = u64(bytes, i + 0x20)
                i += bootRecordSize
                continue
            }
            // A sync record starts with the "Ts " u32 signature.
            if i + syncRecordSize <= count && u32(bytes, i) == syncSignature {
                if curUUID != nil {
                    let ct = u64(bytes, i + 0x08)
                    let wall = u64(bytes, i + 0x10)
                    curAnchors.append(.init(continuousTime: ct, wallTimeNs: wall))
                }
                i += syncRecordSize
                continue
            }
            // Unrecognised byte — advance to re-sync (defensive; well-formed
            // files never hit this).
            i += 1
        }
        flush()
        return boots
    }

    /// Parse and merge several `.timesync` files (a host may rotate them), keyed
    /// by boot UUID — later files win on duplicate boot UUIDs.
    public static func parseAll(_ datas: [Data]) -> [String: TimesyncBoot] {
        var byUUID: [String: TimesyncBoot] = [:]
        for d in datas {
            for boot in parse(d) { byUUID[boot.bootUUID] = boot }
        }
        return byUUID
    }

    // MARK: - little-endian readers (bounds pre-checked by callers)

    private static func u16(_ b: [UInt8], _ o: Int) -> UInt16 {
        UInt16(b[o]) | (UInt16(b[o + 1]) << 8)
    }
    private static func u32(_ b: [UInt8], _ o: Int) -> UInt32 {
        UInt32(b[o]) | (UInt32(b[o + 1]) << 8) | (UInt32(b[o + 2]) << 16) | (UInt32(b[o + 3]) << 24)
    }
    private static func u64(_ b: [UInt8], _ o: Int) -> UInt64 {
        var v: UInt64 = 0
        for k in 0..<8 { v |= UInt64(b[o + k]) << (8 * k) }
        return v
    }
    private static func uuid(_ b: [UInt8], _ o: Int) -> String {
        let h = (o..<o + 16).map { String(format: "%02X", b[$0]) }.joined()
        // 8-4-4-4-12 canonical form.
        let parts = [h.prefix(8), h.dropFirst(8).prefix(4), h.dropFirst(12).prefix(4),
                     h.dropFirst(16).prefix(4), h.dropFirst(20).prefix(12)]
        return parts.map(String.init).joined(separator: "-")
    }
}
