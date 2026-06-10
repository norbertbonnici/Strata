import Foundation

/// Parses Linux `utmp`-format files - `/var/log/wtmp` (logins, logouts,
/// reboots) and `/var/log/btmp` (failed logins) - pure-Swift, like the USN and
/// `$MFT` parsers. The on-disk format is glibc's `struct utmp`: a fixed
/// **384-byte little-endian** record:
///
///     offset  size  field
///          0     2  ut_type        (short; +2 bytes padding)
///          4     4  ut_pid         (int32)
///          8    32  ut_line        (char[32], NUL-padded)
///         40     4  ut_id          (char[4])
///         44    32  ut_user        (char[32])
///         76   256  ut_host        (char[256])
///        332     4  ut_exit        (2 × int16)
///        336     4  ut_session     (int32)
///        340     4  ut_tv.tv_sec   (int32 - yes, 32-bit even on 64-bit Linux)
///        344     4  ut_tv.tv_usec  (int32)
///        348    16  ut_addr_v6     (4 × int32)
///        364    20  __unused
///
/// Truncated trailing bytes (a live host copied mid-write) are ignored.
public nonisolated enum UtmpParser {

    public static let recordSize = 384

    /// `isFailedLogin` should be true when `data` came from a btmp file.
    public static func parse(data: Data, sourceFile: String,
                             isFailedLogin: Bool) -> [UtmpRecord] {
        var records: [UtmpRecord] = []
        let count = data.count / recordSize
        records.reserveCapacity(count)
        let bytes = [UInt8](data)   // index-0-based copy; Data slices keep offsets

        for index in 0..<count {
            let base = index * recordSize
            let type = Int32(readUInt16(bytes, base))
            let pid = Int32(bitPattern: readUInt32(bytes, base + 4))
            let line = readString(bytes, base + 8, 32)
            let user = readString(bytes, base + 44, 32)
            let host = readString(bytes, base + 76, 256)
            let seconds = readUInt32(bytes, base + 340)

            let recordType = UtmpRecord.RecordType(rawValue: type) ?? .other
            // Skip empty slots (zeroed records appear in rotated files).
            if recordType == .other && user.isEmpty && line.isEmpty { continue }

            let timestamp: Date? = seconds == 0
                ? nil
                : Date(timeIntervalSince1970: TimeInterval(seconds))
            records.append(UtmpRecord(type: recordType, pid: pid, line: line,
                                      user: user, host: host, timestamp: timestamp,
                                      isFailedLogin: isFailedLogin,
                                      sourceFile: sourceFile))
        }
        return records
    }

    private static func readUInt16(_ bytes: [UInt8], _ offset: Int) -> UInt16 {
        UInt16(bytes[offset]) | (UInt16(bytes[offset + 1]) << 8)
    }

    private static func readUInt32(_ bytes: [UInt8], _ offset: Int) -> UInt32 {
        UInt32(bytes[offset])
            | (UInt32(bytes[offset + 1]) << 8)
            | (UInt32(bytes[offset + 2]) << 16)
            | (UInt32(bytes[offset + 3]) << 24)
    }

    /// NUL-terminated fixed-width C string, lossy UTF-8.
    private static func readString(_ bytes: [UInt8], _ offset: Int, _ width: Int) -> String {
        var slice = Array(bytes[offset..<(offset + width)])
        if let nul = slice.firstIndex(of: 0) { slice.removeSubrange(nul...) }
        return String(decoding: slice, as: UTF8.self)
            .trimmingCharacters(in: .whitespaces)
    }
}
