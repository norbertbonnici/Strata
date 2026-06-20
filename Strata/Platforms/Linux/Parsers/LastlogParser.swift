import Foundation

/// Parses `/var/log/lastlog` - glibc's "last login per user" database. Pure
/// byte-parser (like `UtmpParser`). The file is a headerless array of fixed
/// **292-byte** records indexed by UID: the record for UID N lives at byte
/// offset `N * 292`. The UID is positional - never stored.
///
///     struct lastlog (x86-64/aarch64 glibc, little-endian):
///       offset  size  field
///            0     4  ll_time   int32 Unix epoch (UTC). 0 = never logged in.
///            4    32  ll_line   tty / pts / "ssh", NUL-padded
///           36   256  ll_host   remote host / IP, NUL-padded
///
/// Empty slots (`ll_time == 0`) are skipped, so only accounts that have ever
/// logged in are returned. `resolveUser` maps the positional UID to a username
/// via the already-parsed `/etc/passwd`.
public nonisolated enum LastlogParser {

    public static let recordSize = 292

    /// `resolveUser(uid)` supplies the username for a UID (from `/etc/passwd`),
    /// or nil. The file is rejected if it begins with the SQLite magic - modern
    /// distros migrate to a `lastlog2.db` SQLite database that this format can't
    /// read.
    public static func parse(data: Data, sourceFile: String,
                             resolveUser: (Int) -> String? = { _ in nil }) -> [LastlogEntry] {
        guard data.count >= recordSize else { return [] }
        let bytes = [UInt8](data)
        // lastlog2 (SQLite) sanity guard.
        if bytes.count >= 16, Array(bytes[0..<15]) == Array("SQLite format 3".utf8) { return [] }

        var entries: [LastlogEntry] = []
        let count = bytes.count / recordSize
        for uid in 0..<count {
            let base = uid * recordSize
            let seconds = Int32(bitPattern: readUInt32(bytes, base))
            if seconds == 0 { continue }   // empty slot
            let line = readString(bytes, base + 4, 32)
            let host = readString(bytes, base + 36, 256)
            entries.append(LastlogEntry(
                uid: uid, user: resolveUser(uid),
                timestamp: Date(timeIntervalSince1970: TimeInterval(seconds)),
                line: line, host: host, sourceFile: sourceFile))
        }
        return entries
    }

    private static func readUInt32(_ bytes: [UInt8], _ offset: Int) -> UInt32 {
        guard offset + 4 <= bytes.count else { return 0 }
        return UInt32(bytes[offset]) | (UInt32(bytes[offset + 1]) << 8)
            | (UInt32(bytes[offset + 2]) << 16) | (UInt32(bytes[offset + 3]) << 24)
    }

    /// NUL-terminated fixed-width C string, cut at the first NUL, lossy UTF-8.
    /// The exact bytes up to the NUL are preserved (no whitespace trimming) so a
    /// recorded value's spacing is faithful for the examiner.
    private static func readString(_ bytes: [UInt8], _ offset: Int, _ width: Int) -> String {
        guard offset + width <= bytes.count else { return "" }
        var slice = Array(bytes[offset..<(offset + width)])
        if let nul = slice.firstIndex(of: 0) { slice.removeSubrange(nul...) }
        return String(decoding: slice, as: UTF8.self)
    }
}
