import Foundation
import GRDB

#if os(macOS)

/// Reads the macOS **Notification Center** database (`db2/db`, under
/// `~/Library/Group Containers/group.com.apple.usernoted/` or the legacy
/// `…/com.apple.notificationcenter/`) into `[MacNotification]`.
///
/// SQLite, so it mirrors the other DB parsers (copy to scratch, open read-write).
/// The `record` table holds one row per delivered notification (app id, dates,
/// and a `data` bplist BLOB); the bundle id is resolved from `app` as a side
/// lookup, and the title/body are recovered from the `data` bplist via
/// `BinaryPlist` (searching for the `titl` / `body` keys across the layouts).
public nonisolated struct NotificationParser: Sendable {
    public init() {}

    public enum NotificationError: Error { case copyFailed }

    public static func parse(fileAt fileURL: URL, sourceFile: String, scope: String,
                             limit: Int = 100_000) throws -> [MacNotification] {
        guard BrowserHistoryParser.isSQLiteDatabase(at: fileURL) else { return [] }
        if let rows = try? read(fileURL, sourceFile: sourceFile, scope: scope, limit: limit, includeSidecars: true) {
            return rows
        }
        return try read(fileURL, sourceFile: sourceFile, scope: scope, limit: limit, includeSidecars: false)
    }

    private static func read(_ fileURL: URL, sourceFile: String, scope: String, limit: Int,
                             includeSidecars: Bool) throws -> [MacNotification] {
        let fm = FileManager.default
        let scratch = fm.temporaryDirectory
            .appendingPathComponent("strata-noted-\(UUID().uuidString)", isDirectory: true)
        try? fm.createDirectory(at: scratch, withIntermediateDirectories: true)
        defer { try? fm.removeItem(at: scratch) }
        let copy = scratch.appendingPathComponent("noted.db")
        do { try fm.copyItem(at: fileURL, to: copy) } catch { throw NotificationError.copyFailed }
        if includeSidecars {
            for suffix in ["-wal", "-shm"] {
                let side = URL(fileURLWithPath: fileURL.path + suffix)
                if fm.fileExists(atPath: side.path) {
                    try? fm.copyItem(at: side, to: URL(fileURLWithPath: copy.path + suffix))
                }
            }
        }

        let queue = try DatabaseQueue(path: copy.path)
        return try queue.read { db in
            guard try db.tableExists("record") else { return [] }

            var appByID: [Int64: String] = [:]
            if (try? db.tableExists("app")) == true {
                for r in (try? Row.fetchAll(db, sql: "SELECT app_id AS aid, identifier AS bid FROM app")) ?? [] {
                    if let aid: Int64 = r["aid"], let bid: String = r["bid"], !bid.isEmpty { appByID[aid] = bid }
                }
            }

            let rows = (try? Row.fetchAll(db, sql: """
                SELECT * FROM record ORDER BY delivered_date DESC LIMIT \(max(0, limit))
                """)) ?? []
            return rows.map { r in
                let (title, body) = decode(r["data"])
                let date = appleTime(r["delivered_date"]) ?? appleTime(r["request_date"])
                return MacNotification(
                    appID: (r["app_id"] as Int64?).flatMap { appByID[$0] },
                    title: title, body: body, deliveredDate: date,
                    scope: scope, sourceFile: sourceFile)
            }
        }
    }

    /// Recover (title, body) from a notification `data` bplist — searching for the
    /// `titl` / `body` keys, which appear under a `req` dict (plain bplist) or
    /// inside an NSKeyedArchiver `$objects` graph across macOS versions.
    static func decode(_ data: Data?) -> (String?, String?) {
        guard let data, let root = BinaryPlist.parse(data) else { return (nil, nil) }
        return (findString(root, keys: ["titl", "title"]),
                findString(root, keys: ["body", "mesg", "subt"]))
    }

    private static func findString(_ node: PlistValue?, keys: Set<String>) -> String? {
        guard let node else { return nil }
        if let dict = node.dictValue {
            for k in keys { if let s = dict[k]?.stringValue, !s.isEmpty { return s } }
            for v in dict.values { if let found = findString(v, keys: keys) { return found } }
        } else if let arr = node.arrayValue {
            for v in arr { if let found = findString(v, keys: keys) { return found } }
        }
        return nil
    }

    /// Notification Center dates are `CFAbsoluteTime` (seconds since 2001); a Unix-
    /// range value is treated as Unix as a safety net.
    private static func appleTime(_ raw: Double?) -> Date? {
        guard let raw, raw > 0 else { return nil }
        return raw > 1_000_000_000 ? Date(timeIntervalSince1970: raw) : Date(timeIntervalSinceReferenceDate: raw)
    }
}

#endif
