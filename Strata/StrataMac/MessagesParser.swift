import Foundation
import GRDB

#if os(macOS)

/// Reads the macOS **Messages** database (`~/Library/Messages/chat.db`) into
/// `[MessageEntry]`.
///
/// `chat.db` is SQLite (WAL-mode), so this mirrors `BrowserHistoryParser`: the
/// evidence file is copied to a throwaway scratch dir (plus its `-wal`/`-shm`
/// sidecars) and opened **read-write** there — a read-only open of a WAL database
/// fails because it can't create the `-shm` wal-index — so SQLite is never
/// pointed at the evidence itself.
///
/// Modern Messages keeps the body in `attributedBody` (an NSAttributedString
/// keyed archive) when the `text` column is NULL; this recovers that text with
/// `BinaryPlist` (the longest plain string in the archive), so most rows still
/// carry their content.
public nonisolated struct MessagesParser: Sendable {
    public init() {}

    public enum MessagesError: Error { case copyFailed }

    /// Newest `limit` messages (ordered by date) — bounds memory on very large
    /// chat.db files while keeping the most relevant window.
    public static func parse(fileAt fileURL: URL, sourceFile: String, scope: String,
                             limit: Int = 100_000) throws -> [MessageEntry] {
        guard BrowserHistoryParser.isSQLiteDatabase(at: fileURL) else { return [] }
        if let rows = try? read(fileURL, sourceFile: sourceFile, scope: scope, limit: limit, includeSidecars: true) {
            return rows
        }
        return try read(fileURL, sourceFile: sourceFile, scope: scope, limit: limit, includeSidecars: false)
    }

    private static func read(_ fileURL: URL, sourceFile: String, scope: String, limit: Int,
                             includeSidecars: Bool) throws -> [MessageEntry] {
        let fm = FileManager.default
        let scratch = fm.temporaryDirectory
            .appendingPathComponent("strata-messages-\(UUID().uuidString)", isDirectory: true)
        try? fm.createDirectory(at: scratch, withIntermediateDirectories: true)
        defer { try? fm.removeItem(at: scratch) }
        let copy = scratch.appendingPathComponent("chat.db")
        do { try fm.copyItem(at: fileURL, to: copy) } catch { throw MessagesError.copyFailed }
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
            guard try db.tableExists("message") else { return [] }

            // Resolve the handle (phone/email) + group-chat name as *side lookups*,
            // not joins, so a schema quirk in `handle` / `chat` / `chat_message_join`
            // can't make the whole query throw and silently return nothing — the
            // message rows depend only on the `message` table.
            var handleByID: [Int64: String] = [:]
            if (try? db.tableExists("handle")) == true {
                for r in (try? Row.fetchAll(db, sql: "SELECT ROWID AS rid, id AS hid FROM handle")) ?? [] {
                    if let rid: Int64 = r["rid"], let hid: String = r["hid"], !hid.isEmpty { handleByID[rid] = hid }
                }
            }
            var chatByMsg: [Int64: String] = [:]
            if (try? db.tableExists("chat_message_join")) == true, (try? db.tableExists("chat")) == true {
                for r in (try? Row.fetchAll(db, sql: """
                    SELECT cmj.message_id AS mid, c.display_name AS cname
                    FROM chat_message_join cmj LEFT JOIN chat c ON c.ROWID = cmj.chat_id
                    """)) ?? [] {
                    if let mid: Int64 = r["mid"], let cname: String = r["cname"], !cname.isEmpty,
                       chatByMsg[mid] == nil { chatByMsg[mid] = cname }
                }
            }

            // SELECT * so an older schema missing a column reads as nil rather than
            // throwing; the explicit ROWID alias survives `SELECT *` either way.
            let rows = (try? Row.fetchAll(db, sql: """
                SELECT *, ROWID AS strata_rowid FROM message ORDER BY date DESC LIMIT \(max(0, limit))
                """)) ?? []

            var out: [MessageEntry] = []
            out.reserveCapacity(rows.count)
            for r in rows {
                var text: String? = nonEmpty(r["text"])
                if text == nil, let body: Data = r["attributedBody"] {
                    text = attributedBodyText(body)
                }
                let handleID: Int64? = r["handle_id"]
                out.append(MessageEntry(
                    guid: r["guid"],
                    service: nonEmpty(r["service"]),
                    handle: handleID.flatMap { handleByID[$0] },
                    isFromMe: (r["is_from_me"] as Int64?).map { $0 != 0 } ?? false,
                    text: text,
                    timestamp: MessageEntry.appleTime(r["date"]),
                    hasAttachment: (r["cache_has_attachments"] as Int64?).map { $0 != 0 } ?? false,
                    chatName: chatByMsg[r["strata_rowid"] ?? 0],
                    scope: scope, sourceFile: sourceFile))
            }
            return out
        }
    }

    private static func nonEmpty(_ s: String?) -> String? {
        guard let s, !s.isEmpty else { return nil }
        return s
    }

    /// Recover message text from an `attributedBody` NSAttributedString keyed
    /// archive: the body is the longest plain string in the archive's `$objects`
    /// that isn't a class name / archive key.
    static func attributedBodyText(_ data: Data) -> String? {
        guard let objects = BinaryPlist.parse(data)?.dictValue?["$objects"]?.arrayValue else { return nil }
        var best: String?
        for obj in objects {
            guard let s = obj.stringValue else { continue }
            if s.hasPrefix("NS") || s.hasPrefix("$") || s.hasPrefix("__") { continue }
            if s == "+" || s.isEmpty { continue }
            if best == nil || s.count > best!.count { best = s }
        }
        return best
    }
}

#endif
