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
            // SELECT m.* so an older schema missing a column (e.g. attributedBody)
            // doesn't throw — absent columns read as nil. The handle + chat name
            // come from the standard joins.
            let rows = (try? Row.fetchAll(db, sql: """
                SELECT m.*, h.id AS strata_handle, c.display_name AS strata_chat
                FROM message m
                LEFT JOIN handle h ON h.ROWID = m.handle_id
                LEFT JOIN chat_message_join cmj ON cmj.message_id = m.ROWID
                LEFT JOIN chat c ON c.ROWID = cmj.chat_id
                ORDER BY m.date DESC
                LIMIT \(max(0, limit))
                """)) ?? []

            var out: [MessageEntry] = []
            var seen = Set<String>()
            for r in rows {
                let guid: String? = r["guid"]
                // A message in several chats yields duplicate join rows — dedupe.
                if let g = guid, !seen.insert(g).inserted { continue }
                var text: String? = nonEmpty(r["text"])
                if text == nil, let body: Data = r["attributedBody"] {
                    text = attributedBodyText(body)
                }
                let hasAttach = (r["cache_has_attachments"] as Int64?).map { $0 != 0 } ?? false
                out.append(MessageEntry(
                    guid: guid,
                    service: nonEmpty(r["service"]),
                    handle: nonEmpty(r["strata_handle"]),
                    isFromMe: (r["is_from_me"] as Int64?).map { $0 != 0 } ?? false,
                    text: text,
                    timestamp: MessageEntry.appleTime(r["date"]),
                    hasAttachment: hasAttach,
                    chatName: nonEmpty(r["strata_chat"]),
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
