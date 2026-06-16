import Foundation
import GRDB

#if os(macOS)

/// Reads the macOS **Mail** `Envelope Index` database into `[MailMessageEntry]`.
///
/// `Envelope Index` is SQLite, so this mirrors `MessagesParser` /
/// `BrowserHistoryParser`: the evidence file is copied to a throwaway scratch dir
/// (plus any `-wal`/`-shm` sidecars) and opened **read-write** there, so SQLite
/// never touches the evidence itself.
///
/// One row per message, joined to the `subjects` / `addresses` / `mailboxes`
/// lookup tables for the sender, subject and owning mailbox; recipients (to + cc)
/// are aggregated separately to avoid multiplying the message rows. Validated
/// against the modern Envelope Index schema (Mail V5+); older layouts that rename
/// these tables degrade to an empty result rather than throwing.
public nonisolated struct MailParser: Sendable {
    public init() {}

    public enum MailError: Error { case copyFailed }

    /// Newest `limit` messages (by received date) — bounds memory on a large mailbox.
    public static func parse(fileAt fileURL: URL, sourceFile: String, scope: String,
                             limit: Int = 100_000) throws -> [MailMessageEntry] {
        guard BrowserHistoryParser.isSQLiteDatabase(at: fileURL) else { return [] }
        if let rows = try? read(fileURL, sourceFile: sourceFile, scope: scope, limit: limit, includeSidecars: true) {
            return rows
        }
        return try read(fileURL, sourceFile: sourceFile, scope: scope, limit: limit, includeSidecars: false)
    }

    private static func read(_ fileURL: URL, sourceFile: String, scope: String, limit: Int,
                             includeSidecars: Bool) throws -> [MailMessageEntry] {
        let fm = FileManager.default
        let scratch = fm.temporaryDirectory
            .appendingPathComponent("strata-mail-\(UUID().uuidString)", isDirectory: true)
        try? fm.createDirectory(at: scratch, withIntermediateDirectories: true)
        defer { try? fm.removeItem(at: scratch) }
        let copy = scratch.appendingPathComponent("EnvelopeIndex.sqlite")
        do { try fm.copyItem(at: fileURL, to: copy) } catch { throw MailError.copyFailed }
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
            guard try db.tableExists("messages") else { return [] }

            // Recipients (to + cc) aggregated per message, so the main query stays
            // one row per message.
            var recipientsByMsg: [Int64: String] = [:]
            if (try? db.tableExists("recipients")) == true, (try? db.tableExists("addresses")) == true {
                let rrows = (try? Row.fetchAll(db, sql: """
                    SELECT r.message_key AS mk, GROUP_CONCAT(a.address, ', ') AS addrs
                    FROM recipients r LEFT JOIN addresses a ON a.ROWID = r.address_id
                    GROUP BY r.message_key
                    """)) ?? []
                for r in rrows {
                    if let mk: Int64 = r["mk"], let addrs: String = r["addrs"], !addrs.isEmpty {
                        recipientsByMsg[mk] = addrs
                    }
                }
            }

            let rows = (try? Row.fetchAll(db, sql: """
                SELECT m.ROWID AS rowid, m.date_sent AS date_sent, m.date_received AS date_received,
                       s.subject AS subject, sa.address AS sender_addr, sa.comment AS sender_name,
                       mb.url AS mailbox
                FROM messages m
                LEFT JOIN subjects s ON s.ROWID = m.subject
                LEFT JOIN addresses sa ON sa.ROWID = m.sender
                LEFT JOIN mailboxes mb ON mb.ROWID = m.mailbox
                ORDER BY m.date_received DESC
                LIMIT \(max(0, limit))
                """)) ?? []

            return rows.map { r in
                MailMessageEntry(
                    subject: nonEmpty(r["subject"]),
                    sender: nonEmpty(r["sender_addr"]),
                    senderDisplay: nonEmpty(r["sender_name"]),
                    recipients: recipientsByMsg[r["rowid"] ?? 0],
                    dateSent: MailMessageEntry.mailTime(r["date_sent"]),
                    dateReceived: MailMessageEntry.mailTime(r["date_received"]),
                    mailbox: nonEmpty(r["mailbox"]),
                    scope: scope, sourceFile: sourceFile)
            }
        }
    }

    private static func nonEmpty(_ s: String?) -> String? {
        guard let s, !s.isEmpty else { return nil }
        return s
    }
}

#endif
