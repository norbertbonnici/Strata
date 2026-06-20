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

            // Resolve the lookup tables as side dictionaries rather than joining
            // them into the main query — so a renamed/absent lookup table can't
            // make the whole query throw and silently return zero messages. The
            // message rows depend only on the `messages` table.
            func lookup(_ table: String, key: String, value: String) -> [Int64: String] {
                guard (try? db.tableExists(table)) == true else { return [:] }
                var out: [Int64: String] = [:]
                for r in (try? Row.fetchAll(db, sql: "SELECT ROWID AS rid, \(key) AS k, \(value) AS v FROM \(table)")) ?? [] {
                    if let rid: Int64 = r["rid"], let v: String = r["v"], !v.isEmpty { out[rid] = v }
                }
                return out
            }
            let subjectByID = lookup("subjects", key: "ROWID", value: "subject")
            let addressByID = lookup("addresses", key: "ROWID", value: "address")
            let commentByID = lookup("addresses", key: "ROWID", value: "comment")
            let mailboxByID = lookup("mailboxes", key: "ROWID", value: "url")

            // Recipients (to + cc) aggregated per message.
            var recipientsByMsg: [Int64: String] = [:]
            if (try? db.tableExists("recipients")) == true, (try? db.tableExists("addresses")) == true {
                for r in (try? Row.fetchAll(db, sql: """
                    SELECT r.message_key AS mk, GROUP_CONCAT(a.address, ', ') AS addrs
                    FROM recipients r LEFT JOIN addresses a ON a.ROWID = r.address_id
                    GROUP BY r.message_key
                    """)) ?? [] {
                    if let mk: Int64 = r["mk"], let addrs: String = r["addrs"], !addrs.isEmpty {
                        recipientsByMsg[mk] = addrs
                    }
                }
            }

            let rows = (try? Row.fetchAll(db, sql: """
                SELECT *, ROWID AS strata_rowid FROM messages ORDER BY date_received DESC LIMIT \(max(0, limit))
                """)) ?? []

            return rows.map { r in
                let rowid: Int64 = r["strata_rowid"] ?? 0
                let subjectID: Int64? = r["subject"]
                let senderID: Int64? = r["sender"]
                let mailboxID: Int64? = r["mailbox"]
                return MailMessageEntry(
                    subject: subjectID.flatMap { subjectByID[$0] },
                    sender: senderID.flatMap { addressByID[$0] },
                    senderDisplay: senderID.flatMap { commentByID[$0] },
                    recipients: recipientsByMsg[rowid],
                    dateSent: MailMessageEntry.mailTime(r["date_sent"]),
                    dateReceived: MailMessageEntry.mailTime(r["date_received"]),
                    mailbox: mailboxID.flatMap { mailboxByID[$0] },
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
