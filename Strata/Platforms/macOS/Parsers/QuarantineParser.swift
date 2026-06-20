import Foundation
import GRDB

#if os(macOS)

/// Reads the macOS **LaunchServices quarantine** store into
/// `[QuarantineEvent]`.
///
/// The store lives at
/// `~/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2` and is a
/// plain SQLite database. Every quarantine-aware app (browsers, mail/messaging
/// clients, installers, `curl`/`wget`) appends a row to its `LSQuarantineEvent`
/// table when it writes a downloaded file: the app that downloaded it, the
/// file's URL, the referring page, and a `CFAbsoluteTime` timestamp. This is
/// macOS download provenance — the single best record of how a file arrived
/// from the network (T1204 User Execution, T1566 phishing-delivery context).
///
/// **Forensic safety** (mirrors `BrowserHistoryParser`). The database is always
/// copied to a throwaway scratch location and SQLite is pointed at that copy —
/// the evidence file itself is never opened. The 16-byte SQLite magic header is
/// checked first so a name collision (a non-database file carrying the same
/// path) is silently skipped rather than surfaced as an error. The copy is
/// opened read-write because the quarantine store can be WAL-mode, and a
/// read-only open of a WAL database fails outright (it cannot create the `-shm`
/// wal-index); the `-wal`/`-shm` sidecars are copied alongside so transactions
/// still pending there are recovered.
public nonisolated struct QuarantineParser: Sendable {
    public init() {}

    public enum QuarantineError: Error { case copyFailed }

    /// Parse the quarantine store at `fileURL`. `sourceFile` is the in-image
    /// path, retained for display.
    public static func parse(fileAt fileURL: URL, sourceFile: String) throws -> [QuarantineEvent] {
        // The store may have been selected by a fixed name; gate on the SQLite
        // magic so a name collision (an unrelated file) is silently skipped.
        guard isSQLiteDatabase(at: fileURL) else { return [] }

        // First read with the `-wal`/`-shm` sidecars, recovering committed-but-
        // not-checkpointed rows; fall back to the main DB alone if that throws.
        if let rows = try? readDatabase(at: fileURL, sourceFile: sourceFile, includeSidecars: true) {
            return rows
        }
        return try readDatabase(at: fileURL, sourceFile: sourceFile, includeSidecars: false)
    }

    /// True when `fileURL` begins with the SQLite file magic
    /// (`"SQLite format 3\0"`, 16 bytes).
    static func isSQLiteDatabase(at fileURL: URL) -> Bool {
        guard let handle = try? FileHandle(forReadingFrom: fileURL) else { return false }
        defer { try? handle.close() }
        guard let header = try? handle.read(upToCount: 16), header.count == 16 else { return false }
        let magic: [UInt8] = Array("SQLite format 3".utf8) + [0]
        return Array(header) == magic
    }

    private static func readDatabase(at fileURL: URL, sourceFile: String,
                                     includeSidecars: Bool) throws -> [QuarantineEvent] {
        // Copy to a private scratch dir: SQLite never touches the evidence file.
        let fm = FileManager.default
        let scratch = fm.temporaryDirectory
            .appendingPathComponent("strata-quarantine-\(UUID().uuidString)", isDirectory: true)
        try? fm.createDirectory(at: scratch, withIntermediateDirectories: true)
        defer { try? fm.removeItem(at: scratch) }
        let copy = scratch.appendingPathComponent("QuarantineEventsV2.db")
        do { try fm.copyItem(at: fileURL, to: copy) } catch { throw QuarantineError.copyFailed }

        // SQLite keys the WAL sidecars off the database filename.
        if includeSidecars {
            for suffix in ["-wal", "-shm"] {
                let side = URL(fileURLWithPath: fileURL.path + suffix)
                if fm.fileExists(atPath: side.path) {
                    try? fm.copyItem(at: side, to: URL(fileURLWithPath: copy.path + suffix))
                }
            }
        }

        // Open the throwaway copy READ-WRITE (WAL-mode stores fail a read-only
        // open). The evidence file itself is never opened by SQLite.
        let queue = try DatabaseQueue(path: copy.path)

        return try queue.read { db in
            guard try db.tableExists("LSQuarantineEvent") else { return [] }
            return rows(db, sourceFile: sourceFile)
        }
    }

    private static func rows(_ db: Database, sourceFile: String) -> [QuarantineEvent] {
        // SELECT * and read columns leniently by name (a missing column reads as
        // nil in GRDB) — the schema has drifted across macOS versions and a few
        // third-party tools add columns of their own.
        let rows = (try? Row.fetchAll(db, sql: "SELECT * FROM LSQuarantineEvent")) ?? []
        return rows.map { r in
            // `LSQuarantineTimeStamp` is a REAL `CFAbsoluteTime`, but some rows
            // (and a few third-party tools) write it as an INTEGER. GRDB coerces
            // either numeric storage class to `Double?`, so one read handles both.
            let cfSeconds: Double? = r["LSQuarantineTimeStamp"]
            return QuarantineEvent(
                agentName: nonEmpty(r["LSQuarantineAgentName"]),
                dataURL: nonEmpty(r["LSQuarantineDataURLString"]),
                originURL: nonEmpty(r["LSQuarantineOriginURLString"]),
                timestamp: QuarantineEvent.quarantineTime(cfSeconds),
                eventID: nonEmpty(r["LSQuarantineEventIdentifier"]),
                sourceFile: sourceFile)
        }
    }

    // MARK: - Lenient column readers

    private static func nonEmpty(_ s: String?) -> String? {
        guard let s, !s.isEmpty else { return nil }
        return s
    }
}

#endif
