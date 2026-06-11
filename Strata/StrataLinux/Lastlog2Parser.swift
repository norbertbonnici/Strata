import Foundation
import GRDB

#if os(macOS)

/// Reads the modern `lastlog2` SQLite store into `[LastlogEntry]` (the same model
/// the binary `LastlogParser` produces, so both fold into the one "last login per
/// user" view with no new UI).
///
/// Background. Through util-linux 2.39 / glibc < 2.40, "last login per user" lived
/// in the binary, UID-indexed `/var/log/lastlog` (a headerless array of fixed
/// 292-byte records - parsed by `LastlogParser`). glibc 2.40 dropped the
/// `lastlog` interface, and util-linux replaced the file with an **empty**
/// `/var/log/lastlog` plus a SQLite database at `/var/log/lastlog2.db`. On those
/// hosts `LastlogParser` rightly returns nothing (it guards on the SQLite magic);
/// this parser is the companion that reads the new store.
///
/// Schema. A single table (canonically `Lastlog2`) keyed by the account **Name**,
/// with a last-login **Time** (Unix epoch seconds) plus **TTY** and **RemoteHost**
/// columns. The schema has drifted across util-linux point releases (column casing
/// and exact names have changed), so we `SELECT *` and read every column
/// **leniently by name, case-insensitively** - tolerating `Name`/`name`,
/// `Time`/`time`/`ll_time`, `TTY`/`tty`/`ll_line`, `RemoteHost`/`remotehost`/
/// `ll_host`. A `Time` of 0 (or missing) maps to a nil timestamp, mirroring the
/// binary parser's "0 = never logged in" rule.
///
/// UID. lastlog2 is **name-keyed**: it does not store the UID. We map the account
/// `Name` to a UID only if a `nameToUID` map (from the already-parsed `/etc/passwd`)
/// is supplied; otherwise the entry carries the sentinel UID **-1** (the row's
/// `account` still reads the username, so the sentinel never surfaces in the UI).
///
/// Forensic safety. Like `BrowserHistoryParser`, the database is copied to a
/// throwaway scratch directory and SQLite is pointed at the copy - the evidence
/// file is never opened. `lastlog2.db` is small (one row per account) so the copy
/// is cheap. The copy is opened read-write so a WAL-mode store (SQLite can't open
/// a WAL DB read-only) still reads.
public nonisolated struct Lastlog2Parser: Sendable {
    public init() {}

    public enum Lastlog2Error: Error { case copyFailed }

    /// Parse the lastlog2 database at `fileURL`.
    ///
    /// - Parameters:
    ///   - fileURL: the extracted `lastlog2.db` on disk (a copy of the evidence).
    ///   - sourceFile: the in-image path, retained for display (the scratch copy's
    ///     on-disk name is meaningless).
    ///   - nameToUID: optional `/etc/passwd`-derived username → UID map; when a row's
    ///     account isn't found (or no map is passed) the entry gets sentinel UID -1.
    public static func parse(fileAt fileURL: URL, sourceFile: String = "/var/log/lastlog2.db",
                             nameToUID: [String: Int] = [:]) throws -> [LastlogEntry] {
        // Gate on the 16-byte SQLite magic: a Linux host can carry an unrelated
        // file of this name, and handing a non-DB to SQLite throws "file is not a
        // database". A name collision should be silently skipped, not surfaced.
        guard isSQLiteDatabase(at: fileURL) else { return [] }

        // Copy to a private scratch dir: SQLite never touches the evidence file.
        let fm = FileManager.default
        let scratch = fm.temporaryDirectory
            .appendingPathComponent("strata-lastlog2-\(UUID().uuidString)", isDirectory: true)
        try? fm.createDirectory(at: scratch, withIntermediateDirectories: true)
        defer { try? fm.removeItem(at: scratch) }
        let copy = scratch.appendingPathComponent("lastlog2.db")
        do { try fm.copyItem(at: fileURL, to: copy) } catch { throw Lastlog2Error.copyFailed }

        // Copy the WAL/SHM sidecars when present so transactions still pending in
        // the `-wal` (a live acquisition) are recovered rather than lost.
        for suffix in ["-wal", "-shm"] {
            let side = URL(fileURLWithPath: fileURL.path + suffix)
            if fm.fileExists(atPath: side.path) {
                try? fm.copyItem(at: side, to: URL(fileURLWithPath: copy.path + suffix))
            }
        }

        // Open the throwaway copy READ-WRITE: a read-only open of a WAL-mode DB
        // fails outright (can't create the `-shm` wal-index).
        let queue = try DatabaseQueue(path: copy.path)
        return try queue.read { db in decode(db, sourceFile: sourceFile, nameToUID: nameToUID) }
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

    /// Find the lastlog2 table (canonically `Lastlog2`, case-insensitively) and
    /// map every row to a `LastlogEntry`. Pure relative to an open connection so
    /// it can be exercised against an in-test fixture DB.
    static func decode(_ db: Database, sourceFile: String,
                       nameToUID: [String: Int]) -> [LastlogEntry] {
        // The table name has been stable as "Lastlog2" but match case-insensitively
        // (and tolerate a stray alternate) in case a release renames it.
        let tables = (try? String.fetchAll(db, sql:
            "SELECT name FROM sqlite_master WHERE type = 'table'")) ?? []
        guard let table = tables.first(where: {
            let n = $0.lowercased()
            return n == "lastlog2" || n == "lastlog"
        }) else { return [] }

        // SELECT * (schema drifts); read columns leniently below.
        let rows = (try? Row.fetchAll(db, sql: "SELECT * FROM \"\(table)\"")) ?? []
        return rows.compactMap { row in
            guard let name = string(row, ["name", "user", "username"]),
                  !name.isEmpty else { return nil }
            let epoch = int64(row, ["time", "ll_time", "lastlogin", "logintime"]) ?? 0
            let timestamp: Date? = epoch > 0
                ? Date(timeIntervalSince1970: TimeInterval(epoch)) : nil
            let line = string(row, ["tty", "ll_line", "line"]) ?? ""
            let host = string(row, ["remotehost", "ll_host", "host", "rhost"]) ?? ""
            let uid = nameToUID[name] ?? -1
            return LastlogEntry(uid: uid, user: name, timestamp: timestamp,
                                line: line, host: host, sourceFile: sourceFile)
        }
    }

    // MARK: - Lenient, case-insensitive column readers

    /// First non-nil string value among `keys`, matched case-insensitively against
    /// the row's actual columns.
    private static func string(_ row: Row, _ keys: [String]) -> String? {
        for key in keys {
            if let col = column(row, key), let v: String = row[col], !v.isEmpty { return v }
        }
        return nil
    }

    /// First non-nil integer value among `keys`, matched case-insensitively.
    private static func int64(_ row: Row, _ keys: [String]) -> Int64? {
        for key in keys {
            if let col = column(row, key), let v: Int64 = row[col] { return v }
        }
        return nil
    }

    /// The row's real column name matching `key` case-insensitively, or nil.
    private static func column(_ row: Row, _ key: String) -> String? {
        let want = key.lowercased()
        return row.columnNames.first { $0.lowercased() == want }
    }
}

#endif
