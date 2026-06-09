import Foundation
import GRDB

#if os(macOS)

/// Reads a web-browser history database into `[BrowserHistoryEntry]`.
///
/// Chromium-family browsers (Chrome/Edge/Brave/Opera/Vivaldi) keep history in a
/// SQLite `History` database; Firefox in `places.sqlite`. Both are SQLite, so —
/// unlike the ESE (`SRUDB.dat`) or `.evtx` artifacts — there is no vendored tool:
/// we read them directly with GRDB, the same library that backs `TSKDatabase`.
///
/// **Forensic safety.** The database is always copied to a throwaway scratch
/// location and SQLite is pointed at that copy — the evidence file itself is
/// never opened. The copy is opened *read-write* on purpose: a read-only open of
/// a WAL-mode database (Chrome's `History` and Firefox's `places.sqlite` are
/// both WAL) fails outright with "unable to open database file", because a
/// read-only connection cannot create the `-shm` wal-index. The `-wal`/`-shm`
/// sidecars are copied alongside the main DB when present, so transactions still
/// in the `-wal` are recovered rather than lost.
///
/// **Known v1 limits:** one row per distinct URL (using its last-visit time),
/// not one per individual visit; Chromium downloads are parsed, Firefox
/// downloads (stored as `moz_annos` annotations) are not.
public nonisolated struct BrowserHistoryParser: Sendable {
    public init() {}

    public enum BrowserHistoryError: Error { case copyFailed }

    /// Parse the database at `fileURL`. `sourceFile` is the in-image path,
    /// retained for display and used to classify the browser + profile (the
    /// on-disk name of the extracted copy is meaningless).
    public static func parse(fileAt fileURL: URL, sourceFile: String) throws -> [BrowserHistoryEntry] {
        // First read with the `-wal`/`-shm` sidecars included, so committed-but-
        // not-yet-checkpointed history (which lives in the `-wal`) is recovered.
        // If that throws — a torn or locked `-wal` from a live acquisition can do
        // that — fall back to the main database alone, which still carries every
        // checkpointed row.
        if let rows = try? readDatabase(at: fileURL, sourceFile: sourceFile, includeSidecars: true) {
            return rows
        }
        return try readDatabase(at: fileURL, sourceFile: sourceFile, includeSidecars: false)
    }

    private static func readDatabase(at fileURL: URL, sourceFile: String,
                                     includeSidecars: Bool) throws -> [BrowserHistoryEntry] {
        let browser = BrowserHistoryEntry.browser(forPath: sourceFile)
        let profile = BrowserHistoryEntry.profile(forPath: sourceFile)

        // Copy to a private scratch dir: SQLite never touches the evidence file.
        let fm = FileManager.default
        let scratch = fm.temporaryDirectory
            .appendingPathComponent("strata-browser-\(UUID().uuidString)", isDirectory: true)
        try? fm.createDirectory(at: scratch, withIntermediateDirectories: true)
        defer { try? fm.removeItem(at: scratch) }
        let copy = scratch.appendingPathComponent("History.db")
        do { try fm.copyItem(at: fileURL, to: copy) } catch { throw BrowserHistoryError.copyFailed }

        // SQLite keys the WAL sidecars off the database filename, so copy any
        // `<source>-wal` / `<source>-shm` to `History.db-wal` / `History.db-shm`.
        // The `-wal` holds the most recent transactions; without it they're lost.
        if includeSidecars {
            for suffix in ["-wal", "-shm"] {
                let side = URL(fileURLWithPath: fileURL.path + suffix)
                if fm.fileExists(atPath: side.path) {
                    try? fm.copyItem(at: side, to: URL(fileURLWithPath: copy.path + suffix))
                }
            }
        }

        // Open the throwaway copy READ-WRITE. A read-only open of a WAL-mode
        // database — which Chrome's `History` and Firefox's `places.sqlite` both
        // are — fails outright with "unable to open database file", because a
        // read-only connection may not create the `-shm` wal-index. Opening our
        // private copy read-write sidesteps that (and lets SQLite fold the `-wal`
        // into the main DB); the evidence file itself is never opened by SQLite.
        let queue = try DatabaseQueue(path: copy.path)

        return try queue.read { db in
            if try db.tableExists("urls") {
                return chromium(db, browser: browser, profile: profile, sourceFile: sourceFile)
            } else if try db.tableExists("moz_places") {
                return firefox(db, profile: profile, sourceFile: sourceFile)
            }
            return []   // a "History"/"places.sqlite" that isn't a browser DB
        }
    }

    // MARK: - Chromium (urls + downloads)

    private static func chromium(_ db: Database, browser: BrowserHistoryEntry.Browser,
                                 profile: String?, sourceFile: String) -> [BrowserHistoryEntry] {
        var out: [BrowserHistoryEntry] = []

        // Visits — one row per distinct URL.
        let visits = (try? Row.fetchAll(db, sql: """
            SELECT url, title, visit_count, typed_count, last_visit_time
            FROM urls
            WHERE last_visit_time > 0
            """)) ?? []
        for r in visits {
            guard let url: String = r["url"], !url.isEmpty else { continue }
            out.append(BrowserHistoryEntry(
                browser: browser, kind: .visit, url: url,
                title: nonEmpty(r["title"]),
                timestamp: BrowserHistoryEntry.chromeTime(r["last_visit_time"]),
                visitCount: intValue(r["visit_count"]),
                typedCount: intValue(r["typed_count"]),
                userProfile: profile, sourceFile: sourceFile))
        }

        // Downloads — schema has drifted across Chrome versions, so SELECT * and
        // read column names leniently (a missing column reads as nil in GRDB).
        let downloads = (try? Row.fetchAll(db, sql: "SELECT * FROM downloads")) ?? []
        for r in downloads {
            let target: String? = r["target_path"] ?? r["current_path"] ?? r["full_path"]
            let originURL: String? = r["tab_url"] ?? r["url"] ?? r["referrer"]
            let url = originURL ?? target ?? ""
            guard !url.isEmpty else { continue }
            out.append(BrowserHistoryEntry(
                browser: browser, kind: .download, url: url,
                title: nil,
                timestamp: BrowserHistoryEntry.chromeTime(r["start_time"]),
                targetPath: target,
                receivedBytes: int64Value(r["received_bytes"]),
                totalBytes: int64Value(r["total_bytes"]),
                referrer: nonEmpty(r["tab_url"]),
                userProfile: profile, sourceFile: sourceFile))
        }
        return out
    }

    // MARK: - Firefox (moz_places)

    private static func firefox(_ db: Database, profile: String?,
                                sourceFile: String) -> [BrowserHistoryEntry] {
        let rows = (try? Row.fetchAll(db, sql: """
            SELECT url, title, visit_count, typed, last_visit_date
            FROM moz_places
            WHERE last_visit_date IS NOT NULL AND last_visit_date > 0
            """)) ?? []
        return rows.compactMap { r in
            guard let url: String = r["url"], !url.isEmpty else { return nil }
            return BrowserHistoryEntry(
                browser: .firefox, kind: .visit, url: url,
                title: nonEmpty(r["title"]),
                timestamp: BrowserHistoryEntry.firefoxTime(r["last_visit_date"]),
                visitCount: intValue(r["visit_count"]),
                typedCount: intValue(r["typed"]),
                userProfile: profile, sourceFile: sourceFile)
        }
    }

    // MARK: - Lenient column readers

    private static func nonEmpty(_ s: String?) -> String? {
        guard let s, !s.isEmpty else { return nil }
        return s
    }
    private static func intValue(_ v: Int64?) -> Int? { v.map(Int.init) }
    private static func int64Value(_ v: Int64?) -> Int64? { v }
}

#endif
