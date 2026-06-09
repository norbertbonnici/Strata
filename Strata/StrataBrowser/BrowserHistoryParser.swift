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
/// location and opened there read-only; the evidence file itself is never opened
/// by SQLite. The copy also gives SQLite a writable directory for the WAL index
/// (`-shm`/`-wal`), without which a read-only open of a WAL-mode database — which
/// Chrome's `History` is — fails outright.
///
/// **Known v1 limits:** one row per distinct URL (using its last-visit time),
/// not one per individual visit; Chromium downloads are parsed, Firefox
/// downloads (stored as `moz_annos` annotations) are not; data sitting in an
/// un-checkpointed `-wal` sidecar is not recovered (only the main DB is copied).
public nonisolated struct BrowserHistoryParser: Sendable {
    public init() {}

    public enum BrowserHistoryError: Error { case copyFailed }

    /// Parse the database at `fileURL`. `sourceFile` is the in-image path,
    /// retained for display and used to classify the browser + profile (the
    /// on-disk name of the extracted copy is meaningless).
    public static func parse(fileAt fileURL: URL, sourceFile: String) throws -> [BrowserHistoryEntry] {
        let browser = BrowserHistoryEntry.browser(forPath: sourceFile)
        let profile = BrowserHistoryEntry.profile(forPath: sourceFile)

        // Copy to a private scratch dir: never let SQLite touch the evidence, and
        // give the WAL index a writable home.
        let fm = FileManager.default
        let scratch = fm.temporaryDirectory
            .appendingPathComponent("strata-browser-\(UUID().uuidString)", isDirectory: true)
        try? fm.createDirectory(at: scratch, withIntermediateDirectories: true)
        defer { try? fm.removeItem(at: scratch) }
        let copy = scratch.appendingPathComponent("History.db")
        do { try fm.copyItem(at: fileURL, to: copy) } catch { throw BrowserHistoryError.copyFailed }

        var config = Configuration()
        config.readonly = true
        let queue = try DatabaseQueue(path: copy.path, configuration: config)

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
