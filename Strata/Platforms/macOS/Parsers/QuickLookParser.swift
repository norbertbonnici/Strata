import Foundation
import GRDB

#if os(macOS)

/// Reads the macOS **QuickLook thumbnail index** (`index.sqlite`) into
/// `[MacActivityItem]` — one entry per file that was previewed.
///
/// SQLite, so it mirrors the other DB parsers (copy to scratch, open read-write).
/// The `files` table holds `folder` + `file_name`; the `thumbnails` table holds
/// `last_hit_date` (a `CFAbsoluteTime`) + `hit_count` keyed by `file_id`. The hit
/// data is read as a *side lookup* (robust to schema drift), so the file rows
/// come back even if `thumbnails` differs — a file's mere presence in `files` is
/// the evidence it was viewed.
public nonisolated struct QuickLookParser: Sendable {
    public init() {}

    public enum QuickLookError: Error { case copyFailed }

    public static func parse(fileAt fileURL: URL, sourceFile: String, scope: String) throws -> [MacActivityItem] {
        guard BrowserHistoryParser.isSQLiteDatabase(at: fileURL) else { return [] }
        if let rows = try? read(fileURL, sourceFile: sourceFile, scope: scope, includeSidecars: true) {
            return rows
        }
        return try read(fileURL, sourceFile: sourceFile, scope: scope, includeSidecars: false)
    }

    private static func read(_ fileURL: URL, sourceFile: String, scope: String,
                             includeSidecars: Bool) throws -> [MacActivityItem] {
        let fm = FileManager.default
        let scratch = fm.temporaryDirectory
            .appendingPathComponent("strata-quicklook-\(UUID().uuidString)", isDirectory: true)
        try? fm.createDirectory(at: scratch, withIntermediateDirectories: true)
        defer { try? fm.removeItem(at: scratch) }
        let copy = scratch.appendingPathComponent("index.sqlite")
        do { try fm.copyItem(at: fileURL, to: copy) } catch { throw QuickLookError.copyFailed }
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
            guard try db.tableExists("files") else { return [] }

            var hitByFile: [Int64: (date: Date?, count: Int)] = [:]
            if (try? db.tableExists("thumbnails")) == true {
                for r in (try? Row.fetchAll(db, sql: """
                    SELECT file_id AS fid, MAX(last_hit_date) AS lhd, SUM(hit_count) AS hc
                    FROM thumbnails GROUP BY file_id
                    """)) ?? [] {
                    guard let fid: Int64 = r["fid"] else { continue }
                    let date = (r["lhd"] as Double?).flatMap { $0 > 0 ? appleTime($0) : nil }
                    hitByFile[fid] = (date, Int(r["hc"] as Int64? ?? 0))
                }
            }

            let rows = (try? Row.fetchAll(db, sql: "SELECT *, rowid AS strata_rowid FROM files")) ?? []
            return rows.compactMap { r in
                guard let folder: String = r["folder"], let file: String = r["file_name"], !file.isEmpty else { return nil }
                let path = (folder as NSString).appendingPathComponent(file)
                let hit = hitByFile[r["strata_rowid"] ?? 0]
                let detail = (hit?.count ?? 0) > 0 ? "viewed \(hit!.count)×" : "viewed"
                return MacActivityItem(kind: .quickLook, path: path, timestamp: hit?.date,
                                       detail: detail, scope: scope, sourceFile: sourceFile)
            }
        }
    }

    /// QuickLook's `last_hit_date` is a `CFAbsoluteTime` (seconds since 2001); a
    /// value in the Unix range is treated as Unix as a safety net.
    private static func appleTime(_ v: Double) -> Date {
        v > 1_000_000_000 ? Date(timeIntervalSince1970: v) : Date(timeIntervalSinceReferenceDate: v)
    }
}

#endif
