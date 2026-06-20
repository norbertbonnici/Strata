import Foundation
import GRDB

#if os(macOS)

/// Reads the macOS **Versions** store (`/.DocumentRevisions-V100/db-V1/db.sqlite`)
/// into `[MacDocumentVersion]` — one entry per saved generation of a document.
///
/// SQLite, so it mirrors the other DB parsers (copy to scratch, open read-write).
/// The `generations` table holds each version (storage id, add time, size, stored
/// path); the original document path is resolved from `files` as a **side
/// lookup** (robust to schema drift — the version rows survive even if `files`
/// differs).
public nonisolated struct DocumentRevisionsParser: Sendable {
    public init() {}

    public enum DocRevError: Error { case copyFailed }

    public static func parse(fileAt fileURL: URL, sourceFile: String, scope: String,
                             limit: Int = 100_000) throws -> [MacDocumentVersion] {
        guard BrowserHistoryParser.isSQLiteDatabase(at: fileURL) else { return [] }
        if let rows = try? read(fileURL, sourceFile: sourceFile, scope: scope, limit: limit, includeSidecars: true) {
            return rows
        }
        return try read(fileURL, sourceFile: sourceFile, scope: scope, limit: limit, includeSidecars: false)
    }

    private static func read(_ fileURL: URL, sourceFile: String, scope: String, limit: Int,
                             includeSidecars: Bool) throws -> [MacDocumentVersion] {
        let fm = FileManager.default
        let scratch = fm.temporaryDirectory
            .appendingPathComponent("strata-docrev-\(UUID().uuidString)", isDirectory: true)
        try? fm.createDirectory(at: scratch, withIntermediateDirectories: true)
        defer { try? fm.removeItem(at: scratch) }
        let copy = scratch.appendingPathComponent("db.sqlite")
        do { try fm.copyItem(at: fileURL, to: copy) } catch { throw DocRevError.copyFailed }
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
            guard try db.tableExists("generations") else { return [] }

            // Original document paths, resolved by storage id as a side lookup.
            var pathByStorage: [Int64: String] = [:]
            if (try? db.tableExists("files")) == true {
                for r in (try? Row.fetchAll(db, sql: "SELECT * FROM files")) ?? [] {
                    guard let storage: Int64 = r["file_storage_id"] else { continue }
                    if let path = nonEmpty(r["file_path"]) ?? nonEmpty(r["file_name"]) {
                        pathByStorage[storage] = path
                    }
                }
            }

            let rows = (try? Row.fetchAll(db, sql: """
                SELECT * FROM generations ORDER BY generation_add_time DESC LIMIT \(max(0, limit))
                """)) ?? []
            return rows.compactMap { r in
                let storage: Int64? = r["generation_storage_id"]
                let path = storage.flatMap { pathByStorage[$0] } ?? nonEmpty(r["generation_name"])
                guard let path, !path.isEmpty else { return nil }
                return MacDocumentVersion(
                    filePath: path,
                    versionTime: docTime(r["generation_add_time"]),
                    size: r["generation_size"],
                    generationPath: nonEmpty(r["generation_path"]),
                    scope: scope, sourceFile: sourceFile)
            }
        }
    }

    private static func nonEmpty(_ s: String?) -> String? {
        guard let s, !s.isEmpty else { return nil }
        return s
    }

    /// `generation_add_time` is Unix epoch seconds; a small value in the
    /// CFAbsoluteTime range is treated as such as a safety net.
    private static func docTime(_ raw: Double?) -> Date? {
        guard let raw, raw > 0 else { return nil }
        return raw > 1_000_000_000 ? Date(timeIntervalSince1970: raw) : Date(timeIntervalSinceReferenceDate: raw)
    }
}

#endif
