import Foundation
import GRDB

#if os(macOS)

/// Reads the macOS **KnowledgeC** database (`knowledgeC.db`) into
/// `[KnowledgeEntry]`. KnowledgeC is SQLite (Core Data), so — like browser
/// history / TCC — there's no vendored tool; it's read with GRDB off a throwaway
/// scratch copy (opened read-write, WAL-safe). Only the **high-value** streams
/// are pulled (app focus/usage/activity, display, lock, power, media, Safari,
/// notifications); the high-volume low-signal streams (`/standby/timer`,
/// `/das/activityRuntime`, battery percentage, …) are skipped.
public nonisolated struct KnowledgeCParser: Sendable {
    public init() {}

    enum KnowledgeError: Error { case copyFailed }

    /// The streams worth surfacing — keeps `knowledgeC.json` lean and the tab
    /// focused on forensically useful behaviour.
    static let streams = [
        "/app/inFocus", "/app/usage", "/app/activity",
        "/display/isBacklit", "/device/isLocked", "/device/isPluggedIn",
        "/media/nowPlaying", "/safari/history", "/notification/usage",
    ]

    public static func parse(fileAt fileURL: URL, scope: String, sourceFile: String) throws -> [KnowledgeEntry] {
        guard isSQLiteDatabase(at: fileURL) else { return [] }
        if let rows = try? read(at: fileURL, scope: scope, sourceFile: sourceFile, includeSidecars: true) {
            return rows
        }
        return try read(at: fileURL, scope: scope, sourceFile: sourceFile, includeSidecars: false)
    }

    static func isSQLiteDatabase(at fileURL: URL) -> Bool {
        guard let handle = try? FileHandle(forReadingFrom: fileURL) else { return false }
        defer { try? handle.close() }
        guard let header = try? handle.read(upToCount: 16), header.count == 16 else { return false }
        return Array(header) == Array("SQLite format 3".utf8) + [0]
    }

    private static func read(at fileURL: URL, scope: String, sourceFile: String,
                             includeSidecars: Bool) throws -> [KnowledgeEntry] {
        let fm = FileManager.default
        let scratch = fm.temporaryDirectory
            .appendingPathComponent("strata-knowledgec-\(UUID().uuidString)", isDirectory: true)
        try? fm.createDirectory(at: scratch, withIntermediateDirectories: true)
        defer { try? fm.removeItem(at: scratch) }
        let copy = scratch.appendingPathComponent("knowledgeC.db")
        do { try fm.copyItem(at: fileURL, to: copy) } catch { throw KnowledgeError.copyFailed }
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
            guard try db.tableExists("ZOBJECT") else { return [] }
            let placeholders = streams.map { _ in "?" }.joined(separator: ",")
            let rows = (try? Row.fetchAll(db, sql: """
                SELECT ZSTREAMNAME, ZVALUESTRING, ZVALUEINTEGER, ZSTARTDATE, ZENDDATE
                FROM ZOBJECT
                WHERE ZSTREAMNAME IN (\(placeholders))
                """, arguments: StatementArguments(streams))) ?? []
            return rows.compactMap { r in
                guard let stream: String = r["ZSTREAMNAME"] else { return nil }
                return KnowledgeEntry(
                    stream: stream,
                    value: nonEmpty(r["ZVALUESTRING"]),
                    valueInt: (r["ZVALUEINTEGER"] as Int64?).map(Int.init),
                    startDate: macTime(r["ZSTARTDATE"]),
                    endDate: macTime(r["ZENDDATE"]),
                    scope: scope, sourceFile: sourceFile)
            }
        }
    }

    /// Core Data "Mac absolute time" (seconds since 2001-01-01) → `Date`.
    private static func macTime(_ v: Double?) -> Date? {
        guard let v, v > 0 else { return nil }
        return Date(timeIntervalSinceReferenceDate: v)
    }
    private static func nonEmpty(_ s: String?) -> String? {
        guard let s, !s.isEmpty else { return nil }
        return s
    }
}

#endif
