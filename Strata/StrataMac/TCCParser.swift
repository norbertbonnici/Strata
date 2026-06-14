import Foundation
import GRDB

#if os(macOS)

/// Reads a macOS **TCC** database (`TCC.db`) `access` table into `[TCCAccess]`.
/// TCC.db is SQLite, so — like browser history — there is no vendored tool; it's
/// read directly with GRDB. The evidence file is copied to a throwaway scratch
/// location and SQLite is pointed at the copy (opened read-write so a WAL-mode DB
/// opens at all); the evidence file itself is never opened by SQLite.
public nonisolated struct TCCParser: Sendable {
    public init() {}

    enum TCCError: Error { case copyFailed }

    /// Parse the TCC.db at `fileURL`. `scope` is `system` or the owning user;
    /// `sourceFile` is the in-image path (retained for display).
    public static func parse(fileAt fileURL: URL, scope: String, sourceFile: String) throws -> [TCCAccess] {
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
                             includeSidecars: Bool) throws -> [TCCAccess] {
        let fm = FileManager.default
        let scratch = fm.temporaryDirectory
            .appendingPathComponent("strata-tcc-\(UUID().uuidString)", isDirectory: true)
        try? fm.createDirectory(at: scratch, withIntermediateDirectories: true)
        defer { try? fm.removeItem(at: scratch) }
        let copy = scratch.appendingPathComponent("TCC.db")
        do { try fm.copyItem(at: fileURL, to: copy) } catch { throw TCCError.copyFailed }
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
            guard try db.tableExists("access") else { return [] }
            // Schema drifted: modern TCC has `auth_value` (0=denied,2=allowed,…);
            // pre-Mojave has a boolean `allowed`. Read whichever is present.
            let columns = try db.columns(in: "access").map(\.name)
            let hasAuthValue = columns.contains("auth_value")
            let hasReason = columns.contains("auth_reason")
            let rows = (try? Row.fetchAll(db, sql: "SELECT * FROM access")) ?? []
            return rows.compactMap { r in
                guard let service: String = r["service"], let client: String = r["client"] else { return nil }
                let av: TCCAccess.AuthValue
                if hasAuthValue {
                    av = TCCAccess.AuthValue(rawValue: intValue(r["auth_value"]) ?? 1) ?? .unknown
                } else {
                    av = (intValue(r["allowed"]) ?? 0) == 1 ? .allowed : .denied
                }
                let lm = int64Value(r["last_modified"])
                return TCCAccess(
                    service: service, client: client,
                    clientType: intValue(r["client_type"]) ?? 0,
                    authValue: av, authReason: hasReason ? (intValue(r["auth_reason"]) ?? 0) : 0,
                    lastModified: lm.map { Date(timeIntervalSince1970: TimeInterval($0)) },
                    scope: scope, sourceFile: sourceFile)
            }
        }
    }

    private static func intValue(_ v: Int64?) -> Int? { v.map(Int.init) }
    private static func int64Value(_ v: Int64?) -> Int64? { v }
}

#endif
