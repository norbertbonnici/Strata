import Foundation
import GRDB

#if os(macOS)

/// Reads the macOS **Powerlog** database (`CurrentPowerlog.PLSQL` under
/// `/private/var/db/powerlog/Library/BatteryLife/`) into `[PowerlogEntry]`.
///
/// Powerlog is an ordinary SQLite3 DB (the `.PLSQL` extension notwithstanding),
/// opened by `powerd` in WAL mode — so it mirrors the other DB parsers: copy to
/// scratch with its `-wal`/`-shm` sidecars and open the copy read-write (a
/// read-only open of a WAL DB fails). Table/column names drift across macOS
/// versions, so every table is feature-detected (`tableExists`) and read with
/// `SELECT *` + null-tolerant column reads.
///
/// Time columns are **Unix epoch seconds** (not CFAbsoluteTime), recorded
/// against a drifting monotonic clock; each is corrected by the signed `system`
/// offset from `PLSTORAGEOPERATOR_EVENTFORWARD_TIMEOFFSET` (the latest offset
/// at-or-before the event's raw time), matching APOLLO's `timestamp + system`
/// formula.
public nonisolated struct PowerlogParser: Sendable {
    public init() {}

    public enum PowerlogError: Error { case copyFailed }

    // Table names (v1 scope: the highest-value execution/activity tables).
    private static let tProcessID   = "PLPROCESSMONITORAGENT_EVENTFORWARD_PROCESSID"
    private static let tAppLifecycle = "PLAPPLICATIONAGENT_EVENTFORWARD_APPLIFECYCLE"
    private static let tFrontmost   = "PLAPPLICATIONAGENT_EVENTFORWARD_FRONTMOSTAPP"
    private static let tNetUsage    = "PLPROCESSNETWORKAGENT_EVENTINTERVAL_USAGEDIFF"
    private static let tAppInfo     = "PLAPPLICATIONAGENT_EVENTNONE_APPINFO"
    private static let tTimeOffset  = "PLSTORAGEOPERATOR_EVENTFORWARD_TIMEOFFSET"

    public static func parse(fileAt fileURL: URL, sourceFile: String, scope: String,
                             limit: Int = 50_000) throws -> [PowerlogEntry] {
        guard BrowserHistoryParser.isSQLiteDatabase(at: fileURL) else { return [] }
        if let rows = try? read(fileURL, sourceFile: sourceFile, scope: scope, limit: limit, includeSidecars: true) {
            return rows
        }
        return try read(fileURL, sourceFile: sourceFile, scope: scope, limit: limit, includeSidecars: false)
    }

    private static func read(_ fileURL: URL, sourceFile: String, scope: String, limit: Int,
                             includeSidecars: Bool) throws -> [PowerlogEntry] {
        let fm = FileManager.default
        let scratch = fm.temporaryDirectory
            .appendingPathComponent("strata-powerlog-\(UUID().uuidString)", isDirectory: true)
        try? fm.createDirectory(at: scratch, withIntermediateDirectories: true)
        defer { try? fm.removeItem(at: scratch) }
        let copy = scratch.appendingPathComponent("powerlog.PLSQL")
        do { try fm.copyItem(at: fileURL, to: copy) } catch { throw PowerlogError.copyFailed }
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
            let offsets = TimeOffsetTable(loadFrom: db, table: tTimeOffset)
            let appNames = loadAppInfo(db)

            var out: [PowerlogEntry] = []

            // Process identity snapshots — the core execution record.
            for r in tableRows(db, tProcessID, limit: limit) {
                guard let date = offsets.date(flexDouble(r, "timestamp")) else { continue }
                let bundle = flexString(r, "BundleID")
                out.append(PowerlogEntry(
                    kind: .process,
                    processName: flexString(r, "ProcessName") ?? bundle.flatMap { appNames[$0] },
                    bundleID: bundle, pid: flexInt(r, "PID"),
                    date: date, scope: scope, sourceFile: sourceFile))
            }

            // App lifecycle (launch/exit/foreground) with PID + EVENT.
            for r in tableRows(db, tAppLifecycle, limit: limit) {
                guard let date = offsets.date(flexDouble(r, "timestamp")) else { continue }
                let bundle = flexString(r, "BundleID")
                out.append(PowerlogEntry(
                    kind: .appLifecycle,
                    processName: bundle.flatMap { appNames[$0] }, bundleID: bundle,
                    pid: flexInt(r, "PID"), event: flexString(r, "EVENT"),
                    date: date, scope: scope, sourceFile: sourceFile))
            }

            // Frontmost (active) app — user attribution.
            for r in tableRows(db, tFrontmost, limit: limit) {
                guard let date = offsets.date(flexDouble(r, "timestamp")) else { continue }
                let bundle = flexString(r, "BundleID")
                out.append(PowerlogEntry(
                    kind: .frontmost,
                    processName: bundle.flatMap { appNames[$0] }, bundleID: bundle,
                    date: date, scope: scope, sourceFile: sourceFile))
            }

            // Per-process network usage interval.
            for r in tableRows(db, tNetUsage, limit: limit) {
                guard let date = offsets.date(flexDouble(r, "timestamp")) else { continue }
                let inBytes = (flexInt(r, "WiFiIn") ?? 0) + (flexInt(r, "CellIn") ?? 0)
                let outBytes = (flexInt(r, "WiFiOut") ?? 0) + (flexInt(r, "CellOut") ?? 0)
                let netBundle = flexString(r, "BundleName")
                out.append(PowerlogEntry(
                    kind: .network,
                    processName: flexString(r, "ProcessName") ?? netBundle.flatMap { appNames[$0] },
                    bundleID: netBundle,
                    date: date, endDate: offsets.date(flexDouble(r, "timestampEnd")),
                    bytesIn: inBytes, bytesOut: outBytes,
                    scope: scope, sourceFile: sourceFile))
            }

            return out
        }
    }

    /// bundle id → human-readable app name (from the APPINFO catalog).
    private static func loadAppInfo(_ db: Database) -> [String: String] {
        var map: [String: String] = [:]
        for r in tableRows(db, tAppInfo, limit: 100_000) {
            guard let bundle = flexString(r, "BundleID"), !bundle.isEmpty else { continue }
            if let name = flexString(r, "Name") ?? flexString(r, "Executable")
                ?? flexString(r, "CFDisplayName") ?? flexString(r, "LSDisplayName") {
                map[bundle] = name
            }
        }
        return map
    }

    /// Feature-detect a table, then read up to `limit` most-recent rows. Returns
    /// `[]` (never throws) when the table is absent or the query fails — the key
    /// to surviving schema drift across macOS versions.
    private static func tableRows(_ db: Database, _ table: String, limit: Int) -> [Row] {
        guard (try? db.tableExists(table)) == true else { return [] }
        return (try? Row.fetchAll(db, sql:
            "SELECT * FROM \"\(table)\" ORDER BY timestamp DESC LIMIT \(max(0, limit))")) ?? []
    }

    /// Untyped column read. The `DatabaseValue` conversion never fails, so this
    /// can't trap — unlike a typed `row[col] as T?` read, which on a copied
    /// `Row.fetchAll` row decodes via `try!` and **crashes** (not nil) when the
    /// stored value's storage class doesn't match `T` (the exact TEXT↔INTEGER
    /// drift these helpers must survive). Returns nil for a missing column.
    private static func dbValue(_ row: Row, _ column: String) -> DatabaseValue? {
        row[column] as DatabaseValue?
    }

    /// Read a column as text, coercing across storage classes (drift-tolerant).
    static func flexString(_ row: Row, _ column: String) -> String? {
        guard let v = dbValue(row, column) else { return nil }
        switch v.storage {
        case .string(let s): return s.isEmpty ? nil : s
        case .int64(let i):  return String(i)
        case .double(let d): return String(d)
        case .blob(let data): return String(data: data, encoding: .utf8)
        case .null: return nil
        }
    }

    /// Read a column as an integer, coercing across storage classes.
    static func flexInt(_ row: Row, _ column: String) -> Int64? {
        guard let v = dbValue(row, column) else { return nil }
        switch v.storage {
        case .int64(let i):  return i
        case .double(let d): return Int64(d)
        case .string(let s): return Int64(s)
        default: return nil
        }
    }

    /// Read a column as a Double, coercing across storage classes (used for the
    /// Unix-epoch time columns).
    static func flexDouble(_ row: Row, _ column: String) -> Double? {
        guard let v = dbValue(row, column) else { return nil }
        switch v.storage {
        case .double(let d): return d
        case .int64(let i):  return Double(i)
        case .string(let s): return Double(s)
        default: return nil
        }
    }
}

/// The Powerlog clock-offset table: a small, append-ordered list of (raw
/// timestamp, signed seconds offset) rows. For any event's raw timestamp it
/// returns the latest offset at-or-before that time and adds it, yielding the
/// corrected wall-clock date.
struct PowerlogTimeOffsetTable {
    /// Sorted ascending by raw timestamp.
    private let rows: [(ts: Double, system: Double)]

    init(loadFrom db: Database, table: String) {
        guard (try? db.tableExists(table)) == true,
              let fetched = try? Row.fetchAll(db, sql:
                "SELECT timestamp, system FROM \"\(table)\" ORDER BY timestamp ASC") else {
            rows = []; return
        }
        rows = fetched.compactMap { r in
            guard let ts = PowerlogParser.flexDouble(r, "timestamp") else { return nil }
            return (ts, PowerlogParser.flexDouble(r, "system") ?? 0)
        }
    }

    /// Corrected date for a raw Unix-epoch timestamp, or nil for an
    /// absent/implausible value (< 2001).
    func date(_ raw: Double?) -> Date? {
        guard let raw, raw > 1_000_000_000 else { return nil }
        return Date(timeIntervalSince1970: raw + offset(for: raw))
    }

    /// Signed seconds offset applicable at `raw` (latest offset whose raw
    /// timestamp is ≤ `raw`; falls back to the earliest offset, else 0).
    private func offset(for raw: Double) -> Double {
        guard !rows.isEmpty else { return 0 }
        // Binary search for the last row with ts <= raw.
        var lo = 0, hi = rows.count - 1, found = -1
        while lo <= hi {
            let mid = (lo + hi) / 2
            if rows[mid].ts <= raw { found = mid; lo = mid + 1 } else { hi = mid - 1 }
        }
        return found >= 0 ? rows[found].system : rows[0].system
    }
}

// Convenience alias so the parser reads naturally.
typealias TimeOffsetTable = PowerlogTimeOffsetTable

#endif
