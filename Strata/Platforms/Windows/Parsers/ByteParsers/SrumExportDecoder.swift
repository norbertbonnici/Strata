import Foundation

/// Pure, cross-platform decoder for the tab-separated text that libesedb's
/// `esedbexport` writes out of a SRUM `SRUDB.dat` ESE database. Kept free of any
/// process/FS I/O so it is unit-testable off-main and on iOS — the macOS-only
/// `SrumParser` shells out to `esedbexport`, reads the per-table files, and hands
/// their contents here.
///
/// esedbexport emits, per table, a headered TSV file (`<Table>.<index>`, no
/// extension): row 1 is the tab-separated column names, each subsequent line a
/// record. Integer columns render as decimal; binary columns (e.g. the id-map's
/// `IdBlob`) as a continuous lowercase hex string; and SRUM's `TimeStamp` /
/// `ConnectStartTime` columns are pre-decoded by esedbexport to libfdatetime
/// **CTIME** strings (e.g. `"Jun 09, 2025 13:45:07.000000000"`).
public nonisolated enum SrumExportDecoder {
    // The provider tables we surface, by their ESE table name.
    public static let networkDataTable        = "{973F5D5C-1D90-4944-BE8E-24B94231A174}"
    public static let appResourceTable        = "{D10CA2FE-6FCF-4F6D-848E-B2E99266FA89}"
    public static let networkConnectivityTable = "{DD6636C4-8929-4683-974E-22C046A43763}"
    public static let idMapTable              = "SruDbIdMapTable"

    /// Top-level: given the four relevant export files' contents (any may be nil/
    /// absent), resolve the id-map and build the unified entry list.
    public static func decode(idMapTSV: String?,
                              networkDataTSV: String?,
                              appResourceTSV: String?,
                              networkConnectivityTSV: String?,
                              sourceFile: String) -> [SrumEntry] {
        let idMap = idMapTSV.map(decodeIdMap) ?? [:]
        let time = CTimeDecoder()
        var out: [SrumEntry] = []
        if let tsv = networkDataTSV {
            out += parseNetworkData(tsv, idMap: idMap, time: time, sourceFile: sourceFile)
        }
        if let tsv = appResourceTSV {
            out += parseAppResource(tsv, idMap: idMap, time: time, sourceFile: sourceFile)
        }
        if let tsv = networkConnectivityTSV {
            out += parseNetworkConnectivity(tsv, idMap: idMap, time: time, sourceFile: sourceFile)
        }
        return out
    }

    // MARK: - Provider tables

    private static func parseNetworkData(_ tsv: String, idMap: [Int: String],
                                         time: CTimeDecoder, sourceFile: String) -> [SrumEntry] {
        parseTSV(tsv).map { r in
            SrumEntry(kind: .networkData,
                      timestamp: time.parse(r["timestamp"]),
                      application: resolve(r["appid"], idMap),
                      userSID: resolve(r["userid"], idMap),
                      bytesSent: int(r["bytessent"]),
                      bytesReceived: int(r["bytesrecvd"]),
                      interfaceLuid: int(r["interfaceluid"]),
                      sourceFile: sourceFile)
        }
    }

    private static func parseAppResource(_ tsv: String, idMap: [Int: String],
                                         time: CTimeDecoder, sourceFile: String) -> [SrumEntry] {
        parseTSV(tsv).map { r in
            let read = (int(r["foregroundbytesread"]) ?? 0) + (int(r["backgroundbytesread"]) ?? 0)
            let written = (int(r["foregroundbyteswritten"]) ?? 0) + (int(r["backgroundbyteswritten"]) ?? 0)
            return SrumEntry(kind: .appResourceUsage,
                             timestamp: time.parse(r["timestamp"]),
                             application: resolve(r["appid"], idMap),
                             userSID: resolve(r["userid"], idMap),
                             bytesRead: read,
                             bytesWritten: written,
                             sourceFile: sourceFile)
        }
    }

    private static func parseNetworkConnectivity(_ tsv: String, idMap: [Int: String],
                                                 time: CTimeDecoder, sourceFile: String) -> [SrumEntry] {
        parseTSV(tsv).map { r in
            SrumEntry(kind: .networkConnectivity,
                      timestamp: time.parse(r["timestamp"]),
                      application: resolve(r["appid"], idMap),
                      userSID: resolve(r["userid"], idMap),
                      interfaceLuid: int(r["interfaceluid"]),
                      connectStart: time.parse(r["connectstarttime"]),
                      connectedSeconds: int(r["connectedtime"]),
                      sourceFile: sourceFile)
        }
    }

    // MARK: - Id map

    /// Build IdIndex -> resolved string from the SruDbIdMapTable export.
    /// IdType 3 => the IdBlob is a binary SID; otherwise it is a UTF-16LE string.
    public static func decodeIdMap(_ tsv: String) -> [Int: String] {
        var map: [Int: String] = [:]
        for r in parseTSV(tsv) {
            guard let idx = int(r["idindex"]).map({ Int($0) }) else { continue }
            let type = int(r["idtype"]) ?? -1
            let bytes = hexToBytes(r["idblob"] ?? "")
            let value = (type == 3) ? decodeSID(bytes) : decodeUTF16LE(bytes)
            if let value, !value.isEmpty { map[idx] = value }
        }
        return map
    }

    private static func resolve(_ field: String?, _ idMap: [Int: String]) -> String? {
        guard let field, let idx = int(field).map({ Int($0) }) else { return nil }
        return idMap[idx]
    }

    // MARK: - TSV

    /// Parse esedbexport's headered TSV into row dicts keyed by **lowercased**
    /// column name (tolerant of column-name case drift between libesedb builds).
    public static func parseTSV(_ tsv: String) -> [[String: String]] {
        // Split on any newline (strips a trailing CR too) so a CRLF-lined export
        // doesn't leave "\r" on the last column name / field value.
        let lines = tsv.split(omittingEmptySubsequences: false, whereSeparator: \.isNewline).map(String.init)
        guard let header = lines.first, !header.isEmpty else { return [] }
        let cols = header.components(separatedBy: "\t").map { $0.lowercased() }
        var rows: [[String: String]] = []
        for line in lines.dropFirst() where !line.isEmpty {
            let fields = line.components(separatedBy: "\t")
            var dict: [String: String] = [:]
            dict.reserveCapacity(cols.count)
            for (i, c) in cols.enumerated() where i < fields.count {
                dict[c] = fields[i]
            }
            rows.append(dict)
        }
        return rows
    }

    private static func int(_ s: String?) -> Int64? {
        guard let s = s?.trimmingCharacters(in: .whitespaces), !s.isEmpty else { return nil }
        return Int64(s)
    }

    // MARK: - Binary blob decoders

    public static func hexToBytes(_ hex: String) -> [UInt8] {
        let chars = Array(hex)
        guard chars.count % 2 == 0 else { return [] }
        var out: [UInt8] = []
        out.reserveCapacity(chars.count / 2)
        var i = 0
        while i < chars.count {
            guard let hi = chars[i].hexDigitValue, let lo = chars[i + 1].hexDigitValue else { return [] }
            out.append(UInt8(hi << 4 | lo))
            i += 2
        }
        return out
    }

    /// Decode a NUL-terminated UTF-16LE blob (an application path / moniker).
    public static func decodeUTF16LE(_ bytes: [UInt8]) -> String? {
        var units: [UInt16] = []
        var i = 0
        while i + 1 < bytes.count {
            let u = UInt16(bytes[i]) | (UInt16(bytes[i + 1]) << 8)
            if u == 0 { break }   // trailing NUL
            units.append(u)
            i += 2
        }
        guard !units.isEmpty else { return nil }
        return String(utf16CodeUnits: units, count: units.count)
    }

    /// Decode a binary Windows NT SID into `S-1-5-21-...` string form.
    public static func decodeSID(_ bytes: [UInt8]) -> String? {
        guard bytes.count >= 8 else { return nil }
        let revision = bytes[0]
        let subCount = Int(bytes[1])
        guard bytes.count >= 8 + subCount * 4 else { return nil }
        var authority: UInt64 = 0
        for i in 2..<8 { authority = (authority << 8) | UInt64(bytes[i]) }
        var sid = "S-\(revision)-\(authority)"
        var off = 8
        for _ in 0..<subCount {
            let sub = UInt32(bytes[off]) | (UInt32(bytes[off + 1]) << 8)
                | (UInt32(bytes[off + 2]) << 16) | (UInt32(bytes[off + 3]) << 24)
            sid += "-\(sub)"
            off += 4
        }
        return sid
    }
}

/// Parses the libfdatetime CTIME strings esedbexport renders for SRUM's
/// `TimeStamp` (an OLE automation date) and `ConnectStartTime` (a FILETIME)
/// columns, e.g. `"Jun 09, 2025 13:45:07.000000000"`. Reuses its `DateFormatter`s
/// across rows. Falls back to interpreting a raw OLE-automation-date double if a
/// build ever emits the unconverted value.
public nonisolated final class CTimeDecoder: @unchecked Sendable {
    private let dateTime: DateFormatter
    private let dateOnly: DateFormatter
    /// OLE automation date epoch: 1899-12-30 00:00:00 UTC.
    private static let oleEpoch = Date(timeIntervalSince1970: -2_209_161_600)

    public init() {
        func fmt(_ pattern: String) -> DateFormatter {
            let f = DateFormatter()
            f.locale = Locale(identifier: "en_US_POSIX")
            f.timeZone = TimeZone(identifier: "UTC")
            f.dateFormat = pattern
            return f
        }
        dateTime = fmt("MMM d, yyyy HH:mm:ss")
        dateOnly = fmt("MMM d, yyyy")
    }

    public func parse(_ raw: String?) -> Date? {
        guard let original = raw?.trimmingCharacters(in: .whitespaces), !original.isEmpty else { return nil }
        // Drop trailing fractional seconds (".NNNNNNNNN") for the CTIME formatters
        // only — the OLE fallback below needs the untouched value, since there a
        // '.' separates whole days from the time-of-day fraction.
        var s = original
        if let dot = s.lastIndex(of: ".") { s = String(s[..<dot]) }
        // Collapse space-padded day runs ("Jun  9" -> "Jun 9").
        let collapsed = s.split(separator: " ", omittingEmptySubsequences: true).joined(separator: " ")
        if let d = dateTime.date(from: collapsed) { return d }
        if let d = dateOnly.date(from: collapsed) { return d }
        // Fallback: a raw OLE automation date (days.fraction since 1899-12-30).
        if let days = Double(original) {
            return CTimeDecoder.oleEpoch.addingTimeInterval(days * 86_400)
        }
        return nil
    }
}
