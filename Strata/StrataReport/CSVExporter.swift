import Foundation

/// Renders export rows to RFC-4180 CSV. Fields containing a comma, double
/// quote, or newline are wrapped in double quotes with interior quotes doubled.
/// Output uses CRLF line endings (the RFC-4180 default, friendliest to Excel).
public nonisolated enum CSVExporter {
    private static let newline = "\r\n"

    /// Escape a single field per RFC-4180.
    static func escape(_ field: String) -> String {
        if field.contains(",") || field.contains("\"") ||
           field.contains("\n") || field.contains("\r") {
            return "\"" + field.replacingOccurrences(of: "\"", with: "\"\"") + "\""
        }
        return field
    }

    /// Join one record's fields into an escaped CSV line.
    static func record(_ fields: [String]) -> String {
        fields.map(escape).joined(separator: ",")
    }

    private static func assemble(header: [String], rows: [[String]]) -> String {
        var lines: [String] = [record(header)]
        lines.reserveCapacity(rows.count + 1)
        for row in rows { lines.append(record(row)) }
        // Trailing newline so the file ends cleanly on its last record.
        return lines.joined(separator: newline) + newline
    }

    public static func timeline(_ rows: [TimelineExportRow]) -> String {
        assemble(
            header: ["timestamp_iso", "source", "macb", "event_id",
                     "path", "size", "deleted", "host"],
            rows: rows.map { r in
                [ReportFormat.iso(r.timestamp), r.source, r.macb,
                 r.eventID.map(String.init) ?? "", r.path, String(r.size),
                 r.deleted ? "true" : "false", r.host]
            })
    }

    public static func findings(_ rows: [FindingExportRow]) -> String {
        assemble(
            header: ["timestamp_iso", "severity", "phase", "attack_id",
                     "attack_name", "title", "detail", "evidence_paths", "host"],
            rows: rows.map { r in
                [ReportFormat.iso(r.timestamp), r.severity, r.phase,
                 r.attackID ?? "", r.attackName ?? "", r.title, r.detail,
                 r.evidencePaths.joined(separator: "; "), r.host]
            })
    }

    public static func iocMatches(_ rows: [IOCMatchExportRow]) -> String {
        assemble(
            header: ["timestamp_iso", "ioc_kind", "ioc_value", "location_type",
                     "location_detail", "context", "host"],
            rows: rows.map { r in
                [ReportFormat.iso(r.timestamp), r.iocKind, r.iocValue,
                 r.locationType, r.locationDetail, r.context, r.host]
            })
    }
}
