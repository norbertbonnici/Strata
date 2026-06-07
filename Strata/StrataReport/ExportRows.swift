import Foundation

// Stable, documented export schemas. These DTOs deliberately sit between the
// internal models and the on-disk CSV/JSON so the export format never shifts
// just because an internal type was refactored (and because `TimelineEvent`
// isn't even `Codable`). CSV and JSON exporters both consume these rows, so the
// two formats can never drift apart.

/// Timeline columns: `timestamp,source,macb,event_id,path,size,deleted,host`.
public nonisolated struct TimelineExportRow: Codable, Sendable {
    public let timestamp: Date
    public let source: String       // FS / EVTX
    public let macb: String         // M / A / C / B
    public let eventID: UInt32?
    public let path: String
    public let size: Int64
    public let deleted: Bool
    public let host: String
}

/// Findings columns:
/// `timestamp,severity,phase,attack_id,attack_name,title,detail,evidence_paths,host`.
public nonisolated struct FindingExportRow: Codable, Sendable {
    public let timestamp: Date?
    public let severity: String
    public let phase: String
    public let attackID: String?
    public let attackName: String?
    public let title: String
    public let detail: String
    public let evidencePaths: [String]
    public let host: String
}

/// IOC-match columns:
/// `timestamp,ioc_kind,ioc_value,location_type,location_detail,context,host`.
public nonisolated struct IOCMatchExportRow: Codable, Sendable {
    public let timestamp: Date?
    public let iocKind: String
    public let iocValue: String
    public let locationType: String     // event / registry / file
    public let locationDetail: String
    public let context: String
    public let host: String
}

/// Flattens the per-host `ReportInputs` into tagged export rows. Every row
/// carries its `host` so attribution survives the case-wide roll-up (the
/// in-memory `TimelineEvent`/`Finding`/`IOCMatch` types have no host field).
public nonisolated enum ExportRowBuilder {
    public static func timelineRows(from hosts: [ReportInputs.Host]) -> [TimelineExportRow] {
        hosts.flatMap { host in
            host.timeline.map { event in
                TimelineExportRow(
                    timestamp: event.date,
                    source: event.source.rawValue,
                    macb: event.kind.rawValue,
                    eventID: event.eventID,
                    path: event.path,
                    size: event.size,
                    deleted: event.isDeleted,
                    host: host.displayName)
            }
        }
    }

    public static func findingRows(from hosts: [ReportInputs.Host]) -> [FindingExportRow] {
        hosts.flatMap { host in
            host.findings.map { finding in
                FindingExportRow(
                    timestamp: finding.timestamp,
                    severity: finding.severity.label,
                    phase: finding.phase.title,
                    attackID: finding.technique?.attackID,
                    attackName: finding.technique?.name,
                    title: finding.title,
                    detail: finding.detail,
                    evidencePaths: finding.evidencePaths,
                    host: host.displayName)
            }
        }
    }

    public static func iocRows(from hosts: [ReportInputs.Host]) -> [IOCMatchExportRow] {
        hosts.flatMap { host in
            host.iocMatches.map { match in
                let loc = locationParts(match.location)
                return IOCMatchExportRow(
                    timestamp: match.timestamp,
                    iocKind: match.iocKind.label,
                    iocValue: match.iocValue,
                    locationType: loc.type,
                    locationDetail: loc.detail,
                    context: match.context,
                    host: host.displayName)
            }
        }
    }

    /// Flatten an `IOCMatch.Location` into a type tag + a human-readable detail.
    static func locationParts(_ location: IOCMatch.Location) -> (type: String, detail: String) {
        switch location {
        case let .event(eventID, recordNumber, channel, sourceFile):
            return ("event", "\(channel) EID \(eventID) record \(recordNumber) [\(sourceFile)]")
        case let .registry(hive, path, name):
            let key = name.isEmpty ? "\(hive)\\\(path)" : "\(hive)\\\(path)\\\(name)"
            return ("registry", key)
        case let .file(path):
            return ("file", path)
        }
    }
}
