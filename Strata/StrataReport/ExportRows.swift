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

/// Chain-of-custody columns:
/// `timestamp,action,actor,detail,evidence`.
public nonisolated struct CustodyExportRow: Codable, Sendable {
    public let timestamp: Date
    public let action: String
    public let actor: String
    public let detail: String
    public let evidence: String   // host display name, or "" for case-level events
}

/// Annotation columns:
/// `target_timestamp,tag,target_kind,source,title,note,author,created,modified,evidence`.
public nonisolated struct AnnotationExportRow: Codable, Sendable {
    public let targetTimestamp: Date?   // the bookmarked item's own time
    public let tag: String
    public let targetKind: String       // finding / timelineEvent
    public let source: String           // "Event Log", "Finding", ...
    public let title: String
    public let note: String
    public let author: String
    public let created: Date
    public let modified: Date
    public let evidence: String         // host display name, "" when unscoped
}

/// Flattens the per-host `ReportInputs` into tagged export rows. Every row
/// carries its `host` so attribution survives the case-wide roll-up (the
/// in-memory `TimelineEvent`/`Finding`/`IOCMatch` types have no host field).
public nonisolated enum ExportRowBuilder {

    /// Flatten the case custody ledger, resolving each event's `evidenceID` to a
    /// host display name. Sorted chronologically (the ledger order).
    public static func custodyRows(from log: [CustodyEvent],
                                   hosts: [ReportInputs.Host]) -> [CustodyExportRow] {
        let nameByID: [UUID: String] = Dictionary(
            hosts.compactMap { host in host.evidenceID.map { ($0, host.displayName) } },
            uniquingKeysWith: { first, _ in first })
        return log.sorted { $0.timestamp < $1.timestamp }.map { event in
            CustodyExportRow(
                timestamp: event.timestamp,
                action: event.action.label,
                actor: event.actor,
                detail: event.detail,
                evidence: event.evidenceID.flatMap { nameByID[$0] } ?? "")
        }
    }

    /// Flatten the analyst annotations, chronological by the *target's* own
    /// timestamp (undated last) so the export reads as the case story.
    public static func annotationRows(from annotations: [Annotation],
                                      hosts: [ReportInputs.Host]) -> [AnnotationExportRow] {
        let nameByID: [UUID: String] = Dictionary(
            hosts.compactMap { host in host.evidenceID.map { ($0, host.displayName) } },
            uniquingKeysWith: { first, _ in first })
        return annotations
            .sorted { ($0.timestamp ?? .distantFuture, $0.createdAt)
                        < ($1.timestamp ?? .distantFuture, $1.createdAt) }
            .map { annotation in
                AnnotationExportRow(
                    targetTimestamp: annotation.timestamp,
                    tag: annotation.tag?.label ?? "",
                    targetKind: annotation.targetKind.rawValue,
                    source: annotation.sourceLabel,
                    title: annotation.title,
                    note: annotation.note,
                    author: annotation.author,
                    created: annotation.createdAt,
                    modified: annotation.modifiedAt,
                    evidence: annotation.evidenceID.flatMap { nameByID[$0] } ?? "")
            }
    }

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
