import Foundation

/// Render-ready chain-of-custody report. Assembled once by `CoCReportModelBuilder`
/// from `ReportInputs`; the HTML and Markdown renderers format it without
/// repeating any selection logic, keeping the two formats in lockstep (mirrors
/// the `ReportModel` / examiner-report split).
public nonisolated struct CoCReportModel: Sendable {
    /// One evidence item's integrity block: provenance + recorded hashes.
    public struct EvidenceSection: Sendable {
        public let displayName: String
        public let kindLabel: String
        public let sourcePath: String
        public let acquisition: AcquisitionInfo?
        public let hashes: [SourceHash]
    }

    /// One custody ledger entry, with its evidence resolved to a name.
    public struct LogEntry: Sendable {
        public let timestamp: Date
        public let action: String
        public let actor: String
        public let detail: String
        public let evidenceName: String?   // nil = case-level event
    }

    public let caseName: String
    public let examiner: String
    public let createdAt: Date
    public let generatedAt: Date
    public let evidence: [EvidenceSection]
    public let log: [LogEntry]
}

/// Builds a `CoCReportModel` from `ReportInputs`. Pure - no I/O, no main-actor
/// state.
public nonisolated enum CoCReportModelBuilder {
    public static func build(from inputs: ReportInputs) -> CoCReportModel {
        let nameByID: [UUID: String] = Dictionary(
            inputs.hosts.compactMap { host in host.evidenceID.map { ($0, host.displayName) } },
            uniquingKeysWith: { first, _ in first })

        let sections = inputs.hosts.map { host in
            CoCReportModel.EvidenceSection(
                displayName: host.displayName,
                kindLabel: host.kindLabel,
                sourcePath: host.sourcePath,
                acquisition: host.acquisition,
                hashes: host.sourceHashes)
        }

        let log = inputs.custodyLog
            .sorted { $0.timestamp < $1.timestamp }
            .map { event in
                CoCReportModel.LogEntry(
                    timestamp: event.timestamp,
                    action: event.action.label,
                    actor: event.actor,
                    detail: event.detail,
                    evidenceName: event.evidenceID.flatMap { nameByID[$0] })
            }

        return CoCReportModel(
            caseName: inputs.caseName,
            examiner: inputs.examiner,
            createdAt: inputs.createdAt,
            generatedAt: inputs.generatedAt,
            evidence: sections,
            log: log)
    }
}
