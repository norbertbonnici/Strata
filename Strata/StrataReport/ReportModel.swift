import Foundation

/// Render-ready representation of an examiner report. `ReportModelBuilder`
/// produces it once; the Markdown and HTML renderers format it without
/// repeating any content-selection logic, so the two formats stay in lockstep.
public nonisolated struct ReportModel: Sendable {
    /// A severity with its count, used for the summary rollups.
    public struct SeverityCount: Sendable {
        public let severity: Severity
        public let count: Int
    }

    /// Findings sharing one kill-chain phase, severity-sorted (high → low).
    public struct PhaseGroup: Sendable {
        public let phase: KillChainPhase
        public let findings: [Finding]
    }

    public struct HostSection: Sendable {
        public let displayName: String
        public let kindLabel: String
        public let sourcePath: String
        public let profile: HostProfile
        public let fileCount: Int
        public let eventCount: Int
        public let registryValueCount: Int
        public let findingCount: Int
        public let iocMatchCount: Int
        /// Non-zero severities only, high → low.
        public let severityCounts: [SeverityCount]
        /// Non-empty phases only, in kill-chain order.
        public let phaseGroups: [PhaseGroup]
        public let iocMatches: [IOCMatch]
        /// Findings carrying a timestamp, chronological - the "timeline excerpt"
        /// of the narrative (the full timeline lives in the CSV/JSON export).
        public let timelineExcerpt: [Finding]
    }

    public let caseName: String
    public let examiner: String
    public let createdAt: Date
    public let generatedAt: Date
    /// The analyst's free-form case narrative; empty when none was written.
    public let narrative: String
    /// Analyst bookmarks, chronological by the target's own timestamp
    /// (undated last) - the pinned "story" items.
    public let bookmarks: [Annotation]
    public let hostSections: [HostSection]
    public let totalFindings: Int
    public let totalIOCMatches: Int
    /// Case-wide severity rollup, high → low, non-zero only.
    public let caseSeverityCounts: [SeverityCount]
    /// Set when the report was filtered to a subset of severities, e.g.
    /// "High, Critical". `nil` when every severity is included - the renderers
    /// surface it so the reader knows the findings are a filtered view.
    public let severityFilterNote: String?
}
