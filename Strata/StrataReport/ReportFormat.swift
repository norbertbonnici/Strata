import Foundation

/// Shared formatting helpers for reports and data exports.
///
/// Every timestamp Strata exports is rendered as **ISO-8601 / UTC** - the
/// de-facto forensic standard: unambiguous, sortable, timezone-explicit, and
/// identical to how the `.strata` bundle persists dates (`CaseStore` uses the
/// `.iso8601` strategy). Using the value-type `ISO8601Format()` API also keeps
/// these helpers `Sendable` so generation can run off the main actor.
nonisolated enum ReportFormat {
    /// ISO-8601 UTC string, or "" for a missing date (CSV / machine columns).
    static func iso(_ date: Date?) -> String {
        date.map { $0.ISO8601Format() } ?? ""
    }

    /// ISO-8601 UTC string, or an em-dash for a missing date (human display).
    static func display(_ date: Date?) -> String {
        date.map { $0.ISO8601Format() } ?? "—"
    }

    /// Filename-safe UTC stamp for the export folder, e.g.
    /// `2026-06-07T091530Z` - ISO-8601 with the colons (the only path-hostile
    /// character) stripped.
    static func fileStamp(_ date: Date) -> String {
        date.ISO8601Format().replacingOccurrences(of: ":", with: "")
    }
}
