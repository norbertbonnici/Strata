import Foundation

/// An AI-generated executive summary of a case's detection findings.
///
/// Produced on-device by the FoundationModels (Apple Intelligence) summarizer
/// in `StrataAI`, persisted case-wide as `summary.json`, surfaced on the Kill
/// Chain / Overview tabs and in the examiner report. Deliberately free of any
/// `FoundationModels` dependency so it codes/decodes on iOS (the read-only
/// viewer) and in tests like every other `StrataCore` value type.
public nonisolated struct CaseSummary: Codable, Sendable, Hashable {
    /// The generated narrative, plain text (rendered verbatim, like the
    /// analyst case narrative).
    public let text: String
    /// When the summary was generated.
    public let generatedAt: Date
    /// Number of findings the summary was built from - lets the UI flag a
    /// summary as stale when the finding count has since changed.
    public let findingCount: Int
    /// Human-readable provenance, e.g. "Apple Intelligence (on-device)".
    public let modelLabel: String

    public init(text: String, generatedAt: Date, findingCount: Int, modelLabel: String) {
        self.text = text
        self.generatedAt = generatedAt
        self.findingCount = findingCount
        self.modelLabel = modelLabel
    }
}
