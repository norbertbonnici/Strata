import Foundation

/// One validated claim in an AI case summary: a single factual statement about
/// attacker activity, with its severity/phase taken from the supporting findings
/// (not the model) and its citations drawn from those findings' real evidence
/// paths. Pure value type - no FoundationModels dependency - so it codes/decodes
/// on iOS (the read-only viewer) and in tests like every other StrataCore type.
public nonisolated struct SummaryClaim: Codable, Sendable, Hashable {
    /// One-sentence description of the activity (the model's prose, retained only
    /// after the claim survives validation).
    public let statement: String
    /// Kill-chain phase, taken from the supporting findings.
    public let phase: KillChainPhase
    /// Severity, taken from the supporting findings - the model cannot relabel it.
    public let severity: Severity
    /// Real evidence paths from the cited findings - never text the model emitted.
    public let citations: [String]
    /// Technique-bucket keys (ATT&CK ID, else finding title) of the findings this
    /// claim actually cites, recorded at validation time. The flat `citations`
    /// paths cannot recover per-claim technique attribution (a path shared across
    /// findings of different techniques would conflate them), so the self-eval
    /// scorer reads this instead of re-deriving it. Empty in summaries written
    /// before this field existed (decoded as []).
    public let citedTechniqueKeys: [String]

    public init(statement: String, phase: KillChainPhase, severity: Severity,
                citations: [String], citedTechniqueKeys: [String] = []) {
        self.statement = statement
        self.phase = phase
        self.severity = severity
        self.citations = citations
        self.citedTechniqueKeys = citedTechniqueKeys
    }

    private enum CodingKeys: String, CodingKey {
        case statement, phase, severity, citations, citedTechniqueKeys
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        statement = try c.decode(String.self, forKey: .statement)
        phase = try c.decode(KillChainPhase.self, forKey: .phase)
        severity = try c.decode(Severity.self, forKey: .severity)
        citations = try c.decode([String].self, forKey: .citations)
        citedTechniqueKeys = try c.decodeIfPresent([String].self, forKey: .citedTechniqueKeys) ?? []
    }
}

/// What the evidence-reference validation pass did to a generated summary -
/// surfaced in the UI (and custody log) as the "calibrated trust" signal: how
/// many model claims were kept, how many were dropped for citing no real
/// finding, how many phantom citation IDs were stripped, and any file-path
/// tokens the model wrote that match no artifact in the case.
public nonisolated struct SummaryValidationReport: Codable, Sendable, Hashable {
    public let claimsProposed: Int
    public let claimsKept: Int
    public let claimsDroppedUnsupported: Int
    public let phantomRefsDropped: Int
    public let flaggedPathTokens: [String]

    public init(claimsProposed: Int, claimsKept: Int, claimsDroppedUnsupported: Int,
                phantomRefsDropped: Int, flaggedPathTokens: [String]) {
        self.claimsProposed = claimsProposed
        self.claimsKept = claimsKept
        self.claimsDroppedUnsupported = claimsDroppedUnsupported
        self.phantomRefsDropped = phantomRefsDropped
        self.flaggedPathTokens = flaggedPathTokens
    }

    /// True when validation changed or questioned the model's output - the UI can
    /// then show a caveat rather than presenting the summary as clean.
    public var hadIssues: Bool {
        claimsDroppedUnsupported > 0 || phantomRefsDropped > 0 || !flaggedPathTokens.isEmpty
    }

    /// Compact, non-zero-only summary of what validation flagged, e.g.
    /// "2 dropped, 1 flagged path". Empty when the report is clean. Single
    /// source of truth so the macOS chip and the iOS caveat can't drift.
    public var issuesSummary: String {
        var parts: [String] = []
        if claimsDroppedUnsupported > 0 { parts.append("\(claimsDroppedUnsupported) dropped") }
        if phantomRefsDropped > 0 {
            parts.append("\(phantomRefsDropped) phantom ref\(phantomRefsDropped == 1 ? "" : "s")")
        }
        if !flaggedPathTokens.isEmpty {
            parts.append("\(flaggedPathTokens.count) flagged path\(flaggedPathTokens.count == 1 ? "" : "s")")
        }
        return parts.joined(separator: ", ")
    }
}
