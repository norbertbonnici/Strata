import Foundation

/// The model's *raw* (pre-validation) summary, mapped off the FoundationModels
/// `@Generable` type into plain value types so the validation pass - and its
/// tests - need no FoundationModels dependency or Apple-Intelligence device.
public struct ProposedSummary: Sendable, Equatable {
    public let overview: String
    public let claims: [ProposedClaim]
    public init(overview: String, claims: [ProposedClaim]) {
        self.overview = overview
        self.claims = claims
    }
}

public struct ProposedClaim: Sendable, Equatable {
    public let statement: String
    public let phase: KillChainPhase
    public let severity: Severity
    public let findingRefs: [String]
    public init(statement: String, phase: KillChainPhase, severity: Severity, findingRefs: [String]) {
        self.statement = statement
        self.phase = phase
        self.severity = severity
        self.findingRefs = findingRefs
    }
}

/// The validated result: cleaned claims + a report of what validation did.
public struct ValidatedSummary: Sendable {
    public let overview: String
    public let claims: [SummaryClaim]
    public let report: SummaryValidationReport
    public init(overview: String, claims: [SummaryClaim], report: SummaryValidationReport) {
        self.overview = overview
        self.claims = claims
        self.report = report
    }
}

/// Evidence-reference validation - the hallucination-containment gate that turns
/// a guided-generation result into something an examiner can trust. Guided
/// generation constrains the model's *shape*; this constrains its *truth*:
///
/// - a claim that cites no real finding is dropped (the model can't assert
///   activity that isn't anchored to evidence);
/// - phantom citation IDs (never present in the digest) are stripped;
/// - a claim's severity and phase are taken from its cited findings, never the
///   model, so it can't quietly upgrade "benign" to "critical";
/// - citations shown to the analyst are the cited findings' own evidence paths,
///   never a path the model typed;
/// - any file-path-looking token the model wrote that matches no path in the
///   case is flagged.
///
/// Pure and `Sendable`; runs off-main and is fully unit-testable without a model.
public struct SummaryValidator: Sendable {
    private let idMap: [String: FindingsSummarizer.DigestItem]
    private let knownPaths: Set<String>

    /// `knownPaths` seeds the "is this a real path" check; the validator also
    /// folds in every cited finding's own evidence paths, so a path that appears
    /// on any finding is recognised even if the caller passes no file index.
    public init(idMap: [String: FindingsSummarizer.DigestItem], knownPaths: Set<String>) {
        self.idMap = idMap
        var known = knownPaths
        for item in idMap.values { known.formUnion(item.rep.evidencePaths) }
        self.knownPaths = known
    }

    public func validate(_ proposed: ProposedSummary) -> ValidatedSummary {
        var kept: [SummaryClaim] = []
        var droppedUnsupported = 0
        var phantomRefs = 0
        var flagged: [String] = []

        for claim in proposed.claims {
            // Normalise refs before lookup: the digest renders IDs parenthesised
            // ("- (F37) …") and the model may copy that form, so strip bracketing
            // punctuation/whitespace or a valid citation would be lost to nil.
            let refs = Self.orderedUnique(claim.findingRefs.compactMap {
                let n = Self.normalizeRef($0); return n.isEmpty ? nil : n
            })
            let cited = refs.compactMap { idMap[$0] }
            phantomRefs += refs.count - cited.count
            guard !cited.isEmpty else { droppedUnsupported += 1; continue }

            // Severity/phase are authoritative from the evidence, not the model.
            let severity = cited.map(\.maxSeverity).max() ?? claim.severity
            let phase = cited.max(by: { $0.maxSeverity < $1.maxSeverity })?.rep.phase ?? claim.phase
            let citations = Self.orderedUnique(cited.flatMap { $0.rep.evidencePaths })
            // Record which technique buckets this claim cites, so downstream
            // scoring needn't re-derive attribution from the (lossy) path list.
            let techniqueKeys = Self.orderedUnique(cited.map { $0.rep.techniqueBucketKey })

            flagged.append(contentsOf: pathLikeTokens(in: claim.statement).filter { !isKnownPath($0) })
            kept.append(SummaryClaim(statement: claim.statement, phase: phase,
                                     severity: severity, citations: citations,
                                     citedTechniqueKeys: techniqueKeys))
        }
        flagged.append(contentsOf: pathLikeTokens(in: proposed.overview).filter { !isKnownPath($0) })

        kept.sort { ($0.severity, $0.citations.count) > ($1.severity, $1.citations.count) }

        let report = SummaryValidationReport(
            claimsProposed: proposed.claims.count,
            claimsKept: kept.count,
            claimsDroppedUnsupported: droppedUnsupported,
            phantomRefsDropped: phantomRefs,
            flaggedPathTokens: Self.orderedUnique(flagged))
        return ValidatedSummary(overview: proposed.overview, claims: kept, report: report)
    }

    // MARK: - Path heuristics

    /// Whether `token` matches some real path in the case. Lenient on purpose -
    /// the model may quote a path verbatim, abbreviate it, or use only a trailing
    /// component - so a substring match counts; the goal is to catch the clearly
    /// invented path, not to police formatting.
    private func isKnownPath(_ token: String) -> Bool {
        if knownPaths.contains(token) { return true }
        return knownPaths.contains { $0.hasSuffix(token) || $0.contains(token) }
    }

    /// Path-looking tokens in free text. Conservative: only Unix paths with at
    /// least two components ("/a/b") or Windows drive paths ("C:\…") qualify, so
    /// hostnames, IPs, commands and ATT&CK IDs (the other things analyzers stuff
    /// into evidence) don't false-fire.
    private func pathLikeTokens(in text: String) -> [String] {
        text.split(whereSeparator: { $0 == " " || $0 == "\n" || $0 == "\t" })
            .map { Self.trimPunctuation(String($0)) }
            .filter { Self.isPathLike($0) }
    }

    static func isPathLike(_ t: String) -> Bool {
        if t.hasPrefix("/"), t.dropFirst().contains("/") { return true }
        let chars = Array(t)
        if chars.count >= 3, chars[0].isLetter, chars[1] == ":", chars[2] == "\\" { return true }
        return false
    }

    static func trimPunctuation(_ s: String) -> String {
        s.trimmingCharacters(in: CharacterSet(charactersIn: "\"'`(),.;"))
    }

    /// Strip the brackets/whitespace a model may wrap a citation ID in, so
    /// "(F37)", " F37 " and "F37" all resolve to the same digest key.
    static func normalizeRef(_ s: String) -> String {
        s.trimmingCharacters(in: CharacterSet(charactersIn: "()[]{} \t\"'.,;"))
    }

    static func orderedUnique(_ xs: [String]) -> [String] {
        var seen = Set<String>(); var out: [String] = []
        out.reserveCapacity(xs.count)
        for x in xs where seen.insert(x).inserted { out.append(x) }
        return out
    }
}
