import Foundation

/// Where a summary's inference ran on the sovereignty spectrum - the talk's
/// central axis, and the provenance the UI + examiner report + custody all key
/// off. Not binary: Apple Private Cloud Compute is a genuine middle tier (data
/// leaves the device, but only to Apple-operated, attested, stateless nodes that
/// retain nothing and need no third-party credential). Lives in `StrataCore`
/// (no `FoundationModels` dependency) so models that persist it, the report
/// renderers, and iOS can all use it; the `InferenceBackend`s in `StrataAI`
/// declare it.
public enum SovereigntyTier: String, Sendable, Hashable, Codable {
    /// Nothing leaves the host (on-device Apple Intelligence).
    case onDevice
    /// Leaves to Apple Private Cloud Compute: off-device, privacy-preserving,
    /// not retained; no API key, no third party.
    case applePrivateCloud
    /// Leaves to a configured third-party endpoint with the analyst's credential.
    case thirdPartyCloud

    /// Best-effort tier for a summary persisted before the tier was stored,
    /// inferred from its `modelLabel`. The **only** place a tier is recovered
    /// from a label string - everything else reads the stored value.
    public static func infer(fromLabel label: String) -> SovereigntyTier {
        if label.contains("Private Cloud") { return .applePrivateCloud }
        if label.hasPrefix("Cloud") { return .thirdPartyCloud }
        return .onDevice
    }
}

/// An AI-generated executive summary of a case's detection findings.
///
/// Produced on-device by the FoundationModels (Apple Intelligence) summarizer
/// in `StrataAI`, persisted case-wide as `summary.json`, surfaced on the Kill
/// Chain / Overview tabs and in the examiner report. Deliberately free of any
/// `FoundationModels` dependency so it codes/decodes on iOS (the read-only
/// viewer) and in tests like every other `StrataCore` value type.
public nonisolated struct CaseSummary: Codable, Sendable, Hashable {
    /// The generated narrative, plain text (rendered verbatim, like the
    /// analyst case narrative). For the validated structured path this is the
    /// executive overview; the per-claim detail lives in `claims`.
    public let text: String
    /// When the summary was generated.
    public let generatedAt: Date
    /// Number of findings the summary was built from - lets the UI flag a
    /// summary as stale when the finding count has since changed.
    public let findingCount: Int
    /// Human-readable provenance, e.g. "Apple Intelligence (on-device)".
    public let modelLabel: String
    /// Where inference ran - the authoritative provenance (the UI glyph, the
    /// examiner report, and custody all read this rather than re-deriving the
    /// tier from `modelLabel`).
    public let sovereignty: SovereigntyTier

    /// Validated, evidence-anchored claims from the structured on-device path.
    /// Empty for legacy summaries and for the plain-text/multi-batch fallback.
    public let claims: [SummaryClaim]
    /// What the evidence-reference validation pass did (the "calibrated trust"
    /// signal). `nil` when the summary was not produced by the validated path.
    public let validation: SummaryValidationReport?

    // Explicit keys so the additive `claims`/`validation`/`sovereignty` decode
    // from new files and are simply absent (→ []/nil/inferred) in older ones.
    // Same back-compat pattern as `Evidence` (acquisition/sourceHashes) in
    // Case.swift, using the same CaseStore encoder/decoder.
    enum CodingKeys: String, CodingKey {
        case text, generatedAt, findingCount, modelLabel, sovereignty, claims, validation
    }

    public init(text: String, generatedAt: Date, findingCount: Int, modelLabel: String,
                sovereignty: SovereigntyTier = .onDevice,
                claims: [SummaryClaim] = [], validation: SummaryValidationReport? = nil) {
        self.text = text
        self.generatedAt = generatedAt
        self.findingCount = findingCount
        self.modelLabel = modelLabel
        self.sovereignty = sovereignty
        self.claims = claims
        self.validation = validation
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        text = try c.decode(String.self, forKey: .text)
        generatedAt = try c.decode(Date.self, forKey: .generatedAt)
        findingCount = try c.decode(Int.self, forKey: .findingCount)
        modelLabel = try c.decode(String.self, forKey: .modelLabel)
        // Tolerate older summary.json that predates the validated structured path:
        // a defaulted stored property is NOT enough (synthesized decode treats a
        // non-optional key as required), so decode these explicitly. A pre-tier
        // summary infers its tier from the recorded label.
        sovereignty = try c.decodeIfPresent(SovereigntyTier.self, forKey: .sovereignty)
            ?? SovereigntyTier.infer(fromLabel: modelLabel)
        claims = try c.decodeIfPresent([SummaryClaim].self, forKey: .claims) ?? []
        validation = try c.decodeIfPresent(SummaryValidationReport.self, forKey: .validation)
    }
}
