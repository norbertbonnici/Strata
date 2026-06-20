import Foundation
import FoundationModels

/// Kill-chain phase as a guided-generation choice. A separate `@Generable` mirror
/// of `KillChainPhase` (which lives in StrataCore and must stay FoundationModels-
/// free for the iOS viewer + tests); the model picks one of these cases and we
/// map it back. Mirroring as an enum means the model physically cannot return a
/// phase that isn't in the kill chain.
@Generable
enum GeneratedPhase {
    case reconnaissance, weaponization, delivery, exploitation
    case installation, commandAndControl, actionsOnObjectives

    var resolved: KillChainPhase {
        switch self {
        case .reconnaissance:      return .reconnaissance
        case .weaponization:       return .weaponization
        case .delivery:            return .delivery
        case .exploitation:        return .exploitation
        case .installation:        return .installation
        case .commandAndControl:   return .commandAndControl
        case .actionsOnObjectives: return .actionsOnObjectives
        }
    }
}

/// Severity as a guided-generation choice (mirror of StrataCore's `Severity`).
@Generable
enum GeneratedSeverity {
    case info, low, medium, high, critical

    var resolved: Severity {
        switch self {
        case .info:     return .info
        case .low:      return .low
        case .medium:   return .medium
        case .high:     return .high
        case .critical: return .critical
        }
    }
}

/// One attacker-activity claim the model proposes. `findingRefs` are the digest
/// citation IDs (e.g. "F03") it must copy from the input; they're validated after
/// generation by `SummaryValidator`, not trusted.
@Generable
struct GeneratedClaim {
    @Guide(description: "One factual past-tense sentence describing this attacker activity.")
    let statement: String

    @Guide(description: "The cyber kill chain phase this activity belongs to.")
    let phase: GeneratedPhase

    @Guide(description: "The severity of this activity.")
    let severity: GeneratedSeverity

    @Guide(description: "Finding IDs supporting this statement, copied verbatim from the input lines (e.g. \"F03\"). Use only IDs that appear in the input.")
    let findingRefs: [String]
}

/// The model's typed executive summary. Guided generation guarantees this
/// *shape*; `SummaryValidator` enforces the *truth* of the references afterwards.
@Generable
struct GeneratedSummary {
    @Guide(description: "A thorough executive overview of the incident in two to four short paragraphs: lead with the most severe activity, walk through how it progresses across the cyber kill chain, and name the notable MITRE ATT&CK techniques. Plain prose - no markdown, no bullet lists.")
    let overview: String

    @Guide(description: "The distinct attacker activities, most severe first.")
    let claims: [GeneratedClaim]
}

/// A claims-only result, used by the multi-batch path's per-batch passes: each
/// batch extracts claims (the executive overview is synthesised once, from the
/// merged claims, not per batch).
@Generable
struct GeneratedClaimSet {
    @Guide(description: "The distinct attacker activities in this batch, most severe first.")
    let claims: [GeneratedClaim]
}

extension GeneratedClaim {
    /// Map into the FM-free `ProposedClaim` the validator consumes.
    func toProposed() -> ProposedClaim {
        ProposedClaim(statement: statement, phase: phase.resolved,
                      severity: severity.resolved, findingRefs: findingRefs)
    }
}

extension GeneratedSummary {
    func toProposed() -> ProposedSummary {
        ProposedSummary(overview: overview, claims: claims.map { $0.toProposed() })
    }
}

extension GeneratedClaimSet {
    func toProposed() -> [ProposedClaim] { claims.map { $0.toProposed() } }
}
