import Foundation

/// Where the summarizer's model inference runs. The summarizer owns the
/// deterministic pipeline (digest → batch → merge → **validate**); a backend
/// owns only the model round-trips, producing the FM-free `ProposedSummary` /
/// `[ProposedClaim]` / overview text that the *same* `SummaryValidator` then
/// gates. That's the point: **escalating to a cloud model is a configuration,
/// not an architecture rewrite**, and the evidence-reference validation is
/// backend-agnostic - hallucination containment applies on-device and in the
/// cloud alike.
///
/// (This is Strata's own protocol - not Apple's `LanguageModel`, which has no
/// public cloud backend.) The default backend is sovereign (`OnDeviceBackend`):
/// evidence-derived data leaves the host only when the analyst explicitly
/// selects, and credentials a cloud backend.
// `SovereigntyTier` lives in StrataCore (CaseSummary.swift) so persisted models
// and the report renderers can read it; the backends below declare it.

public protocol InferenceBackend: Sendable {
    /// Provenance label stamped on the `CaseSummary` (e.g. "Apple Intelligence
    /// (on-device)" or "Cloud · claude-opus-4-8").
    var label: String { get }
    /// Where this backend runs on the sovereignty spectrum. The UI/custody surface
    /// it so a run that leaves the host is never silent, and so Apple Private
    /// Cloud Compute (off-device but attested + non-retaining) is distinguished
    /// from a third-party endpoint the analyst credentialed.
    var sovereignty: SovereigntyTier { get }
    /// Whether this backend can run right now (model present / credentials set).
    func availability() -> SummarizerAvailability

    /// Maximum **input** context this backend's model accepts, in tokens. The
    /// summarizer sizes its per-request digest batches *and* its technique-group
    /// cap to this so a large case fits the *selected* window — on-device is the
    /// tightest, Apple Private Cloud Compute is 32k, a third-party cloud model is
    /// far larger. It is the input budget only; each backend reserves its own
    /// output allowance separately. Sizing to this is what lets a 60k-finding
    /// case generate instead of overflowing the window.
    var contextWindowTokens: Int { get }

    /// One-shot structured summary (overview + claims) from the whole digest.
    func proposeSummary(instructions: String, prompt: String,
                        context: InferenceContext) async throws -> ProposedSummary
    /// Claims-only extraction for one batch (the multi-batch path).
    func proposeClaims(instructions: String, prompt: String,
                       context: InferenceContext) async throws -> [ProposedClaim]
    /// Free-text overview synthesis from already-extracted claims (no schema).
    func synthesizeOverview(instructions: String, prompt: String) async throws -> String
}

public extension InferenceBackend {
    /// True only when nothing leaves the host. Drives the egress gate: anything
    /// that is not fully sovereign (incl. Apple Private Cloud Compute) is
    /// confirmed and clearly labeled before it runs.
    var isSovereign: Bool { sovereignty == .onDevice }
}

/// Read-only artifact data a backend may expose to the model as tools. Only the
/// on-device backend builds FoundationModels tools from it today; the cloud
/// backend ignores it (no evidence is sent beyond the digest).
public nonisolated struct InferenceContext: Sendable {
    public let lookup: CaseLookupIndex
    public let knownPaths: Set<String>
    public init(lookup: CaseLookupIndex = .empty, knownPaths: Set<String> = []) {
        self.lookup = lookup
        self.knownPaths = knownPaths
    }
}

/// Errors a backend can raise (the on-device path reuses the summarizer's own
/// availability error; these cover the cloud transport).
public enum InferenceError: Error, LocalizedError {
    case unavailable(String)
    case transport(String)
    case http(status: Int, body: String)
    case refused(String)
    case decode(String)

    public var errorDescription: String? {
        switch self {
        case .unavailable(let s): return s
        case .transport(let s):   return "Inference transport error: \(s)"
        case .http(let s, _):     return "Cloud model returned HTTP \(s)."
        case .refused(let s):     return "Cloud model declined the request: \(s)"
        case .decode(let s):      return "Could not parse the cloud model response: \(s)"
        }
    }
}
