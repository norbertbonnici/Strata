import Foundation
import FoundationModels

/// The **middle** sovereignty tier (the talk's key nuance that sovereignty isn't
/// binary): generation runs on Apple's server model via **Private Cloud Compute**.
/// Data leaves the device — so this is gated + labeled like any egress — but only
/// to Apple-operated, attested, **stateless** nodes that retain nothing and need
/// **no API key or third party**. It runs the *same* `@Generable` structured +
/// tool-calling pipeline as `OnDeviceBackend`, so the evidence-reference
/// validator gates it identically; only the model swaps (a one-line change in
/// the Foundation Models framework, WWDC 2026).
///
/// `@available(macOS 27 / iOS 27)`: `PrivateCloudComputeLanguageModel` is new in
/// the 2026 SDK and the deployment target is lower, so every construction is
/// `if #available`-guarded (see `InferenceConfiguration.makeBackend`).
///
/// Note: unlike `SystemLanguageModel`, the PCC model exposes no guardrails knob,
/// so the `.permissiveContentTransformations` relaxation the on-device path uses
/// for forensic content (malware/attacker descriptions) isn't available here; a
/// guardrail refusal surfaces as a thrown error the caller already handles.
@available(macOS 27.0, iOS 27.0, visionOS 27.0, *)
public nonisolated struct PrivateCloudComputeBackend: InferenceBackend {
    public let label = "Apple Private Cloud Compute"
    public let sovereignty: SovereigntyTier = .applePrivateCloud

    public init() {}

    public func availability() -> SummarizerAvailability {
        switch PrivateCloudComputeLanguageModel().availability {
        case .available:
            return .available
        case .unavailable(let reason):
            switch reason {
            case .deviceNotEligible:
                return .unavailable(reason: "This device isn't eligible for Apple Private Cloud Compute.")
            case .systemNotReady:
                return .unavailable(reason: "Apple Private Cloud Compute isn't ready yet — make sure Apple Intelligence is enabled, then try again.")
            @unknown default:
                return .unavailable(reason: "Apple Private Cloud Compute is currently unavailable.")
            }
        }
    }

    private func model() -> PrivateCloudComputeLanguageModel { PrivateCloudComputeLanguageModel() }

    /// The model can call these to confirm a file or its download origin against
    /// the real artifact records (empty context ⇒ no tools) — same as on-device.
    private func tools(_ context: InferenceContext) -> [any Tool] {
        context.lookup.isEmpty ? []
            : [LookupFileTool(index: context.lookup, knownPaths: context.knownPaths),
               LookupDownloadOriginTool(index: context.lookup)]
    }

    public func proposeSummary(instructions: String, prompt: String,
                               context: InferenceContext) async throws -> ProposedSummary {
        let session = LanguageModelSession(model: model(), tools: tools(context)) { instructions }
        let generated = try await session.respond(to: prompt, generating: GeneratedSummary.self).content
        return generated.toProposed()
    }

    public func proposeClaims(instructions: String, prompt: String,
                              context: InferenceContext) async throws -> [ProposedClaim] {
        let session = LanguageModelSession(model: model(), tools: tools(context)) { instructions }
        let set = try await session.respond(to: prompt, generating: GeneratedClaimSet.self).content
        return set.toProposed()
    }

    public func synthesizeOverview(instructions: String, prompt: String) async throws -> String {
        let session = LanguageModelSession(model: model()) { instructions }
        let response = try await session.respond(to: prompt)
        return response.content.trimmingCharacters(in: .whitespacesAndNewlines)
    }
}
