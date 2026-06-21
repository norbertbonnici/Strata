import Foundation
import FoundationModels

/// The sovereign default backend: generation runs entirely on-device via Apple
/// FoundationModels. Nothing leaves the host. This is the existing structured /
/// tool-calling path, lifted out of `FindingsSummarizer` so the summarizer can
/// drive any `InferenceBackend` with identical orchestration + validation.
public nonisolated struct OnDeviceBackend: InferenceBackend {
    public let label = FindingsSummarizer.modelLabel   // "Apple Intelligence (on-device)"
    public let sovereignty: SovereigntyTier = .onDevice

    /// Apple's on-device foundation model has the tightest window of the three
    /// backends. Apple doesn't publish an exact figure, so this is deliberately
    /// conservative — the summarizer reserves output/schema room on top, so a
    /// too-high value here is what would surface as `LanguageModelError -1`.
    public let contextWindowTokens = 4_096

    public init() {}

    public func availability() -> SummarizerAvailability { FindingsSummarizer.availability }

    private func model() -> SystemLanguageModel {
        // Forensic findings describe malware/attacker activity, which trips the
        // default safety guardrails; this transformation is documented for it.
        SystemLanguageModel(guardrails: .permissiveContentTransformations)
    }

    /// The model can call these to confirm a file or its download origin against
    /// the real artifact records (empty context ⇒ no tools).
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
