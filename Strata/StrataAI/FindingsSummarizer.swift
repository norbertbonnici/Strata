import Foundation
import FoundationModels

/// Whether the on-device model can be used right now, with a human-readable
/// reason when it can't (so the UI can disable the action and explain why).
public nonisolated enum SummarizerAvailability: Sendable, Equatable {
    case available
    case unavailable(reason: String)

    public var isAvailable: Bool {
        if case .available = self { return true }
        return false
    }
}

/// On-device executive-summary generator for detection findings, backed by
/// Apple Intelligence (FoundationModels). Runs entirely on-device - no network,
/// no evidence leaves the host - which is why it fits Strata's confidentiality
/// rule where a cloud LLM never could.
///
/// Forensic findings describe malware and attacker activity, which trips the
/// model's default safety guardrails, so we use
/// `.permissiveContentTransformations` (documented for exactly this case; it
/// applies only to string generation, which is all we do here).
public nonisolated struct FindingsSummarizer: Sendable {

    public enum SummarizerError: Error, LocalizedError {
        case noFindings
        case unavailable(String)

        public var errorDescription: String? {
            switch self {
            case .noFindings:        return "There are no findings to summarize."
            case .unavailable(let r): return r
            }
        }
    }

    /// Provenance label stamped onto the generated `CaseSummary`.
    public static let modelLabel = "Apple Intelligence (on-device)"

    public init() {}

    // MARK: - Availability

    /// Current availability of the default system model.
    public static var availability: SummarizerAvailability {
        switch SystemLanguageModel.default.availability {
        case .available:
            return .available
        case .unavailable(let reason):
            return .unavailable(reason: describe(reason))
        @unknown default:
            return .unavailable(reason: "Apple Intelligence is unavailable on this device.")
        }
    }

    private static func describe(_ reason: SystemLanguageModel.Availability.UnavailableReason) -> String {
        switch reason {
        case .deviceNotEligible:
            return "This Mac doesn't support Apple Intelligence."
        case .appleIntelligenceNotEnabled:
            return "Apple Intelligence is turned off. Enable it in System Settings to generate summaries."
        case .modelNotReady:
            return "The on-device model is still downloading. Try again shortly."
        @unknown default:
            return "Apple Intelligence is unavailable on this device."
        }
    }

    // MARK: - Generation

    /// Approximate character budget per model request, a conservative proxy for
    /// the on-device context window. The aggregated digest is summarized in
    /// batches under this budget, then the batch summaries are combined - the
    /// long-input recipe Apple documents for `LanguageModelSession`.
    private static let promptBudget = 6_000

    /// Cap on the number of aggregated technique groups fed to the model. A case
    /// can have hundreds of repetitive analyzer hits; aggregation collapses them
    /// by technique, and this cap bounds the worst case so generation stays
    /// responsive (one or two model calls, not dozens). Omitted groups are noted
    /// in the digest so the model - and reader - know the view is truncated.
    static let maxDigestGroups = 60

    /// Generate an executive summary of `findings`. Throws `SummarizerError`
    /// when there is nothing to summarize or the model is unavailable, and
    /// propagates `LanguageModelSession` generation errors otherwise.
    ///
    /// `progress` is called as `(completedCalls, totalCalls)` before each model
    /// round-trip so callers can show movement during a multi-batch run.
    public func summarize(findings: [Finding],
                          progress: (@Sendable (Int, Int) -> Void)? = nil) async throws -> String {
        guard !findings.isEmpty else { throw SummarizerError.noFindings }

        let model = SystemLanguageModel(guardrails: .permissiveContentTransformations)
        guard case .available = model.availability else {
            throw SummarizerError.unavailable(Self.availability.unavailableReason
                ?? "Apple Intelligence is unavailable on this device.")
        }

        // Aggregate hundreds of findings into a compact, deduplicated digest,
        // then split that under the prompt budget.
        let lines = Self.digestLines(findings)
        let batches = Self.batch(lines, underBudget: Self.promptBudget)

        if batches.count == 1 {
            progress?(0, 1)
            return try await respond(model: model,
                                     instructions: Self.executiveInstructions,
                                     prompt: Self.executivePrompt(lines: lines, total: findings.count))
        }

        // Hierarchical: summarize each batch, then combine the partials. The
        // final combine is the extra (+1) call reflected in the total.
        let total = batches.count + 1
        var partials: [String] = []
        partials.reserveCapacity(batches.count)
        for (index, batch) in batches.enumerated() {
            progress?(index, total)
            let partial = try await respond(model: model,
                                            instructions: Self.sectionInstructions,
                                            prompt: Self.sectionPrompt(lines: batch))
            partials.append(partial)
        }
        progress?(batches.count, total)
        return try await respond(model: model,
                                 instructions: Self.executiveInstructions,
                                 prompt: Self.combinePrompt(partials: partials, total: findings.count))
    }

    /// One model round-trip in a fresh session (single-turn).
    private func respond(model: SystemLanguageModel,
                         instructions: String,
                         prompt: String) async throws -> String {
        let session = LanguageModelSession(model: model) { instructions }
        let response = try await session.respond(to: prompt)
        return response.content.trimmingCharacters(in: .whitespacesAndNewlines)
    }

    // MARK: - Prompt construction

    private static let executiveInstructions = """
        You are a digital forensics and incident response (DFIR) analyst assistant. \
        You write concise, factual executive summaries of automated detection findings \
        for an incident report. Base every statement strictly on the findings you are \
        given - never invent hosts, accounts, file paths, timestamps, or techniques. \
        Lead with the most severe activity, describe how the activity maps onto the \
        cyber kill chain, and call out notable MITRE ATT&CK techniques by name. Write \
        plain prose in one to three short paragraphs. Do not use markdown headings or \
        bullet lists.
        """

    private static let sectionInstructions = """
        You are a DFIR analyst assistant. Summarize this batch of automated detection \
        findings into a few factual sentences capturing the most severe activity and \
        notable ATT&CK techniques. Base everything strictly on the findings provided.
        """

    private static func executivePrompt(lines: [String], total: Int) -> String {
        "Summarize the following \(total) detection finding\(total == 1 ? "" : "s") "
        + "into an executive summary:\n\n" + lines.joined(separator: "\n")
    }

    private static func sectionPrompt(lines: [String]) -> String {
        "Summarize the following detection findings:\n\n" + lines.joined(separator: "\n")
    }

    private static func combinePrompt(partials: [String], total: Int) -> String {
        "The following are partial summaries of \(total) detection findings from one "
        + "case. Combine them into a single executive summary, removing repetition:\n\n"
        + partials.enumerated().map { "(\($0.offset + 1)) \($0.element)" }.joined(separator: "\n\n")
    }

    // MARK: - Digest

    /// Aggregated, deduplicated digest - one line per ATT&CK technique (or per
    /// title when a finding is untagged), not one per finding. A case with
    /// hundreds of repetitive analyzer hits collapses to a few dozen lines,
    /// which is both far cheaper to summarize and a better executive view.
    /// Groups are sorted by max severity then frequency, capped at
    /// `maxDigestGroups`, with the omitted count noted.
    static func digestLines(_ findings: [Finding]) -> [String] {
        struct Group { var rep: Finding; var count: Int; var maxSeverity: Severity }
        var groups: [String: Group] = [:]
        var order: [String] = []
        for f in findings {
            let key = f.technique?.attackID ?? f.title
            if var g = groups[key] {
                g.count += 1
                if f.severity > g.maxSeverity { g.maxSeverity = f.severity }
                if f.severity > g.rep.severity { g.rep = f }   // keep worst as representative
                groups[key] = g
            } else {
                groups[key] = Group(rep: f, count: 1, maxSeverity: f.severity)
                order.append(key)
            }
        }

        let sorted = order.compactMap { groups[$0] }
            .sorted { ($0.maxSeverity, $0.count) > ($1.maxSeverity, $1.count) }
        let capped = sorted.prefix(maxDigestGroups)

        var lines = capped.map { g -> String in
            let f = g.rep
            var line = "- [\(g.maxSeverity.label)] \(f.phase.title): \(f.title)"
            if let t = f.technique { line += " (\(t.attackID) \(t.name))" }
            if g.count > 1 { line += " ×\(g.count)" }
            let detail = f.detail.trimmingCharacters(in: .whitespacesAndNewlines)
            if !detail.isEmpty {
                line += " — " + String(detail.prefix(240))
            }
            return line
        }
        if sorted.count > capped.count {
            lines.append("- (+\(sorted.count - capped.count) more lower-severity finding group(s) omitted for brevity)")
        }
        return lines
    }

    /// Greedily group lines into batches whose joined length stays under
    /// `budget`. A single oversized line still forms its own batch.
    static func batch(_ lines: [String], underBudget budget: Int) -> [[String]] {
        var batches: [[String]] = []
        var current: [String] = []
        var size = 0
        for line in lines {
            if !current.isEmpty, size + line.count > budget {
                batches.append(current)
                current = []
                size = 0
            }
            current.append(line)
            size += line.count + 1
        }
        if !current.isEmpty { batches.append(current) }
        return batches.isEmpty ? [[]] : batches
    }
}

private extension SummarizerAvailability {
    nonisolated var unavailableReason: String? {
        if case .unavailable(let r) = self { return r }
        return nil
    }
}
