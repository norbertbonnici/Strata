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

    /// Decode a FoundationModels generation failure into an actionable message,
    /// so a failure surfaces as the real cause instead of the opaque
    /// "The operation couldn't be completed. (…LanguageModelError error -1.)".
    /// Returns nil for a non-FM error (caller falls back to `localizedDescription`).
    ///
    /// The decisive case is a guardrail/refusal: forensic findings describe
    /// malware and attacker activity, which trips the model's *default* safety
    /// guardrails. `OnDeviceBackend` relaxes them with
    /// `.permissiveContentTransformations`, but Apple Private Cloud Compute
    /// exposes **no guardrails knob** (`PrivateCloudComputeLanguageModel` has no
    /// such init), so it refuses such content regardless of context-window size —
    /// exactly the "PCC fails where on-device works, at any window" symptom.
    public static func describeGenerationFailure(_ error: Error, backendLabel: String) -> String? {
        guard #available(macOS 27.0, iOS 27.0, visionOS 27.0, *),
              let e = error as? LanguageModelError else { return nil }
        switch e {
        case .guardrailViolation, .refusal:
            return "\(backendLabel) declined the case on content-safety grounds — the findings "
                + "describe malware and attacker activity, which trips the model's default "
                + "guardrails. Apple Private Cloud Compute can't relax these the way the on-device "
                + "model does, so this is independent of the context window. Use On-device or a "
                + "third-party cloud model for this case."
        case .unsupportedGenerationGuide:
            return "\(backendLabel) doesn't support the structured (guided) generation this summary "
                + "uses. Use On-device or a third-party cloud model."
        case .unsupportedCapability:
            return "\(backendLabel) doesn't support a capability this summary needs (e.g. tool "
                + "calls). Use On-device or a third-party cloud model."
        case .contextSizeExceeded(let info):
            return "The case is too large for \(backendLabel)'s context window "
                + "(\(info.tokenCount) tokens vs \(info.contextSize)). Lower the Context window in "
                + "AI Inference settings, or use a backend with a larger window."
        case .timeout:
            return "\(backendLabel) timed out generating the summary. Try again, or lower the "
                + "Context window so each request is smaller."
        case .rateLimited:
            return "\(backendLabel) is rate-limited right now — wait a moment and try again."
        case .unsupportedLanguageOrLocale:
            return "\(backendLabel) doesn't support the language or locale of this content."
        case .unsupportedTranscriptContent:
            return "\(backendLabel) rejected part of the prompt content."
        @unknown default:
            return nil
        }
    }

    // MARK: - Generation

    /// Floor for the number of aggregated technique groups fed to the model, and
    /// the value `digestGroupCap(forWindow:)` never drops below — so no backend
    /// narrates less of a case than this. A case can have hundreds of repetitive
    /// analyzer hits; aggregation collapses them by technique, and this bounds the
    /// worst case. Omitted groups are noted in the digest so the model — and
    /// reader — know the view is truncated.
    static let maxDigestGroups = 60

    /// Coarse token estimate (~4 chars/token, rounded up). Used only to size
    /// requests against a backend's context window — not a real tokenizer.
    static func estimateTokens(_ text: String) -> Int { (text.count + 3) / 4 }

    /// Character budget for a single model request, derived from the selected
    /// backend's context window. Reserves tokens for the instructions, the
    /// guided-generation schema, the lookup-tool definitions, and the model's own
    /// output, then converts the remaining *input* allowance to characters at a
    /// deliberately low ~3 chars/token so a path-dense forensic digest still fits.
    /// Floored so a tiny window still makes progress. Replacing the old fixed
    /// 6,000-char budget is what makes batching correct for the *smallest*
    /// selected window (on-device) rather than coincidentally safe at one guess —
    /// and on a wide window (Apple PCC's 32k) it lets the whole digest go in one
    /// call instead of needlessly fragmenting into many round-trips.
    static func promptBudgetChars(forWindow window: Int) -> Int {
        let reserveTokens = 3_000            // instructions + schema + tools + output
        let inputTokens = max(800, window - reserveTokens)
        return max(2_000, inputTokens * 3)
    }

    /// How many aggregated technique groups to feed the model, scaled to the
    /// window: a wide window (Apple PCC / cloud) narrates much more of a large
    /// case; a narrow one (on-device) stays terse. Floored at `maxDigestGroups`
    /// so no backend regresses below today's coverage, and ceiling-capped so a
    /// pathological all-distinct-technique case still terminates into the
    /// multi-batch + bounded-merge path rather than an unbounded prompt.
    static func digestGroupCap(forWindow window: Int) -> Int {
        min(600, max(maxDigestGroups, window / 110))
    }

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
        // then split that under the on-device window's prompt budget.
        let window = OnDeviceBackend().contextWindowTokens
        let lines = Self.digestLines(findings, maxGroups: Self.digestGroupCap(forWindow: window))
        let batches = Self.batch(lines, underBudget: Self.promptBudgetChars(forWindow: window))

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

    /// Structured, **validated** variant of `summarize`. The model returns a
    /// typed `GeneratedSummary` (guided generation) whose claims cite findings by
    /// the digest's `F01`-style IDs; `SummaryValidator` then drops any claim that
    /// cites no real finding, strips phantom IDs, takes severity/phase from the
    /// cited findings (not the model), sources citations from those findings' real
    /// evidence paths, and flags any invented file-path token. The caller maps the
    /// resulting `ValidatedSummary` into a persisted `CaseSummary`.
    ///
    /// `fileIndex` is the set of real file paths in the case (e.g. every
    /// `FileEntry.fullPath`); it widens the corpus used to recognise a path the
    /// model quotes, beyond the paths already carried on the findings.
    ///
    /// Single-batch (the common case after aggregation) is one typed round-trip.
    /// A larger case is split into prompt-budget batches: each batch extracts
    /// typed claims (citing its slice of the global digest IDs), the claims are
    /// merged deterministically, and one executive overview is synthesised from
    /// the merge - then the whole proposed summary goes through the **same**
    /// validator, so the evidence-anchored guarantee holds at any case size.
    /// `lookupIndex`, when non-empty, exposes read-only **tools** (`lookupFile`,
    /// `lookupDownloadOrigin`) the model can call during generation to confirm a
    /// file or its download origin against the real artifact records instead of
    /// guessing.
    /// `backend` selects where the model inference runs - the sovereign
    /// `OnDeviceBackend` by default, or a cloud backend when policy permits. The
    /// orchestration (digest → batch → merge) and the `SummaryValidator` gate are
    /// identical for every backend: escalation is a configuration, and evidence-
    /// reference validation is backend-agnostic.
    public func summarizeStructured(findings: [Finding],
                                    fileIndex: Set<String> = [],
                                    lookupIndex: CaseLookupIndex = .empty,
                                    backend: any InferenceBackend = OnDeviceBackend(),
                                    progress: (@Sendable (Int, Int) -> Void)? = nil) async throws -> ValidatedSummary {
        guard !findings.isEmpty else { throw SummarizerError.noFindings }
        guard case .available = backend.availability() else {
            throw SummarizerError.unavailable(backend.availability().unavailableReason
                ?? "The selected inference backend is unavailable.")
        }

        // Size the digest cap and the per-request batch budget to the *selected*
        // backend's context window, so a 60k-finding case fits whatever window is
        // in play (on-device is tightest; Apple PCC is 32k; cloud is far larger).
        let window = backend.contextWindowTokens
        let budget = Self.promptBudgetChars(forWindow: window)
        let groupCap = Self.digestGroupCap(forWindow: window)

        let (items, _) = Self.digest(findings, maxGroups: groupCap)
        let lines = Self.digestLines(findings, maxGroups: groupCap)
        let batches = Self.batch(lines, underBudget: budget)
        let validator = SummaryValidator(idMap: Self.idMap(items), knownPaths: fileIndex)
        let context = InferenceContext(lookup: lookupIndex, knownPaths: fileIndex)

        let proposed: ProposedSummary
        if batches.count == 1 {
            progress?(0, 1)
            proposed = try await backend.proposeSummary(
                instructions: Self.structuredInstructions,
                prompt: Self.executivePrompt(lines: lines, total: findings.count),
                context: context)
        } else {
            proposed = try await structuredMultiBatch(backend: backend, context: context,
                                                      batches: batches, total: findings.count,
                                                      budgetChars: budget, progress: progress)
        }
        return validator.validate(proposed)
    }

    /// Warm the on-device model ahead of an anticipated summary request (e.g.
    /// when the Kill Chain / summary surface appears) so the first generation is
    /// faster. No-op when Apple Intelligence is unavailable.
    public static func prewarm() {
        guard case .available = SystemLanguageModel.default.availability else { return }
        LanguageModelSession(model: SystemLanguageModel(guardrails: .permissiveContentTransformations)).prewarm()
    }

    /// Typed multi-batch path: extract claims per batch (each citing the global
    /// `F01`-style digest IDs that appear in its slice), merge them, then
    /// synthesise one executive overview from the merged claims. The merged
    /// proposed summary is returned for the caller's single validator pass.
    private func structuredMultiBatch(backend: any InferenceBackend,
                                      context: InferenceContext,
                                      batches: [[String]],
                                      total: Int,
                                      budgetChars: Int,
                                      progress: (@Sendable (Int, Int) -> Void)?) async throws -> ProposedSummary {
        let progressTotal = batches.count + 1   // one pass per batch + the overview synthesis
        var sectionClaims: [[ProposedClaim]] = []
        sectionClaims.reserveCapacity(batches.count)
        for (index, batch) in batches.enumerated() {
            progress?(index, progressTotal)
            let claims = try await backend.proposeClaims(
                instructions: Self.structuredSectionInstructions,
                prompt: Self.sectionPrompt(lines: batch),
                context: context)
            sectionClaims.append(claims)
        }
        let merged = Self.mergeProposedClaims(sectionClaims)

        progress?(batches.count, progressTotal)
        // Synthesise the overview WITHOUT ever building a prompt larger than the
        // window. This is the one place the old flat path could overflow: with
        // many batches, the merged-claims prompt (or the empty-merge fallback,
        // which previously re-fed *every* digest line at once) could exceed the
        // window and throw an opaque model error. Both branches now reduce
        // hierarchically under `budgetChars`.
        let overview: String
        if merged.isEmpty {
            // No claims survived: summarise each (already budget-sized) batch,
            // then combine the partials under budget — never the whole digest.
            var partials: [String] = []
            partials.reserveCapacity(batches.count)
            for batch in batches {
                partials.append(try await backend.synthesizeOverview(
                    instructions: Self.sectionInstructions,
                    prompt: Self.sectionPrompt(lines: batch)))
            }
            overview = try await combineBounded(backend: backend, partials: partials,
                                                total: total, budgetChars: budgetChars)
        } else {
            // Severity order so "lead with the most severe" matches what the
            // model sees (the validator re-sorts the kept claims regardless).
            let ordered = merged.sorted { ($0.severity, $0.findingRefs.count) > ($1.severity, $1.findingRefs.count) }
            overview = try await overviewFromClaimsBounded(backend: backend, claims: ordered,
                                                           total: total, budgetChars: budgetChars)
        }
        return ProposedSummary(overview: overview, claims: merged)
    }

    /// Synthesize one overview from severity-ordered claims without exceeding
    /// `budgetChars`. If the whole claims prompt fits, it's one call; otherwise
    /// the claims are packed into budget-sized chunks, each chunk summarised, and
    /// the partials combined (recursively). Only the final prose is unvalidated;
    /// the citeable record stays the merged `claims`, which the caller validates.
    private func overviewFromClaimsBounded(backend: any InferenceBackend,
                                           claims: [ProposedClaim],
                                           total: Int,
                                           budgetChars: Int) async throws -> String {
        let chunks = Self.chunk(claims, budgetChars: budgetChars) { Self.overviewFromClaimsPrompt($0) }
        if chunks.count <= 1 {
            return try await backend.synthesizeOverview(
                instructions: Self.executiveInstructions,
                prompt: Self.overviewFromClaimsPrompt(claims))
        }
        var partials: [String] = []
        partials.reserveCapacity(chunks.count)
        for chunk in chunks {
            partials.append(try await backend.synthesizeOverview(
                instructions: Self.sectionInstructions,
                prompt: Self.overviewFromClaimsPrompt(chunk)))
        }
        return try await combineBounded(backend: backend, partials: partials,
                                        total: total, budgetChars: budgetChars)
    }

    /// Combine prose partials into one overview, never exceeding `budgetChars`.
    /// If the combine prompt fits (or there's one partial), it's a single call;
    /// otherwise partials are grouped under budget, each group combined, and the
    /// result reduced again. Terminates because each pass strictly shrinks the
    /// count (or falls through to a best-effort direct combine).
    private func combineBounded(backend: any InferenceBackend,
                                partials: [String],
                                total: Int,
                                budgetChars: Int) async throws -> String {
        guard partials.count > 1 else { return partials.first ?? "" }
        let prompt = Self.combinePrompt(partials: partials, total: total)
        if prompt.count <= budgetChars {
            return try await backend.synthesizeOverview(
                instructions: Self.executiveInstructions, prompt: prompt)
        }
        let groups = Self.chunk(partials, budgetChars: budgetChars) { Self.combinePrompt(partials: $0, total: total) }
        guard groups.count > 1, groups.count < partials.count else {
            // Can't reduce further (each partial already ~budget): best-effort
            // direct combine rather than loop forever. Partials are bounded model
            // outputs, so this is reachable only pathologically.
            return try await backend.synthesizeOverview(
                instructions: Self.executiveInstructions, prompt: prompt)
        }
        var reduced: [String] = []
        reduced.reserveCapacity(groups.count)
        for group in groups {
            reduced.append(try await backend.synthesizeOverview(
                instructions: Self.sectionInstructions,
                prompt: Self.combinePrompt(partials: group, total: total)))
        }
        return try await combineBounded(backend: backend, partials: reduced,
                                        total: total, budgetChars: budgetChars)
    }

    /// Greedily pack `items` into groups whose rendered `prompt` stays under
    /// `budgetChars`. A single item whose own prompt already exceeds the budget
    /// forms its own (oversized) group — best effort, but a single digest
    /// claim/line is far smaller than any real window.
    static func chunk<T>(_ items: [T], budgetChars: Int, prompt: ([T]) -> String) -> [[T]] {
        var groups: [[T]] = []
        var current: [T] = []
        for item in items {
            if !current.isEmpty, prompt(current + [item]).count > budgetChars {
                groups.append(current)
                current = [item]
            } else {
                current.append(item)
            }
        }
        if !current.isEmpty { groups.append(current) }
        return groups
    }

    /// Merge per-batch proposed claims, de-duplicating by normalised statement
    /// (batches cover disjoint findings, so this only removes accidental repeats)
    /// and dropping blanks. Order is preserved; the validator applies the final
    /// severity ordering. Pure + FM-free so it is unit-testable without a model.
    static func mergeProposedClaims(_ sets: [[ProposedClaim]]) -> [ProposedClaim] {
        var seen = Set<String>()
        var merged: [ProposedClaim] = []
        for set in sets {
            for claim in set {
                let key = claim.statement.lowercased().trimmingCharacters(in: .whitespacesAndNewlines)
                if !key.isEmpty, seen.insert(key).inserted { merged.append(claim) }
            }
        }
        return merged
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
        You write thorough, factual executive summaries of automated detection findings \
        for an incident report. Base every statement strictly on the findings you are \
        given - never invent hosts, accounts, file paths, timestamps, or techniques. \
        Lead with the most severe activity, then walk through how the activity \
        progresses across the cyber kill chain - initial access, execution, \
        persistence, and impact - and call out notable MITRE ATT&CK techniques by name \
        with their IDs. Note affected hosts and accounts where the findings name them. \
        Write a substantive narrative of two to four short paragraphs. Do not use \
        markdown headings or bullet lists.
        """

    private static let sectionInstructions = """
        You are a DFIR analyst assistant. Summarize this batch of automated detection \
        findings into a few factual sentences capturing the most severe activity and \
        notable ATT&CK techniques. Base everything strictly on the findings provided.
        """

    private static let structuredInstructions = """
        You are a digital forensics and incident response (DFIR) analyst assistant. \
        You convert automated detection findings into a structured executive summary \
        for an incident report. Each input line begins with a finding ID in \
        parentheses, e.g. "(F03)". Base every statement strictly on the findings \
        given - never invent hosts, accounts, file paths, timestamps, or techniques, \
        and never write a path or identifier that does not appear in the findings. \
        For each distinct attacker activity, write one factual sentence and list the \
        supporting finding IDs using the bare ID - for a line beginning "(F03)", cite \
        F03 without the parentheses. When a finding names a file, you may call the \
        lookupFile and lookupDownloadOrigin tools to confirm the file and where it \
        came from before describing it; rely on tool results, not guesses. Lead with \
        the most severe activity. Write the overview as a substantive two to four \
        short paragraphs of plain prose that walk through the incident across the \
        kill chain - no markdown.
        """

    private static let structuredSectionInstructions = """
        You are a DFIR analyst assistant. From this batch of automated detection \
        findings, extract the distinct attacker activities. Each input line begins \
        with a finding ID in parentheses, e.g. "(F37)". For each activity write one \
        factual sentence and list the supporting finding IDs using the bare ID \
        (e.g. F37, not "(F37)") - use only IDs that appear here. You may call the \
        lookupFile / lookupDownloadOrigin tools to confirm a file or its download \
        origin before describing it. Base everything strictly on the findings; never \
        invent paths, hosts, accounts, or techniques.
        """

    private static func executivePrompt(lines: [String], total: Int) -> String {
        "Summarize the following \(total) detection finding\(total == 1 ? "" : "s") "
        + "into an executive summary:\n\n" + lines.joined(separator: "\n")
    }

    private static func sectionPrompt(lines: [String]) -> String {
        "Summarize the following detection findings:\n\n" + lines.joined(separator: "\n")
    }

    /// Prompt for synthesising the executive overview from already-extracted
    /// claims (the multi-batch path). The claims are the validated facts; the
    /// overview is pure narrative synthesis over them.
    private static func overviewFromClaimsPrompt(_ claims: [ProposedClaim]) -> String {
        "Write a thorough executive overview (two to four short paragraphs, plain prose, "
        + "no markdown) of an incident characterised by the following activities. Lead "
        + "with the most severe and walk through how the activity progresses across the "
        + "kill chain. Do not introduce any host, path, account, or detail not present "
        + "below:\n\n"
        + claims.map { "- [\($0.severity.label)] \($0.statement)" }.joined(separator: "\n")
    }

    private static func combinePrompt(partials: [String], total: Int) -> String {
        "The following are partial summaries of \(total) detection findings from one "
        + "case. Combine them into a single executive summary, removing repetition:\n\n"
        + partials.enumerated().map { "(\($0.offset + 1)) \($0.element)" }.joined(separator: "\n\n")
    }

    // MARK: - Digest

    /// One aggregated, deduplicated digest entry - one per ATT&CK technique (or
    /// per title when a finding is untagged), not one per finding. Carries a
    /// short stable **citation ID** (`F01`, `F02`, …) assigned in display order,
    /// so the structured summarizer can have the model cite findings by ID
    /// instead of re-emitting (and potentially hallucinating) their evidence.
    public nonisolated struct DigestItem: Sendable {
        public let id: String
        public let rep: Finding        // representative (worst) finding in the group
        public let count: Int
        public let maxSeverity: Severity
        public init(id: String, rep: Finding, count: Int, maxSeverity: Severity) {
            self.id = id; self.rep = rep; self.count = count; self.maxSeverity = maxSeverity
        }
    }

    /// Aggregate findings into citable digest items + the number of lower-severity
    /// groups dropped past `maxDigestGroups`. Items are sorted by max severity
    /// then frequency; a case with hundreds of repetitive analyzer hits collapses
    /// to a few dozen items, which is both far cheaper to summarize and a better
    /// executive view.
    static func digest(_ findings: [Finding],
                       maxGroups: Int = maxDigestGroups) -> (items: [DigestItem], omittedCount: Int) {
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
        let capped = Array(sorted.prefix(max(0, maxGroups)))
        let items = capped.enumerated().map { index, g in
            DigestItem(id: String(format: "F%02d", index + 1),
                       rep: g.rep, count: g.count, maxSeverity: g.maxSeverity)
        }
        return (items, sorted.count - capped.count)
    }

    /// `id -> item` lookup for citation validation.
    static func idMap(_ items: [DigestItem]) -> [String: DigestItem] {
        Dictionary(items.map { ($0.id, $0) }, uniquingKeysWith: { a, _ in a })
    }

    /// Human-readable digest lines (one per item, plus an omission note),
    /// embedding each item's citation ID so the model can reference it. This is
    /// the text fed to the model in both the prose and structured paths; groups
    /// are sorted by max severity then frequency, with the omitted count noted.
    static func digestLines(_ findings: [Finding],
                            maxGroups: Int = maxDigestGroups) -> [String] {
        let (items, omitted) = digest(findings, maxGroups: maxGroups)
        var lines = items.map { line(for: $0) }
        if omitted > 0 {
            lines.append("- (+\(omitted) more lower-severity finding group(s) omitted for brevity)")
        }
        return lines
    }

    private static func line(for item: DigestItem) -> String {
        let f = item.rep
        var line = "- (\(item.id)) [\(item.maxSeverity.label)] \(f.phase.title): \(f.title)"
        if let t = f.technique { line += " (\(t.attackID) \(t.name))" }
        if item.count > 1 { line += " ×\(item.count)" }
        let detail = f.detail.trimmingCharacters(in: .whitespacesAndNewlines)
        if !detail.isEmpty {
            line += " — " + String(detail.prefix(240))
        }
        return line
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
