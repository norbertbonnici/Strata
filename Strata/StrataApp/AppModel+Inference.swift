import Foundation
import SwiftUI

#if os(macOS)

extension AppModel {
    // MARK: - Cloud-egress confirmation

    /// The cloud destination (base URL + model) the analyst has already
    /// acknowledged sending finding summaries to; nil until first confirmed.
    /// Persisted in UserDefaults (examiner config, not case evidence).
    private static let confirmedCloudDestinationKey = "com.bonnicilabs.strata.confirmedCloudDestination"

    /// Gated entry point for the summary-card **Generate** button. Routes through
    /// the first-run confirmation when the run would actually send evidence-derived
    /// data off-host (cloud selected AND credentialed) to a destination the
    /// analyst hasn't yet acknowledged.
    func requestSummaryGeneration() { routeCloud(.generateSummary) }

    /// Gated entry point for **Tools ▸ Run Summary Self-Eval** (the eval corpus
    /// runs through the same configured backend, so it has the same egress
    /// implications as a real summary).
    func requestSummaryEval() { routeCloud(.runEval) }

    /// Resume a deferred action after the analyst confirmed the cloud egress,
    /// remembering the acknowledged destination so this prompt isn't shown again
    /// for it. Builds the backend from the SAME config read it fingerprints, then
    /// threads that exact instance to the runner (see `routeCloud`).
    func proceedAfterCloudConfirm(_ action: PendingCloudAction) {
        let cfg = InferenceConfiguration.load()
        UserDefaults.standard.set(cfg.destinationFingerprint, forKey: Self.confirmedCloudDestinationKey)
        dispatch(action, backend: cfg.makeBackend(credentials: KeychainCredentialStore()))
    }

    /// True when `action` would send finding summaries to a not-yet-acknowledged
    /// cloud destination. Checks the *effective* backend (cloud mode without a
    /// key fails safe to on-device, so nothing leaves and no prompt is needed).
    ///
    /// Resolves the effective backend **once** and threads that instance through
    /// to the runner. `CloudInferenceBackend` captures baseURL/model/key at
    /// construction, so "destination sent to == destination checked here" is
    /// atomic: a settings change between this gate and the (deferred) run can't
    /// silently redirect the egress.
    private func routeCloud(_ action: PendingCloudAction) {
        let cfg = InferenceConfiguration.load()
        let backend = cfg.makeBackend(credentials: KeychainCredentialStore())
        let confirmed = UserDefaults.standard.string(forKey: Self.confirmedCloudDestinationKey)
        if !backend.isSovereign, cfg.destinationFingerprint != confirmed {
            activeSheet = .cloudInferenceConfirm(action)
        } else {
            dispatch(action, backend: backend)
        }
    }

    private func dispatch(_ action: PendingCloudAction, backend: any InferenceBackend) {
        switch action {
        case .generateSummary: Task { await generateSummary(backend: backend) }
        case .runEval:         Task { await runSummaryEval(backend: backend) }
        }
    }

    /// Generate an on-device (Apple Intelligence) executive summary of the
    /// current case findings. Mirrors `enrichIndicators()`: opt-in, case-wide,
    /// persisted to its own JSON (`summary.json`), and custody-logged. Runs
    /// entirely on-device - no evidence leaves the host.
    ///
    /// Summarizes the combined "All" scope (per-host findings + correlation),
    /// independent of the active tab scope, so the persisted summary is the
    /// whole-case executive narrative.
    ///
    /// **Private on purpose**: callers must go through `requestSummaryGeneration()`
    /// so a cloud run can never skip the egress confirmation. `backend` is the
    /// instance resolved (and, for cloud, confirmed) at the gate — never
    /// re-resolved here, so the destination can't shift between gate and run.
    private func generateSummary(backend: any InferenceBackend) async {
        guard !isWorking else { return }
        guard let bundleURL = currentCaseBundleURL else { return }

        // Whole-case findings regardless of the active scope.
        let allFindings = evidenceList.flatMap { states[$0.id]?.findings ?? [] } + correlationFindings
        guard !allFindings.isEmpty else {
            statusMessage = "No findings to summarize — run the analyzers first."
            return
        }
        if case .unavailable(let reason) = backend.availability() {
            errorMessage = reason
            return
        }

        // Cheap COW snapshots on main; the heavy per-entry work is off-main below,
        // like runIOCMatch.
        let fileSnapshots = evidenceList.compactMap { states[$0.id]?.files }
        let whereFromSnapshots = evidenceList.compactMap { states[$0.id]?.whereFroms }

        errorMessage = nil
        isWorking = true
        defer { isWorking = false }
        statusMessage = "Generating summary of \(allFindings.count) finding(s) via \(backend.label)…"

        do {
            // Off the main actor (`fullPath` allocates per entry): the path-set that
            // widens the validator's recognition, and the artifact lookup index the
            // model's tools query during generation.
            let (fileIndex, lookupIndex) = await Task.detached(priority: .userInitiated) {
                () -> (Set<String>, CaseLookupIndex) in
                let allFiles = fileSnapshots.flatMap { $0 }
                let index = Set(allFiles.map(\.fullPath))
                let lookup = CaseLookupIndex.build(findings: allFindings, files: allFiles,
                                                   whereFroms: whereFromSnapshots.flatMap { $0 })
                return (index, lookup)
            }.value

            let validated = try await FindingsSummarizer().summarizeStructured(
                findings: allFindings, fileIndex: fileIndex, lookupIndex: lookupIndex,
                backend: backend) { done, total in
                Task { @MainActor in
                    // Only show step counts for genuinely multi-call runs.
                    if total > 1 {
                        self.statusMessage = "Generating summary… (step \(done + 1) of \(total))"
                    }
                }
            }
            // `text` stays the rendered narrative (the executive overview); the
            // per-claim detail rides structured in `claims`/`validation`. Trim so
            // "empty" agrees with the report builder (which also trims).
            let text = validated.overview.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !text.isEmpty || !validated.claims.isEmpty else {
                statusMessage = "The model returned an empty summary. Try regenerating."
                return
            }
            let summary = CaseSummary(text: text, generatedAt: Date(),
                                      findingCount: allFindings.count,
                                      modelLabel: backend.label,
                                      sovereignty: backend.sovereignty,
                                      claims: validated.claims,
                                      validation: validated.report)
            caseSummary = summary
            try? CaseStore.writeSummary(summary, in: bundleURL)
            statusMessage = "Generated summary of \(allFindings.count) finding(s) via \(backend.label)."
            // Custody records the provenance (and whether evidence-derived data
            // left the host) + what the evidence-ref validation actually did -
            // including the worst case where every model claim was dropped
            // (claimsProposed > 0 but claimsKept == 0). claimsProposed is 0 only
            // when the model produced no claims at all (a bare entry then).
            let v = validated.report
            let sovereignty: String
            switch backend.sovereignty {
            case .onDevice:
                sovereignty = "on-device"
            case .applePrivateCloud:
                sovereignty = "via Apple Private Cloud Compute (off-device; Apple-operated, attested, not retained)"
            case .thirdPartyCloud:
                sovereignty = "via third-party cloud (evidence-derived data left the host)"
            }
            var custodyDetail = "AI executive summary generated \(sovereignty) using \(backend.label) from \(allFindings.count) finding\(allFindings.count == 1 ? "" : "s")."
            if v.claimsProposed > 0 {
                custodyDetail += " \(v.claimsKept) of \(v.claimsProposed) model claim(s) validated"
                if v.hadIssues {
                    custodyDetail += "; \(v.claimsDroppedUnsupported) dropped, \(v.phantomRefsDropped) phantom ref(s) stripped, \(v.flaggedPathTokens.count) path(s) flagged"
                }
                custodyDetail += "."
            }
            appendCustody(.summarized, detail: custodyDetail)
        } catch {
            errorMessage = "Summary generation failed: \(error.localizedDescription)"
            statusMessage = ""
        }
    }

    /// Run the built-in labeled corpus through the configured backend and produce
    /// a hit/miss report - the quantified numbers (technique recall, confabulation
    /// rate, validator containment) for the talk. Opt-in (Tools menu), uses the
    /// same validated pipeline, custody-logged.
    ///
    /// **Private on purpose**: callers go through `requestSummaryEval()` so a
    /// cloud-backed eval run can never skip the egress confirmation. `backend` is
    /// the instance resolved (and, for cloud, confirmed) at the gate.
    private func runSummaryEval(backend: any InferenceBackend) async {
        guard !isWorking else { return }
        if case .unavailable(let reason) = backend.availability() { errorMessage = reason; return }

        errorMessage = nil
        isWorking = true
        defer { isWorking = false }
        statusMessage = "Running summary self-eval via \(backend.label)…"

        let report = await SummaryEvalHarness().run(corpus: SummaryEvalCorpus.sample, backend: backend)
        let markdown = report.markdown()
        summaryEvalMarkdown = markdown
        // A QA / methodology artifact, not case evidence - write to a temp file
        // (never into the .strata package, whose layout is owned by CaseStore) so
        // it can be opened; the in-memory copy above drives the in-app display.
        let url = FileManager.default.temporaryDirectory.appendingPathComponent("strata-summary-self-eval.md")
        try? markdown.data(using: .utf8)?.write(to: url, options: .atomic)

        let pct = { (d: Double) in String(format: "%.0f%%", d * 100) }
        let confab = report.confabulationRate.map(pct) ?? "n/a"
        // Failures are excluded from the means; say so plainly rather than let a
        // dragged-down number stand in for an infrastructure error.
        let failedNote = report.failedCaseNames.isEmpty ? ""
            : " (\(report.failedCaseCount) case\(report.failedCaseCount == 1 ? "" : "s") failed to run, excluded)"
        statusMessage = "Summary self-eval: \(pct(report.meanRecall)) recall, \(confab) confabulation, "
            + "\(report.totalClaimsDropped)/\(report.totalClaimsProposed) claims dropped — over \(report.caseCount) labeled case(s)\(failedNote)."
        appendCustody(.summarized,
                      detail: "Summary self-eval run via \(backend.label) over \(report.caseCount) labeled case(s)\(failedNote): "
                            + "mean technique recall \(pct(report.meanRecall)), confabulation rate \(confab), "
                            + "validator dropped \(report.totalClaimsDropped)/\(report.totalClaimsProposed) claim(s), "
                            + "stripped \(report.totalPhantomRefsDropped) phantom ref(s).")
    }
}

#endif
