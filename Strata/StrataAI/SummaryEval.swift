import Foundation

/// Quantified hit/miss evaluation of the validated summarizer - the honest
/// numbers the talk's Q&A needs. Two metric axes are kept deliberately separate:
///
/// 1. **Model quality** (measured AFTER the validator gate): technique
///    **recall** (coverage), per-severity + severity-weighted; and the headline
///    **confabulation rate** - the residual the validator structurally cannot
///    catch: a kept claim that links >=2 real findings whose pairing the case
///    labels causally *unsupported* (a plausible-but-wrong causal link).
/// 2. **Validator containment** (read straight off the report): how much
///    reference hallucination the structural gate absorbed (dropped claims,
///    stripped phantom refs, flagged path tokens).
///
/// Plus a **digest coverage ceiling** so recall is never penalised for activity
/// the model was never shown (the 60-group digest cap).
///
/// Technique ground-truth is DERIVED from the findings (the detection layer is
/// the oracle): this measures fidelity of the SUMMARY to the FINDINGS, not
/// whether detection itself was correct. Scoring is pure / model-free, so it is
/// unit-testable; a live-model run just substitutes a real `ProposedSummary`
/// into the same validator + scorer.

/// One labeled eval case.
public nonisolated struct SummaryEvalCase: Sendable {
    public let name: String
    public let findings: [Finding]
    /// Technique-key *pairs* (each a 2-element sorted array) the case marks as
    /// causally **unsupported** - a kept claim linking such a pair is a
    /// confabulation. Pairs absent here are treated as supported / neutral.
    public let unsupportedCausalPairs: Set<[String]>

    public init(name: String, findings: [Finding],
                unsupportedCausalPairs: Set<[String]> = []) {
        self.name = name
        self.findings = findings
        self.unsupportedCausalPairs = unsupportedCausalPairs
    }

    /// Canonical (order-independent) key for a technique pair.
    public static func causalPair(_ a: String, _ b: String) -> [String] { [a, b].sorted() }
}

/// Covered / total technique count for one severity band.
public nonisolated struct SeverityRecall: Sendable, Codable, Hashable {
    public let covered: Int
    public let total: Int
    public init(covered: Int, total: Int) { self.covered = covered; self.total = total }
    public var rate: Double { total == 0 ? 1 : Double(covered) / Double(total) }
}

/// Per-case score (FM-free, Codable so a report persists / decodes on iOS).
public nonisolated struct SummaryEvalResult: Sendable, Codable, Hashable {
    public let name: String
    // recall (over the digest-shown universe)
    public let groundTruthTechniques: Int
    public let coveredTechniques: Int
    public let recallBySeverity: [String: SeverityRecall]
    // precision sanity check (structurally 1.0 - a kept claim's technique keys
    // are taken from real cited findings, all of which are in-case; retained as
    // an invariant, not surfaced as a headline number).
    public let assertedTechniques: Int
    public let assertedInGroundTruth: Int
    // confabulation (causal-eligible denominator)
    public let keptClaims: Int
    public let causalClaims: Int
    public let confabulatedClaims: Int
    // validator containment (separate axis)
    public let claimsProposed: Int
    public let claimsDroppedUnsupported: Int
    public let phantomRefsDropped: Int
    public let flaggedPaths: Int
    // denominator integrity
    public let techniquesInCase: Int   // all distinct buckets incl. digest-capped

    public var recall: Double { groundTruthTechniques == 0 ? 1 : Double(coveredTechniques) / Double(groundTruthTechniques) }
    public var precision: Double { assertedTechniques == 0 ? 1 : Double(assertedInGroundTruth) / Double(assertedTechniques) }
    /// nil when the summary made no causal (>=2-technique) claim - "no causal
    /// claims", never a flattering 0%.
    public var confabulationRate: Double? { causalClaims == 0 ? nil : Double(confabulatedClaims) / Double(causalClaims) }
    public var dropRate: Double { claimsProposed == 0 ? 0 : Double(claimsDroppedUnsupported) / Double(claimsProposed) }
    public var digestCeiling: Double { techniquesInCase == 0 ? 1 : Double(groundTruthTechniques) / Double(techniquesInCase) }

    /// Severity-weighted macro recall - gives the rare critical band its due
    /// over the abundant info/low ones.
    public var severityWeightedRecall: Double {
        let w: [String: Double] = ["Critical": 5, "High": 4, "Medium": 3, "Low": 2, "Info": 1]
        var num = 0.0, den = 0.0
        for (sev, sr) in recallBySeverity {
            let weight = w[sev] ?? 1
            num += weight * sr.rate
            den += weight
        }
        return den == 0 ? 1 : num / den
    }
}

/// Corpus-wide rollup.
public nonisolated struct SummaryEvalReport: Sendable, Codable {
    public let backendLabel: String
    public let results: [SummaryEvalResult]
    /// Cases whose inference call failed (timeout / refusal / generation error)
    /// before producing a summary. Kept OUT of `results` so an infrastructure
    /// failure never drags the quality/containment means - it is reported
    /// separately instead of being silently scored as a 0-recall model run.
    public let failedCaseNames: [String]

    public init(backendLabel: String, results: [SummaryEvalResult], failedCaseNames: [String] = []) {
        self.backendLabel = backendLabel
        self.results = results
        self.failedCaseNames = failedCaseNames
    }

    private enum CodingKeys: String, CodingKey {
        case backendLabel, results, failedCaseNames
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        backendLabel = try c.decode(String.self, forKey: .backendLabel)
        results = try c.decode([SummaryEvalResult].self, forKey: .results)
        failedCaseNames = try c.decodeIfPresent([String].self, forKey: .failedCaseNames) ?? []
    }

    /// Cases that produced a score (failures excluded). The means are over these.
    public var caseCount: Int { results.count }
    public var failedCaseCount: Int { failedCaseNames.count }
    public var totalKeptClaims: Int { results.reduce(0) { $0 + $1.keptClaims } }
    public var meanRecall: Double { mean(results.map(\.recall)) }
    public var meanSeverityWeightedRecall: Double { mean(results.map(\.severityWeightedRecall)) }
    public var meanDigestCeiling: Double { mean(results.map(\.digestCeiling)) }
    public var totalCausalClaims: Int { results.reduce(0) { $0 + $1.causalClaims } }
    public var totalConfabulatedClaims: Int { results.reduce(0) { $0 + $1.confabulatedClaims } }
    /// Pooled confabulation rate over causal-eligible claims; nil when none.
    public var confabulationRate: Double? {
        totalCausalClaims == 0 ? nil : Double(totalConfabulatedClaims) / Double(totalCausalClaims)
    }
    public var totalClaimsProposed: Int { results.reduce(0) { $0 + $1.claimsProposed } }
    public var totalClaimsDropped: Int { results.reduce(0) { $0 + $1.claimsDroppedUnsupported } }
    public var totalPhantomRefsDropped: Int { results.reduce(0) { $0 + $1.phantomRefsDropped } }
    public var totalFlaggedPaths: Int { results.reduce(0) { $0 + $1.flaggedPaths } }
    public var dropRate: Double { totalClaimsProposed == 0 ? 0 : Double(totalClaimsDropped) / Double(totalClaimsProposed) }

    private func mean(_ xs: [Double]) -> Double { xs.isEmpty ? 0 : xs.reduce(0, +) / Double(xs.count) }

    /// A concise examiner-facing report (n is shown next to every metric - a
    /// DFIR eval corpus is tens of cases, not thousands, so the raw counts are
    /// the honesty).
    public func markdown() -> String {
        func pct(_ d: Double) -> String { String(format: "%.0f%%", d * 100) }
        let confab = confabulationRate.map { "\(pct($0)) (\(totalConfabulatedClaims)/\(totalCausalClaims) causal claims)" }
            ?? "n/a (no causal claims)"
        var out = "# Summary self-evaluation\n\n"
        out += "Backend: \(backendLabel) · \(caseCount) case\(caseCount == 1 ? "" : "s") scored, \(totalKeptClaims) kept claim\(totalKeptClaims == 1 ? "" : "s")\n\n"
        if !failedCaseNames.isEmpty {
            out += "> ⚠️ \(failedCaseCount) of \(caseCount + failedCaseCount) case\(failedCaseCount == 1 ? "" : "s") failed to run "
            out += "(inference error) and \(failedCaseCount == 1 ? "is" : "are") excluded from every metric below: "
            out += "\(failedCaseNames.joined(separator: ", ")).\n\n"
        }
        out += "## Model quality (measured after the validation gate)\n\n"
        out += "| Metric | Value |\n|---|---|\n"
        out += "| Technique recall (mean) | \(pct(meanRecall)) |\n"
        out += "| Severity-weighted recall | \(pct(meanSeverityWeightedRecall)) |\n"
        out += "| Confabulation rate (causal claims) | \(confab) |\n"
        out += "| Digest coverage ceiling | \(pct(meanDigestCeiling)) |\n\n"
        out += "## Validator containment (what the structural gate absorbed)\n\n"
        out += "| Metric | Value |\n|---|---|\n"
        out += "| Unsupported claims dropped | \(totalClaimsDropped)/\(totalClaimsProposed) (\(pct(dropRate))) |\n"
        out += "| Phantom citation refs stripped | \(totalPhantomRefsDropped) |\n"
        out += "| Invented path tokens flagged | \(totalFlaggedPaths) |\n\n"
        out += "_Recall is scored only against techniques that survived the digest cap (see ceiling); "
        out += "this measures fidelity of the summary to the findings, not detection accuracy. "
        out += "Containment is reported on a separate axis so a strong validator never flatters the model. "
        out += "Scoring covers the structured claims only — the free-text executive overview is path-token "
        out += "scanned by the validator but not otherwise evaluated here for causal or technique fidelity._\n\n"
        out += "## Per case\n\n| Case | Recall | Confab | Kept | Dropped |\n|---|---|---|---|---|\n"
        for r in results {
            let c = r.confabulationRate.map(pct) ?? "—"
            out += "| \(r.name) | \(r.coveredTechniques)/\(r.groundTruthTechniques) (\(pct(r.recall))) | \(c) | \(r.keptClaims) | \(r.claimsDroppedUnsupported) |\n"
        }
        return out
    }
}

/// Pure, model-free scorer.
public nonisolated enum SummaryEvalScorer {

    /// Digest bucket key for a finding - the SAME keying the validator records
    /// per claim, so a kept claim's `citedTechniqueKeys` line up with the
    /// ground-truth buckets here.
    static func techniqueKey(_ f: Finding) -> String { f.techniqueBucketKey }

    public static func score(_ validated: ValidatedSummary, case c: SummaryEvalCase) -> SummaryEvalResult {
        let findings = c.findings

        // Ground-truth technique universe: buckets the model was SHOWN (survived
        // the digest cap) vs. all buckets in the case (for the ceiling).
        let (items, _) = FindingsSummarizer.digest(findings)
        let shownKeys = Set(items.map { techniqueKey($0.rep) })
        let allKeys = Set(findings.map(techniqueKey))

        // key -> max severity (the bucket severity), for per-severity recall.
        var keySeverity: [String: Severity] = [:]
        for f in findings {
            keySeverity[techniqueKey(f)] = Swift.max(keySeverity[techniqueKey(f)] ?? .info, f.severity)
        }

        // What each kept claim asserted = the technique buckets it actually
        // cited, as recorded by the validator. NOT re-derived from the citation
        // paths: a path shared by findings of different techniques would conflate
        // buckets, fabricating causal links and over-crediting recall.
        var covered = Set<String>()
        var assertedAll = Set<String>()
        var causalClaims = 0, confabulated = 0
        for claim in validated.claims {
            let a = Set(claim.citedTechniqueKeys)
            assertedAll.formUnion(a)
            covered.formUnion(a.intersection(shownKeys))
            guard a.count >= 2 else { continue }
            causalClaims += 1
            let keys = a.sorted()
            confab: for i in keys.indices {
                for j in (i + 1)..<keys.count where c.unsupportedCausalPairs.contains([keys[i], keys[j]]) {
                    confabulated += 1
                    break confab
                }
            }
        }

        var bySev: [String: SeverityRecall] = [:]
        for sev in Severity.allCases {
            let total = shownKeys.filter { keySeverity[$0] == sev }
            guard !total.isEmpty else { continue }
            bySev[sev.label] = SeverityRecall(covered: total.filter(covered.contains).count, total: total.count)
        }

        let r = validated.report
        return SummaryEvalResult(
            name: c.name,
            groundTruthTechniques: shownKeys.count,
            coveredTechniques: covered.count,
            recallBySeverity: bySev,
            assertedTechniques: assertedAll.count,
            assertedInGroundTruth: assertedAll.intersection(allKeys).count,
            keptClaims: validated.claims.count,
            causalClaims: causalClaims,
            confabulatedClaims: confabulated,
            claimsProposed: r.claimsProposed,
            claimsDroppedUnsupported: r.claimsDroppedUnsupported,
            phantomRefsDropped: r.phantomRefsDropped,
            flaggedPaths: r.flaggedPathTokens.count,
            techniquesInCase: allKeys.count)
    }
}

/// Runs a corpus through a backend (live model) → validated → scored → report.
/// The scoring is pure; only `run` needs a model, so it composes the existing
/// `summarizeStructured` with the eval scorer.
public nonisolated struct SummaryEvalHarness: Sendable {
    public init() {}

    public func run(corpus: [SummaryEvalCase],
                    backend: any InferenceBackend) async -> SummaryEvalReport {
        let summarizer = FindingsSummarizer()
        var results: [SummaryEvalResult] = []
        var failed: [String] = []
        for c in corpus {
            let fileIndex = Set(c.findings.flatMap { $0.evidencePaths })
            do {
                let validated = try await summarizer.summarizeStructured(
                    findings: c.findings, fileIndex: fileIndex, backend: backend)
                results.append(SummaryEvalScorer.score(validated, case: c))
            } catch {
                // An inference failure (timeout / refusal / generation error) is
                // an infrastructure event, NOT a zero-recall model result -
                // record it separately so it never contaminates the means.
                failed.append(c.name)
            }
        }
        return SummaryEvalReport(backendLabel: backend.label, results: results, failedCaseNames: failed)
    }
}

/// A small built-in, labeled corpus so the harness has something to run on stage.
/// Illustrative - a production corpus is the analyst's own labeled cases; these
/// exercise the full metric set (incl. confabulation, via the labeled pairs).
public nonisolated enum SummaryEvalCorpus {
    public static var sample: [SummaryEvalCase] { [ransomware, credentialAccess] }

    private static func f(_ title: String, _ sev: Severity, _ attackID: String,
                         _ phase: KillChainPhase, _ paths: [String]) -> Finding {
        Finding(title: title, detail: title, severity: sev, phase: phase,
                technique: AttackTechnique(attackID: attackID, name: attackID), evidencePaths: paths)
    }

    /// Mass encryption + recovery inhibition + indicator removal. The encryption
    /// and the (separate, earlier) log clearing are NOT causally linked.
    static var ransomware: SummaryEvalCase {
        SummaryEvalCase(
            name: "Ransomware burst",
            findings: [
                f("Mass file encryption", .critical, "T1486", .actionsOnObjectives, ["/Users/v/Documents/q4.docx.locked"]),
                f("Inhibit system recovery", .critical, "T1490", .actionsOnObjectives, ["/Windows/System32/vssadmin.exe"]),
                f("Indicator removal: log cleared", .medium, "T1070.001", .actionsOnObjectives, ["/Windows/System32/winevt/Logs/Security.evtx"]),
            ],
            unsupportedCausalPairs: [SummaryEvalCase.causalPair("T1486", "T1070.001")])
    }

    /// Credential dumping + valid-account reuse (these ARE linked) plus an
    /// unrelated browser download (not causally tied to the credential theft).
    static var credentialAccess: SummaryEvalCase {
        SummaryEvalCase(
            name: "Credential access",
            findings: [
                f("LSASS memory dump", .high, "T1003.001", .exploitation, ["/Windows/System32/lsass.exe"]),
                f("Valid account reuse", .high, "T1078", .actionsOnObjectives, ["/Users/admin/ntuser.dat"]),
                f("Suspicious download", .medium, "T1105", .commandAndControl, ["/Users/v/Downloads/tool.exe"]),
            ],
            unsupportedCausalPairs: [SummaryEvalCase.causalPair("T1003.001", "T1105")])
    }
}
