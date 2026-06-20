//
//  SummaryEvalTests.swift
//  StrataTests
//
//  Covers the pure, model-free hit/miss scorer. Each test builds findings + a
//  ProposedSummary fixture, runs the REAL SummaryValidator, then scores the
//  ValidatedSummary — so the validator + scorer pipeline is exercised
//  deterministically. A live-model run substitutes a real ProposedSummary into
//  the same scorer.
//

import Testing
import Foundation
@testable import Strata

struct SummaryEvalTests {

    private func finding(_ title: String, _ sev: Severity, _ attackID: String, _ paths: [String]) -> Finding {
        Finding(title: title, detail: "d", severity: sev, phase: .installation,
                technique: AttackTechnique(attackID: attackID, name: "n"), evidencePaths: paths)
    }

    private func validate(_ proposed: ProposedSummary, _ findings: [Finding]) -> ValidatedSummary {
        let (items, _) = FindingsSummarizer.digest(findings)
        return SummaryValidator(idMap: FindingsSummarizer.idMap(items),
                                knownPaths: Set(findings.flatMap { $0.evidencePaths })).validate(proposed)
    }

    /// The digest ID assigned to the bucket of a given technique.
    private func id(_ attackID: String, _ findings: [Finding]) -> String {
        let (items, _) = FindingsSummarizer.digest(findings)
        return items.first { $0.rep.technique?.attackID == attackID }!.id
    }

    private func claim(_ statement: String, _ refs: [String]) -> ProposedClaim {
        ProposedClaim(statement: statement, phase: .installation, severity: .high, findingRefs: refs)
    }

    @Test func goldenSummaryFullRecallNoConfabulation() {
        let f = [
            finding("ransom", .critical, "T1486", ["/a.locked"]),
            finding("inhibit", .high, "T1490", ["/cmd"]),
            finding("creds", .high, "T1003", ["/lsass"]),
        ]
        let c = SummaryEvalCase(name: "golden", findings: f)
        let proposed = ProposedSummary(overview: "o", claims: [
            claim("encryption", [id("T1486", f)]),
            claim("recovery inhibition", [id("T1490", f)]),
            claim("cred dump", [id("T1003", f)]),
        ])
        let r = SummaryEvalScorer.score(validate(proposed, f), case: c)
        #expect(r.groundTruthTechniques == 3)
        #expect(r.coveredTechniques == 3)
        #expect(r.recall == 1.0)
        #expect(r.causalClaims == 0)            // all single-technique claims
        #expect(r.confabulationRate == nil)     // "no causal claims" — not a flattering 0%
        #expect(r.claimsDroppedUnsupported == 0)
        #expect(r.digestCeiling == 1.0)
    }

    @Test func confabulationFlaggedViaUnsupportedPair() {
        let f = [
            finding("ransom", .critical, "T1486", ["/a.locked"]),
            finding("creds", .high, "T1003", ["/lsass"]),
        ]
        // The case says T1486 and T1003 are NOT causally linked.
        let c = SummaryEvalCase(name: "confab", findings: f,
                                unsupportedCausalPairs: [SummaryEvalCase.causalPair("T1486", "T1003")])
        // One claim links both — a causal claim the case rejects.
        let proposed = ProposedSummary(overview: "o", claims: [
            claim("dumped creds then encrypted", [id("T1486", f), id("T1003", f)]),
        ])
        let r = SummaryEvalScorer.score(validate(proposed, f), case: c)
        #expect(r.causalClaims == 1)
        #expect(r.confabulatedClaims == 1)
        #expect(r.confabulationRate == 1.0)
    }

    @Test func supportedCausalLinkIsNotConfabulation() {
        let f = [
            finding("download", .medium, "T1105", ["/dl"]),
            finding("execution", .high, "T1059", ["/exec"]),
        ]
        // No unsupported pairs → a causal claim linking them is fine.
        let c = SummaryEvalCase(name: "ok", findings: f)
        let proposed = ProposedSummary(overview: "o", claims: [
            claim("downloaded then executed", [id("T1105", f), id("T1059", f)]),
        ])
        let r = SummaryEvalScorer.score(validate(proposed, f), case: c)
        #expect(r.causalClaims == 1)
        #expect(r.confabulatedClaims == 0)
        #expect(r.confabulationRate == 0.0)
    }

    @Test func partialRecallCountsTheMissAndSeverityWeights() {
        let f = [
            finding("ransom", .critical, "T1486", ["/a.locked"]),
            finding("inhibit", .high, "T1490", ["/cmd"]),
            finding("creds", .high, "T1003", ["/lsass"]),
        ]
        let c = SummaryEvalCase(name: "miss", findings: f)
        let proposed = ProposedSummary(overview: "o", claims: [claim("encryption", [id("T1486", f)])])
        let r = SummaryEvalScorer.score(validate(proposed, f), case: c)
        #expect(r.coveredTechniques == 1)
        #expect(r.groundTruthTechniques == 3)
        #expect(abs(r.recall - 1.0 / 3.0) < 0.001)
        #expect(r.recallBySeverity["Critical"] == SeverityRecall(covered: 1, total: 1))
        #expect(r.recallBySeverity["High"] == SeverityRecall(covered: 0, total: 2))
        // The covered critical lifts the weighted recall above the flat 1/3.
        #expect(r.severityWeightedRecall > r.recall)
    }

    @Test func containmentReadsValidatorDrops() {
        let f = [finding("ransom", .critical, "T1486", ["/a.locked"])]
        let c = SummaryEvalCase(name: "contain", findings: f)
        let real = id("T1486", f)
        let proposed = ProposedSummary(overview: "o", claims: [
            claim("real", [real, "F99"]),   // F99 phantom (stripped), claim kept
            claim("invented", ["F98"]),      // cites nothing real → dropped
        ])
        let r = SummaryEvalScorer.score(validate(proposed, f), case: c)
        #expect(r.claimsProposed == 2)
        #expect(r.claimsDroppedUnsupported == 1)
        #expect(r.phantomRefsDropped == 2)   // F99 + F98 (both unknown ids)
        #expect(r.keptClaims == 1)
        #expect(r.coveredTechniques == 1)    // the surviving claim still covers T1486
    }

    /// Two findings of DIFFERENT techniques share one evidence path (realistic:
    /// analyzers emit shared source-file / "unified log" handles). A claim citing
    /// only one bucket must NOT be reconstructed as a 2-technique causal claim -
    /// the prior path-reconstruction scorer conflated them and fabricated a
    /// confabulation here.
    @Test func sharedEvidencePathDoesNotFabricateCausalLink() {
        let f = [
            finding("encrypt", .critical, "T1486", ["/shared.log", "/a.locked"]),
            finding("creds", .high, "T1003", ["/shared.log", "/lsass"]),
        ]
        let c = SummaryEvalCase(name: "shared", findings: f,
                                unsupportedCausalPairs: [SummaryEvalCase.causalPair("T1486", "T1003")])
        // Cites ONLY the encryption bucket → single-technique, not causal.
        let proposed = ProposedSummary(overview: "o", claims: [claim("encryption", [id("T1486", f)])])
        let r = SummaryEvalScorer.score(validate(proposed, f), case: c)
        #expect(r.causalClaims == 0)
        #expect(r.confabulatedClaims == 0)
        #expect(r.confabulationRate == nil)
        #expect(r.coveredTechniques == 1)        // covers T1486 only, NOT the co-located T1003
        #expect(r.groundTruthTechniques == 2)
    }

    /// The flip side: a genuine 2-bucket causal claim is still counted (and
    /// flagged) even when the two findings share an evidence path.
    @Test func genuineCausalClaimCountsWithSharedPaths() {
        let f = [
            finding("encrypt", .critical, "T1486", ["/shared.log", "/a.locked"]),
            finding("creds", .high, "T1003", ["/shared.log", "/lsass"]),
        ]
        let c = SummaryEvalCase(name: "shared2", findings: f,
                                unsupportedCausalPairs: [SummaryEvalCase.causalPair("T1486", "T1003")])
        let proposed = ProposedSummary(overview: "o", claims: [
            claim("dumped then encrypted", [id("T1486", f), id("T1003", f)]),
        ])
        let r = SummaryEvalScorer.score(validate(proposed, f), case: c)
        #expect(r.causalClaims == 1)
        #expect(r.confabulatedClaims == 1)
        #expect(r.confabulationRate == 1.0)
    }

    /// A failed inference is recorded separately and excluded from the means -
    /// not fabricated as a 0-recall result that drags meanRecall.
    @Test func reportExcludesFailedCasesFromMeans() {
        let f = [finding("ransom", .critical, "T1486", ["/a.locked"])]
        let c = SummaryEvalCase(name: "x", findings: f)
        let r = SummaryEvalScorer.score(
            validate(ProposedSummary(overview: "o", claims: [claim("e", [id("T1486", f)])]), f), case: c)
        let report = SummaryEvalReport(backendLabel: "Test", results: [r], failedCaseNames: ["Timed out case"])
        #expect(report.caseCount == 1)            // only scored cases
        #expect(report.failedCaseCount == 1)
        #expect(report.meanRecall == 1.0)         // failure excluded, not a 0
        let md = report.markdown()
        #expect(md.contains("failed to run"))
        #expect(md.contains("Timed out case"))
    }

    /// End-to-end: a throwing backend yields a failed-case entry, no scored
    /// result, and a means denominator that doesn't include the failure.
    @Test func harnessRecordsBackendFailureSeparately() async {
        let f = [finding("ransom", .critical, "T1486", ["/a.locked"])]
        let c = SummaryEvalCase(name: "Times out", findings: f)
        let backend = CloudInferenceBackend(apiKey: "k", transport: { _ in (Data("err".utf8), 500) })
        let report = await SummaryEvalHarness().run(corpus: [c], backend: backend)
        #expect(report.caseCount == 0)
        #expect(report.failedCaseNames == ["Times out"])
        #expect(report.markdown().contains("failed to run"))
    }

    @Test func reportAggregatesAndRenders() {
        let f = [finding("ransom", .critical, "T1486", ["/a.locked"])]
        let c = SummaryEvalCase(name: "x", findings: f)
        let r = SummaryEvalScorer.score(
            validate(ProposedSummary(overview: "o", claims: [claim("e", [id("T1486", f)])]), f), case: c)
        let report = SummaryEvalReport(backendLabel: "Test", results: [r, r])
        #expect(report.caseCount == 2)
        #expect(report.meanRecall == 1.0)
        #expect(report.confabulationRate == nil)
        let md = report.markdown()
        #expect(md.contains("Summary self-evaluation"))
        #expect(md.contains("Technique recall"))
        #expect(md.contains("Validator containment"))
    }
}
