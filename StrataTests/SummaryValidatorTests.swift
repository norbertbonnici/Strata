//
//  SummaryValidatorTests.swift
//  StrataTests
//
//  Covers the pure, model-free evidence-reference validation pass that gates the
//  structured on-device summarizer: digest citation IDs, dropping unsupported
//  claims, stripping phantom refs, taking severity/phase from the evidence,
//  sourcing citations from real findings, and flagging invented file paths.
//  The FoundationModels generation that produces the raw summary is not
//  exercised here - it needs an Apple-Intelligence host and is verified manually.
//

import Testing
import Foundation
@testable import Strata

struct SummaryValidatorTests {

    private func finding(_ title: String, sev: Severity, phase: KillChainPhase = .installation,
                         paths: [String] = [], attackID: String? = nil) -> Finding {
        Finding(title: title, detail: "d", severity: sev, phase: phase,
                technique: attackID.map { AttackTechnique(attackID: $0, name: "n") },
                evidencePaths: paths)
    }

    private func item(_ id: String, _ f: Finding) -> FindingsSummarizer.DigestItem {
        FindingsSummarizer.DigestItem(id: id, rep: f, count: 1, maxSeverity: f.severity)
    }

    private func validator(_ items: [FindingsSummarizer.DigestItem],
                           knownPaths: Set<String> = []) -> SummaryValidator {
        SummaryValidator(idMap: FindingsSummarizer.idMap(items), knownPaths: knownPaths)
    }

    // MARK: - Digest citation IDs

    @Test func digestAssignsSequentialStableIDsHighestSeverityFirst() {
        let findings = [
            finding("med", sev: .medium, attackID: "T2"),
            finding("crit", sev: .critical, attackID: "T1"),
        ]
        let (items, omitted) = FindingsSummarizer.digest(findings)
        #expect(omitted == 0)
        #expect(items.map(\.id) == ["F01", "F02"])
        #expect(items[0].rep.title == "crit")              // ID order follows severity
        #expect(FindingsSummarizer.digestLines(findings)[0].contains("(F01)"))
    }

    // MARK: - Reference validation

    @Test func dropsClaimThatCitesNoRealFinding() {
        let v = validator([item("F01", finding("real", sev: .high))])
        let out = v.validate(ProposedSummary(overview: "o", claims: [
            ProposedClaim(statement: "invented activity", phase: .exploitation,
                          severity: .critical, findingRefs: ["F99"])
        ]))
        #expect(out.claims.isEmpty)
        #expect(out.report.claimsKept == 0)
        #expect(out.report.claimsDroppedUnsupported == 1)
        #expect(out.report.phantomRefsDropped == 1)
        #expect(out.report.hadIssues)
    }

    @Test func stripsPhantomRefsButKeepsClaimWithAValidRef() {
        let f = finding("real", sev: .high, paths: ["/etc/passwd"])
        let out = validator([item("F01", f)]).validate(ProposedSummary(overview: "o", claims: [
            ProposedClaim(statement: "s", phase: .installation, severity: .high,
                          findingRefs: ["F01", "F42"])
        ]))
        #expect(out.claims.count == 1)
        #expect(out.report.phantomRefsDropped == 1)
        #expect(out.claims[0].citations == ["/etc/passwd"])
    }

    @Test func normalizesParenthesizedAndPaddedRefs() {
        // The digest renders IDs as "(F01)"; a model copying that form verbatim
        // (or adding whitespace) must still resolve, not get dropped as phantom.
        let f = finding("real", sev: .high, paths: ["/etc/passwd"])
        let out = validator([item("F01", f)]).validate(ProposedSummary(overview: "o", claims: [
            ProposedClaim(statement: "s", phase: .installation, severity: .high,
                          findingRefs: ["(F01)", " F01 "])
        ]))
        #expect(out.claims.count == 1)
        #expect(out.report.phantomRefsDropped == 0)      // both normalise to F01
        #expect(out.claims[0].citations == ["/etc/passwd"])
    }

    @Test func severityAndPhaseComeFromCitedFindingsNotModel() {
        // Model claims low/recon; cited finding is critical/C2 - the evidence wins.
        let f = finding("real", sev: .critical, phase: .commandAndControl)
        let out = validator([item("F01", f)]).validate(ProposedSummary(overview: "o", claims: [
            ProposedClaim(statement: "s", phase: .reconnaissance, severity: .low,
                          findingRefs: ["F01"])
        ]))
        #expect(out.claims.count == 1)
        #expect(out.claims[0].severity == .critical)
        #expect(out.claims[0].phase == .commandAndControl)
    }

    @Test func citationsAreFindingEvidencePathsNotModelText() {
        let f = finding("real", sev: .high, paths: ["/Library/LaunchAgents/x.plist"])
        let out = validator([item("F01", f)]).validate(ProposedSummary(overview: "o", claims: [
            ProposedClaim(statement: "persistence at /Users/evil/fake.plist",
                          phase: .installation, severity: .high, findingRefs: ["F01"])
        ]))
        // The citation is the finding's real path, not the path in the sentence.
        #expect(out.claims[0].citations == ["/Library/LaunchAgents/x.plist"])
    }

    @Test func flagsInventedPathTokenButNotARealOne() {
        let real = "/Library/LaunchAgents/legit.plist"
        let f = finding("real", sev: .high, paths: [real])
        let out = validator([item("F01", f)], knownPaths: [real]).validate(ProposedSummary(
            overview: "Activity referencing \(real) and /Users/attacker/implant.dylib here.",
            claims: [ProposedClaim(statement: "s", phase: .installation, severity: .high,
                                   findingRefs: ["F01"])]))
        #expect(out.report.flaggedPathTokens.contains("/Users/attacker/implant.dylib"))
        #expect(!out.report.flaggedPathTokens.contains(real))
    }

    // MARK: - Multi-batch merge

    private func proposed(_ statement: String, _ sev: Severity = .high,
                          refs: [String] = ["F01"]) -> ProposedClaim {
        ProposedClaim(statement: statement, phase: .installation, severity: sev, findingRefs: refs)
    }

    @Test func mergeProposedClaimsDedupsByStatementPreservingOrder() {
        let a = proposed("Alpha activity.", refs: ["F01"])
        let b = proposed("Beta activity.", .medium, refs: ["F31"])
        let aDup = proposed("  alpha activity. ", .low, refs: ["F02"])   // same text, different case/space
        let merged = FindingsSummarizer.mergeProposedClaims([[a], [b, aDup]])
        #expect(merged.map(\.statement) == ["Alpha activity.", "Beta activity."])
    }

    @Test func mergeProposedClaimsDropsBlankStatements() {
        let real = proposed("Real activity.")
        let blank = proposed("   ", refs: [])
        let merged = FindingsSummarizer.mergeProposedClaims([[real, blank]])
        #expect(merged.count == 1)
        #expect(merged.first?.statement == "Real activity.")
    }

    @Test func mergeProposedClaimsHandlesEmptyInput() {
        #expect(FindingsSummarizer.mergeProposedClaims([]).isEmpty)
        #expect(FindingsSummarizer.mergeProposedClaims([[], []]).isEmpty)
    }

    @Test func keptClaimsSortBySeverityDescending() {
        let lo = finding("lo", sev: .low)
        let hi = finding("hi", sev: .critical)
        let out = validator([item("F01", lo), item("F02", hi)]).validate(ProposedSummary(overview: "o", claims: [
            ProposedClaim(statement: "low one", phase: .installation, severity: .low, findingRefs: ["F01"]),
            ProposedClaim(statement: "high one", phase: .installation, severity: .critical, findingRefs: ["F02"]),
        ]))
        #expect(out.claims.map(\.severity) == [.critical, .low])
    }
}
