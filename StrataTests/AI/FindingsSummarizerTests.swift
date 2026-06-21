//
//  FindingsSummarizerTests.swift
//  StrataTests
//
//  Covers the pure, model-free parts of the on-device findings summarizer
//  (digest formatting + prompt batching) and the summary persistence path.
//  The actual FoundationModels generation is not exercised here - it requires
//  an Apple-Intelligence-capable host and is verified manually.
//

import Testing
import Foundation
@testable import Strata

struct FindingsSummarizerTests {

    private static func finding(_ title: String, severity: Severity,
                                phase: KillChainPhase = .installation,
                                attackID: String? = nil,
                                detail: String = "detail") -> Finding {
        Finding(title: title, detail: detail, severity: severity, phase: phase,
                technique: attackID.map { AttackTechnique(attackID: $0, name: "tech") })
    }

    // MARK: - Digest

    @Test func digestLinesAreSeveritySortedHighestFirst() {
        let findings = [
            Self.finding("low one", severity: .low),
            Self.finding("critical one", severity: .critical),
            Self.finding("medium one", severity: .medium),
        ]
        let lines = FindingsSummarizer.digestLines(findings)
        #expect(lines.count == 3)
        #expect(lines[0].contains("critical one"))
        #expect(lines[0].contains("[Critical]"))
        #expect(lines[2].contains("low one"))
    }

    @Test func digestIncludesTechniqueAndTruncatesDetail() {
        let longDetail = String(repeating: "x", count: 500)
        let lines = FindingsSummarizer.digestLines([
            Self.finding("t", severity: .high, attackID: "T1059.001", detail: longDetail)
        ])
        let line = lines[0]
        #expect(line.contains("T1059.001"))
        // Detail is capped at 240 chars, so the full 500-char run can't appear.
        #expect(!line.contains(longDetail))
    }

    @Test func digestAggregatesRepeatedTechniqueIntoOneLine() {
        // 50 hits of one technique + 1 of another must collapse to 2 lines,
        // not 51 - this is what keeps a large case down to one model call.
        var findings = (0..<50).map {
            Self.finding("brute force \($0)", severity: .high, attackID: "T1110")
        }
        findings.append(Self.finding("one off", severity: .medium, attackID: "T1059"))
        let lines = FindingsSummarizer.digestLines(findings)
        #expect(lines.count == 2)
        #expect(lines[0].contains("T1110"))
        #expect(lines[0].contains("×50"))          // frequency annotated
        #expect(lines[0].contains("[High]"))       // highest severity first
    }

    @Test func digestCapsGroupsAndNotesOmission() {
        // More distinct techniques than the cap → capped + an "omitted" note.
        let findings = (0..<(FindingsSummarizer.maxDigestGroups + 10)).map {
            Self.finding("t\($0)", severity: .low, attackID: "T\(1000 + $0)")
        }
        let lines = FindingsSummarizer.digestLines(findings)
        #expect(lines.count == FindingsSummarizer.maxDigestGroups + 1)  // +1 omission note
        #expect(lines.last?.contains("omitted") == true)
    }

    // MARK: - Batching

    @Test func batchingKeepsEverythingUnderBudgetInOneBatchWhenSmall() {
        let lines = (0..<5).map { "line \($0)" }
        let batches = FindingsSummarizer.batch(lines, underBudget: 10_000)
        #expect(batches.count == 1)
        #expect(batches[0].count == 5)
    }

    @Test func batchingSplitsWhenOverBudgetAndLosesNoLines() {
        let lines = (0..<20).map { _ in String(repeating: "a", count: 100) }
        let batches = FindingsSummarizer.batch(lines, underBudget: 250)
        #expect(batches.count > 1)
        #expect(batches.reduce(0) { $0 + $1.count } == 20)  // nothing dropped
    }

    @Test func availabilityReportsAReasonStringWhenUnavailable() {
        // We can't force the device state, but whatever it is, an unavailable
        // result must carry a non-empty reason for the UI to show.
        if case .unavailable(let reason) = FindingsSummarizer.availability {
            #expect(!reason.isEmpty)
        }
    }

    // MARK: - Persistence

    @Test func caseStoreRoundTripsSummary() throws {
        let fm = FileManager.default
        let bundle = fm.temporaryDirectory.appendingPathComponent("sum-\(UUID().uuidString).strata")
        try fm.createDirectory(at: bundle, withIntermediateDirectories: true)
        defer { try? fm.removeItem(at: bundle) }

        // Whole-second date: the store encodes ISO-8601 (no sub-second).
        let summary = CaseSummary(text: "Two critical findings indicate persistence.",
                                  generatedAt: Date(timeIntervalSinceReferenceDate: 100),
                                  findingCount: 4,
                                  modelLabel: "Apple Intelligence (on-device)")
        try CaseStore.writeSummary(summary, in: bundle)
        let back = try CaseStore.readSummary(in: bundle)
        #expect(back == summary)

        // A bundle without the file reads back as nil, not an error.
        let empty = fm.temporaryDirectory.appendingPathComponent("sum-empty-\(UUID().uuidString)")
        try fm.createDirectory(at: empty, withIntermediateDirectories: true)
        defer { try? fm.removeItem(at: empty) }
        #expect(try CaseStore.readSummary(in: empty) == nil)
    }

    // MARK: - Window-aware budgeting (60k findings / small window)

    @Test func windowDerivedBudgetAndCapScaleWithWindow() {
        let onDevice = OnDeviceBackend().contextWindowTokens               // 4_096
        let pcc = 32_000   // PrivateCloudComputeBackend is macOS-27-gated; its window
        let cloud = CloudInferenceBackend(apiKey: nil).contextWindowTokens  // 200_000

        // Budget grows with the window — the whole point: PCC's 32k holds far
        // more per request than the on-device window.
        #expect(FindingsSummarizer.promptBudgetChars(forWindow: onDevice)
                < FindingsSummarizer.promptBudgetChars(forWindow: pcc))
        #expect(FindingsSummarizer.promptBudgetChars(forWindow: pcc)
                < FindingsSummarizer.promptBudgetChars(forWindow: cloud))

        // Group cap is floored at maxDigestGroups, scales up with the window,
        // and is ceiling-capped so a pathological case still terminates.
        #expect(FindingsSummarizer.digestGroupCap(forWindow: onDevice) == FindingsSummarizer.maxDigestGroups)
        #expect(FindingsSummarizer.digestGroupCap(forWindow: pcc) > FindingsSummarizer.maxDigestGroups)
        #expect(FindingsSummarizer.digestGroupCap(forWindow: cloud) == 600)
        #expect(FindingsSummarizer.digestGroupCap(forWindow: 100) == FindingsSummarizer.maxDigestGroups)  // floor
    }

    @Test func digestHonorsExplicitMaxGroups() {
        let findings = (0..<40).map { Self.finding("t\($0)", severity: .low, attackID: "T\(2000 + $0)") }
        let (items, omitted) = FindingsSummarizer.digest(findings, maxGroups: 5)
        #expect(items.count == 5)
        #expect(omitted == 35)
        #expect(FindingsSummarizer.digest(findings, maxGroups: 600).items.count == 40)
        // Default is unchanged for existing callers.
        #expect(FindingsSummarizer.digest(findings).items.count == min(40, FindingsSummarizer.maxDigestGroups))
    }

    @Test func chunkPacksItemsUnderBudgetAndLosesNone() {
        let items = (0..<20).map { "item\($0)" }
        let render: ([String]) -> String = { $0.joined(separator: ",") }
        let groups = FindingsSummarizer.chunk(items, budgetChars: 30) { render($0) }
        #expect(groups.count > 1)
        #expect(groups.allSatisfy { render($0).count <= 30 || $0.count == 1 })
        #expect(groups.flatMap { $0 } == items)   // order preserved, nothing dropped
    }

    /// Scriptable backend that records every prompt it's asked to run, so a test
    /// can assert the summarizer never builds a prompt larger than the window.
    private final class RecordingBackend: InferenceBackend, @unchecked Sendable {
        let label = "Test"
        let sovereignty: SovereigntyTier = .onDevice
        let contextWindowTokens: Int
        private(set) var prompts: [String] = []
        private var claimCounter = 0
        init(window: Int) { contextWindowTokens = window }
        func availability() -> SummarizerAvailability { .available }
        func proposeSummary(instructions: String, prompt: String, context: InferenceContext) async throws -> ProposedSummary {
            prompts.append(prompt)
            return ProposedSummary(overview: "overview", claims: [
                ProposedClaim(statement: "activity", phase: .installation, severity: .high, findingRefs: ["F01"])])
        }
        func proposeClaims(instructions: String, prompt: String, context: InferenceContext) async throws -> [ProposedClaim] {
            prompts.append(prompt)
            let start = claimCounter; claimCounter += 25
            return (start..<(start + 25)).map {
                ProposedClaim(statement: "distinct attacker activity number \($0) observed across hosts and files",
                              phase: .installation, severity: .high, findingRefs: ["F01"])
            }
        }
        func synthesizeOverview(instructions: String, prompt: String) async throws -> String {
            prompts.append(prompt)
            return "partial overview"
        }
    }

    @Test func multiBatchOverviewNeverExceedsTheWindow() async throws {
        // Regression for the unguarded final merge that threw LanguageModelError
        // -1 on a large case: force the multi-batch path with a tiny window and a
        // claim-heavy backend, then assert NO prompt exceeds the window and the
        // summary still generates. Under the old flat path the merged-claims
        // overview prompt (125 claims) far exceeds this window.
        let window = 1_500
        let backend = RecordingBackend(window: window)
        let findings = (0..<120).map {
            Self.finding("technique \($0) with some descriptive text", severity: .high,
                         attackID: "T\(3000 + $0)", detail: String(repeating: "d", count: 120))
        }
        let result = try await FindingsSummarizer().summarizeStructured(findings: findings, backend: backend)

        #expect(!result.overview.isEmpty)
        #expect(backend.prompts.count > 1)   // genuinely multi-batch
        // The invariant that lets a 60k case generate: every prompt fits the window.
        #expect(backend.prompts.allSatisfy { FindingsSummarizer.estimateTokens($0) <= window })
        // Sanity: the naive single overview of all merged claims WOULD have
        // overflowed (proving the guard did real work).
        let flatOverview = (0..<125).map {
            "- [High] distinct attacker activity number \($0) observed across hosts and files"
        }.joined(separator: "\n")
        #expect(FindingsSummarizer.estimateTokens(flatOverview) > window)
    }
}
