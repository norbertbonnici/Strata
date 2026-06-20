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
}
