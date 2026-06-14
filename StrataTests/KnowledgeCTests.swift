//
//  KnowledgeCTests.swift
//  StrataTests
//
//  Covers the KnowledgeC behavioural model + analyzer. The ZOBJECT schema
//  (ZSTREAMNAME, ZVALUESTRING, ZVALUEINTEGER, ZSTARTDATE/ZENDDATE as Mac
//  absolute time) is pinned against a REAL knowledgeC.db from a macOS-12 image
//  (e.g. /app/inFocus → com.apple.Terminal with start/end); these tests
//  exercise the value-type logic with synthetic records.
//

import Testing
import Foundation
@testable import Strata

struct KnowledgeCTests {

    private func entry(_ stream: String, value: String? = nil, valueInt: Int? = nil,
                       start: Double = 700_000_000, end: Double? = nil) -> KnowledgeEntry {
        KnowledgeEntry(stream: stream, value: value, valueInt: valueInt,
                       startDate: Date(timeIntervalSinceReferenceDate: start),
                       endDate: end.map { Date(timeIntervalSinceReferenceDate: $0) },
                       scope: "system", sourceFile: "knowledgeC.db")
    }

    @Test func categoryMappingAndSummary() {
        let focus = entry("/app/inFocus", value: "com.apple.Terminal", start: 100, end: 182)
        #expect(focus.category == .appFocus)
        #expect(focus.duration == 82)
        #expect(focus.summary == "com.apple.Terminal (82s)")

        #expect(entry("/display/isBacklit", valueInt: 1).summary == "Screen on")
        #expect(entry("/display/isBacklit", valueInt: 0).summary == "Screen off")
        #expect(entry("/safari/history", value: "https://x.test/").summary == "https://x.test/")
        #expect(entry("/media/nowPlaying", value: "com.google.Chrome").summary == "Now playing: com.google.Chrome")
        #expect(entry("/standby/timer").category == .other)
    }

    @Test func macAbsoluteTimeDecodes() {
        // ZSTARTDATE is seconds since 2001-01-01 → Date(timeIntervalSinceReferenceDate:).
        let e = entry("/app/inFocus", value: "x", start: 0)
        #expect(e.startDate == Date(timeIntervalSinceReferenceDate: 0))
    }

    @Test func analyzerFlagsRemoteAccessInFocus() {
        let ctx = AnalysisContext(
            files: [], events: [], timeline: [], registryValues: [],
            knowledgeC: [
                entry("/app/inFocus", value: "com.teamviewer.TeamViewer", start: 100, end: 200),
                entry("/app/inFocus", value: "com.teamviewer.TeamViewer", start: 300, end: 360),
                entry("/app/inFocus", value: "com.apple.Terminal", start: 400, end: 460),  // normal → no
                entry("/app/usage", value: "com.anydesk.AnyDesk", start: 500),
            ])
        let findings = KnowledgeCAnalyzer().analyze(context: ctx)
        #expect(findings.count == 2)   // TeamViewer (deduped) + AnyDesk
        #expect(findings.allSatisfy { $0.technique?.attackID == "T1219" })
        #expect(findings.allSatisfy { $0.severity == .high })
    }

    @Test func analyzerIgnoresNonAppStreams() {
        let ctx = AnalysisContext(files: [], events: [], timeline: [], registryValues: [],
                                  knowledgeC: [entry("/safari/history", value: "teamviewer.com")])
        #expect(KnowledgeCAnalyzer().analyze(context: ctx).isEmpty)
    }
}
