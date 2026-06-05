//
//  StrataTests.swift
//  StrataTests
//
//  Created by Norbert Bonnici on 02/06/2026.
//

import Testing
import Foundation
@testable import Strata

struct StrataTests {

    @Test func example() async throws {
        // Write your test here and use APIs like `#expect(...)` to check expected conditions.
        // Swift Testing Documentation
        // https://developer.apple.com/documentation/testing
    }

}

struct GapAnalyzerTests {

    private static let epoch = Date(timeIntervalSinceReferenceDate: 0)

    /// One event at `offsetMin` minutes past the shared epoch. Source is
    /// `.evtx` so tests mirror the real DFIR scope where gap analysis
    /// matters most.
    private static func event(_ offsetMin: Double) -> TimelineEvent {
        TimelineEvent(date: epoch.addingTimeInterval(offsetMin * 60),
                      kind: .changed,
                      source: .evtx,
                      fileID: 0,
                      path: "x",
                      size: 0,
                      isDeleted: false)
    }

    @Test func emptyInputYieldsNothing() {
        let (sessions, gaps) = GapAnalyzer.analyze([], threshold: 3600)
        #expect(sessions.isEmpty)
        #expect(gaps.isEmpty)
    }

    @Test func singleEventIsOneSessionNoGap() {
        let (sessions, gaps) = GapAnalyzer.analyze([Self.event(0)], threshold: 3600)
        #expect(sessions.count == 1)
        #expect(sessions[0].count == 1)
        #expect(sessions[0].duration == 0)
        #expect(gaps.isEmpty)
    }

    @Test func splitsAtGapAboveThreshold() {
        // Two clusters separated by a 4-hour gap; threshold 1h.
        let events = [Self.event(0),   Self.event(5),   Self.event(10),
                      Self.event(250), Self.event(255)]
        let (sessions, gaps) = GapAnalyzer.analyze(events, threshold: 3600)

        #expect(sessions.count == 2)
        #expect(sessions[0].count == 3)
        #expect(sessions[0].duration == 10 * 60)
        #expect(sessions[1].count == 2)
        #expect(sessions[1].duration == 5 * 60)

        #expect(gaps.count == 1)
        // Gap runs from the last event in cluster 1 (t=10m) to the first
        // event in cluster 2 (t=250m) = 240 minutes.
        #expect(gaps[0].duration == 240 * 60)
    }

    @Test func exactlyAtThresholdIsNotAGap() {
        // Delta == threshold should stay inside the same session (analyzer
        // uses strict `>` so the boundary isn't a gap).
        let events = [Self.event(0), Self.event(60)]
        let (sessions, gaps) = GapAnalyzer.analyze(events, threshold: 3600)
        #expect(sessions.count == 1)
        #expect(sessions[0].count == 2)
        #expect(gaps.isEmpty)
    }

    @Test func nonPositiveThresholdFallsBackToOneHour() {
        // Same data as splitsAtGapAboveThreshold; threshold of 0 must not
        // produce a degenerate "every event is its own session" output.
        let events = [Self.event(0),   Self.event(5),   Self.event(10),
                      Self.event(250), Self.event(255)]
        let (sessions, gaps) = GapAnalyzer.analyze(events, threshold: 0)
        #expect(sessions.count == 2)
        #expect(gaps.count == 1)
    }
}
