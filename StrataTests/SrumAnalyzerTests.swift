//
//  SrumAnalyzerTests.swift
//  StrataTests
//
//  Validates the two SRUM detection rules: execution from a suspicious path
//  (App Resource Usage) and outbound network volume from a suspicious-path app
//  (Network Data Usage), both gated on user-writable staging locations.
//

import Testing
import Foundation
@testable import Strata

struct SrumAnalyzerTests {
    private static let when = Date(timeIntervalSince1970: 1_700_000_000)

    private func exec(_ path: String, when: Date? = SrumAnalyzerTests.when) -> SrumEntry {
        SrumEntry(kind: .appResourceUsage, timestamp: when, application: path, userSID: "S-1-5-18",
                  bytesRead: 100, bytesWritten: 50, sourceFile: "SRUDB.dat")
    }

    private func net(_ path: String, sent: Int64, when: Date? = SrumAnalyzerTests.when) -> SrumEntry {
        SrumEntry(kind: .networkData, timestamp: when, application: path, userSID: "S-1-5-18",
                  bytesSent: sent, bytesReceived: 1024, sourceFile: "SRUDB.dat")
    }

    private func context(_ srum: [SrumEntry]) -> AnalysisContext {
        AnalysisContext(files: [], events: [], timeline: [], registryValues: [], srum: srum)
    }

    @Test func flagsExecutionFromSuspiciousPath() throws {
        let findings = SrumAnalyzer().analyze(context: context([
            exec(#"\Device\HarddiskVolume2\Users\Public\evil.exe"#),
        ]))
        let f = try #require(findings.first { $0.title.contains("execution from suspicious path") })
        #expect(f.severity == .high)
        #expect(f.phase == .exploitation)
        #expect(f.technique?.attackID == "T1204.002")
    }

    @Test func ignoresExecutionFromSystemPath() {
        let findings = SrumAnalyzer().analyze(context: context([
            exec(#"\Device\HarddiskVolume2\Windows\System32\svchost.exe"#),
        ]))
        #expect(findings.contains { $0.title.contains("execution from suspicious path") } == false)
    }

    @Test func aggregatesRepeatedExecutionIntoOneFinding() {
        // Same staged binary in three hourly buckets -> a single finding, not three.
        let p = #"C:\Users\Public\evil.exe"#
        let findings = SrumAnalyzer().analyze(context: context([exec(p), exec(p), exec(p)]))
        #expect(findings.filter { $0.title.contains("execution from suspicious path") }.count == 1)
    }

    @Test func flagsNetworkEgressFromSuspiciousPath() throws {
        let findings = SrumAnalyzer().analyze(context: context([
            net(#"C:\Users\Public\beacon.exe"#, sent: 50 * 1024 * 1024),
        ]))
        let f = try #require(findings.first { $0.title.contains("network egress from suspicious path") })
        #expect(f.severity == .high)            // > 10 MB
        #expect(f.phase == .actionsOnObjectives)
        #expect(f.technique?.attackID == "T1048")
    }

    @Test func smallEgressFromSuspiciousPathIsMedium() throws {
        let f = try #require(SrumAnalyzer().analyze(context: context([
            net(#"C:\Users\Public\beacon.exe"#, sent: 4096),
        ])).first { $0.title.contains("network egress") })
        #expect(f.severity == .medium)
    }

    @Test func ignoresNetworkEgressFromBenignPath() {
        let findings = SrumAnalyzer().analyze(context: context([
            net(#"C:\Program Files\Mozilla Firefox\firefox.exe"#, sent: 5_000_000_000),
        ]))
        #expect(findings.contains { $0.title.contains("network egress") } == false)
    }

    @Test func emptyYieldsNothing() {
        #expect(SrumAnalyzer().analyze(context: context([])).isEmpty)
    }
}
