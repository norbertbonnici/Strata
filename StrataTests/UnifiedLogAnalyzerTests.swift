//
//  UnifiedLogAnalyzerTests.swift
//  StrataTests
//
//  Covers the high-precision UnifiedLogAnalyzer rules over resolved unified-log
//  entries: sudo, osascript, SSH accepted / brute force, Screen Sharing auth,
//  and local account creation.
//

import Testing
import Foundation
@testable import Strata

struct UnifiedLogAnalyzerTests {

    private func entry(process: String, message: String, at seconds: TimeInterval? = nil,
                       source: String = "/var/db/diagnostics/Persist/0000.tracev3") -> UnifiedLogEntry {
        UnifiedLogEntry(timestamp: seconds.map { Date(timeIntervalSince1970: $0) },
                        eventType: .log, level: .default, pid: nil, process: process,
                        subsystem: nil, category: nil, message: message, sourceFile: source)
    }

    private func run(_ entries: [UnifiedLogEntry]) -> [Finding] {
        UnifiedLogAnalyzer().analyze(context: AnalysisContext(
            files: [], events: [], timeline: [], registryValues: [], unifiedLog: entries))
    }

    // MARK: - Existing high-precision rules

    @Test func sudoAndOsascriptAndAcceptedSSH() {
        let findings = run([
            entry(process: "sudo", message: "user : TTY=ttys000 ; PWD=/ ; USER=root ; COMMAND=/bin/sh", at: 1),
            entry(process: "osascript", message: "running script", at: 2),
            entry(process: "sshd", message: "Accepted password for root from 10.0.0.2 port 22 ssh2", at: 3),
        ])
        #expect(findings.contains { $0.technique?.attackID == "T1548.003" })
        #expect(findings.contains { $0.technique?.attackID == "T1059.002" })
        #expect(findings.contains { $0.technique?.attackID == "T1021.004" && $0.title.contains("accepted") })
    }

    // MARK: - SSH brute force

    @Test func sshFailedBurstIsBruteForceHigh() {
        let entries = (0..<6).map {
            entry(process: "sshd", message: "Failed password for invalid user admin from 203.0.113.7 port 40\($0)",
                  at: Double(100 + $0))
        }
        let findings = run(entries)
        let bf = findings.first { $0.technique?.attackID == "T1110.001" }
        #expect(bf != nil)
        #expect(bf?.severity == .high)
        #expect(bf?.title.contains("brute-force") == true)
        #expect(bf?.detail.contains("203.0.113.7") == true)
    }

    @Test func sshFewFailuresIsMedium() {
        let findings = run([
            entry(process: "sshd", message: "Failed password for root from 10.0.0.9 port 22", at: 1),
            entry(process: "sshd", message: "Failed password for root from 10.0.0.9 port 22", at: 2),
        ])
        let bf = findings.first { $0.technique?.attackID == "T1110.001" }
        #expect(bf?.severity == .medium)
    }

    // MARK: - Screen Sharing / VNC

    @Test func screenSharingAuthIsFlagged() {
        let findings = run([
            entry(process: "screensharingd", message: "Authentication: SUCCEEDED :: User Name: admin", at: 1),
        ])
        let f = findings.first { $0.technique?.attackID == "T1021.001" }
        #expect(f != nil)
        #expect(f?.severity == .high)
    }

    // MARK: - Account creation

    @Test func accountCreationViaSysadminctl() {
        let findings = run([
            entry(process: "sysadminctl", message: "-addUser backdoor -admin", at: 1),
        ])
        let f = findings.first { $0.technique?.attackID == "T1136.001" }
        #expect(f != nil)
        #expect(f?.severity == .high)
    }

    @Test func accountCreationViaDscl() {
        let findings = run([
            entry(process: "dscl", message: "create /Users/svc UserShell /bin/bash", at: 1),
        ])
        #expect(findings.contains { $0.technique?.attackID == "T1136.001" })
    }

    // MARK: - Edge cases

    @Test func emptyInputNoFindings() {
        #expect(run([]).isEmpty)
    }

    @Test func benignEntriesProduceNothing() {
        let findings = run([
            entry(process: "kernel", message: "AppleACPICPU: ProcessorId=1", at: 1),
            entry(process: "WindowServer", message: "display reconfigured", at: 2),
        ])
        #expect(findings.isEmpty)
    }
}
