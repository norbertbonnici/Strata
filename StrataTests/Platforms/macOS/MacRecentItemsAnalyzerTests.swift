//
//  MacRecentItemsAnalyzerTests.swift
//  StrataTests
//
//  Covers the MacRecentItemsAnalyzer detection rules over macOS recent-item
//  stores (LSSharedFileList .sfl2, recent servers/documents). Exercises the
//  analyzer logic directly with synthetic MacRecentItem fixtures.
//

import Testing
import Foundation
@testable import Strata

struct MacRecentItemsAnalyzerTests {

    private func item(_ kind: MacRecentItem.ListKind, _ value: String,
                      at seconds: TimeInterval? = nil,
                      source: String = "/Users/x/Library/Application Support/com.apple.sharedfilelist/test.sfl2") -> MacRecentItem {
        MacRecentItem(kind: kind, title: (value as NSString).lastPathComponent, value: value,
                      timestamp: seconds.map { Date(timeIntervalSince1970: $0) },
                      scope: "user", sourceFile: source)
    }

    // MARK: - Rule 1: recent remote-server connections

    @Test func flagsSMBServerConnection() {
        let findings = MacRecentItemsAnalyzer().analyze([
            item(.servers, "smb://fileserver.corp.local/share"),
        ])
        #expect(findings.count == 1)
        #expect(findings[0].technique?.attackID == "T1021.002")
        #expect(findings[0].severity == .medium)
        #expect(findings[0].title.contains("fileserver.corp.local"))
    }

    @Test func rawIPServerIsHigh() {
        let findings = MacRecentItemsAnalyzer().analyze([
            item(.servers, "smb://10.0.0.5/exfil"),
        ])
        #expect(findings.count == 1)
        #expect(findings[0].severity == .high)
        #expect(findings[0].detail.contains("raw IP"))
    }

    @Test func sshSchemeMapsToSSHTechnique() {
        let findings = MacRecentItemsAnalyzer().analyze([item(.servers, "ssh://admin@box.example.com")])
        #expect(findings.first?.technique?.attackID == "T1021.004")
        #expect(findings.first?.title.contains("box.example.com") == true)
    }

    @Test func bareHostUnderServersList() {
        let findings = MacRecentItemsAnalyzer().analyze([item(.hosts, "192.168.1.50")])
        #expect(findings.count == 1)
        #expect(findings[0].severity == .high)            // raw IP
        #expect(findings[0].technique?.attackID == "T1021")
    }

    @Test func aggregatesRepeatedHostEntries() {
        let findings = MacRecentItemsAnalyzer().analyze([
            item(.servers, "smb://nas.local/a", at: 1),
            item(.servers, "smb://nas.local/b", at: 2),
        ])
        #expect(findings.count == 1)
        #expect(findings[0].detail.contains("2 entries"))
    }

    // MARK: - Rule 2: recent items in suspicious locations

    @Test func flagsStagingPathDocument() {
        let findings = MacRecentItemsAnalyzer().analyze([
            item(.documents, "/tmp/payload.sh"),
        ])
        #expect(findings.count == 1)
        #expect(findings[0].technique?.attackID == "T1204.002")
        #expect(findings[0].severity == .medium)
        #expect(findings[0].detail.contains("staging path"))
        #expect(findings[0].detail.contains("risky extension"))
    }

    @Test func flagsRiskyExtensionOutsideStaging() {
        let findings = MacRecentItemsAnalyzer().analyze([
            item(.documents, "/Users/x/Downloads/installer.dmg"),
        ])
        #expect(findings.count == 1)
        #expect(findings[0].detail.contains("risky extension (.dmg)"))
    }

    @Test func ignoresBenignDocument() {
        let findings = MacRecentItemsAnalyzer().analyze([
            item(.documents, "/Users/x/Documents/quarterly-report.pdf"),
            item(.applications, "/Applications/Safari.app"),
        ])
        #expect(findings.isEmpty)
    }

    @Test func fileURLPathIsResolved() {
        let findings = MacRecentItemsAnalyzer().analyze([
            item(.documents, "file:///private/var/tmp/drop.command"),
        ])
        #expect(findings.count == 1)
        #expect(findings[0].technique?.attackID == "T1204.002")
    }

    // MARK: - Edge cases

    @Test func emptyInputNoFindings() {
        #expect(MacRecentItemsAnalyzer().analyze([]).isEmpty)
    }

    @Test func threadedThroughContext() {
        let ctx = AnalysisContext(
            files: [], events: [], timeline: [], registryValues: [],
            macRecentItems: [item(.servers, "smb://10.10.10.10/c$")])
        let findings = MacRecentItemsAnalyzer().analyze(context: ctx)
        #expect(findings.count == 1)
        #expect(findings[0].severity == .high)
    }
}
