//
//  MacInstallHistoryTests.swift
//  StrataTests
//
//  Covers the macOS install-history parser (InstallHistory.plist array +
//  PackageKit receipt dict) over plist fixtures, the analyzer's
//  scripting-installer / staging-path detections, and the timeline projection.
//

import Testing
import Foundation
@testable import Strata

struct MacInstallHistoryTests {

    private let when = Date(timeIntervalSince1970: 1_700_000_000)

    private func arrayPlist(_ obj: [[String: Any]]) -> Data {
        try! PropertyListSerialization.data(fromPropertyList: obj, format: .binary, options: 0)
    }
    private func dictPlist(_ obj: [String: Any]) -> Data {
        try! PropertyListSerialization.data(fromPropertyList: obj, format: .binary, options: 0)
    }

    // MARK: - Parser: InstallHistory.plist (array)

    @Test func parsesInstallHistoryArray() {
        let data = arrayPlist([
            ["displayName": "Acme App", "date": when, "displayVersion": "1.2",
             "processName": "installer", "packageIdentifiers": ["com.acme.app"], "contentType": "package"],
            ["displayName": "macOS 14.5", "date": when, "processName": "softwareupdated",
             "packageIdentifiers": ["com.apple.pkg.update"], "contentType": "softwareUpdate"],
        ])
        let s = MacInstallHistoryParser.parse(data, sourceFile: "/Library/Receipts/InstallHistory.plist", scope: "system")
        #expect(s.count == 2)
        let acme = s.first { $0.displayName == "Acme App" }
        #expect(acme?.version == "1.2")
        #expect(acme?.processName == "installer")
        #expect(acme?.packageIdentifiers == ["com.acme.app"])
        #expect(acme?.contentType == "package")
        #expect(acme?.source == .installHistory)
        #expect(acme?.date != nil)
    }

    // MARK: - Parser: PackageKit receipt (dict)

    @Test func parsesReceiptDict() {
        let data = dictPlist([
            "PackageIdentifier": "com.vendor.tool",
            "InstallDate": when,
            "InstallProcessName": "installer",
            "PackageFileName": "Tool.pkg",
            "InstallPrefixPath": "/",
            "PackageVersion": "3.0",
        ])
        let s = MacInstallHistoryParser.parse(data, sourceFile: "/private/var/db/receipts/com.vendor.tool.plist", scope: "system")
        #expect(s.count == 1)
        #expect(s[0].packageIdentifiers == ["com.vendor.tool"])
        #expect(s[0].version == "3.0")
        #expect(s[0].packageFile == "Tool.pkg")
        #expect(s[0].source == .receipt)
    }

    @Test func receiptWithoutIdentifierIgnored() {
        let data = dictPlist(["SomeOtherKey": "x"])
        let s = MacInstallHistoryParser.parse(data, sourceFile: "/private/var/db/receipts/x.plist", scope: "system")
        #expect(s.isEmpty)
    }

    @Test func garbageReturnsEmpty() {
        let s = MacInstallHistoryParser.parse(Data("nope".utf8),
                                              sourceFile: "/Library/Receipts/InstallHistory.plist", scope: "system")
        #expect(s.isEmpty)
    }

    // MARK: - Analyzer

    private func entry(process: String? = nil, name: String = "Pkg", ids: [String] = [],
                       file: String? = nil) -> MacInstallEntry {
        MacInstallEntry(displayName: name, packageIdentifiers: ids, date: when, processName: process,
                        packageFile: file, source: .installHistory, scope: "system",
                        sourceFile: "/Library/Receipts/InstallHistory.plist")
    }

    @Test func flagsAbnormalInstallerProcessHigh() {
        // A scripting interpreter as the install process (programmatic install).
        let f = MacInstallAnalyzer().analyze([entry(process: "/bin/bash", name: "Backdoor")])
        #expect(f.count == 1)
        #expect(f[0].technique?.attackID == "T1059")
        #expect(f[0].severity == .high)
    }

    @Test func flagsRemoteAccessPackageHigh() {
        // RMM software is routinely shipped as .pkg — the higher-recall rule.
        let f = MacInstallAnalyzer().analyze([
            entry(process: "installer", name: "TeamViewer", ids: ["com.teamviewer.teamviewer"]),
        ])
        #expect(f.count == 1)
        #expect(f[0].technique?.attackID == "T1219")
        #expect(f[0].severity == .high)
    }

    @Test func flagsOffensivePackageHigh() {
        let f = MacInstallAnalyzer().analyze([entry(process: "installer", name: "mimikatz-installer")])
        #expect(f.count == 1)
        #expect(f[0].technique?.attackID == "T1588.002")
    }

    @Test func ignoresNormalInstall() {
        let f = MacInstallAnalyzer().analyze([
            entry(process: "installer", name: "Acme", ids: ["com.acme.app"]),
            entry(process: "softwareupdated", name: "macOS"),
        ])
        #expect(f.isEmpty)
    }

    @Test func dedupesRepeatedSuspicious() {
        // Same package seen in both InstallHistory and a receipt → one finding.
        let f = MacInstallAnalyzer().analyze([
            entry(process: "bash", name: "Backdoor", ids: ["com.x.backdoor"]),
            entry(process: "bash", name: "Backdoor", ids: ["com.x.backdoor"]),
        ])
        #expect(f.count == 1)
    }

    @Test func distinctUnnamedInstallsNotMerged() {
        // Two unnamed installs at different times must stay separate (the old
        // displayTitle-based key collapsed both to "install").
        let a = MacInstallEntry(date: Date(timeIntervalSince1970: 1_700_000_000), processName: "bash",
                                source: .receipt, scope: "system", sourceFile: "/x")
        let b = MacInstallEntry(date: Date(timeIntervalSince1970: 1_700_009_999), processName: "bash",
                                source: .receipt, scope: "system", sourceFile: "/x")
        #expect(MacInstallAnalyzer().analyze([a, b]).count == 2)
    }

    @Test func analyzerEmptyNoFindings() {
        #expect(MacInstallAnalyzer().analyze([]).isEmpty)
    }

    @Test func analyzerThreadedThroughContext() {
        let ctx = AnalysisContext(files: [], events: [], timeline: [], registryValues: [],
                                  installHistory: [entry(process: "python3", name: "x")])
        let f = MacInstallAnalyzer().analyze(context: ctx)
        #expect(f.count == 1)
        #expect(f[0].severity == .high)
    }

    // MARK: - Timeline

    @Test func timelineProjectsDatedInstalls() {
        let dated = entry(process: "installer", name: "A")
        let undated = MacInstallEntry(displayName: "B", date: nil, source: .receipt,
                                      scope: "system", sourceFile: "/x")
        let events = TimelineBuilder.build(from: [dated, undated])
        #expect(events.count == 1)   // undated dropped
        #expect(events[0].source == .install)
        #expect(events[0].path.contains("A"))
    }
}
