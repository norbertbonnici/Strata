//
//  BTMTests.swift
//  StrataTests
//
//  Covers the Background Task Management (.btm) parser over a real
//  NSKeyedArchiver graph + the background-item analyzer's detection.
//

import Testing
import Foundation
@testable import Strata

struct BTMTests {

    /// Archive an array of item-record dicts the way a `.btm` keyed archive looks.
    private func btmData(_ records: [[String: Any]]) -> Data {
        try! NSKeyedArchiver.archivedData(withRootObject: records, requiringSecureCoding: false)
    }

    // MARK: - Parser

    @Test func parsesBackgroundItems() {
        let data = btmData([
            ["name": "EvilAgent", "url": "/tmp/evil", "type": 8, "disposition": 0,
             "bundleIdentifier": "com.evil.agent"],
            ["name": "Updater", "url": URL(fileURLWithPath: "/Applications/Updater.app"),
             "type": 4, "disposition": 1, "bundleIdentifier": "com.vendor.updater",
             "developerName": "Vendor"],
            ["name": "AppleThing", "type": 8, "disposition": 1, "bundleIdentifier": "com.apple.thing"],
        ])
        let items = BTMParser.parse(data: data, sourceFile: "/private/var/db/com.apple.backgroundtaskmanagement/BackgroundItems-v7.btm", scope: "system")
        #expect(items.count == 3)
        let evil = items.first { $0.bundleID == "com.evil.agent" }
        #expect(evil?.name == "EvilAgent")
        #expect(evil?.executable == "/tmp/evil")
        #expect(evil?.typeRaw == 8)
        #expect(evil?.enabled == false)         // disposition bit0 clear
        #expect(evil?.isApple == false)
        let updater = items.first { $0.bundleID == "com.vendor.updater" }
        #expect(updater?.developerName == "Vendor")
        #expect(updater?.enabled == true)
        #expect(updater?.executable?.contains("Updater.app") == true)   // NSURL resolved
        #expect(items.contains { $0.isApple })  // the com.apple one
    }

    @Test func ignoresNonRecordObjects() {
        // A graph with no type/disposition + identity shape yields nothing.
        let data = btmData([["note": "just a string", "count": 3]])
        #expect(BTMParser.parse(data: data, sourceFile: "/x.btm", scope: "system").isEmpty)
    }

    @Test func rejectsNonArchive() {
        #expect(BTMParser.parse(data: Data("nope".utf8), sourceFile: "/x.btm", scope: "system").isEmpty)
    }

    // MARK: - Analyzer

    private func item(_ name: String, exec: String?, bundle: String?, disposition: Int? = 1,
                      developer: String? = nil) -> MacBackgroundItem {
        MacBackgroundItem(name: name, executable: exec, bundleID: bundle, developerName: developer,
                          typeRaw: 8, disposition: disposition, scope: "system", sourceFile: "/x.btm")
    }

    @Test func flagsStagingPathHighAndNormalMedium() {
        let findings = MacBackgroundItemAnalyzer().analyze([
            item("EvilAgent", exec: "/tmp/evil", bundle: "com.evil.agent"),
            item("Updater", exec: "/Applications/Updater.app/Contents/MacOS/Updater", bundle: "com.vendor.updater"),
        ])
        #expect(findings.count == 2)
        #expect(findings.allSatisfy { $0.technique?.attackID == "T1547.015" })
        let staging = findings.first { $0.title.contains("staging") }
        #expect(staging?.severity == .high)
        let normal = findings.first { $0.title.contains("Non-Apple") }
        #expect(normal?.severity == .medium)
    }

    @Test func ignoresAppleItems() {
        let findings = MacBackgroundItemAnalyzer().analyze([
            item("AppleThing", exec: "/System/Library/x", bundle: "com.apple.thing"),
            item("Spotlight", exec: nil, bundle: nil, developer: "Apple"),
        ])
        #expect(findings.isEmpty)
    }

    @Test func emptyInputNoFindings() {
        #expect(MacBackgroundItemAnalyzer().analyze([]).isEmpty)
    }

    @Test func threadedThroughContext() {
        let ctx = AnalysisContext(files: [], events: [], timeline: [], registryValues: [],
                                  backgroundItems: [item("X", exec: "/tmp/x", bundle: "com.evil.x")])
        let findings = MacBackgroundItemAnalyzer().analyze(context: ctx)
        #expect(findings.count == 1)
        #expect(findings[0].severity == .high)
    }
}
