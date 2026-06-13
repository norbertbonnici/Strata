//
//  MacInstallHistoryParserTests.swift
//  StrataTests
//
//  Covers parsing /Library/Receipts/InstallHistory.plist and the OS-version
//  recovery used as the host-card fallback when the sealed System volume's
//  SystemVersion.plist is unreadable (its content lives in an APFS snapshot).
//  Fixture mirrors the real macOS-12.7.6 image structure.
//

import Testing
import Foundation
@testable import Strata

struct MacInstallHistoryParserTests {

    /// Build an InstallHistory.plist (array of dicts with a real NSDate `date`).
    private func plist(_ entries: [[String: Any]]) -> Data {
        try! PropertyListSerialization.data(fromPropertyList: entries, format: .xml, options: 0)
    }

    private func date(_ unix: TimeInterval) -> Date { Date(timeIntervalSince1970: unix) }

    @Test func parsesEntriesNewestFirst() {
        let data = plist([
            ["displayName": "macOS 12.7.4", "displayVersion": "12.7.4",
             "processName": "softwareupdated", "date": date(1_742_575_969)],
            ["displayName": "macOS 12.7.6", "displayVersion": "12.7.6",
             "processName": "softwareupdated", "date": date(1_742_578_630)],
            ["displayName": "Safari", "displayVersion": "17.6",
             "processName": "softwareupdated", "date": date(1_742_576_739)],
        ])
        let events = MacInstallHistoryParser.parse(data, sourceFile: "/Library/Receipts/InstallHistory.plist")
        #expect(events.count == 3)
        #expect(events.first?.name == "macOS 12.7.6")   // newest first
        #expect(events.first?.isOSInstall == true)
        #expect(events.first { $0.name == "Safari" }?.isOSInstall == false)
    }

    @Test func latestOSVersionPicksNewestMacOS() {
        let data = plist([
            ["displayName": "macOS 12.7.4", "displayVersion": "12.7.4", "date": date(100)],
            ["displayName": "macOS 12.7.6", "displayVersion": "12.7.6", "date": date(300)],
            ["displayName": "Xcode", "displayVersion": "16.2", "date": date(400)],
        ])
        let events = MacInstallHistoryParser.parse(data, sourceFile: "x")
        #expect(MacInstallHistoryParser.latestOSVersion(in: events) == "12.7.6")
    }

    @Test func appliesOSVersionOnlyWhenMissing() {
        let events = [MacInstallEvent(date: Date(timeIntervalSince1970: 300),
                                      name: "macOS 12.7.6", version: "12.7.6",
                                      process: "softwareupdated", sourceFile: "x")]
        // SystemVersion was unreadable → fill in.
        var empty = MacHostInfo()
        MacInstallHistoryParser.applyOSVersion(events, to: &empty)
        #expect(empty.productVersion == "12.7.6")
        #expect(empty.productName == "macOS")

        // SystemVersion succeeded → install history must NOT override it.
        var fromPlist = MacHostInfo()
        fromPlist.productName = "macOS"; fromPlist.productVersion = "14.4.1"; fromPlist.buildVersion = "23E224"
        MacInstallHistoryParser.applyOSVersion(events, to: &fromPlist)
        #expect(fromPlist.productVersion == "14.4.1")
    }

    @Test func malformedReturnsEmpty() {
        #expect(MacInstallHistoryParser.parse(Data([0, 1, 2]), sourceFile: "x").isEmpty)
        #expect(MacInstallHistoryParser.latestOSVersion(in: []) == nil)
    }
}
