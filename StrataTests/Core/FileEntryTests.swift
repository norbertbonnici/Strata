//
//  FileEntryTests.swift
//  StrataTests
//
//  Locks the `isSlackEntry` contract that every slack-exclusion guard in the app
//  depends on — the ransomware entropy burst scan, the macOS WhereFroms candidate
//  filter, and the parseMac content/xattr extractors. A TSK `<name>-slack`
//  pseudo-entry is the unused tail of an allocated cluster, never a real file, so
//  it must never be a target for a content or xattr read.
//

import Testing
import Foundation
@testable import Strata

struct FileEntryTests {
    private func file(_ name: String) -> FileEntry {
        FileEntry(id: 1, metaAddr: nil, name: name, parentPath: "/Users/x/Downloads",
                  size: 1024, isDirectory: false, isDeleted: false,
                  modified: nil, accessed: nil, changed: nil, created: nil)
    }

    @Test func isSlackEntryMatchesTskPseudoEntriesOnly() {
        #expect(file("messagesxboxlogo.png-slack").isSlackEntry)
        #expect(file("report.docx-slack").isSlackEntry)
        // A real file is never slack — even one whose name merely contains "slack".
        #expect(!file("messagesxboxlogo.png").isSlackEntry)
        #expect(!file("slack.dmg").isSlackEntry)
        #expect(!file("team-slack-export.zip").isSlackEntry)
    }

    @Test func slackEntryExtensionIsMisleading() {
        // The pathExtension of a "<name>.png-slack" entry is the compound
        // "png-slack" (everything after the last dot) — not "png" — so it matches
        // no real extension allow/deny list. The location-based WhereFroms filter
        // ignores extension entirely, which is why it leaked slack until the
        // isSlackEntry guard was added; exact-name/suffix filters never matched it.
        #expect(file("messagesxboxlogo.png-slack").fileExtension == "png-slack")
    }
}
