//
//  FSEventsParserTests.swift
//  StrataTests
//
//  Covers the pure-Swift FSEvents DLS-page byte-parser and the FSEventsAnalyzer
//  detections. Synthetic DLS v1 / v2 pages are built in-test (no real
//  /.fseventsd/ corpus is bundled).
//

import Testing
import Foundation
@testable import Strata

struct FSEventsParserTests {

    private func leU32(_ v: UInt32) -> [UInt8] { (0..<4).map { UInt8((v >> ($0 * 8)) & 0xff) } }
    private func leU64(_ v: UInt64) -> [UInt8] { (0..<8).map { UInt8((v >> ($0 * 8)) & 0xff) } }

    /// Build one DLS page (v1 = 12-byte trailer, v2 adds the 8-byte node ID).
    private func page(version: Int, records: [(String, UInt64, UInt32, UInt64?)]) -> [UInt8] {
        var body: [UInt8] = []
        for (path, eid, flags, node) in records {
            body += Array(path.utf8); body.append(0)
            body += leU64(eid)
            body += leU32(flags)
            if version == 2 { body += leU64(node ?? 0) }
        }
        let magic: [UInt8] = version == 2 ? [0x32, 0x53, 0x4C, 0x44] : [0x31, 0x53, 0x4C, 0x44]
        var out = magic
        out += leU32(0)                          // reserved
        out += leU32(UInt32(12 + body.count))    // page length incl. header
        out += body
        return out
    }

    @Test func parsesDLS1Records() {
        let bytes = page(version: 1, records: [
            ("Users/jane/evil.sh", 100, FSEventFlag.fileEvent | FSEventFlag.created, nil),
            ("Library/LaunchDaemons/x.plist", 101, FSEventFlag.fileEvent | FSEventFlag.modified, nil),
        ])
        let recs = FSEventsParser.parse(decompressed: Data(bytes), sourceFile: "0000")
        #expect(recs.count == 2)
        #expect(recs[0].path == "Users/jane/evil.sh")
        #expect(recs[0].eventID == 100)
        #expect(recs[0].wasCreated)
        #expect(recs[0].isFile)
        #expect(recs[0].nodeID == nil)
        #expect(recs[1].wasModified)
    }

    @Test func parsesDLS2NodeID() {
        let bytes = page(version: 2, records: [
            ("Users/jane/.hidden/payload", 7, FSEventFlag.fileEvent | FSEventFlag.created | FSEventFlag.removed, 4242),
        ])
        let recs = FSEventsParser.parse(decompressed: Data(bytes), sourceFile: "0001")
        #expect(recs.count == 1)
        #expect(recs[0].nodeID == 4242)
        #expect(recs[0].wasCreated && recs[0].wasRemoved)
        #expect(recs[0].flagNames.contains("Created"))
        #expect(recs[0].flagNames.contains("Removed"))
    }

    @Test func parsesMultipleConcatenatedPages() {
        var bytes = page(version: 1, records: [("a/b", 1, FSEventFlag.modified, nil)])
        bytes += page(version: 2, records: [("c/d", 2, FSEventFlag.created, 9)])
        let recs = FSEventsParser.parse(decompressed: Data(bytes), sourceFile: "x")
        #expect(recs.count == 2)
        #expect(recs[0].path == "a/b")
        #expect(recs[1].path == "c/d")
        #expect(recs[1].nodeID == 9)
    }

    @Test func stopsOnGarbageInsteadOfCrashing() {
        let bytes: [UInt8] = [0x00, 0x01, 0x02, 0x03, 0x04]   // no DLS magic
        #expect(FSEventsParser.parse(decompressed: Data(bytes), sourceFile: "x").isEmpty)
    }

    @Test func gzippedNonGzipReturnsEmpty() {
        #expect(FSEventsParser.parse(gzipped: Data([0, 1, 2, 3]), sourceFile: "x").isEmpty)
    }
}

struct FSEventsAnalyzerTests {
    private let analyzer = FSEventsAnalyzer()

    @Test func createdThenRemovedInStagingFlagged() {
        let recs = [
            FSEventRecord(path: "private/tmp/.x/dropper.sh", eventID: 1,
                          flags: FSEventFlag.fileEvent | FSEventFlag.created | FSEventFlag.removed,
                          sourceFile: "0000"),
        ]
        let findings = analyzer.analyze(recs)
        #expect(findings.contains { $0.title.hasPrefix("FSEvents: files created then deleted") })
        #expect(findings.first?.severity == .high)
    }

    @Test func createdOnlyNotFlagged() {
        let recs = [
            FSEventRecord(path: "private/tmp/note.txt", eventID: 1,
                          flags: FSEventFlag.fileEvent | FSEventFlag.created, sourceFile: "0000"),
        ]
        #expect(analyzer.analyze(recs).isEmpty)
    }

    @Test func launchdPlistWriteFlagged() {
        let recs = [
            FSEventRecord(path: "Library/LaunchDaemons/com.evil.plist", eventID: 1,
                          flags: FSEventFlag.fileEvent | FSEventFlag.created, sourceFile: "0000"),
        ]
        let findings = analyzer.analyze(recs)
        #expect(findings.contains { $0.title.hasPrefix("FSEvents: launchd persistence write") })
    }

    @Test func emptyInputNoFindings() {
        #expect(analyzer.analyze([]).isEmpty)
    }
}
