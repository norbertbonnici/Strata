//
//  UsnAnalyzerTests.swift
//  StrataTests
//
//  Validates the three correlated USN-journal detection rules: created-then-deleted
//  executable, rename-into-executable, and a mass-deletion burst.
//

import Testing
import Foundation
@testable import Strata

struct UsnAnalyzerTests {
    private static let when = Date(timeIntervalSince1970: 1_700_000_000)

    private func record(_ fileName: String, mft: UInt64, reason: UInt32,
                        when: Date? = UsnAnalyzerTests.when, usn: UInt64 = 0) -> UsnRecord {
        UsnRecord(usn: usn, timestamp: when, fileName: fileName, isDirectory: false,
                  mftEntry: mft, mftSequence: 1, parentMftEntry: 5,
                  reasonRaw: reason, fileAttributes: 0x20, sourceFile: "$J")
    }

    private func context(_ usn: [UsnRecord]) -> AnalysisContext {
        AnalysisContext(files: [], events: [], timeline: [], registryValues: [], usn: usn)
    }

    @Test func flagsCreatedThenDeletedExecutable() throws {
        let recs = [
            record("payload.exe", mft: 42, reason: UsnReason.fileCreate, usn: 1),
            record("payload.exe", mft: 42, reason: UsnReason.fileDelete | UsnReason.close, usn: 2),
        ]
        let findings = UsnAnalyzer().analyze(context: context(recs))
        let f = try #require(findings.first { $0.title.contains("Created-then-deleted") })
        #expect(f.severity == .high)
        #expect(f.phase == .actionsOnObjectives)
        #expect(f.technique?.attackID == "T1070.004")
    }

    @Test func ignoresCreatedThenDeletedNonExecutable() {
        let recs = [
            record("notes.txt", mft: 7, reason: UsnReason.fileCreate, usn: 1),
            record("notes.txt", mft: 7, reason: UsnReason.fileDelete, usn: 2),
        ]
        let findings = UsnAnalyzer().analyze(context: context(recs))
        #expect(findings.contains { $0.title.contains("Created-then-deleted") } == false)
    }

    @Test func flagsRenameIntoExecutable() throws {
        let recs = [
            record("update.tmp", mft: 9, reason: UsnReason.renameOldName, usn: 1),
            record("update.exe", mft: 9, reason: UsnReason.renameNewName, usn: 2),
        ]
        let findings = UsnAnalyzer().analyze(context: context(recs))
        let f = try #require(findings.first { $0.title.contains("Renamed to executable") })
        #expect(f.severity == .medium)
        #expect(f.technique?.attackID == "T1036.003")
    }

    @Test func ignoresRenameExeToExe() {
        let recs = [
            record("a.exe", mft: 9, reason: UsnReason.renameOldName, usn: 1),
            record("b.exe", mft: 9, reason: UsnReason.renameNewName, usn: 2),
        ]
        let findings = UsnAnalyzer().analyze(context: context(recs))
        #expect(findings.contains { $0.title.contains("Renamed to executable") } == false)
    }

    @Test func flagsMassDeletion() throws {
        var recs: [UsnRecord] = []
        for i in 0..<250 {
            recs.append(record("f\(i).dat", mft: UInt64(1000 + i),
                               reason: UsnReason.fileDelete, usn: UInt64(i)))
        }
        let findings = UsnAnalyzer().analyze(context: context(recs))
        let f = try #require(findings.first { $0.title.contains("Mass file deletion") })
        #expect(f.severity == .medium)
        #expect(f.technique?.attackID == "T1070.004")
    }

    @Test func quietBelowMassDeletionThreshold() {
        let recs = (0..<10).map {
            record("f\($0).dat", mft: UInt64(1000 + $0), reason: UsnReason.fileDelete, usn: UInt64($0))
        }
        let findings = UsnAnalyzer().analyze(context: context(recs))
        #expect(findings.contains { $0.title.contains("Mass file deletion") } == false)
    }

    @Test func emptyYieldsNothing() {
        #expect(UsnAnalyzer().analyze(context: context([])).isEmpty)
    }
}
