//
//  MftParserTests.swift
//  StrataTests
//
//  Validates MftParser against REAL `$MFT` records (records 0/$MFT, 5/root, and
//  7/$Boot, captured verbatim from the libfsntfs test corpus's
//  mft_metadata_file.1) plus a synthetic timestomped record. The real records
//  exercise the update-sequence-array fixup, $STANDARD_INFORMATION /
//  $FILE_NAME decoding, namespace preference, and parent-reference path
//  resolution against bytes a real Windows wrote.
//

import Testing
import Foundation
@testable import Strata

struct MftParserTests {
    // Real 1 KB MFT records (base64). REC0 = $MFT (rec 0), REC5 = root "." (rec 5,
    // a directory), REC7 = $Boot (rec 7). All parent -> record 5 (root).
    private static let rec0 = "RklMRTAAAwBRURAAAAAAAAEAAQA4AAEAoAEAAAAEAAAAAAAAAAAAAAcAAAAAAAAAAgAAAAAAAAAQAAAAYAAAAAAAGAAAAAAASAAAABgAAACQee1xMKHVAZB57XEwodUBkHntcTCh1QGQee1xMKHVAQYAAAAAAAAAAAAAAAAAAAAAAAAAAAEAAAAAAAAAAAAAAAAAAAAAAAAwAAAAaAAAAAAAGAAAAAMASgAAABgAAQAFAAAAAAAFAJB57XEwodUBkHntcTCh1QGQee1xMKHVAZB57XEwodUBAEAAAAAAAAAAQAAAAAAAAAYAAAAAAAAABAMkAE0ARgBUAAAAAAAAAIAAAABIAAAAAQBAAAAABgAAAAAAAAAAAD8AAAAAAAAAQAAAAAAAAAAAAAQAAAAAAAAABAAAAAAAAAAEAAAAAAAhQFACAAAAALAAAABQAAAAAQBAAAAABQAAAAAAAAAAAAEAAAAAAAAAQAAAAAAAAAAAIAAAAAAAAAgQAAAAAAAACBAAAAAAAAAhAU8CIQHW/QAAAAAAAAAA/////wAAAAAAAAQAAAAAACFAUAIAAAAAsAAAAFAAAAABAEAAAAAFAAAAAAAAAAAAAQAAAAAAAABAAAAAAAAAAAAgAAAAAAAACBAAAAAAAAAIEAAAAAAAACEBTwIhAdb9AAAAAAAAAgD/////AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACAA=="
    private static let rec5 = "RklMRTAAAwDWfBAAAAAAAAUAAQA4AAMAIAMAAAAEAAAAAAAAAAAAAAoAAAAFAAAABQAwAAAAAAAQAAAASAAAAAAAGAAAAAAAMAAAABgAAACQee1xMKHVAWSoEHMwodUBZKgQczCh1QFkqBBzMKHVAQYAAAAAAAAAAAAAAAAAAAAwAAAAYAAAAAAAGAAAAAEARAAAABgAAQAFAAAAAAAFAJB57XEwodUBkHntcTCh1QGQee1xMKHVAZB57XEwodUBAAAAAAAAAAAAAAAAAAAAAAYAABAAAAAAAQMuAAAAAABQAAAAAAEAAAAAGAAAAAIA5AAAABgAAAABAASAzAAAANgAAAAAAAAAFAAAAAIAuAAIAAAAAAAYAP8BHwABAgAAAAAABSAAAAAgAgAAAAsYAAAAABABAgAAAAAABSAAAAAgAgAAAAAUAP8BHwABAQAAAAAABRIAAAAACxQAAAAAEAEBAAAAAAAFEgAAAAAAFAC/ARMAAQEAAAAAAAULAAAAAAsUAAAAAeABAQAAAAAABQsAAAAAABgAqQASAAECAAAAAAAFIAAAACECAAAACxgAAAAAoAECAAAAAAAFIAAAACECAAABAQAAAAAABRIAAAABAQAAAAAABRIAAAAAAAAAkAAAAFgAAAAABBgAAAAGADgAAAAgAAAAJABJADMABQAwAAAAAQAAAAAQAAABAAAAEAAAACgAAAAoAAAAAQAAAAAAAAAAAAAAGAAAAAMAAAAAAAAAAAAAAKAAAABQAAAAAQRAAAAACAAAAAAAAAAAAAAAAAAAAAAASAAAAAAAAAAAEAAAAAAAAAAQAAAAAAAAABAAAAAAAAAkAEkAMwAwABEBJAAAAAAAsAAAACgAAAAABBgAAAAHAAgAAAAgAAAAJABJADMAMAABAAAAAAAAAAABAABoAAAAAAkYAAAACQA4AAAAMAAAACQAVABYAEYAXwBEAEEAVABBAAAAAAAAAAUAAAAAAAUAAQAAAAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIAAAAAAAAA/////wAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAFAA=="
    private static let rec7 = "RklMRTAAAwAAAAAAAAAAAAcAAQA4AAEAuAEAAAAEAAAAAAAAAAAAAAQAAAAHAAAAAwAAAAAAAAAQAAAASAAAAAAAGAAAAAAAMAAAABgAAACQee1xMKHVAZB57XEwodUBkHntcTCh1QGQee1xMKHVAQYAAAAAAAAAAAAAAAAAAAAwAAAAaAAAAAAAGAAAAAIATAAAABgAAQAFAAAAAAAFAJB57XEwodUBkHntcTCh1QGQee1xMKHVAZB57XEwodUBACAAAAAAAAAAIAAAAAAAAAYAAAAAAAAABQMkAEIAbwBvAHQAAAAAAFAAAACAAAAAAAAYAAAAAwBkAAAAGAAAAAEABIBIAAAAVAAAAAAAAAAUAAAAAgA0AAIAAAAAABQAiQASAAEBAAAAAAAFEgAAAAAAGACJABIAAQIAAAAAAAUgAAAAIAIAAAEBAAAAAAAFEgAAAAECAAAAAAAFIAAAACACAAAAAAAAgAAAAEgAAAABAEAAAAABAAAAAAAAAAAAAQAAAAAAAABAAAAAAAAAAAAgAAAAAAAAACAAAAAAAAAAIAAAAAAAABECAAAAAAAA/////wAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADAA=="

    private func realRecords() -> [UInt8] {
        [Self.rec0, Self.rec5, Self.rec7].flatMap { [UInt8](Data(base64Encoded: $0)!) }
    }

    @Test func parsesRealMftRecords() throws {
        let entries = MftParser.parse(bytes: realRecords(), sourceFile: "/x/$MFT")
        #expect(entries.count == 3)

        let mft = try #require(entries.first { $0.recordNumber == 0 })
        #expect(mft.fileName == "$MFT")
        #expect(mft.inUse)
        #expect(!mft.isDirectory)
        #expect(mft.parentRecord == 5)
        #expect(mft.fullPath == #"\$MFT"#)        // parent is root
        #expect(mft.siCreated != nil)
        #expect(mft.fnCreated != nil)

        let root = try #require(entries.first { $0.recordNumber == 5 })
        #expect(root.fileName == ".")
        #expect(root.isDirectory)
        #expect(root.fullPath == #"\"#)

        let boot = try #require(entries.first { $0.recordNumber == 7 })
        #expect(boot.fileName == "$Boot")
        #expect(boot.fullPath == #"\$Boot"#)
    }

    @Test func realTimestampsDecodeToExpectedInstant() throws {
        // mft_metadata_file.1 was created 2019-11-22T12:29:11.918837 UTC.
        let entries = MftParser.parse(bytes: realRecords(), sourceFile: "/x/$MFT")
        let mft = try #require(entries.first { $0.recordNumber == 0 })
        let created = try #require(mft.siCreated)
        let expected = Date(timeIntervalSince1970: 1_574_425_751.918)   // 2019-11-22T12:29:11.918Z
        #expect(abs(created.timeIntervalSince(expected)) < 1)
    }

    @Test func ignoresNonFileRecords() {
        var bytes = realRecords()
        // Append a junk (non-"FILE") record; it must be skipped, not crash.
        bytes.append(contentsOf: [UInt8](repeating: 0, count: MftParser.recordSize))
        let entries = MftParser.parse(bytes: bytes, sourceFile: "/x/$MFT")
        #expect(entries.count == 3)
    }

    @Test func emptyInputYieldsNothing() {
        #expect(MftParser.parse(bytes: [], sourceFile: "/x/$MFT").isEmpty)
        #expect(MftParser.parse(bytes: [UInt8](repeating: 0, count: 4096), sourceFile: "/x/$MFT").isEmpty)
    }

    // MARK: - Timestomping signals on the model

    @Test func detectsSiCreatedPredatingFn() {
        let real = Date(timeIntervalSince1970: 1_700_000_000)   // $FN created (real)
        let backdated = real.addingTimeInterval(-86_400 * 365)  // $SI rolled back a year
        let e = MftEntry(recordNumber: 42, sequence: 1, inUse: true, isDirectory: false,
                         fileName: "evil.exe", fullPath: #"\Users\Public\evil.exe"#, parentRecord: 5,
                         siCreated: backdated, siModified: backdated, siChanged: real, siAccessed: real,
                         fnCreated: real, fnModified: real, fnChanged: real, fnAccessed: real,
                         size: 1024, sourceFile: "/x/$MFT")
        #expect(e.siCreatedPredatesFn)
    }

    @Test func normalTimesAreNotFlagged() {
        let t = Date(timeIntervalSince1970: 1_700_000_000.5)    // sub-second -> not whole
        let e = MftEntry(recordNumber: 9, sequence: 1, inUse: true, isDirectory: false,
                         fileName: "ok.exe", fullPath: #"\Windows\System32\ok.exe"#, parentRecord: 5,
                         siCreated: t, siModified: t, siChanged: t, siAccessed: t,
                         fnCreated: t, fnModified: t, fnChanged: t, fnAccessed: t,
                         size: 1024, sourceFile: "/x/$MFT")
        #expect(!e.siCreatedPredatesFn)
        #expect(!e.siHasZeroedSubseconds)
    }

    @Test func detectsWholeSecondSubseconds() {
        let whole = Date(timeIntervalSince1970: 1_500_000_000)   // exact second
        let e = MftEntry(recordNumber: 9, sequence: 1, inUse: true, isDirectory: false,
                         fileName: "x.exe", fullPath: nil, parentRecord: 5,
                         siCreated: whole, siModified: whole, siChanged: whole, siAccessed: whole,
                         fnCreated: nil, fnModified: nil, fnChanged: nil, fnAccessed: nil,
                         size: nil, sourceFile: "/x/$MFT")
        #expect(e.siHasZeroedSubseconds)
    }
}

struct MftAnalyzerTests {
    private static let fnReal = Date(timeIntervalSince1970: 1_700_000_000)   // real $FN created

    /// Build an entry with a `$SI` creation `backdate` seconds before `$FN`.
    private func entry(name: String, path: String, backdate: TimeInterval,
                       wholeSecond: Bool = true) -> MftEntry {
        let fn = Self.fnReal
        let si = (wholeSecond ? fn : fn.addingTimeInterval(0.5)).addingTimeInterval(-backdate)
        return MftEntry(recordNumber: 100, sequence: 1, inUse: true, isDirectory: false,
                        fileName: name, fullPath: path, parentRecord: 5,
                        siCreated: si, siModified: si, siChanged: fn, siAccessed: fn,
                        fnCreated: fn, fnModified: fn, fnChanged: fn, fnAccessed: fn,
                        size: 4096, sourceFile: "/x/$MFT")
    }

    private func context(_ mft: [MftEntry]) -> AnalysisContext {
        AnalysisContext(files: [], events: [], timeline: [], registryValues: [], mft: mft)
    }

    @Test func flagsBackdatedExeInSuspiciousPathHigh() throws {
        let findings = MftAnalyzer().analyze(context: context([
            entry(name: "evil.exe", path: #"\Users\Public\evil.exe"#, backdate: 86_400 * 200, wholeSecond: true),
        ]))
        let f = try #require(findings.first { $0.title.localizedCaseInsensitiveContains("timestomp") })
        #expect(f.severity == .high)             // whole-second + suspicious path
        #expect(f.technique?.attackID == "T1070.006")
        #expect(f.phase == .actionsOnObjectives)
    }

    @Test func wholeSecondBackdateOutsideStagingIsMedium() throws {
        let findings = MftAnalyzer().analyze(context: context([
            entry(name: "impl.dll", path: #"\Windows\System32\impl.dll"#, backdate: 86_400 * 30, wholeSecond: true),
        ]))
        let f = try #require(findings.first)
        #expect(f.severity == .medium)
    }

    @Test func ignoresBackdateWithoutCorroboration() {
        // Sub-second $SI (not whole) in a benign path -> no corroborating signal.
        let findings = MftAnalyzer().analyze(context: context([
            entry(name: "app.exe", path: #"\Program Files\App\app.exe"#, backdate: 86_400 * 30, wholeSecond: false),
        ]))
        #expect(findings.isEmpty)
    }

    @Test func ignoresNonExecutable() {
        let findings = MftAnalyzer().analyze(context: context([
            entry(name: "notes.txt", path: #"\Users\Public\notes.txt"#, backdate: 86_400 * 200, wholeSecond: true),
        ]))
        #expect(findings.isEmpty)
    }

    @Test func ignoresSmallBackdate() {
        let findings = MftAnalyzer().analyze(context: context([
            entry(name: "evil.exe", path: #"\Users\Public\evil.exe"#, backdate: 120, wholeSecond: true),
        ]))
        #expect(findings.isEmpty)   // under the 1-hour floor
    }

    @Test func ignoresNormalExecutable() {
        // $SI == $FN (no backdate).
        let t = Self.fnReal
        let e = MftEntry(recordNumber: 1, sequence: 1, inUse: true, isDirectory: false,
                         fileName: "cmd.exe", fullPath: #"\Windows\System32\cmd.exe"#, parentRecord: 5,
                         siCreated: t, siModified: t, siChanged: t, siAccessed: t,
                         fnCreated: t, fnModified: t, fnChanged: t, fnAccessed: t,
                         size: 1024, sourceFile: "/x/$MFT")
        #expect(MftAnalyzer().analyze(context: context([e])).isEmpty)
    }

    @Test func emptyYieldsNothing() {
        #expect(MftAnalyzer().analyze(context: context([])).isEmpty)
    }
}
