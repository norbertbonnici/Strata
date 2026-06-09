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

    // REC32 = $Tops (rec 32, parent 30) — a metadata file with 100 bytes of
    // RESIDENT $DATA, used to validate small-file recovery from the MFT.
    private static let rec32 = "RklMRTAAAwBBWRAAAAAAAAEAAQA4AAEA2AEAAAAEAAAAAAAAAAAAAAUAAAAgAAAAAwAAAAAAAAAQAAAAYAAAAAAAAAAAAAAASAAAABgAAAB1fQxyMKHVAXV9DHIwodUBdX0McjCh1QF1fQxyMKHVAQYAAAAAAAAAAAAAAAAAAAAAAAAAAgEAAAAAAAAAAAAAAAAAAAAAAAAwAAAAaAAAAAAAAAAAAAEATAAAABgAAQAeAAAAAAABAHV9DHIwodUBdX0McjCh1QF1fQxyMKHVAXV9DHIwodUBAAAAAAAAAAAAAAAAAAAAAAYAAAAAAAAABQAkAFQAbwBwAHMAAAAAAIAAAACAAAAAAAAYAAAAAgBkAAAAGAAAAAoAZAABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAP////8AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA////////////////AAAAAP////8AAAAAgAAAAFAAAAABAkAAAAAEAAAAAAAAAAAA/wAAAAAAAABIAAAAAAAAAAAAEAAAAAAAAAAQAAAAAAAAABAAAAAAACQAVAAAAAAAIgABgQMAAAD/////gnlHEQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADAA=="

    private func realRecords() -> [UInt8] {
        [Self.rec0, Self.rec5, Self.rec7].flatMap { [UInt8](Data(base64Encoded: $0)!) }
    }

    /// FILETIME ticks (100-ns since 1601) for a Date — for building test entries.
    static func ticks(_ date: Date) -> UInt64 {
        UInt64((date.timeIntervalSince1970 + 11_644_473_600) * 10_000_000)
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
        // Lossless 100-ns precision is preserved in the raw value.
        #expect(FileTime.precise(mft.siCreatedRaw) == "2019-11-22 12:29:11.9188368")
    }

    @Test func recoversResidentData() throws {
        let bytes = [UInt8](Data(base64Encoded: Self.rec32)!)
        let entries = MftParser.parse(bytes: bytes, sourceFile: "/x/$MFT")
        let tops = try #require(entries.first)
        #expect(tops.fileName == "$Tops")
        #expect(tops.hasResidentData)
        #expect(tops.residentData?.count == 100)        // small file content held in the MFT
        #expect(FileTime.precise(tops.siCreatedRaw) == "2019-11-22 12:29:12.1220981")
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
        let backdated = Self.ticks(real.addingTimeInterval(-86_400 * 365))  // $SI rolled back a year
        let r = Self.ticks(real)
        let e = MftEntry(recordNumber: 42, sequence: 1, inUse: true, isDirectory: false,
                         fileName: "evil.exe", fullPath: #"\Users\Public\evil.exe"#, parentRecord: 5,
                         siCreatedRaw: backdated, siModifiedRaw: backdated, siChangedRaw: r, siAccessedRaw: r,
                         fnCreatedRaw: r, fnModifiedRaw: r, fnChangedRaw: r, fnAccessedRaw: r,
                         size: 1024, sourceFile: "/x/$MFT")
        #expect(e.siCreatedPredatesFn)
    }

    @Test func normalTimesAreNotFlagged() {
        let t = Self.ticks(Date(timeIntervalSince1970: 1_700_000_000)) + 5_000_000   // +0.5s sub-second
        let e = MftEntry(recordNumber: 9, sequence: 1, inUse: true, isDirectory: false,
                         fileName: "ok.exe", fullPath: #"\Windows\System32\ok.exe"#, parentRecord: 5,
                         siCreatedRaw: t, siModifiedRaw: t, siChangedRaw: t, siAccessedRaw: t,
                         fnCreatedRaw: t, fnModifiedRaw: t, fnChangedRaw: t, fnAccessedRaw: t,
                         size: 1024, sourceFile: "/x/$MFT")
        #expect(!e.siCreatedPredatesFn)
        #expect(!e.siHasZeroedSubseconds)
    }

    @Test func detectsWholeSecondSubseconds() {
        let whole = Self.ticks(Date(timeIntervalSince1970: 1_500_000_000))   // exact second
        let e = MftEntry(recordNumber: 9, sequence: 1, inUse: true, isDirectory: false,
                         fileName: "x.exe", fullPath: nil, parentRecord: 5,
                         siCreatedRaw: whole, siModifiedRaw: whole, siChangedRaw: whole, siAccessedRaw: whole,
                         size: nil, sourceFile: "/x/$MFT")
        #expect(e.siHasZeroedSubseconds)
    }

    @Test func nearMaxRawTimestampDoesNotTrap() {
        // A crafted/corrupt $SI value near UInt64.max must not trap the predates
        // check (the old `si + tolerance` addition would have).
        let e = MftEntry(recordNumber: 1, sequence: 1, inUse: true, isDirectory: false,
                         fileName: "x.exe", fullPath: nil, parentRecord: 5,
                         siCreatedRaw: .max, fnCreatedRaw: 1_000, size: nil, sourceFile: "/x/$MFT")
        #expect(!e.siCreatedPredatesFn)   // max isn't before 1000 — and no crash
    }
}

struct MftAnalyzerTests {
    private static let fnReal = Date(timeIntervalSince1970: 1_700_000_000)   // real $FN created

    /// Build an entry with a `$SI` creation `backdate` seconds before `$FN`.
    private func entry(name: String, path: String, backdate: TimeInterval,
                       wholeSecond: Bool = true) -> MftEntry {
        let fn = Self.fnReal
        let si = (wholeSecond ? fn : fn.addingTimeInterval(0.5)).addingTimeInterval(-backdate)
        let siR = MftParserTests.ticks(si), fnR = MftParserTests.ticks(fn)
        return MftEntry(recordNumber: 100, sequence: 1, inUse: true, isDirectory: false,
                        fileName: name, fullPath: path, parentRecord: 5,
                        siCreatedRaw: siR, siModifiedRaw: siR, siChangedRaw: fnR, siAccessedRaw: fnR,
                        fnCreatedRaw: fnR, fnModifiedRaw: fnR, fnChangedRaw: fnR, fnAccessedRaw: fnR,
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
        let t = MftParserTests.ticks(Self.fnReal)
        let e = MftEntry(recordNumber: 1, sequence: 1, inUse: true, isDirectory: false,
                         fileName: "cmd.exe", fullPath: #"\Windows\System32\cmd.exe"#, parentRecord: 5,
                         siCreatedRaw: t, siModifiedRaw: t, siChangedRaw: t, siAccessedRaw: t,
                         fnCreatedRaw: t, fnModifiedRaw: t, fnChangedRaw: t, fnAccessedRaw: t,
                         size: 1024, sourceFile: "/x/$MFT")
        #expect(MftAnalyzer().analyze(context: context([e])).isEmpty)
    }

    @Test func emptyAnalyzerYieldsNothing() {
        #expect(MftAnalyzer().analyze(context: context([])).isEmpty)
    }
}

struct MftTreeTests {
    private func file(_ name: String, path: String, volume: String = "$MFT",
                      isDir: Bool = false, rec: UInt64) -> MftEntry {
        MftEntry(recordNumber: rec, sequence: 1, inUse: true, isDirectory: isDir,
                 fileName: name, fullPath: path, parentRecord: 5, volume: volume,
                 size: 10, sourceFile: "/x/$MFT")
    }

    @Test func buildsSingleVolumeTreeFromPaths() throws {
        let entries = [
            file("Windows", path: #"\Windows"#, isDir: true, rec: 100),
            file("cmd.exe", path: #"\Windows\System32\cmd.exe"#, rec: 101),
            file("System32", path: #"\Windows\System32"#, isDir: true, rec: 102),
            file("note.txt", path: #"\note.txt"#, rec: 103),
        ]
        let tree = MftNode.buildTree(from: entries)
        // Single volume → no volume wrapper; top level is \Windows and \note.txt.
        #expect(tree.allSatisfy { !$0.isVolume })
        let windows = try #require(tree.first { $0.name == "Windows" })
        #expect(windows.children?.contains { $0.name == "System32" } == true)
        let sys32 = try #require(windows.children?.first { $0.name == "System32" })
        #expect(sys32.children?.contains { $0.entry?.recordNumber == 101 } == true)   // cmd.exe nested
    }

    @Test func groupsMultipleVolumes() throws {
        let entries = [
            file("a.txt", path: #"\a.txt"#, volume: "NTFS · system", rec: 10),
            file("b.txt", path: #"\b.txt"#, volume: "NTFS · recovery", rec: 11),
        ]
        let tree = MftNode.buildTree(from: entries)
        #expect(tree.count == 2)
        #expect(tree.allSatisfy { $0.isVolume })
        #expect(Set(tree.map(\.name)).contains { $0.contains("system") })
    }

    @Test func parsedRealRecordsFormATree() {
        let entries = MftParser.parse(
            bytes: [MftParserTests.rec0Data, MftParserTests.rec5Data, MftParserTests.rec7Data].flatMap { $0 },
            sourceFile: "/x/$MFT")
        let tree = MftNode.buildTree(from: entries)
        // $MFT and $Boot are file leaves at the root; the root dir attaches implicitly.
        #expect(tree.contains { $0.name == "$MFT" })
        #expect(tree.contains { $0.name == "$Boot" })
    }
}

extension MftParserTests {
    static var rec0Data: [UInt8] { [UInt8](Data(base64Encoded: rec0)!) }
    static var rec5Data: [UInt8] { [UInt8](Data(base64Encoded: rec5)!) }
    static var rec7Data: [UInt8] { [UInt8](Data(base64Encoded: rec7)!) }
}
