//
//  LnkParserTests.swift
//  StrataTests
//
//  Validates the LNK parser against REAL lnkinfo output (captured from the
//  vendored liblnk run on a hand-crafted MS-SHLLINK sample), including the
//  backslash un-doubling lnkinfo applies to every path.
//

import Testing
import Foundation
@testable import Strata

#if os(macOS)

struct LnkParserTests {
    // 2024-03-12 10:30:45 UTC, the timestamp baked into the sample.
    private static var knownDate: Date {
        var c = DateComponents()
        c.year = 2024; c.month = 3; c.day = 12; c.hour = 10; c.minute = 30; c.second = 45
        c.timeZone = TimeZone(identifier: "UTC")
        return Calendar(identifier: .gregorian).date(from: c)!
    }

    /// Verbatim lnkinfo 20240423 output for the crafted sample (tabs real,
    /// backslashes doubled exactly as lnkinfo emits them).
    private static let realOutput = [
        "lnkinfo 20240423",
        "",
        "Windows Shortcut information:",
        "\tContains a command line arguments string",
        "\tNumber of data blocks\t\t: 0",
        "",
        "Link information:",
        "\tCreation time\t\t\t: Mar 12, 2024 10:30:45.000000000 UTC",
        "\tModification time\t\t: Mar 12, 2024 10:30:45.000000000 UTC",
        "\tAccess time\t\t\t: Mar 12, 2024 10:30:45.000000000 UTC",
        "\tFile size\t\t\t: 1234 bytes",
        "\tIcon index\t\t\t: 0",
        "\tShow Window value\t\t: 0x00000001",
        "\tFile attribute flags\t\t: 0x00000020",
        "\t\tShould be archived (FILE_ATTRIBUTE_ARCHIVE)",
        "\tDrive type\t\t\t: Fixed (3)",
        "\tDrive serial number\t\t: 0x12345678",
        "\tVolume label\t\t\t: OS",
        "\tLocal path\t\t\t: C:\\\\Windows\\\\System32\\\\cmd.exe",
        "\tCommand line arguments\t\t: /c whoami",
    ].joined(separator: "\n")

    @Test func parsesRealLnkinfoOutput() throws {
        let e = try #require(LnkParser.entry(from: Self.realOutput, sourceFile: "/Recent/sample.lnk"))
        #expect(e.localPath == #"C:\Windows\System32\cmd.exe"#)   // backslashes un-doubled
        #expect(e.arguments == "/c whoami")
        #expect(e.targetSize == 1234)                             // " bytes" suffix dropped
        #expect(e.driveType == "Fixed (3)")
        #expect(e.volumeSerial == "0x12345678")
        #expect(e.volumeLabel == "OS")
        #expect(e.targetCreated == Self.knownDate)
        #expect(e.targetModified == Self.knownDate)
        #expect(e.name == "sample")                               // from the .lnk filename
    }

    @Test func unDoublesNetworkUNCPath() throws {
        let unc = #"\\server\share\x.exe"#
        let escaped = unc.replacingOccurrences(of: #"\"#, with: #"\\"#)   // simulate lnkinfo doubling
        let output = "Windows Shortcut information:\n\tNetwork path\t\t\t: \(escaped)"
        let e = try #require(LnkParser.entry(from: output, sourceFile: "/x/y.lnk"))
        #expect(e.networkPath == unc)
        #expect(e.targetPath == unc)
    }

    @Test func parsesNotSetTimesAsNil() throws {
        let output = [
            "\tCreation time\t\t\t: Not set (0)",
            "\tLocal path\t\t\t: C:\\\\Temp\\\\a.exe",
        ].joined(separator: "\n")
        let e = try #require(LnkParser.entry(from: output, sourceFile: "/x/a.lnk"))
        #expect(e.targetCreated == nil)
        #expect(e.localPath == #"C:\Temp\a.exe"#)
    }

    @Test func returnsNilWhenNothingUseful() {
        #expect(LnkParser.entry(from: "Windows Shortcut information:\n\tNumber of data blocks\t\t: 0",
                                sourceFile: "/x/empty.lnk") == nil)
        #expect(LnkParser.entry(from: "", sourceFile: "/x/empty.lnk") == nil)
    }
}

struct LnkAnalyzerTests {
    private func context(_ entries: [LnkEntry]) -> AnalysisContext {
        AnalysisContext(files: [], events: [], timeline: [], registryValues: [], lnk: entries)
    }

    @Test func flagsPowershellArgsAsHigh() throws {
        let e = LnkEntry(sourceFile: #"\Users\a\Recent\invoice.lnk"#,
                         localPath: #"C:\Windows\System32\cmd.exe"#,
                         arguments: "/c powershell -nop -w hidden -enc ZQBj")
        let f = try #require(LnkAnalyzer().analyze(context: context([e])).first)
        #expect(f.severity == .high)
        #expect(f.technique?.attackID == "T1204.002")
        #expect(f.title.contains("command-line arguments"))
    }

    @Test func flagsPlainArgsAsMedium() throws {
        let e = LnkEntry(sourceFile: #"\x\y.lnk"#, localPath: #"C:\app\tool.exe"#, arguments: "--config foo")
        let f = try #require(LnkAnalyzer().analyze(context: context([e])).first)
        #expect(f.severity == .medium)
    }

    @Test func flagsSuspiciousTargetWithoutArgs() throws {
        let e = LnkEntry(sourceFile: #"\x\y.lnk"#, localPath: #"C:\Users\Public\evil.exe"#)
        let f = try #require(LnkAnalyzer().analyze(context: context([e])).first)
        #expect(f.severity == .high)
        #expect(f.title.contains("suspicious path"))
    }

    @Test func ignoresBenignDocumentShortcut() {
        let e = LnkEntry(sourceFile: #"\Users\a\Recent\report.lnk"#,
                         localPath: #"C:\Users\a\Documents\report.docx"#)
        #expect(LnkAnalyzer().analyze(context: context([e])).isEmpty)
    }
}

#endif
