//
//  PrefetchParserTests.swift
//  StrataTests
//
//  Covers the pure prefetch parse (PrefetchParser.entry) against a captured
//  sccainfo report - mirroring how CustodyTests checks the EWF parsers against
//  captured ewfinfo output - plus the PrefetchAnalyzer's path/LOLBin rules.
//

import Testing
import Foundation
@testable import Strata

#if os(macOS)

struct PrefetchParserTests {

    /// A representative `sccainfo` report for a Win10 (format 30) prefetch file,
    /// built from libscca's exact `info_handle.c` print format: tab-padded
    /// "label: value" lines, CTIME timestamps, a "Not set (0)" for an unused run
    /// slot, and the file-metrics list that carries the executable's full path.
    private static let win10Report = """
    Windows Prefetch File (PF) information:
    \tFormat version\t\t\t: 30
    \tPrefetch hash\t\t\t: 0x1a2b3c4d
    \tExecutable filename\t\t: EVIL.EXE
    \tRun count\t\t\t: 12
    \tLast run time:\t\t\t: Mar 12, 2024 10:30:45.123456789 UTC
    \tLast run time: 2\t\t: Mar 11, 2024 09:15:00.000000000 UTC
    \tLast run time: 3\t\t: Not set (0)

    Filenames:
    \tNumber of filenames\t\t: 3
    \tFilename: 1\t\t\t: \\VOLUME{01d9a1b2c3d4e5f6}\\USERS\\PUBLIC\\EVIL.EXE
    \tFilename: 2\t\t\t: \\VOLUME{01d9a1b2c3d4e5f6}\\WINDOWS\\SYSTEM32\\NTDLL.DLL
    \tFilename: 3\t\t\t: \\VOLUME{01d9a1b2c3d4e5f6}\\WINDOWS\\SYSTEM32\\KERNEL32.DLL

    Volumes:
    \tNumber of volumes\t\t: 1
    Volume: 1 information:
    \tDevice path\t\t\t: \\VOLUME{01d9a1b2c3d4e5f6}
    """

    @Test func parsesHeaderFields() throws {
        let entry = try #require(PrefetchParser.entry(from: Self.win10Report, sourceFile: "/x/EVIL.EXE-12345678.pf"))
        #expect(entry.executableName == "EVIL.EXE")
        #expect(entry.runCount == 12)
        #expect(entry.formatVersion == 30)
        #expect(entry.fileCount == 3)
        #expect(entry.volumeCount == 1)
        #expect(entry.sourceFile == "/x/EVIL.EXE-12345678.pf")
    }

    @Test func recoversExecutablePathFromMetrics() throws {
        let entry = try #require(PrefetchParser.entry(from: Self.win10Report, sourceFile: "x.pf"))
        // Matched on basename against the filename list, not the DLLs.
        #expect(entry.executablePath == #"\VOLUME{01d9a1b2c3d4e5f6}\USERS\PUBLIC\EVIL.EXE"#)
    }

    @Test func keepsSetRunTimesAndSkipsNotSet() throws {
        let entry = try #require(PrefetchParser.entry(from: Self.win10Report, sourceFile: "x.pf"))
        // Two real timestamps; the "Not set (0)" slot is dropped.
        #expect(entry.lastRunTimes.count == 2)

        var comps = DateComponents()
        comps.year = 2024; comps.month = 3; comps.day = 12
        comps.hour = 10; comps.minute = 30; comps.second = 45
        comps.timeZone = TimeZone(identifier: "UTC")
        let expected = Calendar(identifier: .gregorian).date(from: comps)
        #expect(entry.lastRun == expected)
    }

    @Test func parsesWin7SingleRunTime() throws {
        // Format < 26 emits a single, unindexed "Last run time:" line.
        let report = """
        Windows Prefetch File (PF) information:
        \tFormat version\t\t\t: 17
        \tExecutable filename\t\t: CMD.EXE
        \tRun count\t\t\t: 3
        \tLast run time:\t\t\t: Jan 01, 2021 00:00:00.000000000 UTC
        \tNumber of filenames\t\t: 0
        \tNumber of volumes\t\t: 1
        """
        let entry = try #require(PrefetchParser.entry(from: report, sourceFile: "x.pf"))
        #expect(entry.formatVersion == 17)
        #expect(entry.lastRunTimes.count == 1)
        #expect(entry.executablePath == nil)   // no metrics list to match against
    }

    @Test func returnsNilWithoutExecutableName() {
        #expect(PrefetchParser.entry(from: "Windows Prefetch File (PF) information:\n", sourceFile: "x.pf") == nil)
        #expect(PrefetchParser.entry(from: "", sourceFile: "x.pf") == nil)
    }
}

struct PrefetchAnalyzerTests {
    private func context(_ entries: [PrefetchEntry]) -> AnalysisContext {
        AnalysisContext(files: [], events: [], timeline: [], registryValues: [], prefetch: entries)
    }

    @Test func flagsExecutionFromSuspiciousPath() {
        let entry = PrefetchEntry(executableName: "EVIL.EXE",
                                  executablePath: #"\VOLUME{1}\USERS\PUBLIC\EVIL.EXE"#,
                                  runCount: 2, lastRunTimes: [Date()], sourceFile: "x.pf")
        let findings = PrefetchAnalyzer().analyze(context: context([entry]))
        let pathFinding = try? #require(findings.first { $0.title.contains("suspicious path") })
        #expect(pathFinding?.severity == .high)
        #expect(pathFinding?.technique?.attackID == "T1204.002")
    }

    @Test func flagsLOLBinExecution() {
        // A LOLBin (here rundll32, a classic proxy-execution binary) is surfaced
        // on execution with its ATT&CK technique, even from System32.
        let entry = PrefetchEntry(executableName: "RUNDLL32.EXE",
                                  executablePath: #"\VOLUME{1}\WINDOWS\SYSTEM32\RUNDLL32.EXE"#,
                                  runCount: 5, lastRunTimes: [Date()], sourceFile: "x.pf")
        let findings = PrefetchAnalyzer().analyze(context: context([entry]))
        let lolbin = try? #require(findings.first { $0.title.contains("LOLBin") })
        #expect(lolbin?.technique?.attackID == "T1218.011")
    }

    @Test func psexecIsMediumSeverity() {
        // Remote-exec tooling carries more weight than the .low interpreters.
        let entry = PrefetchEntry(executableName: "PSEXESVC.EXE",
                                  executablePath: #"\VOLUME{1}\WINDOWS\PSEXESVC.EXE"#,
                                  runCount: 1, lastRunTimes: [Date()], sourceFile: "x.pf")
        let findings = PrefetchAnalyzer().analyze(context: context([entry]))
        let lolbin = try? #require(findings.first { $0.title.contains("LOLBin") })
        #expect(lolbin?.severity == .medium)
        #expect(lolbin?.technique?.attackID == "T1569.002")
    }

    @Test func lolbinFromSuspiciousPathYieldsBothLenses() {
        // A LOLBin run from a staging location triggers BOTH rules: the
        // suspicious-path escalation (high) and the LOLBin execution finding.
        let entry = PrefetchEntry(executableName: "POWERSHELL.EXE",
                                  executablePath: #"\VOLUME{1}\WINDOWS\TEMP\POWERSHELL.EXE"#,
                                  runCount: 1, lastRunTimes: [Date()], sourceFile: "x.pf")
        let findings = PrefetchAnalyzer().analyze(context: context([entry]))
        let pathFinding = try? #require(findings.first { $0.title.contains("suspicious path") })
        #expect(pathFinding?.severity == .high)
        #expect(pathFinding?.technique?.attackID == "T1204.002")
        #expect(findings.contains { $0.title.contains("LOLBin") })
    }

    @Test func ignoresBenignSystemExecutable() {
        let entry = PrefetchEntry(executableName: "NOTEPAD.EXE",
                                  executablePath: #"\VOLUME{1}\WINDOWS\SYSTEM32\NOTEPAD.EXE"#,
                                  runCount: 1, lastRunTimes: [Date()], sourceFile: "x.pf")
        #expect(PrefetchAnalyzer().analyze(context: context([entry])).isEmpty)
    }
}

#endif
