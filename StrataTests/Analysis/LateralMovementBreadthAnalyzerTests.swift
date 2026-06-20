//
//  LateralMovementBreadthAnalyzerTests.swift
//  StrataTests
//
//  Validates the lateral-movement-breadth detections (WinRM/PSRemoting,
//  WMI remote exec, DCOM, SMB admin-share push) — each with a positive case
//  that fires and a negative case that must stay quiet.
//

import Testing
import Foundation
@testable import Strata

struct LateralMovementBreadthAnalyzerTests {
    private static let when = Date(timeIntervalSince1970: 1_700_000_000)

    /// Build a Sysmon-1 process-creation record with the given parent/child/cmd.
    private func sysmon1(parent: String, image: String, cmdline: String,
                         eid: UInt32 = 1) -> EventLogRecord {
        let xml = """
        <EventData>\
        <Data Name="Image">\(image)</Data>\
        <Data Name="ParentImage">\(parent)</Data>\
        <Data Name="CommandLine">\(cmdline)</Data>\
        </EventData>
        """
        return EventLogRecord(
            recordNumber: 1, writtenAt: Self.when, eventID: eid, level: 4,
            channel: "Microsoft-Windows-Sysmon/Operational",
            provider: "Microsoft-Windows-Sysmon", computer: "WS01",
            payloadXML: xml, sourceFile: "/evd/Sysmon.evtx")
    }

    private func context(_ events: [EventLogRecord]) -> AnalysisContext {
        AnalysisContext(files: [], events: events, timeline: [], registryValues: [])
    }

    // MARK: WinRM / PowerShell Remoting

    @Test func flagsWsmprovhostSpawningPowerShell() throws {
        let rec = sysmon1(parent: #"C:\Windows\System32\wsmprovhost.exe"#,
                          image: #"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"#,
                          cmdline: "powershell.exe -enc SQBFAFgA")
        let findings = LateralMovementBreadthAnalyzer().analyze(context: context([rec]))
        let f = try #require(findings.first { $0.title.contains("WinRM") && $0.title.contains("spawned") })
        #expect(f.severity == .high)
        #expect(f.phase == .exploitation)
        #expect(f.technique?.attackID == "T1021.006")
    }

    @Test func ignoresInteractiveCmdSpawningPowerShell() {
        // A normal interactive cmd.exe -> powershell.exe must NOT look like WinRM.
        let rec = sysmon1(parent: #"C:\Windows\System32\cmd.exe"#,
                          image: #"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"#,
                          cmdline: "powershell.exe Get-Process")
        let findings = LateralMovementBreadthAnalyzer().analyze(context: context([rec]))
        #expect(findings.isEmpty)
    }

    // MARK: WMI remote exec — provider host parent

    @Test func flagsWmiPrvSESpawningCmd() throws {
        let rec = sysmon1(parent: #"C:\Windows\System32\wbem\WmiPrvSE.exe"#,
                          image: #"C:\Windows\System32\cmd.exe"#,
                          cmdline: #"cmd.exe /c whoami > C:\out.txt"#)
        let findings = LateralMovementBreadthAnalyzer().analyze(context: context([rec]))
        let f = try #require(findings.first { $0.title.contains("WMI remote execution") })
        #expect(f.severity == .high)
        #expect(f.technique?.attackID == "T1047")
    }

    // MARK: WMI remote exec — wmic /node: command token

    @Test func flagsWmicNodeProcessCallCreate() throws {
        let rec = sysmon1(parent: #"C:\Windows\System32\cmd.exe"#,
                          image: #"C:\Windows\System32\wbem\wmic.exe"#,
                          cmdline: #"wmic /node:DC01 process call create "cmd.exe /c calc""#)
        let findings = LateralMovementBreadthAnalyzer().analyze(context: context([rec]))
        let f = try #require(findings.first { $0.title.contains("wmic /node:") })
        #expect(f.severity == .medium)
        #expect(f.technique?.attackID == "T1047")
    }

    @Test func ignoresLocalWmicNode() {
        // Local-only wmic against localhost must not fire.
        let rec = sysmon1(parent: #"C:\Windows\System32\cmd.exe"#,
                          image: #"C:\Windows\System32\wbem\wmic.exe"#,
                          cmdline: "wmic /node:localhost process call create cmd.exe")
        let findings = LateralMovementBreadthAnalyzer().analyze(context: context([rec]))
        #expect(findings.contains { $0.title.contains("wmic /node:") } == false)
    }

    // MARK: DCOM object moniker

    @Test func flagsMmc20ApplicationMoniker() throws {
        let rec = sysmon1(parent: #"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"#,
                          image: #"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"#,
                          cmdline: #"powershell [Activator]::CreateInstance([Type]::GetTypeFromProgID("MMC20.Application","10.0.0.5"))"#)
        let findings = LateralMovementBreadthAnalyzer().analyze(context: context([rec]))
        let f = try #require(findings.first { $0.title.localizedCaseInsensitiveContains("DCOM") })
        #expect(f.severity == .medium)
        #expect(f.technique?.attackID == "T1021.003")
    }

    @Test func ignoresLegitimateExcelAutomation() {
        // Excel.Application is a high-FP legitimate-automation ProgID and is
        // deliberately NOT a DCOM-lateral moniker — a benign admin script must
        // not be flagged as DCOM lateral movement.
        let rec = sysmon1(parent: #"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"#,
                          image: #"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"#,
                          cmdline: #"powershell $x = New-Object -ComObject Excel.Application; $x.Visible = $false"#)
        let findings = LateralMovementBreadthAnalyzer().analyze(context: context([rec]))
        #expect(findings.contains { $0.title.localizedCaseInsensitiveContains("DCOM") } == false)
    }

    // MARK: SMB admin-share push

    @Test func flagsAdminSharePush() throws {
        let rec = sysmon1(parent: #"C:\Windows\System32\cmd.exe"#,
                          image: #"C:\Windows\System32\cmd.exe"#,
                          cmdline: #"cmd.exe /c copy payload.exe \\10.0.0.5\ADMIN$\evil.exe"#)
        let findings = LateralMovementBreadthAnalyzer().analyze(context: context([rec]))
        let f = try #require(findings.first { $0.title.localizedCaseInsensitiveContains("admin-share") })
        #expect(f.severity == .medium)
        #expect(f.technique?.attackID == "T1021.002")
    }

    @Test func ignoresLocalDriveLetterNotAdminShare() {
        // A bare drive-letter path (no UNC \\) must not be read as an admin share.
        let rec = sysmon1(parent: #"C:\Windows\System32\cmd.exe"#,
                          image: #"C:\Windows\System32\cmd.exe"#,
                          cmdline: #"cmd.exe /c copy payload.exe C:\Users\Public\evil.exe"#)
        let findings = LateralMovementBreadthAnalyzer().analyze(context: context([rec]))
        #expect(findings.contains { $0.title.localizedCaseInsensitiveContains("admin-share") } == false)
    }

    // MARK: WinRM operational channel (presence-only)

    @Test func flagsWinRMOperationalListener() throws {
        let rec = EventLogRecord(
            recordNumber: 9, writtenAt: Self.when, eventID: 5985, level: 4,
            channel: "Microsoft-Windows-WinRM/Operational",
            provider: "Microsoft-Windows-Windows Remote Management", computer: "WS01",
            payloadXML: "<EventData></EventData>", sourceFile: "/evd/WinRM.evtx")
        let findings = LateralMovementBreadthAnalyzer().analyze(context: context([rec]))
        let f = try #require(findings.first { $0.title.contains("WinRM remote-management activity") })
        #expect(f.severity == .low)
        #expect(f.technique?.attackID == "T1021.006")
    }

    @Test func ignoresUnrelatedEventWithSamePort() {
        // An unrelated channel carrying "5985" in its payload must not fire.
        let rec = EventLogRecord(
            recordNumber: 10, writtenAt: Self.when, eventID: 4624, level: 4,
            channel: "Security", provider: "Microsoft-Windows-Security-Auditing",
            computer: "WS01",
            payloadXML: "<EventData><Data Name=\"IpPort\">5985</Data></EventData>",
            sourceFile: "/evd/Security.evtx")
        let findings = LateralMovementBreadthAnalyzer().analyze(context: context([rec]))
        #expect(findings.isEmpty)
    }

    // MARK: Empty

    @Test func emptyContextYieldsNothing() {
        #expect(LateralMovementBreadthAnalyzer().analyze(context: context([])).isEmpty)
    }
}
