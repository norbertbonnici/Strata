//
//  ADReconAnalyzerTests.swift
//  StrataTests
//
//  Validates the three AD/Kerberos recon detections: a Kerberoasting RC4 burst
//  (T1558.003), an AS-REP-roastable account (PreAuthType=0, T1558.004), and a
//  domain-discovery command burst (T1087/T1018). Each rule has one positive
//  case that fires and a negative case that must stay quiet.
//

import Testing
import Foundation
@testable import Strata

struct ADReconAnalyzerTests {
    private static let base = Date(timeIntervalSince1970: 1_700_000_000)

    // MARK: helpers

    /// Security 4769 service-ticket request for one SPN by one account.
    private func ticket4769(account: String, service: String, encType: String,
                            offset: TimeInterval) -> EventLogRecord {
        let xml = """
        <EventData>\
        <Data Name="TargetUserName">\(account)</Data>\
        <Data Name="ServiceName">\(service)</Data>\
        <Data Name="TicketEncryptionType">\(encType)</Data>\
        <Data Name="TicketOptions">0x40810000</Data>\
        </EventData>
        """
        return EventLogRecord(recordNumber: 1, writtenAt: Self.base.addingTimeInterval(offset),
                              eventID: 4769, level: 4, channel: "Security",
                              provider: "Microsoft-Windows-Security-Auditing",
                              computer: "DC01", payloadXML: xml, sourceFile: "Security.evtx")
    }

    /// Security 4768 TGT request.
    private func tgt4768(account: String, preAuth: String, encType: String) -> EventLogRecord {
        let xml = """
        <EventData>\
        <Data Name="TargetUserName">\(account)</Data>\
        <Data Name="PreAuthType">\(preAuth)</Data>\
        <Data Name="TicketEncryptionType">\(encType)</Data>\
        </EventData>
        """
        return EventLogRecord(recordNumber: 2, writtenAt: Self.base, eventID: 4768, level: 4,
                              channel: "Security", provider: "Microsoft-Windows-Security-Auditing",
                              computer: "DC01", payloadXML: xml, sourceFile: "Security.evtx")
    }

    /// Security 4688 process creation.
    private func proc4688(image: String, cmd: String, host: String = "WS01",
                          offset: TimeInterval) -> EventLogRecord {
        let xml = """
        <EventData>\
        <Data Name="NewProcessName">\(image)</Data>\
        <Data Name="CommandLine">\(cmd)</Data>\
        </EventData>
        """
        return EventLogRecord(recordNumber: 3, writtenAt: Self.base.addingTimeInterval(offset),
                              eventID: 4688, level: 4, channel: "Security",
                              provider: "Microsoft-Windows-Security-Auditing",
                              computer: host, payloadXML: xml, sourceFile: "Security.evtx")
    }

    private func context(_ events: [EventLogRecord]) -> AnalysisContext {
        AnalysisContext(files: [], events: events, timeline: [], registryValues: [])
    }

    // MARK: Kerberoasting (T1558.003)

    @Test func flagsKerberoastingBurst() throws {
        // One account pulls RC4 (0x17) tickets for 7 distinct SPNs in ~2 minutes.
        var events: [EventLogRecord] = []
        for i in 0..<7 {
            events.append(ticket4769(account: "attacker", service: "MSSQLSvc/sql\(i).corp.local:1433",
                                     encType: "0x17", offset: Double(i) * 20))
        }
        let findings = ADReconAnalyzer().analyze(context: context(events))
        let f = try #require(findings.first { $0.title.contains("Kerberoasting burst") })
        #expect(f.severity == .high)
        #expect(f.phase == .reconnaissance)
        #expect(f.technique?.attackID == "T1558.003")
    }

    @Test func ignoresFewRC4Tickets() {
        // Only 2 distinct SPNs (below the 6-service burst gate) - benign.
        let events = [
            ticket4769(account: "svc-sql", service: "MSSQLSvc/sql0.corp.local:1433",
                       encType: "0x17", offset: 0),
            ticket4769(account: "svc-sql", service: "MSSQLSvc/sql1.corp.local:1433",
                       encType: "0x17", offset: 30),
        ]
        let findings = ADReconAnalyzer().analyze(context: context(events))
        #expect(findings.contains { $0.title.contains("Kerberoasting burst") } == false)
    }

    @Test func ignoresAESTicketBurst() {
        // Many distinct SPNs but AES (0x12) encryption - not the roasting downgrade.
        var events: [EventLogRecord] = []
        for i in 0..<8 {
            events.append(ticket4769(account: "workstation", service: "HOST/server\(i).corp.local",
                                     encType: "0x12", offset: Double(i) * 10))
        }
        let findings = ADReconAnalyzer().analyze(context: context(events))
        #expect(findings.contains { $0.title.contains("Kerberoasting burst") } == false)
    }

    @Test func ignoresMachineAccountRC4Burst() {
        // A computer account ($) legitimately pulls many RC4 service tickets in
        // bulk - it must be excluded as the requestor.
        var events: [EventLogRecord] = []
        for i in 0..<8 {
            events.append(ticket4769(account: "WS01$", service: "cifs/file\(i).corp.local",
                                     encType: "0x17", offset: Double(i) * 10))
        }
        let findings = ADReconAnalyzer().analyze(context: context(events))
        #expect(findings.contains { $0.title.contains("Kerberoasting burst") } == false)
    }

    // MARK: AS-REP roasting (T1558.004)

    @Test func flagsASREPRoastableAccount() throws {
        let findings = ADReconAnalyzer().analyze(context: context([
            tgt4768(account: "svc-legacy", preAuth: "0", encType: "0x17"),
        ]))
        let f = try #require(findings.first { $0.title.contains("AS-REP roastable") })
        #expect(f.severity == .high)
        #expect(f.phase == .reconnaissance)
        #expect(f.technique?.attackID == "T1558.004")
    }

    @Test func ignoresNormalPreAuthTGT() {
        // PreAuthType=2 (encrypted timestamp) is the default - pre-auth is on.
        let findings = ADReconAnalyzer().analyze(context: context([
            tgt4768(account: "alice", preAuth: "2", encType: "0x12"),
        ]))
        #expect(findings.contains { $0.title.contains("AS-REP roastable") } == false)
    }

    // MARK: Discovery command burst (T1087 / T1018)

    @Test func flagsDiscoveryBurst() throws {
        // 4 distinct enumeration commands from one host inside the 5-minute window.
        let events = [
            proc4688(image: #"C:\Windows\System32\net.exe"#,
                     cmd: #"net group "Domain Admins" /domain"#, offset: 0),
            proc4688(image: #"C:\Windows\System32\nltest.exe"#,
                     cmd: "nltest /dclist:corp.local", offset: 30),
            proc4688(image: #"C:\Windows\System32\whoami.exe"#,
                     cmd: "whoami /all", offset: 60),
            proc4688(image: #"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"#,
                     cmd: #"powershell -c "Get-ADUser -Filter *""#, offset: 90),
        ]
        let findings = ADReconAnalyzer().analyze(context: context(events))
        let f = try #require(findings.first { $0.title.contains("Domain reconnaissance burst") })
        #expect(f.severity == .medium)
        #expect(f.phase == .reconnaissance)
        #expect(f.technique?.attackID == "T1087")
    }

    @Test func ignoresSingleDiscoveryCommand() {
        // A lone `net group /domain` (1 distinct command) is benign admin activity.
        let findings = ADReconAnalyzer().analyze(context: context([
            proc4688(image: #"C:\Windows\System32\net.exe"#,
                     cmd: "net group /domain", offset: 0),
        ]))
        #expect(findings.contains { $0.title.contains("Domain reconnaissance burst") } == false)
    }

    @Test func ignoresBenignNetUsage() {
        // `net use` mapping a share and `net start` - not enumeration tokens.
        let events = [
            proc4688(image: #"C:\Windows\System32\net.exe"#,
                     cmd: #"net use Z: \\fileserver\share"#, offset: 0),
            proc4688(image: #"C:\Windows\System32\net.exe"#,
                     cmd: "net start spooler", offset: 30),
            proc4688(image: #"C:\Windows\System32\net.exe"#,
                     cmd: "net stop spooler", offset: 60),
        ]
        let findings = ADReconAnalyzer().analyze(context: context(events))
        #expect(findings.contains { $0.title.contains("Domain reconnaissance burst") } == false)
    }

    @Test func emptyYieldsNothing() {
        #expect(ADReconAnalyzer().analyze(context: context([])).isEmpty)
    }
}
