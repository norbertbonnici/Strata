//
//  WindowsMRUAnalyzerTests.swift
//  StrataTests
//
//  Validates the WindowsMRUAnalyzer rules over per-user Explorer MRU registry
//  artifacts (RunMRU, TypedPaths, RecentDocs, ComDlg32 dialog MRUs, UserAssist).
//  Each rule has a positive case that must fire and a negative case (benign MRU
//  entry) that must NOT, so a clean host produces zero findings.
//

import Testing
import Foundation
@testable import Strata

struct WindowsMRUAnalyzerTests {
    private static let when = Date(timeIntervalSince1970: 1_700_000_000)

    /// NTUSER MRU values carry a `Software\...\Explorer\...` path, mirroring how
    /// the registry parser renders per-user hive paths.
    private func reg(_ keyTail: String, name: String, data: String,
                     type: RegistryValue.ValueType = .sz) -> RegistryValue {
        RegistryValue(
            hive: "NTUSER",
            path: "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\\(keyTail)",
            name: name, type: type, data: data,
            lastWritten: WindowsMRUAnalyzerTests.when,
            sourceFile: "/Users/victim/NTUSER.DAT")
    }

    private func context(_ values: [RegistryValue]) -> AnalysisContext {
        AnalysisContext(files: [], events: [], timeline: [], registryValues: values)
    }

    // MARK: RunMRU

    @Test func flagsEncodedPowerShellInRunMRU() throws {
        let findings = WindowsMRUAnalyzer().analyze(context: context([
            reg("RunMRU", name: "a",
                data: "powershell -nop -w hidden -enc SQBFAFgA\\1"),
        ]))
        let f = try #require(findings.first { $0.title.contains("Run-box command") })
        #expect(f.severity == .medium)
        #expect(f.phase == .exploitation)
        #expect(f.technique?.attackID == "T1059.001")
        // The trailing `\1` verb suffix is stripped from the rendered command.
        #expect(f.detail.contains("Command: powershell -nop -w hidden -enc SQBFAFgA"))
    }

    @Test func ignoresBenignRunMRUAndMRUList() {
        let findings = WindowsMRUAnalyzer().analyze(context: context([
            reg("RunMRU", name: "a", data: "notepad\\1"),
            reg("RunMRU", name: "b", data: "calc\\1"),
            reg("RunMRU", name: "MRUList", data: "ab"),
        ]))
        #expect(findings.isEmpty)
    }

    // MARK: TypedPaths

    @Test func flagsUNCPathInTypedPaths() throws {
        let f = try #require(WindowsMRUAnalyzer().analyze(context: context([
            reg("TypedPaths", name: "url1", data: "\\\\10.0.0.5\\share\\loot"),
        ])).first)
        #expect(f.title.contains("path typed in Explorer"))
        #expect(f.severity == .medium)
        #expect(f.phase == .exploitation)
        #expect(f.technique?.attackID == "T1021.002")
    }

    @Test func ignoresBenignLocalTypedPath() {
        let findings = WindowsMRUAnalyzer().analyze(context: context([
            reg("TypedPaths", name: "url1", data: "C:\\Users\\victim\\Documents"),
        ]))
        #expect(findings.isEmpty)
    }

    // MARK: RecentDocs / dialog MRUs

    @Test func flagsRiskyExtensionInRecentDocs() throws {
        let f = try #require(WindowsMRUAnalyzer().analyze(context: context([
            reg("RecentDocs", name: "0", data: "invoice.iso"),
        ])).first)
        #expect(f.title.contains("Risky file"))
        #expect(f.technique?.attackID == "T1204.002")
        #expect(f.severity == .medium)
    }

    @Test func ignoresBenignDocumentInRecentDocs() {
        let findings = WindowsMRUAnalyzer().analyze(context: context([
            reg("RecentDocs", name: "0", data: "quarterly-report.docx"),
            reg("RecentDocs", name: "MRUListEx", data: ""),
        ]))
        #expect(findings.isEmpty)
    }

    // MARK: UserAssist (ROT13)

    @Test func flagsSuspiciousPathInRot13UserAssist() throws {
        // ROT13 of "C:\Users\Public\evil.exe" -> the value name as stored.
        let encoded = WindowsMRUAnalyzer.rot13(#"C:\Users\Public\evil.exe"#)
        let f = try #require(WindowsMRUAnalyzer().analyze(context: context([
            reg("UserAssist\\{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}\\Count",
                name: encoded, data: "", type: .binary),
        ])).first)
        #expect(f.title.contains("UserAssist"))
        #expect(f.detail.contains(#"C:\Users\Public\evil.exe"#))   // decoded back
        #expect(f.severity == .medium)
        #expect(f.technique?.attackID == "T1204.002")
    }

    @Test func ignoresBenignRot13UserAssist() {
        let encoded = WindowsMRUAnalyzer.rot13(#"C:\Program Files\Notepad++\notepad++.exe"#)
        let findings = WindowsMRUAnalyzer().analyze(context: context([
            reg("UserAssist\\{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}\\Count",
                name: encoded, data: "", type: .binary),
            reg("UserAssist\\{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}",
                name: "Version", data: "3", type: .dword),
        ]))
        #expect(findings.isEmpty)
    }

    /// Regression guard for the FP-hardening: UserAssist uses a *tighter* path
    /// set than the other rules, deliberately excluding the broad `\AppData\`
    /// so the many legit apps that self-update out of `\AppData\Local\`
    /// (Slack, Teams, Discord, VS Code's updater, GitHub Desktop) don't flood
    /// findings. A program launched from a plain `\AppData\Local\<app>\` must
    /// NOT fire - only the staging sub-paths (Temp, Public, Downloads, ...) do.
    @Test func ignoresAppDataLocalSelfUpdaterInUserAssist() {
        let encoded = WindowsMRUAnalyzer.rot13(
            #"C:\Users\victim\AppData\Local\Microsoft\Teams\current\Teams.exe"#)
        let findings = WindowsMRUAnalyzer().analyze(context: context([
            reg("UserAssist\\{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}\\Count",
                name: encoded, data: "", type: .binary),
        ]))
        #expect(findings.isEmpty)
    }

    /// ...but a program launched from `\AppData\Local\Temp\` *is* staging and
    /// must still fire, proving the tighter list keeps the high-signal case.
    @Test func flagsAppDataLocalTempInUserAssist() throws {
        let encoded = WindowsMRUAnalyzer.rot13(
            #"C:\Users\victim\AppData\Local\Temp\update.exe"#)
        let f = try #require(WindowsMRUAnalyzer().analyze(context: context([
            reg("UserAssist\\{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}\\Count",
                name: encoded, data: "", type: .binary),
        ])).first)
        #expect(f.title.contains("UserAssist"))
        #expect(f.severity == .medium)
        #expect(f.technique?.attackID == "T1204.002")
    }

    // MARK: RunMRU cradle-token FP hardening

    /// A benign Run-box command carrying a bare `-e ` flag (a common tool
    /// shorthand, e.g. `7z -e ...`) with no interpreter / cradle / suspicious
    /// path must NOT fire - the bare `-e ` token was deliberately dropped.
    @Test func ignoresBareDashEFlagInRunMRU() {
        let findings = WindowsMRUAnalyzer().analyze(context: context([
            reg("RunMRU", name: "a", data: "7z -e archive.zip\\1"),
        ]))
        #expect(findings.isEmpty)
    }

    /// The retained, specific PowerShell encoded-command form still fires even
    /// without the `powershell` token spelled out (defence in depth).
    @Test func flagsEncodedCommandCradleInRunMRU() throws {
        let f = try #require(WindowsMRUAnalyzer().analyze(context: context([
            reg("RunMRU", name: "a",
                data: "pwsh -EncodedCommand SQBFAFgA\\1"),
        ])).first)
        #expect(f.severity == .medium)
        #expect(f.phase == .exploitation)
        // `pwsh` is an interpreter token -> PowerShell technique.
        #expect(f.technique?.attackID == "T1059.001")
    }

    // MARK: ROT13 helper round-trip

    @Test func rot13IsItsOwnInverseAndPreservesNonLetters() {
        let s = #"C:\Users\Public\evil.exe-{123}"#
        #expect(WindowsMRUAnalyzer.rot13(WindowsMRUAnalyzer.rot13(s)) == s)
    }

    @Test func emptyContextYieldsNothing() {
        #expect(WindowsMRUAnalyzer().analyze(context: context([])).isEmpty)
    }
}
