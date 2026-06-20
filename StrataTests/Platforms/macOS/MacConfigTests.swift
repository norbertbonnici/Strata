//
//  MacConfigTests.swift
//  StrataTests
//
//  Covers the macOS configuration-posture parser (firewall, screen-lock,
//  software-update, Gatekeeper, remote-service enablement, login-window) over
//  binary-plist fixtures, the presence-only credential handling, and the
//  MacConfigAnalyzer projection into findings.
//

import Testing
import Foundation
@testable import Strata

struct MacConfigTests {

    private func plist(_ obj: [String: Any]) -> Data {
        try! PropertyListSerialization.data(fromPropertyList: obj, format: .binary, options: 0)
    }

    private func parse(_ obj: [String: Any], _ source: String, scope: String = "system") -> [MacConfigSetting] {
        MacConfigParser.parse(plist(obj), sourceFile: source, scope: scope)
    }

    // MARK: - Firewall

    @Test func firewallOffFlaggedHigh() {
        let s = parse(["globalstate": 0], "/Library/Preferences/com.apple.alf.plist")
        let g = s.first { $0.key == "firewall.globalstate" }
        #expect(g?.risk == .high)
        #expect(g?.attackID == "T1562.004")
        #expect(g?.value == "off")
    }

    @Test func firewallOnNotFlagged() {
        let s = parse(["globalstate": 1, "loggingenabled": 1, "stealthenabled": 1],
                      "/Library/Preferences/com.apple.alf.plist")
        #expect(s.allSatisfy { !$0.isFlagged })
    }

    @Test func firewallLoggingOffMedium() {
        let s = parse(["globalstate": 1, "loggingenabled": 0],
                      "/Library/Preferences/com.apple.alf.plist")
        #expect(s.first { $0.key == "firewall.logging" }?.risk == .medium)
    }

    // MARK: - Software Update

    @Test func criticalUpdateDisabledHigh() {
        let s = parse(["CriticalUpdateInstall": false, "ConfigDataInstall": false, "AutomaticCheckEnabled": true],
                      "/Library/Preferences/com.apple.SoftwareUpdate.plist")
        #expect(s.first { $0.key == "update.criticalInstall" }?.risk == .high)
        #expect(s.first { $0.key == "update.configDataInstall" }?.risk == .high)
        // AutomaticCheckEnabled=true → present but not flagged.
        #expect(s.first { $0.key == "update.autoCheck" }?.isFlagged == false)
    }

    // MARK: - Gatekeeper

    @Test func gatekeeperDisabledHigh() {
        let s = parse(["enabled": "no"], "/private/var/db/SystemPolicy-prefs.plist")
        #expect(s.first?.key == "gatekeeper.enabled")
        #expect(s.first?.risk == .high)
        #expect(s.first?.attackID == "T1562.001")
    }

    @Test func gatekeeperEnabledNotFlagged() {
        let s = parse(["enabled": "yes"], "/private/var/db/SystemPolicy-prefs.plist")
        #expect(s.first?.isFlagged == false)
    }

    @Test func gatekeeperDisabledViaBoolHigh() {
        // `enabled` written as a CFBoolean <false/> must flag the same as "no"
        // (the asymmetric-fallback bug would silently drop this).
        let s = parse(["enabled": false], "/private/var/db/SystemPolicy-prefs.plist")
        #expect(s.first?.value == "disabled")
        #expect(s.first?.risk == .high)
        #expect(s.first?.attackID == "T1562.001")
    }

    @Test func gatekeeperEnabledViaBoolNotFlagged() {
        let s = parse(["enabled": true], "/private/var/db/SystemPolicy-prefs.plist")
        #expect(s.first?.isFlagged == false)
    }

    // MARK: - Login window

    @Test func autoLoginFlaggedHigh() {
        let s = parse(["autoLoginUser": "alice"], "/Library/Preferences/com.apple.loginwindow.plist")
        let a = s.first { $0.key == "loginwindow.autoLoginUser" }
        #expect(a?.risk == .high)
        #expect(a?.attackID == "T1078")
        #expect(a?.value == "alice")
    }

    @Test func hiddenUsersFlaggedHigh() {
        let s = parse(["HiddenUsersList": ["backdoor"]], "/Library/Preferences/com.apple.loginwindow.plist")
        let h = s.first { $0.key == "loginwindow.hiddenUsers" }
        #expect(h?.risk == .high)
        #expect(h?.attackID == "T1564.002")
        #expect(h?.category == .account)
    }

    @Test func guestEnabledMedium() {
        let s = parse(["GuestEnabled": true], "/Library/Preferences/com.apple.loginwindow.plist")
        #expect(s.first { $0.key == "loginwindow.guest" }?.risk == .medium)
    }

    // MARK: - Remote services (inverted-bool disabled.plist)

    @Test func sshEnabledViaDisabledFalse() {
        // disabled==false ⇒ the service is ENABLED (override un-disables it).
        let s = parse(["com.openssh.sshd": false, "com.apple.smbd": true],
                      "/private/var/db/com.apple.xpc.launchd/disabled.plist")
        let ssh = s.first { $0.key == "service.com.openssh.sshd" }
        #expect(ssh?.risk == .high)
        #expect(ssh?.attackID == "T1021.004")
        // smbd disabled==true ⇒ off ⇒ no setting emitted.
        #expect(s.contains { $0.key == "service.com.apple.smbd" } == false)
    }

    @Test func absentServiceNotFlagged() {
        let s = parse(["com.apple.somethingelse": false],
                      "/private/var/db/com.apple.xpc.launchd/disabled.plist")
        #expect(s.isEmpty)   // no known remote-service label enabled
    }

    @Test func legacyOverridesNestedDisabled() {
        let s = parse(["com.apple.screensharing": ["Disabled": false]],
                      "/var/db/launchd.db/com.apple.launchd/overrides.plist")
        #expect(s.first { $0.key == "service.com.apple.screensharing" }?.risk == .high)
    }

    // MARK: - Screen lock (per-user, undetermined-safe)

    @Test func screenLockOffMedium() {
        let s = parse(["askForPassword": 0],
                      "/Users/alice/Library/Preferences/ByHost/com.apple.screensaver.ABC.plist",
                      scope: "alice")
        #expect(s.first?.risk == .medium)
        #expect(s.first?.scope == "alice")
    }

    @Test func screenLockAbsentKeyIsUndetermined() {
        // No askForPassword key → emit nothing (never assume "disabled").
        let s = parse(["idleTime": 600],
                      "/Users/alice/Library/Preferences/com.apple.screensaver.plist", scope: "alice")
        #expect(s.isEmpty)
    }

    // MARK: - Credentials (presence only, never decoded)

    @Test func kcpasswordPresenceOnly() {
        let s = MacConfigParser.parse(Data([0x01, 0x02, 0x03]), sourceFile: "/private/etc/kcpassword", scope: "system")
        #expect(s.count == 1)
        #expect(s[0].value == "present")          // not the decoded secret
        #expect(s[0].attackID == "T1078")
        #expect(s[0].risk == .high)
    }

    @Test func vncPasswordPresenceOnly() {
        let s = MacConfigParser.parse(Data("aabb".utf8),
                                      sourceFile: "/Library/Preferences/com.apple.VNCSettings.txt", scope: "system")
        #expect(s.count == 1)
        #expect(s[0].value == "present")
        #expect(s[0].attackID == "T1021.005")
    }

    @Test func nonPlistGarbageReturnsEmpty() {
        let s = MacConfigParser.parse(Data("not a plist".utf8),
                                      sourceFile: "/Library/Preferences/com.apple.alf.plist", scope: "system")
        #expect(s.isEmpty)
    }

    // MARK: - Analyzer

    private func setting(_ risk: MacConfigSetting.Risk, category: MacConfigSetting.Category = .firewall,
                         attack: String? = "T1562.004") -> MacConfigSetting {
        MacConfigSetting(category: category, key: "k", name: "Test", value: "off",
                         interpretation: "x", risk: risk, attackID: attack, attackName: "n",
                         scope: "system", sourceFile: "/x/com.apple.alf.plist")
    }

    @Test func analyzerEmitsFindingsForFlaggedOnly() {
        let f = MacConfigAnalyzer().analyze([setting(.high), setting(.none)])
        #expect(f.count == 1)
        #expect(f[0].severity == .high)
        #expect(f[0].technique?.attackID == "T1562.004")
    }

    @Test func analyzerPhaseMapping() {
        let remote = MacConfigAnalyzer().analyze([setting(.high, category: .remoteAccess, attack: "T1021.004")])
        #expect(remote[0].phase == .commandAndControl)
        let fw = MacConfigAnalyzer().analyze([setting(.high, category: .firewall)])
        #expect(fw[0].phase == .exploitation)
        let login = MacConfigAnalyzer().analyze([setting(.high, category: .loginWindow, attack: "T1078")])
        #expect(login[0].phase == .installation)
    }

    @Test func analyzerEmptyNoFindings() {
        #expect(MacConfigAnalyzer().analyze([]).isEmpty)
    }

    @Test func analyzerThreadedThroughContext() {
        let ctx = AnalysisContext(files: [], events: [], timeline: [], registryValues: [],
                                  config: [setting(.high)])
        let f = MacConfigAnalyzer().analyze(context: ctx)
        #expect(f.count == 1)
    }
}
