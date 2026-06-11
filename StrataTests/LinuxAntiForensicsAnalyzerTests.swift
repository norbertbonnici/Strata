//
//  LinuxAntiForensicsAnalyzerTests.swift
//  StrataTests
//
//  Validates the Linux anti-forensics / indicator-removal detections
//  (T1070.002 log clearing, T1070.003 history clearing, T1070.006 timestomp,
//  T1562 audit/logging tampering) across shell history, audit EXECVE, syslog,
//  and journald — and confirms each rule stays quiet on benign look-alikes.
//

import Testing
import Foundation
@testable import Strata

struct LinuxAntiForensicsAnalyzerTests {
    private static let when = Date(timeIntervalSince1970: 1_700_000_000)

    // MARK: - Builders

    private func history(_ command: String, user: String = "root",
                         shell: ShellHistoryEntry.Shell = .bash,
                         line: Int = 1) -> ShellHistoryEntry {
        ShellHistoryEntry(user: user, shell: shell, command: command,
                          timestamp: Self.when, lineNumber: line,
                          sourceFile: "/home/\(user)/.bash_history")
    }

    private func audit(_ commandLine: String) -> AuditEvent {
        AuditEvent(timestamp: Self.when, serial: 1, recordType: "EXECVE",
                   syscall: "execve", success: true, exit: 0,
                   commandLine: commandLine, auid: 1000, uid: 0,
                   sourceFile: "/var/log/audit/audit.log")
    }

    private func ctx(history: [ShellHistoryEntry] = [], audit: [AuditEvent] = [],
                     syslog: [SyslogEntry] = [], journald: [JournaldEntry] = []) -> AnalysisContext {
        AnalysisContext(files: [], events: [], timeline: [], registryValues: [],
                        shellHistory: history, journald: journald, audit: audit, syslog: syslog)
    }

    private func run(_ c: AnalysisContext) -> [Finding] {
        LinuxAntiForensicsAnalyzer().analyze(context: c)
    }

    // MARK: - History clearing (T1070.003)
    // Positive: a signal ShellHistoryAnalyzer's tamper rule does NOT carry.

    @Test func flagsHistoryDisableNotCoveredElsewhere() throws {
        let findings = run(ctx(history: [history("export HISTFILE=/dev/null")]))
        let f = try #require(findings.first { $0.technique?.attackID == "T1070.003" })
        #expect(f.severity == .medium)            // disabling, not wiping
        #expect(f.phase == .exploitation)
    }

    @Test func ignoresBenignHistoryReadback() {
        // Listing history (no clear/disable verb) must not fire.
        let findings = run(ctx(history: [history("history | grep ssh")]))
        #expect(findings.isEmpty)
    }

    @Test func flagsZshHistoryRemoval() throws {
        let findings = run(ctx(history: [history("rm ~/.zsh_history", shell: .zsh)]))
        let f = try #require(findings.first { $0.title.contains("history file removed") })
        #expect(f.severity == .high)
        #expect(f.technique?.attackID == "T1070.003")
    }

    @Test func doesNotDoubleReportBashHistoryRemoval() {
        // `rm ~/.bash_history` is owned by ShellHistoryAnalyzer's tamper rule.
        // This analyzer must stay silent on it so the two don't both fire.
        let findings = run(ctx(history: [history("rm ~/.bash_history")]))
        #expect(findings.contains { $0.title.contains("history file removed") } == false)
    }

    // MARK: - Log clearing (T1070.002)

    @Test func flagsAuthLogTruncation() throws {
        let findings = run(ctx(history: [history("echo -n > /var/log/auth.log")]))
        let f = try #require(findings.first { $0.title.contains("/var/log/auth.log") })
        #expect(f.severity == .high)
        #expect(f.technique?.attackID == "T1070.002")
    }

    @Test func flagsJournalVacuum() throws {
        let findings = run(ctx(history: [history("journalctl --vacuum-time=1s")]))
        let f = try #require(findings.first { $0.title.contains("journal cleared") })
        #expect(f.severity == .high)
        #expect(f.technique?.attackID == "T1070.002")
    }

    @Test func ignoresLogRead() {
        // Reading a log (no destructive verb on the path) is everyday work.
        let findings = run(ctx(history: [history("tail -f /var/log/syslog")]))
        #expect(findings.isEmpty)
    }

    @Test func ignoresUnrelatedRedirect() {
        // Writing to a non-log file must not be mistaken for a log wipe.
        let findings = run(ctx(history: [history("echo done > /tmp/build.txt")]))
        #expect(findings.isEmpty)
    }

    @Test func ignoresRemoveOfOtherPathWhileLogOnlyRead() {
        // The `rm` targets /tmp; the log is only `cat`-read afterwards. The
        // verb-precedes-target gate must keep this quiet (no log was destroyed).
        let findings = run(ctx(history: [history("rm /tmp/x && cat /var/log/auth.log")]))
        #expect(findings.contains { $0.technique?.attackID == "T1070.002" } == false)
    }

    // MARK: - Audit / logging tampering (T1562)

    @Test func flagsAuditDaemonStop() throws {
        let findings = run(ctx(history: [history("systemctl stop auditd")]))
        let f = try #require(findings.first { $0.title.contains("Audit daemon stopped") })
        #expect(f.severity == .medium)
        #expect(f.technique?.attackID == "T1562.001")
    }

    @Test func ignoresAuditDaemonStart() {
        // Starting/restarting the daemon is the opposite of tampering.
        let findings = run(ctx(history: [history("systemctl start auditd")]))
        #expect(findings.isEmpty)
    }

    // MARK: - Timestomp (T1070.006)

    @Test func flagsTimestompInStagingPath() throws {
        let findings = run(ctx(history: [history("touch -t 202001010000 /tmp/payload")]))
        let f = try #require(findings.first { $0.technique?.attackID == "T1070.006" })
        #expect(f.severity == .high)              // staging path escalates
    }

    @Test func ignoresPlainTouch() {
        // `touch newfile` with no timestamp-override flag stamps "now" — benign.
        let findings = run(ctx(history: [history("touch /tmp/lockfile")]))
        #expect(findings.contains { $0.technique?.attackID == "T1070.006" } == false)
    }

    // MARK: - Cross-source: audit EXECVE catches the wipe history missed.

    @Test func flagsLogClearFromAuditExecve() throws {
        let findings = run(ctx(audit: [audit("rm -f /var/log/wtmp /var/log/btmp")]))
        let f = try #require(findings.first { $0.technique?.attackID == "T1070.002" })
        #expect(f.severity == .high)
        #expect(f.evidencePaths.contains("/var/log/audit/audit.log"))
    }

    @Test func flagsDaemonStopFromJournald() throws {
        let entry = JournaldEntry(timestamp: Self.when,
                                  message: "service rsyslog stop invoked by operator",
                                  identifier: "sudo", sourceFile: "system.journal")
        let findings = run(ctx(journald: [entry]))
        let f = try #require(findings.first { $0.title.contains("logging daemon stopped") })
        #expect(f.technique?.attackID == "T1562.006")
    }

    // MARK: - Dedupe + empty

    @Test func dedupesRepeatedHistoryCommand() {
        let recs = (1...5).map { history("set +o history", line: $0) }
        let findings = run(ctx(history: recs))
        #expect(findings.filter { $0.title.contains("history logging disabled") }.count == 1)
    }

    @Test func emptyContextYieldsNothing() {
        #expect(run(ctx()).isEmpty)
    }
}
