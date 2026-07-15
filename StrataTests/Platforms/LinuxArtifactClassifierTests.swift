//
//  LinuxArtifactClassifierTests.swift
//  StrataTests
//
//  Covers the pure file→Linux-artifact classifier extracted from parseLinux.
//  The parsers run over every case regardless of OS, so the classifier must be
//  path-anchored and slack-safe — a loose name match drags unrelated files (a
//  Windows `messagesxboxlogo.png`) into a Linux bucket and re-extracts them on
//  every open.
//

import Testing
import Foundation
@testable import Strata

struct LinuxArtifactClassifierTests {

    /// Build a plain (allocated, non-deleted, non-empty) file entry at a path.
    private func file(_ fullPath: String, size: Int64 = 128) -> FileEntry {
        let ns = fullPath as NSString
        var parent = ns.deletingLastPathComponent
        if !parent.hasSuffix("/") { parent += "/" }
        return FileEntry(id: 1, metaAddr: nil, name: ns.lastPathComponent,
                         parentPath: parent, size: size, isDirectory: false, isDeleted: false,
                         modified: nil, accessed: nil, changed: nil, created: nil)
    }

    /// The reported bug: a file whose name merely starts with "messages" but is
    /// NOT under /var/log/ (a Windows Store asset) must not be a syslog.
    @Test func nonLogFileNamedLikeMessagesIsNotSyslog() {
        #expect(LinuxArtifactClassifier.classify(
            file("/Program Files/WindowsApps/Microsoft.XboxApp/Assets/messagesxboxlogo.png")) == nil)
        #expect(LinuxArtifactClassifier.classify(file("/home/u/messages")) == nil)
        #expect(LinuxArtifactClassifier.classify(file("/opt/app/syslog.conf")) == nil)
    }

    /// TSK `<name>-slack` pseudo-entries are never classified — even for names
    /// that would otherwise match a rotation prefix.
    @Test func slackPseudoEntriesAreNeverClassified() {
        #expect(LinuxArtifactClassifier.classify(file("/var/log/messages.1-slack")) == nil)
        #expect(LinuxArtifactClassifier.classify(file("/var/log/syslog-slack")) == nil)
        #expect(LinuxArtifactClassifier.classify(file("/x/messagesxboxlogo.png-slack")) == nil)
    }

    /// Real syslog files + rotations still classify — but only under /var/log/.
    @Test func syslogAndRotationsClassifyUnderVarLog() {
        for path in ["/var/log/syslog", "/var/log/syslog.1",
                     "/var/log/messages", "/var/log/messages.1", "/var/log/messages-20240101",
                     "/var/log/kern.log", "/var/log/kern.log.1"] {
            #expect(LinuxArtifactClassifier.classify(file(path)) == .syslog, "expected \(path) → .syslog")
        }
    }

    /// Spot-check a spread of other kinds survived the extraction intact.
    @Test func otherArtifactKindsStillClassify() {
        #expect(LinuxArtifactClassifier.classify(file("/var/log/auth.log")) == .auth)
        #expect(LinuxArtifactClassifier.classify(file("/var/log/audit/audit.log")) == .audit)
        #expect(LinuxArtifactClassifier.classify(file("/var/log/journal/abc/system.journal")) == .journald)
        #expect(LinuxArtifactClassifier.classify(file("/etc/passwd")) == .sysinfo)
        #expect(LinuxArtifactClassifier.classify(file("/home/u/.ssh/authorized_keys")) == .sshAuthorized)
        #expect(LinuxArtifactClassifier.classify(file("/home/u/.bash_history")) == .shellHistory)
        #expect(LinuxArtifactClassifier.classify(file("/etc/ssh/sshd_config")) == .sshdConfig)
        #expect(LinuxArtifactClassifier.classify(file("/etc/sudoers")) == .sudoers)
    }

    /// Directories, deleted, and zero-length entries are skipped.
    @Test func directoriesDeletedAndEmptyAreSkipped() {
        let dir = FileEntry(id: 1, metaAddr: nil, name: "messages", parentPath: "/var/log/",
                            size: 128, isDirectory: true, isDeleted: false,
                            modified: nil, accessed: nil, changed: nil, created: nil)
        let empty = FileEntry(id: 1, metaAddr: nil, name: "messages", parentPath: "/var/log/",
                              size: 0, isDirectory: false, isDeleted: false,
                              modified: nil, accessed: nil, changed: nil, created: nil)
        let deleted = FileEntry(id: 1, metaAddr: nil, name: "messages", parentPath: "/var/log/",
                                size: 128, isDirectory: false, isDeleted: true,
                                modified: nil, accessed: nil, changed: nil, created: nil)
        #expect(LinuxArtifactClassifier.classify(dir) == nil)
        #expect(LinuxArtifactClassifier.classify(empty) == nil)
        #expect(LinuxArtifactClassifier.classify(deleted) == nil)
    }
}
