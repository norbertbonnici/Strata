//
//  ImpactDestructionAnalyzerTests.swift
//  StrataTests
//
//  Validates the impact / destruction detections: Inhibit System Recovery
//  (T1490), data-destruction / disk-wipe commands (T1485 / T1561), and the
//  ransomware mass-encryption burst + ransom-note drop (T1486). Each family has
//  one positive case that must fire and one near-miss that must NOT.
//

import Testing
import Foundation
@testable import Strata

struct ImpactDestructionAnalyzerTests {
    private static let when = Date(timeIntervalSince1970: 1_700_000_000)

    // MARK: - Builders

    private func proc4688(_ commandLine: String, image: String = "C:\\Windows\\System32\\cmd.exe") -> EventLogRecord {
        EventLogRecord(
            recordNumber: 1, writtenAt: Self.when, eventID: 4688, level: 4,
            channel: "Security", provider: "Microsoft-Windows-Security-Auditing",
            computer: "WIN-VICTIM",
            payloadXML: "<Data Name=\"NewProcessName\">\(image)</Data>"
                + "<Data Name=\"CommandLine\">\(commandLine)</Data>",
            sourceFile: "C:/Windows/System32/winevt/Logs/Security.evtx")
    }

    private func shell(_ command: String) -> ShellHistoryEntry {
        ShellHistoryEntry(user: "root", shell: .bash, command: command,
                          timestamp: Self.when, lineNumber: 1,
                          sourceFile: "/root/.bash_history")
    }

    private func file(_ name: String, parent: String = "/Users/victim/Documents") -> FileEntry {
        FileEntry(id: Int64(abs(name.hashValue % 1_000_000)), metaAddr: nil, name: name,
                  parentPath: parent, size: 1024, isDirectory: false, isDeleted: false,
                  modified: Self.when, accessed: Self.when, changed: Self.when, created: Self.when)
    }

    private func ctx(events: [EventLogRecord] = [], shell: [ShellHistoryEntry] = [],
                     files: [FileEntry] = [],
                     entropy: [String: EncryptionEntropyStat] = [:]) -> AnalysisContext {
        AnalysisContext(files: files, events: events, timeline: [], registryValues: [],
                        shellHistory: shell, encryptionEntropy: entropy)
    }

    private func entropyStat(_ mean: Double, files: Int = 6, high: Int? = nil) -> EncryptionEntropyStat {
        EncryptionEntropyStat(sampledFiles: files,
                              highEntropyFiles: high ?? (mean >= EncryptionEntropyStat.encryptedThreshold ? files : 0),
                              meanEntropy: mean, maxEntropy: mean)
    }

    // MARK: - Inhibit System Recovery (T1490)

    @Test func flagsVssadminDeleteShadows() throws {
        let event = proc4688("vssadmin.exe delete shadows /all /quiet",
                             image: "C:\\Windows\\System32\\vssadmin.exe")
        let findings = ImpactDestructionAnalyzer().analyze(context: ctx(events: [event]))
        let f = try #require(findings.first { $0.title.contains("Inhibit System Recovery") })
        #expect(f.severity == .critical)
        #expect(f.phase == .actionsOnObjectives)
        #expect(f.technique?.attackID == "T1490")
    }

    @Test func ignoresVssadminListShadows() {
        // Read-only enumeration an admin legitimately runs - must NOT fire.
        let event = proc4688("vssadmin.exe list shadows",
                             image: "C:\\Windows\\System32\\vssadmin.exe")
        let findings = ImpactDestructionAnalyzer().analyze(context: ctx(events: [event]))
        #expect(findings.isEmpty)
    }

    @Test func flagsBcdeditDisableRecoveryFromShell() throws {
        let findings = ImpactDestructionAnalyzer()
            .analyze(context: ctx(shell: [shell("bcdedit /set {default} recoveryenabled no")]))
        let f = try #require(findings.first { $0.title.contains("Inhibit System Recovery") })
        #expect(f.technique?.attackID == "T1490")
    }

    // MARK: - Data destruction / disk wipe (T1485 / T1561)

    @Test func flagsDdToBlockDevice() throws {
        let findings = ImpactDestructionAnalyzer()
            .analyze(context: ctx(shell: [shell("dd if=/dev/zero of=/dev/sda bs=1M")]))
        let f = try #require(findings.first { $0.title.contains("Data destruction / disk wipe") })
        #expect(f.severity == .high)
        #expect(f.technique?.attackID == "T1561.002")
    }

    @Test func ignoresDdToRegularFile() {
        // A backup image to a file - not a device wipe.
        let findings = ImpactDestructionAnalyzer()
            .analyze(context: ctx(shell: [shell("dd if=/dev/sda1 of=/mnt/backup/disk.img bs=4M")]))
        #expect(findings.isEmpty)
    }

    @Test func flagsCipherWipe() throws {
        let event = proc4688("cipher.exe /w:C:\\",
                             image: "C:\\Windows\\System32\\cipher.exe")
        let findings = ImpactDestructionAnalyzer().analyze(context: ctx(events: [event]))
        let f = try #require(findings.first { $0.title.contains("Data destruction") })
        #expect(f.technique?.attackID == "T1485")
    }

    // MARK: - Ransomware mass-encryption (T1486)

    @Test func flagsMassEncryptionBurst() throws {
        // 40 distinct files all renamed to the known-ransom '.locked' extension.
        let files = (0..<40).map { file("report\($0).docx.locked") }
        let findings = ImpactDestructionAnalyzer().analyze(context: ctx(files: files))
        let f = try #require(findings.first { $0.title.contains("Possible mass file encryption") })
        #expect(f.severity == .critical)
        #expect(f.technique?.attackID == "T1486")
    }

    @Test func ignoresBulkArchiveFolder() {
        // 40 .zip files - a normal download/archive folder, not encryption.
        let files = (0..<40).map { file("dataset\($0).zip") }
        let findings = ImpactDestructionAnalyzer().analyze(context: ctx(files: files))
        #expect(findings.contains { $0.title.contains("mass file encryption") } == false)
    }

    @Test func ignoresBulkDatabasePages() {
        // 60 InnoDB tablespace files on a DB server - a benign high-cardinality
        // family that the hardened allow-list must cover (no critical finding).
        let files = (0..<60).map { file("table\($0).ibd", parent: "/var/lib/mysql/app") }
        let findings = ImpactDestructionAnalyzer().analyze(context: ctx(files: files))
        #expect(findings.contains { $0.title.contains("mass file encryption") } == false)
    }

    @Test func ignoresBulkGitPackObjects() {
        // 40 git pack files - .pack is on the dev/build allow-list.
        let files = (0..<40).map { file("pack-\($0).pack", parent: "/src/.git/objects/pack") }
        let findings = ImpactDestructionAnalyzer().analyze(context: ctx(files: files))
        #expect(findings.contains { $0.title.contains("mass file encryption") } == false)
    }

    @Test func quietBelowBurstThreshold() {
        // Only 10 .locked files - below the 25 threshold.
        let files = (0..<10).map { file("f\($0).locked") }
        let findings = ImpactDestructionAnalyzer().analyze(context: ctx(files: files))
        #expect(findings.contains { $0.title.contains("mass file encryption") } == false)
    }

    // MARK: - Ransomware entropy verification (T1486)

    @Test func entropyHighCorroboratesAndKeepsCritical() throws {
        // High-entropy sampled content corroborates that the '.locked' batch was
        // encrypted - stays critical, with a "consistent with encryption" note.
        let files = (0..<40).map { file("report\($0).docx.locked") }
        let findings = ImpactDestructionAnalyzer()
            .analyze(context: ctx(files: files, entropy: ["locked": entropyStat(7.97)]))
        let f = try #require(findings.first { $0.title.contains("Possible mass file encryption") })
        #expect(f.severity == .critical)
        #expect(f.detail.contains("consistent with encryption"))
    }

    @Test func lowEntropyDoesNotRefuteNovelBurst() throws {
        // Low head/window entropy can NEITHER confirm nor refute - partial /
        // append encryptors leave plaintext - so a novel-extension burst must
        // stay critical, NOT be demoted to a "false positive".
        let files = (0..<40).map { file("data\($0).xyz") }
        let findings = ImpactDestructionAnalyzer()
            .analyze(context: ctx(files: files, entropy: ["xyz": entropyStat(4.2)]))
        let f = try #require(findings.first { $0.technique?.attackID == "T1486" })
        #expect(f.severity == .critical)
        #expect(f.title.contains("Possible mass file encryption"))
        #expect(f.detail.contains("neither confirms nor refutes"))
    }

    @Test func lowEntropyKeepsKnownRansomCritical() throws {
        // '.locked' but low entropy: still critical (could be partial encryption
        // or a renamed/destroyed batch - either way a known ransom marker burst).
        let files = (0..<40).map { file("f\($0).locked") }
        let findings = ImpactDestructionAnalyzer()
            .analyze(context: ctx(files: files, entropy: ["locked": entropyStat(3.5)]))
        let f = try #require(findings.first { $0.technique?.attackID == "T1486" })
        #expect(f.severity == .critical)
    }

    @Test func noEntropyVerdictStaysCriticalUnverified() throws {
        // No bytes sampled (content unavailable) → preserve the metadata-only
        // critical, but mark it unverified rather than silently claiming proof.
        let files = (0..<40).map { file("report\($0).docx.locked") }
        let findings = ImpactDestructionAnalyzer().analyze(context: ctx(files: files))
        let f = try #require(findings.first { $0.title.contains("Possible mass file encryption") })
        #expect(f.severity == .critical)
        #expect(f.detail.contains("not verified"))
    }

    @Test func flagsRansomNote() throws {
        let findings = ImpactDestructionAnalyzer()
            .analyze(context: ctx(files: [file("HOW_TO_DECRYPT.txt")]))
        let f = try #require(findings.first { $0.title.contains("Ransom note") })
        #expect(f.severity == .high)
        #expect(f.technique?.attackID == "T1486")
    }

    @Test func ignoresPlainReadme() {
        // A bare project README has no decrypt/recover intent - must NOT fire.
        let findings = ImpactDestructionAnalyzer()
            .analyze(context: ctx(files: [file("README.md", parent: "/src/project")]))
        #expect(findings.contains { $0.title.contains("Ransom note") } == false)
    }

    @Test func ignoresLibraryReadmeSubstring() {
        // A library file containing "readme" as a substring (lib_readme.txt) must
        // NOT be mistaken for the STOP/Djvu "_readme.txt" note - it has no intent
        // verb and the bare "_readme" substring marker was removed.
        let findings = ImpactDestructionAnalyzer()
            .analyze(context: ctx(files: [file("lib_readme.txt", parent: "/usr/share/doc/foo")]))
        #expect(findings.contains { $0.title.contains("Ransom note") } == false)
    }

    @Test func emptyYieldsNothing() {
        #expect(ImpactDestructionAnalyzer().analyze(context: ctx()).isEmpty)
    }
}
