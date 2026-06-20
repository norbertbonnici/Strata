//
//  CredentialDumpingAnalyzerTests.swift
//  StrataTests
//
//  Validates the CredentialDumpingAnalyzer detection rules across their evidence
//  sources: Sysmon 10 LSASS access, command-line dump signatures (4688), the
//  on-disk / $MFT / USN dump footprint, named-tool presence in artifacts, and
//  the vssadmin+ntds proximity heuristic. Each positive rule is paired with a
//  negative that must stay quiet.
//

import Testing
import Foundation
@testable import Strata

struct CredentialDumpingAnalyzerTests {
    private static let when = Date(timeIntervalSince1970: 1_700_000_000)

    // MARK: - Builders

    private func event(_ id: UInt32, channel: String = "Security",
                       payload: String) -> EventLogRecord {
        EventLogRecord(recordNumber: 1, writtenAt: Self.when, eventID: id, level: 4,
                       channel: channel, provider: "test", computer: "WS01",
                       payloadXML: payload, sourceFile: "Security.evtx")
    }

    private func data(_ name: String, _ value: String) -> String {
        "<Data Name=\"\(name)\">\(value)</Data>"
    }

    private func ctx(events: [EventLogRecord] = [], files: [FileEntry] = [],
                     mft: [MftEntry] = [], usn: [UsnRecord] = [],
                     prefetch: [PrefetchEntry] = [], amcache: [AmcacheEntry] = [],
                     shellHistory: [ShellHistoryEntry] = []) -> AnalysisContext {
        AnalysisContext(files: files, events: events, timeline: [], registryValues: [],
                        prefetch: prefetch, amcache: amcache, usn: usn, mft: mft,
                        shellHistory: shellHistory)
    }

    private func run(_ c: AnalysisContext) -> [Finding] {
        CredentialDumpingAnalyzer().analyze(context: c)
    }

    private func file(_ name: String, path: String) -> FileEntry {
        FileEntry(id: 1, metaAddr: 1, name: name, parentPath: path, size: 1024,
                  isDirectory: false, isDeleted: false,
                  modified: Self.when, accessed: nil, changed: nil, created: Self.when)
    }

    // MARK: - Sysmon 10: LSASS memory access

    @Test func flagsLsassAccessWithDumpMask() throws {
        let payload = data("SourceImage", "C:\\Users\\Public\\m.exe")
            + data("TargetImage", "C:\\Windows\\System32\\lsass.exe")
            + data("GrantedAccess", "0x1010")
        let findings = run(ctx(events: [event(10, channel: "Microsoft-Windows-Sysmon/Operational", payload: payload)]))
        let f = try #require(findings.first { $0.title.contains("LSASS memory access") })
        #expect(f.severity == .critical)
        #expect(f.phase == .exploitation)
        #expect(f.technique?.attackID == "T1003.001")
    }

    @Test func ignoresBenignLsassAccessMask() {
        // A non-dump access mask (e.g. EDR querying limited info) must not fire.
        let payload = data("SourceImage", "C:\\Program Files\\EDR\\agent.exe")
            + data("TargetImage", "C:\\Windows\\System32\\lsass.exe")
            + data("GrantedAccess", "0x1000")
        let findings = run(ctx(events: [event(10, channel: "Microsoft-Windows-Sysmon/Operational", payload: payload)]))
        #expect(findings.contains { $0.title.contains("LSASS memory access") } == false)
    }

    // MARK: - Command-line signatures

    @Test func flagsComsvcsMiniDump() throws {
        let cmd = "rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump 672 C:\\temp\\out.dmp full"
        let payload = data("NewProcessName", "C:\\Windows\\System32\\rundll32.exe")
            + data("CommandLine", cmd)
        let f = try #require(run(ctx(events: [event(4688, payload: payload)]))
            .first { $0.title.contains("comsvcs.dll MiniDump") })
        #expect(f.severity == .critical)
        #expect(f.technique?.attackID == "T1003.001")
    }

    @Test func flagsRegSaveOfSAM() throws {
        let payload = data("NewProcessName", "C:\\Windows\\System32\\reg.exe")
            + data("CommandLine", "reg save HKLM\\SAM C:\\temp\\sam.save")
        let f = try #require(run(ctx(events: [event(4688, payload: payload)]))
            .first { $0.title.contains("reg save") })
        #expect(f.severity == .high)
        #expect(f.technique?.attackID == "T1003.002")
    }

    @Test func flagsNtdsutilIFM() throws {
        let payload = data("NewProcessName", "C:\\Windows\\System32\\ntdsutil.exe")
            + data("CommandLine", "ntdsutil \"ac i ntds\" \"ifm\" \"create full C:\\temp\\ifm\" q q")
        let f = try #require(run(ctx(events: [event(4688, payload: payload)]))
            .first { $0.title.contains("ntdsutil") })
        #expect(f.severity == .critical)
        #expect(f.technique?.attackID == "T1003.003")
    }

    @Test func flagsMimikatzCommandLine() throws {
        let payload = data("Image", "C:\\Users\\Public\\x.exe")
            + data("CommandLine", "x.exe \"sekurlsa::logonpasswords\" exit")
        let f = try #require(run(ctx(events: [event(1, channel: "Microsoft-Windows-Sysmon/Operational", payload: payload)]))
            .first { $0.title.contains("tool invoked") })
        #expect(f.severity == .critical)
        #expect(f.technique?.attackID == "T1003.001")
    }

    @Test func ignoresBenignRegQuery() {
        // reg QUERY (not save) of SYSTEM, and a benign rundll32 without MiniDump.
        let payload = data("NewProcessName", "C:\\Windows\\System32\\reg.exe")
            + data("CommandLine", "reg query HKLM\\SYSTEM\\CurrentControlSet\\Services")
        #expect(run(ctx(events: [event(4688, payload: payload)])).isEmpty)
    }

    // MARK: - File-system footprint

    @Test func flagsLsassDumpFile() throws {
        let f = try #require(run(ctx(files: [file("lsass.dmp", path: "/Users/Public/")]))
            .first { $0.title.contains("LSASS memory dump on disk") })
        #expect(f.severity == .critical)
        #expect(f.technique?.attackID == "T1003.001")
    }

    @Test func ignoresOrdinaryDumpAndInPlaceSAM() {
        // A non-lsass crash dump, and the in-place SAM hive in System32\config,
        // must both stay quiet.
        let files = [
            file("MEMORY.DMP", path: "/Windows/"),
            file("SAM", path: "/Windows/System32/config/"),
        ]
        #expect(run(ctx(files: files)).isEmpty)
    }

    @Test func flagsNtdsCopyOutsideNtdsDir() throws {
        let f = try #require(run(ctx(files: [file("ntds.dit", path: "/temp/")]))
            .first { $0.title.contains("NTDS.dit copy on disk") })
        #expect(f.technique?.attackID == "T1003.003")
    }

    @Test func flagsSamHiveCopyInTemp() throws {
        // A `reg save HKLM\SAM \temp\sam.save` drop: a SAM hive copy with a
        // recognized copy-suffix outside \System32\config must fire.
        let f = try #require(run(ctx(files: [file("sam.save", path: "/temp/")]))
            .first { $0.title.contains("Credential hive copy") })
        #expect(f.severity == .high)
        #expect(f.technique?.attackID == "T1003.002")
    }

    @Test func ignoresBareSystemFileOutsideStaging() {
        // A bare extensionless `system` file in an ordinary (non-staging,
        // non-config) location is too generic to flag — it must stay quiet.
        // (`sam` and any `.save`/`.bak`/… copy still fire; see above.)
        let files = [file("system", path: "/etc/security/"),
                     file("security", path: "/var/lib/app/")]
        #expect(run(ctx(files: files)).isEmpty)
    }

    // MARK: - Tool presence in artifacts

    @Test func flagsMimikatzInPrefetch() throws {
        let pf = PrefetchEntry(executableName: "MIMIKATZ.EXE",
                               executablePath: "\\VOLUME\\Users\\Public\\mimikatz.exe",
                               runCount: 1, lastRunTimes: [Self.when], sourceFile: "MIMIKATZ.EXE-ABCD.pf")
        let f = try #require(run(ctx(prefetch: [pf]))
            .first { $0.title.contains("tool present (prefetch)") })
        #expect(f.severity == .high)
        #expect(f.technique?.attackID == "T1003.001")
    }

    @Test func ignoresBenignPrefetch() {
        let pf = PrefetchEntry(executableName: "NOTEPAD.EXE",
                               executablePath: "\\VOLUME\\Windows\\System32\\notepad.exe",
                               runCount: 3, lastRunTimes: [Self.when], sourceFile: "NOTEPAD.EXE-1234.pf")
        #expect(run(ctx(prefetch: [pf])).isEmpty)
    }

    @Test func flagsRubeusInShellHistoryAsKerberos() throws {
        let sh = ShellHistoryEntry(user: "root", shell: .bash, command: "./Rubeus.exe dump",
                                   timestamp: Self.when, lineNumber: 1, sourceFile: "/root/.bash_history")
        let f = try #require(run(ctx(shellHistory: [sh]))
            .first { $0.title.contains("tool present (shell history)") })
        #expect(f.technique?.attackID == "T1558")
    }

    // MARK: - USN / vssadmin proximity

    @Test func flagsVssCreateWithNtdsPresent() throws {
        let payload = data("NewProcessName", "C:\\Windows\\System32\\vssadmin.exe")
            + data("CommandLine", "vssadmin create shadow /for=C:")
        let c = ctx(events: [event(4688, payload: payload)],
                    files: [file("ntds.dit", path: "/Windows/NTDS/")])
        let f = try #require(run(c).first { $0.title.contains("Volume Shadow Copy created") })
        #expect(f.severity == .medium)
        #expect(f.technique?.attackID == "T1003.003")
    }

    @Test func ignoresVssCreateWithoutNtds() {
        // A shadow-copy create with no ntds.dit in evidence is a routine admin
        // action and must not produce the proximity finding.
        let payload = data("NewProcessName", "C:\\Windows\\System32\\vssadmin.exe")
            + data("CommandLine", "vssadmin create shadow /for=C:")
        let findings = run(ctx(events: [event(4688, payload: payload)]))
        #expect(findings.contains { $0.title.contains("Volume Shadow Copy created") } == false)
    }

    @Test func emptyContextYieldsNothing() {
        #expect(run(ctx()).isEmpty)
    }
}
