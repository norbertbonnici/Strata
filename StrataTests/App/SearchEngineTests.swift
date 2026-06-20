//
//  SearchEngineTests.swift
//  StrataTests
//
//  Exercises the pure cross-artifact global-search engine (roadmap #6):
//  case-insensitive substring matching across files / events / registry /
//  timeline / findings, the exact > name > body ranking, the result cap, and
//  the short/empty-query guard. Fixtures span ≥3 collection kinds with both
//  positive and negative cases.
//

import Testing
import Foundation
@testable import Strata

struct SearchEngineTests {

    // MARK: - Fixtures

    private static let when = Date(timeIntervalSince1970: 1_700_000_000)

    private func file(_ name: String, _ parent: String, id: Int64 = 1) -> FileEntry {
        FileEntry(id: id, metaAddr: nil, name: name, parentPath: parent,
                  size: 1024, isDirectory: false, isDeleted: false,
                  modified: Self.when, accessed: nil, changed: nil, created: nil)
    }

    private func event(id: UInt32, channel: String, provider: String = "Provider",
                       payload: String = "") -> EventLogRecord {
        EventLogRecord(recordNumber: 1, writtenAt: Self.when, eventID: id, level: 4,
                       channel: channel, provider: provider, computer: "HOST01",
                       payloadXML: payload, sourceFile: "/Security.evtx")
    }

    private func reg(hive: String, path: String, name: String, data: String) -> RegistryValue {
        RegistryValue(hive: hive, path: path, name: name, type: .sz, data: data,
                      lastWritten: Self.when, sourceFile: "/SOFTWARE")
    }

    private func timeline(_ path: String) -> TimelineEvent {
        TimelineEvent(date: Self.when, kind: .modified, source: .filesystem,
                      fileID: 1, path: path, size: 0, isDeleted: false)
    }

    private func finding(_ title: String, detail: String,
                         attack: AttackTechnique? = nil) -> Finding {
        Finding(title: title, detail: detail, severity: .high,
                phase: .installation, technique: attack)
    }

    /// A small case that has a "mimikatz" needle reachable through five
    /// distinct surfaces (name, payload, registry data, timeline path, finding
    /// title) plus clear non-matches in each collection.
    private func sampleCase() -> (files: [FileEntry], events: [EventLogRecord],
                                  registry: [RegistryValue], timeline: [TimelineEvent],
                                  findings: [Finding]) {
        let files = [
            file("mimikatz.exe", "/Users/evil/Downloads/", id: 10),      // name match
            file("notes.txt", "/Users/evil/mimikatz-stuff/", id: 11),    // path-only match
            file("kernel32.dll", "/Windows/System32/", id: 12),          // no match
        ]
        let events = [
            event(id: 4688, channel: "Security",
                  payload: "<Data Name=\"CommandLine\">C:\\tmp\\mimikatz.exe sekurlsa</Data>"), // body match
            event(id: 7045, channel: "System",
                  payload: "<Data Name=\"ServiceName\">benign update</Data>"),                 // no match
        ]
        let registry = [
            reg(hive: "SOFTWARE", path: "\\Microsoft\\Windows\\CurrentVersion\\Run",
                name: "Updater", data: "C:\\ProgramData\\mimikatz.exe"),  // data (body) match
            reg(hive: "SYSTEM", path: "\\ControlSet001\\Services\\W32Time",
                name: "Start", data: "2"),                                 // no match
        ]
        let timeline = [
            timeline("/Users/evil/Downloads/mimikatz.exe"),   // leaf match (name-tier)
            timeline("/Windows/System32/svchost.exe"),        // no match
        ]
        let findings = [
            finding("Mimikatz execution detected",
                    detail: "Credential dumping via LSASS access.",
                    attack: AttackTechnique(attackID: "T1003.001", name: "LSASS Memory")),  // title
            finding("Scheduled task created",
                    detail: "A persistence task was registered.",
                    attack: AttackTechnique(attackID: "T1053.005", name: "Scheduled Task")), // no match
        ]
        return (files, events, registry, timeline, findings)
    }

    private func run(_ query: String, _ c: (files: [FileEntry], events: [EventLogRecord],
                                            registry: [RegistryValue], timeline: [TimelineEvent],
                                            findings: [Finding]),
                     limit: Int = 500) -> [SearchHit] {
        SearchEngine.search(query: query, files: c.files, events: c.events,
                            registry: c.registry, timeline: c.timeline,
                            findings: c.findings, limit: limit)
    }

    // MARK: - Cross-collection coverage

    /// The needle reaches all five collections; every kind should be represented,
    /// and the obvious non-matches must not appear.
    @Test func matchesAcrossAllCollections() {
        let hits = run("mimikatz", sampleCase())
        let kinds = Set(hits.map(\.kind))
        #expect(kinds == Set(SearchHit.Kind.allCases))   // file, event, registry, timeline, finding

        // Negative: nothing from the clearly-unrelated records leaks in.
        #expect(!hits.contains { $0.snippet.lowercased().contains("svchost") })
        #expect(!hits.contains { $0.title.lowercased().contains("scheduled task") })
        #expect(!hits.contains { $0.title == "kernel32.dll" })
    }

    /// Case-insensitive: an upper/mixed-case query matches lowercase content.
    @Test func caseInsensitive() {
        let lower = run("mimikatz", sampleCase())
        let mixed = run("MimiKatz", sampleCase())
        #expect(lower.count == mixed.count)
        #expect(!mixed.isEmpty)
    }

    // MARK: - Ranking

    /// A file whose *name* is the query outranks one matched only on its path,
    /// and an exact event-channel/finding-title match floats to the top band.
    @Test func rankingExactNameBeatsBody() {
        let hits = run("mimikatz", sampleCase())

        // The .exe (name match) must outrank the notes.txt (path-only/body match).
        let exeIdx = hits.firstIndex { $0.kind == .file && $0.title == "mimikatz.exe" }
        let notesIdx = hits.firstIndex { $0.kind == .file && $0.title == "notes.txt" }
        #expect(exeIdx != nil && notesIdx != nil)
        #expect(exeIdx! < notesIdx!)

        // Name/title-tier hits (file name, timeline leaf, finding title) must all
        // score above the pure body matches (event payload, registry data).
        let nameTierMax = hits.filter {
            ($0.kind == .file && $0.title == "mimikatz.exe") ||
            ($0.kind == .finding) ||
            ($0.kind == .timeline)
        }
        let bodyTier = hits.filter { $0.kind == .event || $0.kind == .registry }
        let minNameScore = nameTierMax.map(\.score).min() ?? 0
        let maxBodyScore = bodyTier.map(\.score).max() ?? 0
        #expect(minNameScore > maxBodyScore)
    }

    /// An exact identifier match scores higher than a mere substring of a longer
    /// identifier. "Security" == the channel exactly; "ecurit" is only a substring.
    @Test func exactBeatsSubstring() {
        let c = sampleCase()
        let exact = run("security", c).first { $0.kind == .event }
        let substr = run("ecurit", c).first { $0.kind == .event }
        #expect(exact != nil && substr != nil)
        #expect(exact!.score > substr!.score)
    }

    /// Event IDs are searchable as identifiers.
    @Test func matchesEventIDNumerically() {
        let hits = run("4688", sampleCase())
        #expect(hits.contains { $0.kind == .event })
        #expect(!hits.contains { $0.kind == .event && $0.title.contains("7045") })
    }

    /// ATT&CK technique IDs on a finding are searchable (body tier).
    @Test func matchesAttackTechnique() {
        let hits = run("T1003", sampleCase())
        let f = hits.first { $0.kind == .finding }
        #expect(f != nil)
        #expect(f!.title == "Mimikatz execution detected")
    }

    // MARK: - References (pivot-back identity)

    /// Each hit carries the correct back-reference identity for its source.
    @Test func referencesLocateSource() {
        let hits = run("mimikatz", sampleCase())

        let fileHit = hits.first { $0.kind == .file && $0.title == "mimikatz.exe" }
        if case .file(let id, let path)? = fileHit?.reference {
            #expect(id == 10)
            #expect(path == "/Users/evil/Downloads/mimikatz.exe")
        } else {
            Issue.record("file hit missing .file reference")
        }

        let tlHit = hits.first { $0.kind == .timeline }
        if case .timeline(let key)? = tlHit?.reference {
            #expect(key.contains("/Users/evil/Downloads/mimikatz.exe"))
        } else {
            Issue.record("timeline hit missing .timeline reference")
        }
    }

    // MARK: - Guards & cap

    /// Empty, whitespace, and sub-minimum queries return nothing.
    @Test func emptyAndShortQueriesReturnEmpty() {
        let c = sampleCase()
        #expect(run("", c).isEmpty)
        #expect(run("   ", c).isEmpty)
        #expect(run("m", c).isEmpty)                 // 1 char < minimumQueryLength
        #expect(SearchEngine.minimumQueryLength == 2)
    }

    /// A query that hits nothing returns an empty result, not a crash.
    @Test func noMatchReturnsEmpty() {
        #expect(run("zzz-not-present-anywhere", sampleCase()).isEmpty)
    }

    /// The result count is capped at `limit`, and the cap keeps the top scorers.
    @Test func capLimitsResultsAndKeepsBest() {
        // 200 files all named to match; the cap should trim to `limit`.
        var files: [FileEntry] = []
        for i in 0..<200 {
            files.append(file("payload\(i).exe", "/staging/", id: Int64(1000 + i)))
        }
        // One high-signal finding that must survive the cut.
        let findings = [finding("payload dropper", detail: "drops payload to disk")]

        let hits = SearchEngine.search(query: "payload", files: files,
                                       findings: findings, limit: 10)
        #expect(hits.count == 10)
        // The finding (title-tier + kind bias) outranks file name matches, so it
        // survives truncation.
        #expect(hits.contains { $0.kind == .finding })
        // Sorted descending by score.
        let scores = hits.map(\.score)
        #expect(scores == scores.sorted(by: >))
    }

    /// Results are deterministically ordered (stable tie-break) so paging is stable.
    @Test func orderingIsDeterministic() {
        let c = sampleCase()
        let a = run("mimikatz", c)
        let b = run("mimikatz", c)
        // Identity (UUID) differs per run, but the visible ordering is stable.
        #expect(a.map { [$0.kind.rawValue, $0.title, $0.snippet] }
                == b.map { [$0.kind.rawValue, $0.title, $0.snippet] })
    }
}
