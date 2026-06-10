//
//  AnnotationTests.swift
//  StrataTests
//
//  Covers roadmap #5 (super-timeline + tagging/notes): the stable timeline-
//  event identity bookmarks key off, the six new TimelineBuilder artifact
//  projections, the Annotation/CaseNotes models + CaseStore persistence, and
//  the analyst-narrative / bookmarked-items report + export surfaces.
//

import Testing
import Foundation
@testable import Strata

struct TimelineStableKeyTests {

    @Test func stableKeySurvivesRebuildButIDDoesNot() {
        let date = Date(timeIntervalSinceReferenceDate: 12345.5)
        let a = TimelineEvent(date: date, kind: .born, source: .filesystem,
                              fileID: 7, path: "/Windows/evil.exe", size: 9, isDeleted: false)
        let b = TimelineEvent(date: date, kind: .born, source: .filesystem,
                              fileID: 7, path: "/Windows/evil.exe", size: 9, isDeleted: false)
        #expect(a.id != b.id)                  // parse-time UUID: ephemeral
        #expect(a.stableKey == b.stableKey)    // content identity: stable
    }

    @Test func stableKeyDiscriminates() {
        let date = Date(timeIntervalSinceReferenceDate: 1000)
        let base = TimelineEvent(date: date, kind: .changed, source: .evtx,
                                 fileID: 0, path: "Security", size: 0,
                                 isDeleted: false, eventID: 4624)
        let otherEID = TimelineEvent(date: date, kind: .changed, source: .evtx,
                                     fileID: 0, path: "Security", size: 0,
                                     isDeleted: false, eventID: 4625)
        let otherDate = TimelineEvent(date: date + 1, kind: .changed, source: .evtx,
                                      fileID: 0, path: "Security", size: 0,
                                      isDeleted: false, eventID: 4624)
        let otherSource = TimelineEvent(date: date, kind: .changed, source: .usn,
                                        fileID: 0, path: "Security", size: 0,
                                        isDeleted: false, eventID: 4624)
        #expect(base.stableKey != otherEID.stableKey)
        #expect(base.stableKey != otherDate.stableKey)
        #expect(base.stableKey != otherSource.stableKey)
    }
}

struct TimelineArtifactProjectionTests {

    private static let when = Date(timeIntervalSinceReferenceDate: 700_000_000)

    @Test func registryDedupesValuesToKeyWrites() {
        // Three values in one key share the key's last-written time -> one
        // event. A same-label key from a DIFFERENT hive file (two users'
        // NTUSER) must stay distinct. A value without a timestamp is dropped.
        func value(_ name: String, file: String) -> RegistryValue {
            RegistryValue(hive: "NTUSER", path: "Software\\Run", name: name,
                          type: .sz, data: "x", lastWritten: Self.when, sourceFile: file)
        }
        let values = [
            value("a", file: "/Users/alice/NTUSER.DAT"),
            value("b", file: "/Users/alice/NTUSER.DAT"),
            value("c", file: "/Users/alice/NTUSER.DAT"),
            value("a", file: "/Users/bob/NTUSER.DAT"),
            RegistryValue(hive: "SYSTEM", path: "Select", name: "Current",
                          type: .dword, data: "1", lastWritten: nil, sourceFile: "/sys"),
        ]
        let events = TimelineBuilder.build(from: values)
        #expect(events.count == 2)
        #expect(events.allSatisfy { $0.source == .registry && $0.kind == .modified })
        #expect(events.allSatisfy { $0.path.contains("NTUSER\\Software\\Run") })
    }

    @Test func prefetchEmitsOneEventPerRecordedRun() {
        let entry = PrefetchEntry(executableName: "EVIL.EXE", runCount: 12,
                                  lastRunTimes: [Self.when, Self.when - 60, Self.when - 120],
                                  sourceFile: "/Windows/Prefetch/EVIL.EXE-1.pf")
        let events = TimelineBuilder.build(from: [entry])
        #expect(events.count == 3)
        #expect(events.allSatisfy { $0.source == .prefetch && $0.kind == .changed })
        #expect(events.allSatisfy { $0.path.contains("EVIL.EXE") && $0.path.contains("12 runs") })
        // Sorted ascending regardless of the entry's most-recent-first order.
        #expect(events.first?.date == Self.when - 120)
    }

    @Test func lnkEmitsTargetMACAndSkipsNils() {
        let entry = LnkEntry(sourceFile: "C:\\Users\\u\\Recent\\doc.lnk",
                             localPath: "C:\\Temp\\payload.exe",
                             targetCreated: Self.when, targetModified: Self.when + 5,
                             targetAccessed: nil)
        let events = TimelineBuilder.build(from: [entry])
        #expect(events.count == 2)
        #expect(Set(events.map(\.kind)) == [.born, .modified])
        #expect(events.allSatisfy { $0.source == .lnk })
        #expect(events.allSatisfy { $0.path.contains("C:\\Temp\\payload.exe") })
        #expect(events.allSatisfy { $0.path.contains("[lnk: doc]") })
    }

    @Test func jumpListUsesDestListAccessTime() {
        let dated = JumpListEntry(appID: "5f7b5f1e01b83767", application: "Remote Desktop",
                                  listType: .automatic, targetPath: "\\\\srv01\\share",
                                  lastAccessed: Self.when, sourceFile: "/x")
        let undated = JumpListEntry(appID: "abc", listType: .custom, sourceFile: "/y")
        let events = TimelineBuilder.build(from: [dated, undated])
        #expect(events.count == 1)
        #expect(events.first?.kind == .accessed)
        #expect(events.first?.source == .jumplist)
        #expect(events.first?.path.contains("Remote Desktop") == true)
    }

    @Test func shimcacheAndAmcacheProject() {
        let shim = ShimcacheEntry(path: "C:\\Tools\\psexec.exe", lastModified: Self.when,
                                  insertionOrder: 0, version: .windows10, sourceFile: "/sys")
        let shimEvents = TimelineBuilder.build(from: [shim])
        #expect(shimEvents.count == 1)
        #expect(shimEvents.first?.source == .shimcache)
        #expect(shimEvents.first?.kind == .modified)
        #expect(shimEvents.first?.path.contains("psexec.exe") == true)

        let amc = AmcacheEntry(name: "mimikatz.exe", fullPath: "C:\\Temp\\mimikatz.exe",
                               registeredAt: Self.when, source: .inventoryApplicationFile,
                               sourceFile: "/amcache")
        let amcEvents = TimelineBuilder.build(from: [amc])
        #expect(amcEvents.count == 1)
        #expect(amcEvents.first?.source == .amcache)
        #expect(amcEvents.first?.path.contains("C:\\Temp\\mimikatz.exe") == true)

        // No timestamp -> no row, never a 1970/2001 artifact.
        #expect(TimelineBuilder.build(from: [ShimcacheEntry(path: "x", lastModified: nil,
                                                            insertionOrder: 1, version: .unknown,
                                                            sourceFile: "/s")]).isEmpty)
    }
}

struct AnnotationModelTests {

    @Test func annotationRoundTrips() throws {
        let annotation = Annotation(author: "Jane", targetKind: .timelineEvent,
                                    targetKey: "EVTX|C|12345|4624|Security",
                                    evidenceID: UUID(), tag: .malicious,
                                    note: "Initial access logon",
                                    title: "Security", timestamp: Date(timeIntervalSinceReferenceDate: 5),
                                    sourceLabel: "Event Log")
        let back = try JSONDecoder().decode(Annotation.self, from: JSONEncoder().encode(annotation))
        #expect(back == annotation)
    }

    @Test func caseStoreRoundTripsAnnotationsAndNotes() throws {
        let fm = FileManager.default
        let bundle = fm.temporaryDirectory.appendingPathComponent("anno-\(UUID().uuidString).strata")
        try fm.createDirectory(at: bundle, withIntermediateDirectories: true)
        defer { try? fm.removeItem(at: bundle) }

        // Whole-second dates: the store encodes ISO-8601, which drops
        // sub-second precision, and this test compares whole values.
        let annotations = [
            Annotation(createdAt: Date(timeIntervalSinceReferenceDate: 100),
                       modifiedAt: Date(timeIntervalSinceReferenceDate: 200),
                       author: "Jane", targetKind: .finding, targetKey: UUID().uuidString,
                       tag: .followUp, note: "check this", title: "Suspicious run key",
                       timestamp: Date(timeIntervalSinceReferenceDate: 50),
                       sourceLabel: "Finding"),
        ]
        try CaseStore.writeAnnotations(annotations, in: bundle)
        let backAnnotations = try CaseStore.readAnnotations(in: bundle)
        #expect(backAnnotations == annotations)

        let notes = CaseNotes(text: "Day 1: triage started.", modifiedAt: Date(), author: "Jane")
        try CaseStore.writeNotes(notes, in: bundle)
        let backNotes = try CaseStore.readNotes(in: bundle)
        #expect(backNotes.text == notes.text)
        #expect(backNotes.author == "Jane")

        // A bundle without either file reads back as empty, not an error.
        let empty = fm.temporaryDirectory.appendingPathComponent("anno-empty-\(UUID().uuidString)")
        try fm.createDirectory(at: empty, withIntermediateDirectories: true)
        defer { try? fm.removeItem(at: empty) }
        #expect(try CaseStore.readAnnotations(in: empty).isEmpty)
        #expect(try CaseStore.readNotes(in: empty).isEmpty)
    }
}

struct AnnotationReportTests {

    private static func inputs(notes: String = "", annotations: [Annotation] = []) -> ReportInputs {
        let host = ReportInputs.Host(
            displayName: "HOST-1", kindLabel: "E01 image", sourcePath: "/e/h.E01",
            registryValues: [], findings: [], iocMatches: [], timeline: [],
            fileCount: 0, eventCount: 0, evidenceID: UUID())
        return ReportInputs(caseName: "Op Story", examiner: "Jane",
                            createdAt: Date(timeIntervalSinceReferenceDate: 0),
                            generatedAt: Date(timeIntervalSinceReferenceDate: 10),
                            hosts: [host], caseNotes: notes, annotations: annotations)
    }

    private static func bookmark(_ title: String, at t: TimeInterval?,
                                 tag: AnalystTag? = .suspicious, note: String = "") -> Annotation {
        Annotation(author: "Jane", targetKind: .timelineEvent, targetKey: "k-\(title)",
                   tag: tag, note: note, title: title,
                   timestamp: t.map { Date(timeIntervalSinceReferenceDate: $0) },
                   sourceLabel: "Event Log")
    }

    @Test func builderSortsBookmarksChronologicallyUndatedLast() {
        let model = ReportModelBuilder.build(from: Self.inputs(
            notes: "  The story.  ",
            annotations: [Self.bookmark("late", at: 300),
                          Self.bookmark("undated", at: nil),
                          Self.bookmark("early", at: 100)]))
        #expect(model.narrative == "The story.")
        #expect(model.bookmarks.map(\.title) == ["early", "late", "undated"])
    }

    @Test func renderersIncludeNarrativeAndBookmarks() {
        let model = ReportModelBuilder.build(from: Self.inputs(
            notes: "Attacker landed via <phish>.",
            annotations: [Self.bookmark("C:\\Temp\\evil.exe", at: 100,
                                        tag: .malicious, note: "dropper & loader")]))
        let md = MarkdownReportRenderer.render(model)
        #expect(md.contains("## Analyst narrative"))
        #expect(md.contains("Attacker landed"))
        #expect(md.contains("## Bookmarked items"))
        #expect(md.contains("Malicious"))
        let html = HTMLReportRenderer.render(model)
        #expect(html.contains("Analyst narrative"))
        // HTML-escaped, never raw markup.
        #expect(html.contains("&lt;phish&gt;"))
        #expect(!html.contains("<phish>"))
        #expect(html.contains("dropper &amp; loader"))
    }

    @Test func emptyNarrativeAndBookmarksOmitSections() {
        let model = ReportModelBuilder.build(from: Self.inputs())
        let md = MarkdownReportRenderer.render(model)
        #expect(!md.contains("Analyst narrative"))
        #expect(!md.contains("Bookmarked items"))
    }

    @Test func generatorEmitsAnnotationExports() {
        let evidenceID = UUID()
        let host = ReportInputs.Host(
            displayName: "HOST-1", kindLabel: "E01 image", sourcePath: "/e/h.E01",
            registryValues: [], findings: [], iocMatches: [], timeline: [],
            fileCount: 0, eventCount: 0, evidenceID: evidenceID)
        let inputs = ReportInputs(caseName: "Op Story", examiner: "Jane",
                                  createdAt: Date(timeIntervalSinceReferenceDate: 0),
                                  generatedAt: Date(timeIntervalSinceReferenceDate: 10),
                                  hosts: [host],
                                  annotations: [Annotation(author: "Jane", targetKind: .finding,
                                                           targetKey: UUID().uuidString,
                                                           evidenceID: evidenceID, tag: .benign,
                                                           note: "fp, signed updater",
                                                           title: "Run key", sourceLabel: "Finding")])
        let files = ExportGenerator.generate(
            inputs: inputs,
            selection: ExportSelection(annotationsCSV: true, annotationsJSON: true))
        let names = Set(files.map(\.filename))
        #expect(names.contains("Op Story-annotations.csv"))
        #expect(names.contains("Op Story-annotations.json"))

        let csv = files.first { $0.filename.hasSuffix(".csv") }
            .map { String(decoding: $0.data, as: UTF8.self) } ?? ""
        #expect(csv.contains("target_timestamp_iso,tag,target_kind,source,title,note,author"))
        #expect(csv.contains("Benign"))
        #expect(csv.contains("HOST-1"))   // evidenceID resolved to the host name
    }
}
