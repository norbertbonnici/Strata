//
//  StrataReportTests.swift
//  StrataTests
//
//  Covers the StrataReport generators: CSV escaping, JSON round-trip, the
//  report-model builder's grouping/rollups, Markdown content, and HTML escaping.
//

import Testing
import Foundation
@testable import Strata

struct StrataReportTests {

    // MARK: - Fixtures

    private static let epoch = Date(timeIntervalSinceReferenceDate: 0)  // 2001-01-01T00:00:00Z

    /// A host with two findings (different phases + severities), one IOC match,
    /// two timeline events, and the registry values needed to derive a profile.
    private static func sampleHost(name: String = "EVID-1") -> ReportInputs.Host {
        let findings = [
            Finding(title: "Office spawned PowerShell",
                    detail: "winword.exe -> powershell.exe -enc …",
                    severity: .high, phase: .exploitation,
                    technique: AttackTechnique(attackID: "T1059.001",
                                               name: "PowerShell"),
                    timestamp: epoch.addingTimeInterval(120),
                    evidencePaths: ["/Users/admin/doc.docm"]),
            Finding(title: "Run key persistence",
                    detail: "HKLM\\…\\Run added Updater",
                    severity: .critical, phase: .installation,
                    technique: AttackTechnique(attackID: "T1547.001",
                                               name: "Registry Run Keys"),
                    timestamp: epoch.addingTimeInterval(300),
                    evidencePaths: []),
            // No-timestamp finding: must be excluded from the timeline excerpt.
            Finding(title: "Suspicious service", detail: "n/a",
                    severity: .medium, phase: .installation,
                    timestamp: nil)
        ]
        let matches = [
            IOCMatch(iocValue: "10.0.0.9", iocKind: .ip,
                     location: .event(eventID: 4624, recordNumber: 5,
                                      channel: "Security", sourceFile: "Security.evtx"),
                     context: "logon from 10.0.0.9",
                     timestamp: epoch.addingTimeInterval(60))
        ]
        let timeline = [
            TimelineEvent(date: epoch, kind: .born, source: .filesystem,
                          fileID: 1, path: "/Windows/System32/evil.exe",
                          size: 2048, isDeleted: false),
            TimelineEvent(date: epoch.addingTimeInterval(60), kind: .changed,
                          source: .evtx, fileID: 0, path: "Logon",
                          size: 0, isDeleted: false, eventID: 4624)
        ]
        let registry = [
            RegistryValue(hive: "SYSTEM",
                          path: "ControlSet001\\Control\\ComputerName\\ComputerName",
                          name: "ComputerName", type: .sz, data: "WIN-TEST",
                          sourceFile: "SYSTEM"),
            RegistryValue(hive: "SOFTWARE",
                          path: "Microsoft\\Windows NT\\CurrentVersion",
                          name: "ProductName", type: .sz, data: "Windows 10 Pro",
                          sourceFile: "SOFTWARE")
        ]
        return ReportInputs.Host(displayName: name, kindLabel: "E01 image",
                                 sourcePath: "/cases/disk.E01",
                                 registryValues: registry, findings: findings,
                                 iocMatches: matches, timeline: timeline,
                                 fileCount: 42, eventCount: 7)
    }

    private static func sampleInputs() -> ReportInputs {
        ReportInputs(caseName: "Operation Test", examiner: "J. Doe",
                     createdAt: epoch, generatedAt: epoch.addingTimeInterval(3600),
                     hosts: [sampleHost()])
    }

    // MARK: - CSV escaping

    @Test func csvEscapesSpecialCharacters() {
        #expect(CSVExporter.escape("plain") == "plain")
        #expect(CSVExporter.escape("a,b") == "\"a,b\"")
        #expect(CSVExporter.escape("say \"hi\"") == "\"say \"\"hi\"\"\"")
        #expect(CSVExporter.escape("line1\nline2") == "\"line1\nline2\"")
    }

    @Test func findingsCSVHasHeaderRowsAndHostColumn() {
        let rows = ExportRowBuilder.findingRows(from: [Self.sampleHost(name: "HOST-A")])
        let csv = CSVExporter.findings(rows)
        let lines = csv.split(separator: "\r\n", omittingEmptySubsequences: true)
        // header + 3 findings
        #expect(lines.count == 4)
        #expect(lines.first == "timestamp_iso,severity,phase,attack_id,attack_name,title,detail,evidence_paths,host")
        // Every data row is tagged with the host.
        #expect(lines.dropFirst().allSatisfy { $0.hasSuffix(",HOST-A") })
    }

    @Test func timelineCSVQuotesPathsAndCarriesHost() {
        let host = ReportInputs.Host(
            displayName: "H", kindLabel: "k", sourcePath: "/p",
            registryValues: [], findings: [], iocMatches: [],
            timeline: [TimelineEvent(date: Self.epoch, kind: .modified,
                                     source: .filesystem, fileID: 1,
                                     path: "/a,b/c.txt", size: 1, isDeleted: true)],
            fileCount: 0, eventCount: 0)
        let csv = CSVExporter.timeline(ExportRowBuilder.timelineRows(from: [host]))
        #expect(csv.contains("\"/a,b/c.txt\""))   // comma in path -> quoted
        #expect(csv.contains(",true,H"))           // deleted flag + host column
    }

    // MARK: - JSON

    @Test func jsonRoundTripsAndUsesISO8601() throws {
        let rows = ExportRowBuilder.timelineRows(from: [Self.sampleHost()])
        let data = try JSONExporter.encode(rows)
        let json = String(decoding: data, as: UTF8.self)
        #expect(json.contains("2001-01-01T00:00:00Z"))  // ISO-8601 UTC

        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        let decoded = try decoder.decode([TimelineExportRow].self, from: data)
        #expect(decoded.count == rows.count)
        #expect(decoded.first?.host == "EVID-1")
    }

    @Test func iocLocationFlattensByType() {
        let parts = ExportRowBuilder.locationParts(
            .registry(hive: "SOFTWARE", path: "Run", name: "Updater"))
        #expect(parts.type == "registry")
        #expect(parts.detail == "SOFTWARE\\Run\\Updater")
    }

    // MARK: - Report-model builder

    @Test func builderGroupsFindingsByPhaseInOrder() {
        let model = ReportModelBuilder.build(from: Self.sampleInputs())
        let host = try! #require(model.hostSections.first)

        // Two phases have findings (exploitation, installation); ordered by phase.
        let phases = host.phaseGroups.map(\.phase)
        #expect(phases == [.exploitation, .installation])

        // Installation group has 2 findings, severity-sorted (critical before medium).
        let installation = host.phaseGroups.first { $0.phase == .installation }!
        #expect(installation.findings.map(\.severity) == [.critical, .medium])
    }

    @Test func builderComputesSeverityRollupAndProfile() {
        let model = ReportModelBuilder.build(from: Self.sampleInputs())
        let host = model.hostSections.first!

        // Case severity rollup is high → low and drops zero buckets.
        let pairs = model.caseSeverityCounts.map { ($0.severity, $0.count) }
        #expect(pairs.first?.0 == .critical)
        #expect(model.totalFindings == 3)
        #expect(model.totalIOCMatches == 1)

        // Host profile surfaced from the registry input.
        #expect(host.profile.hostname == "WIN-TEST")
        #expect(host.profile.osProductName == "Windows 10 Pro")

        // Timeline excerpt = only findings carrying a timestamp (2 of 3).
        #expect(host.timelineExcerpt.count == 2)
    }

    // MARK: - Report severity filter

    @Test func reportSeverityFilterLimitsFindingsButNotDataExport() {
        let inputs = Self.sampleInputs()
        let model = ReportModelBuilder.build(from: inputs, severities: [.critical])
        let host = model.hostSections.first!
        #expect(host.findingCount == 1)            // only the critical finding
        #expect(model.totalFindings == 1)
        #expect(host.phaseGroups.allSatisfy { group in
            group.findings.allSatisfy { $0.severity == .critical }
        })
        #expect(host.timelineExcerpt.allSatisfy { $0.severity == .critical })
        #expect(model.severityFilterNote == "Critical")

        // The raw findings export is NOT filtered - all 3 findings remain.
        #expect(ExportRowBuilder.findingRows(from: inputs.hosts).count == 3)
    }

    @Test func noSeverityFilterNoteWhenAllIncluded() {
        let model = ReportModelBuilder.build(from: Self.sampleInputs())
        #expect(model.severityFilterNote == nil)
    }

    @Test func generatorAppliesReportSeverityFilter() {
        var selection = ExportSelection(reportMarkdown: true)
        selection.reportSeverities = [.high, .critical]
        let files = ExportGenerator.generate(inputs: Self.sampleInputs(), selection: selection)
        let report = try! #require(files.first { $0.filename.hasSuffix("-report.md") })
        let text = String(decoding: report.data, as: UTF8.self)
        #expect(text.contains("Findings limited to severities: Critical, High"))
        #expect(!text.contains("Suspicious service"))   // the medium finding is excluded
    }

    // MARK: - Markdown

    @Test func markdownContainsKeySections() {
        let model = ReportModelBuilder.build(from: Self.sampleInputs())
        let md = MarkdownReportRenderer.render(model)
        #expect(md.contains("# Strata Examiner Report — Operation Test"))
        #expect(md.contains("Host: WIN-TEST"))
        #expect(md.contains("Office spawned PowerShell"))
        #expect(md.contains("#### Installation"))      // kill-chain phase heading
        #expect(md.contains("`T1547.001`"))            // ATT&CK tag
    }

    // MARK: - HTML safety

    @Test func htmlEscapesInjectedMarkup() {
        let host = ReportInputs.Host(
            displayName: "H", kindLabel: "k", sourcePath: "/p",
            registryValues: [],
            findings: [Finding(title: "XSS <b>", detail: "<script>alert('x')</script>",
                               severity: .low, phase: .delivery)],
            iocMatches: [], timeline: [], fileCount: 0, eventCount: 0)
        let model = ReportModelBuilder.build(from:
            ReportInputs(caseName: "C & <co>", examiner: "", createdAt: Self.epoch,
                         generatedAt: Self.epoch, hosts: [host]))
        let html = HTMLReportRenderer.render(model)
        #expect(html.contains("&lt;script&gt;"))
        #expect(!html.contains("<script>alert"))       // never raw
        #expect(html.contains("C &amp; &lt;co&gt;"))   // case name escaped in <title>/header
    }

    @Test func sanitizeMakesCaseNameFilenameSafe() {
        #expect(CaseExportWriter.sanitize("a/b:c") == "a_b_c")
        #expect(CaseExportWriter.sanitize("   ") == "Case")
    }

    // MARK: - README

    @Test func readmeDocumentsSetAndPDFPathWhenHTMLPresent() {
        let files = ExportGenerator.generate(inputs: Self.sampleInputs(),
            selection: ExportSelection(reportHTML: true, timelineCSV: true))
        let readme = try! #require(files.first { $0.filename == "README.txt" })
        let text = String(decoding: readme.data, as: UTF8.self)
        #expect(text.contains("Operation Test"))
        #expect(text.contains("Operation Test-report.html"))
        #expect(text.contains("Print > Save as PDF"))     // print-to-PDF guidance
        // README never lists itself.
        #expect(!text.contains("README.txt"))
    }

    @Test func readmeOmitsPDFGuidanceWithoutHTML() {
        let files = ExportGenerator.generate(inputs: Self.sampleInputs(),
            selection: ExportSelection(timelineCSV: true))
        let readme = try! #require(files.first { $0.filename == "README.txt" })
        let text = String(decoding: readme.data, as: UTF8.self)
        #expect(!text.contains("Save as PDF"))
    }

    // MARK: - End-to-end generate + write

    @Test func generateAndWriteProducesSelectedFiles() throws {
        let selection = ExportSelection(
            reportMarkdown: true, reportHTML: true,
            timelineCSV: true, timelineJSON: true,
            findingsCSV: true, findingsJSON: false,
            iocMatchesCSV: false, iocMatchesJSON: true)
        let files = ExportGenerator.generate(inputs: Self.sampleInputs(), selection: selection)
        let names = Set(files.map(\.filename))
        #expect(names == [
            "Operation Test-report.md", "Operation Test-report.html",
            "Operation Test-timeline.csv", "Operation Test-timeline.json",
            "Operation Test-findings.csv", "Operation Test-iocmatches.json",
            "README.txt"
        ])

        let fm = FileManager.default
        let root = fm.temporaryDirectory.appendingPathComponent("exp-\(UUID().uuidString)",
                                                                 isDirectory: true)
        try fm.createDirectory(at: root, withIntermediateDirectories: true)
        defer { try? fm.removeItem(at: root) }

        let output = try CaseExportWriter.write(files, caseName: "Operation Test",
                                                timestamp: Self.epoch, to: root)
        // Lands in a single timestamped subfolder, never the destination root.
        #expect(output.folderURL.lastPathComponent == "Operation Test Export 2001-01-01T000000Z")
        for name in output.filenames {
            #expect(fm.fileExists(atPath: output.folderURL.appendingPathComponent(name).path))
        }
    }
}
