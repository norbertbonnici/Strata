import Foundation

/// Top-level entry point for the export feature: turns `ReportInputs` +
/// `ExportSelection` into the set of named files to write. Pure and `Sendable`
/// so `AppModel` can run it inside a `Task.detached`, off the main actor.
///
/// Filenames share a sanitized case-name prefix (matching the export folder)
/// so the set reads as one cohesive bundle.
public nonisolated enum ExportGenerator {
    public static func generate(inputs: ReportInputs, selection: ExportSelection) -> [ExportedFile] {
        var files: [ExportedFile] = []
        let prefix = CaseExportWriter.sanitize(inputs.caseName)

        // Examiner report (build the model once, render the chosen formats).
        if selection.wantsReport {
            let model = ReportModelBuilder.build(from: inputs,
                                                 severities: selection.reportSeverities)
            if selection.reportMarkdown {
                let markdown = MarkdownReportRenderer.render(model)
                files.append(ExportedFile(filename: "\(prefix)-report.md",
                                          data: Data(markdown.utf8)))
            }
            if selection.reportHTML {
                let html = HTMLReportRenderer.render(model)
                files.append(ExportedFile(filename: "\(prefix)-report.html",
                                          data: Data(html.utf8)))
            }
        }

        // Timeline.
        if selection.timelineCSV || selection.timelineJSON {
            let rows = ExportRowBuilder.timelineRows(from: inputs.hosts)
            if selection.timelineCSV {
                files.append(ExportedFile(filename: "\(prefix)-timeline.csv",
                                          data: Data(CSVExporter.timeline(rows).utf8)))
            }
            if selection.timelineJSON, let data = try? JSONExporter.encode(rows) {
                files.append(ExportedFile(filename: "\(prefix)-timeline.json", data: data))
            }
        }

        // Findings.
        if selection.findingsCSV || selection.findingsJSON {
            let rows = ExportRowBuilder.findingRows(from: inputs.hosts)
            if selection.findingsCSV {
                files.append(ExportedFile(filename: "\(prefix)-findings.csv",
                                          data: Data(CSVExporter.findings(rows).utf8)))
            }
            if selection.findingsJSON, let data = try? JSONExporter.encode(rows) {
                files.append(ExportedFile(filename: "\(prefix)-findings.json", data: data))
            }
        }

        // IOC matches.
        if selection.iocMatchesCSV || selection.iocMatchesJSON {
            let rows = ExportRowBuilder.iocRows(from: inputs.hosts)
            if selection.iocMatchesCSV {
                files.append(ExportedFile(filename: "\(prefix)-iocmatches.csv",
                                          data: Data(CSVExporter.iocMatches(rows).utf8)))
            }
            if selection.iocMatchesJSON, let data = try? JSONExporter.encode(rows) {
                files.append(ExportedFile(filename: "\(prefix)-iocmatches.json", data: data))
            }
        }

        // Chain-of-custody report (acquisition + hashes + ledger).
        if selection.wantsCoC {
            let model = CoCReportModelBuilder.build(from: inputs)
            if selection.cocPDF {
                files.append(ExportedFile(filename: "\(prefix)-chain-of-custody.pdf",
                                          data: CoCPDFRenderer.pdf(model)))
            }
            if selection.cocMarkdown {
                files.append(ExportedFile(filename: "\(prefix)-chain-of-custody.md",
                                          data: Data(CoCReportRenderer.markdown(model).utf8)))
            }
            if selection.cocHTML {
                files.append(ExportedFile(filename: "\(prefix)-chain-of-custody.html",
                                          data: Data(CoCReportRenderer.html(model).utf8)))
            }
        }

        // Custody-log data export.
        if selection.custodyCSV || selection.custodyJSON {
            let rows = ExportRowBuilder.custodyRows(from: inputs.custodyLog, hosts: inputs.hosts)
            if selection.custodyCSV {
                files.append(ExportedFile(filename: "\(prefix)-custody.csv",
                                          data: Data(CSVExporter.custody(rows).utf8)))
            }
            if selection.custodyJSON, let data = try? JSONExporter.encode(rows) {
                files.append(ExportedFile(filename: "\(prefix)-custody.json", data: data))
            }
        }

        // Analyst-annotations data export.
        if selection.annotationsCSV || selection.annotationsJSON {
            let rows = ExportRowBuilder.annotationRows(from: inputs.annotations, hosts: inputs.hosts)
            if selection.annotationsCSV {
                files.append(ExportedFile(filename: "\(prefix)-annotations.csv",
                                          data: Data(CSVExporter.annotations(rows).utf8)))
            }
            if selection.annotationsJSON, let data = try? JSONExporter.encode(rows) {
                files.append(ExportedFile(filename: "\(prefix)-annotations.json", data: data))
            }
        }

        // Document the set (and the print-to-PDF path) once we know what it holds.
        if !files.isEmpty {
            let readme = ExportReadme.render(inputs: inputs, filenames: files.map(\.filename))
            files.append(ExportedFile(filename: ExportReadme.filename, data: Data(readme.utf8)))
        }

        return files
    }
}
