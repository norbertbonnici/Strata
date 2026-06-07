#if os(macOS)
import SwiftUI
import AppKit
import UniformTypeIdentifiers

/// Tools ▸ Export. Pick which artifacts and formats to write, choose one
/// destination folder, and Strata writes the whole set into a timestamped
/// subfolder. Mirrors `EnrichmentSheet`'s single-sheet layout and the
/// `.fileImporter` folder-pick pattern used elsewhere (one importer per view).
///
/// Exports always cover the entire case (every host), independent of the
/// current scope selection - so the counts shown here are case-wide.
struct ExportSheet: View {
    @EnvironmentObject private var model: AppModel
    @Environment(\.dismiss) private var dismiss

    @State private var reportMarkdown = true
    @State private var reportHTML = true
    @State private var timelineCSV = true
    @State private var timelineJSON = false
    @State private var findingsCSV = true
    @State private var findingsJSON = false
    @State private var iocCSV = true
    @State private var iocJSON = false
    @State private var showFolderPicker = false

    private var selection: ExportSelection {
        ExportSelection(reportMarkdown: reportMarkdown, reportHTML: reportHTML,
                        timelineCSV: timelineCSV, timelineJSON: timelineJSON,
                        findingsCSV: findingsCSV, findingsJSON: findingsJSON,
                        iocMatchesCSV: iocCSV, iocMatchesJSON: iocJSON)
    }

    // Case-wide counts: the export ignores the active-host scope, so sum across
    // every host rather than reading the scope-aware count accessors.
    private func caseCount(_ keyPath: KeyPath<EvidenceState, Int>) -> Int {
        model.evidenceList.reduce(0) { $0 + (model.states[$1.id]?[keyPath: keyPath] ?? 0) }
    }
    private var timelineCount: Int { caseCount(\.timeline.count) }
    private var findingCount: Int { caseCount(\.findings.count) }
    private var iocCount: Int { caseCount(\.iocMatches.count) }

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            VStack(alignment: .leading, spacing: 4) {
                Text("Export Case").font(.title2).bold()
                let hosts = model.evidenceList.count
                Text("Write a report and data exports for all \(hosts) host\(hosts == 1 ? "" : "s") into a timestamped folder. All timestamps are ISO-8601 / UTC.")
                    .font(.caption).foregroundStyle(.secondary)
            }

            groupBox("Examiner report") {
                Toggle("Markdown (.md)", isOn: $reportMarkdown)
                Toggle("HTML (.html)", isOn: $reportHTML)
                Text("Per-host profile, findings grouped by kill-chain phase with ATT&CK tags, IOC matches, and a findings timeline.")
                    .font(.caption).foregroundStyle(.secondary)
            }

            groupBox("Data exports") {
                dataRow("Timeline", count: timelineCount, csv: $timelineCSV, json: $timelineJSON)
                Divider()
                dataRow("Findings", count: findingCount, csv: $findingsCSV, json: $findingsJSON)
                Divider()
                dataRow("IOC matches", count: iocCount, csv: $iocCSV, json: $iocJSON)
            }

            HStack(spacing: 8) {
                if model.isWorking {
                    ProgressView().controlSize(.small)
                    Text("Exporting…").font(.caption).foregroundStyle(.secondary)
                }
                Spacer()
                Button("Cancel") { dismiss() }
                Button("Export…") { showFolderPicker = true }
                    .keyboardShortcut(.defaultAction)
                    .disabled(selection.isEmpty || model.isWorking)
            }
        }
        .padding(20)
        .frame(width: 480)
        // One `.fileImporter` per view tree (see CLAUDE.md) - the folder picker
        // for the export destination.
        .fileImporter(isPresented: $showFolderPicker,
                      allowedContentTypes: [.folder],
                      allowsMultipleSelection: false) { result in
            guard case .success(let urls) = result, let folder = urls.first else { return }
            Task {
                let didStart = folder.startAccessingSecurityScopedResource()
                defer { if didStart { folder.stopAccessingSecurityScopedResource() } }
                if let created = await model.exportSet(selection, to: folder) {
                    NSWorkspace.shared.activateFileViewerSelecting([created])
                }
                dismiss()
            }
        }
    }

    @ViewBuilder
    private func groupBox(_ title: String, @ViewBuilder content: () -> some View) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            Text(title).font(.headline)
            content()
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(12)
        .background(.quaternary, in: RoundedRectangle(cornerRadius: 6))
    }

    @ViewBuilder
    private func dataRow(_ title: String, count: Int,
                         csv: Binding<Bool>, json: Binding<Bool>) -> some View {
        HStack {
            VStack(alignment: .leading, spacing: 1) {
                Text(title)
                Text("\(count) row\(count == 1 ? "" : "s")")
                    .font(.caption).foregroundStyle(.secondary)
            }
            Spacer()
            Toggle("CSV", isOn: csv)
            Toggle("JSON", isOn: json).padding(.leading, 8)
        }
    }
}
#endif
