#if os(macOS)
import SwiftUI
import AppKit
import UniformTypeIdentifiers

/// Tools ▸ Export. Pick which endpoints, artifacts, and formats to write, choose
/// one destination folder, and Strata writes the whole set into a timestamped
/// subfolder. Mirrors `EnrichmentSheet`'s single-sheet layout and the
/// `.fileImporter` folder-pick pattern (one importer per view).
///
/// Endpoint selection applies to everything (report + data exports). The
/// severity selection applies to the *report* only - the raw findings export
/// stays complete.
struct ExportSheet: View {
    @EnvironmentObject private var model: AppModel
    @Environment(\.dismiss) private var dismiss

    @State private var selectedHosts: Set<UUID> = []
    @State private var didInitHosts = false

    @State private var reportMarkdown = true
    @State private var reportHTML = true
    @State private var reportSeverities: Set<Severity> = Set(Severity.allCases)

    @State private var timelineCSV = true
    @State private var timelineJSON = false
    @State private var findingsCSV = true
    @State private var findingsJSON = false
    @State private var iocCSV = true
    @State private var iocJSON = false
    @State private var showFolderPicker = false

    private var wantsReport: Bool { reportMarkdown || reportHTML }

    private var selection: ExportSelection {
        ExportSelection(reportMarkdown: reportMarkdown, reportHTML: reportHTML,
                        timelineCSV: timelineCSV, timelineJSON: timelineJSON,
                        findingsCSV: findingsCSV, findingsJSON: findingsJSON,
                        iocMatchesCSV: iocCSV, iocMatchesJSON: iocJSON,
                        reportSeverities: reportSeverities)
    }

    private var canExport: Bool {
        !selection.isEmpty && !selectedHosts.isEmpty && !model.isWorking
            && !(wantsReport && reportSeverities.isEmpty)
    }

    // Counts reflect only the selected endpoints.
    private func count(_ keyPath: KeyPath<EvidenceState, Int>) -> Int {
        model.evidenceList
            .filter { selectedHosts.contains($0.id) }
            .reduce(0) { $0 + (model.states[$1.id]?[keyPath: keyPath] ?? 0) }
    }
    private var timelineCount: Int { count(\.timeline.count) }
    private var findingCount: Int { count(\.findings.count) }
    private var iocCount: Int { count(\.iocMatches.count) }

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            VStack(alignment: .leading, spacing: 4) {
                Text("Export Case").font(.title2).bold()
                Text("Write a report and data exports for the selected endpoints into a timestamped folder. All timestamps are ISO-8601 / UTC.")
                    .font(.caption).foregroundStyle(.secondary)
            }

            endpointsSection
            reportSection
            dataSection

            HStack(spacing: 8) {
                if model.isWorking {
                    ProgressView().controlSize(.small)
                    Text("Exporting…").font(.caption).foregroundStyle(.secondary)
                }
                Spacer()
                Button("Cancel") { dismiss() }
                Button("Export…") { showFolderPicker = true }
                    .keyboardShortcut(.defaultAction)
                    .disabled(!canExport)
            }
        }
        .padding(20)
        .frame(width: 500)
        .onAppear {
            if !didInitHosts {
                selectedHosts = Set(model.evidenceList.map(\.id))
                didInitHosts = true
            }
        }
        // One `.fileImporter` per view tree (see CLAUDE.md) - the export folder.
        .fileImporter(isPresented: $showFolderPicker,
                      allowedContentTypes: [.folder],
                      allowsMultipleSelection: false) { result in
            guard case .success(let urls) = result, let folder = urls.first else { return }
            Task {
                let didStart = folder.startAccessingSecurityScopedResource()
                defer { if didStart { folder.stopAccessingSecurityScopedResource() } }
                if let created = await model.exportSet(selection, hostIDs: selectedHosts,
                                                       to: folder) {
                    NSWorkspace.shared.activateFileViewerSelecting([created])
                }
                dismiss()
            }
        }
    }

    // MARK: - Sections

    private var endpointsSection: some View {
        groupBox("Endpoints") {
            HStack {
                Text("\(selectedHosts.count) of \(model.evidenceList.count) selected")
                    .font(.caption).foregroundStyle(.secondary)
                Spacer()
                Button("All") { selectedHosts = Set(model.evidenceList.map(\.id)) }
                    .buttonStyle(.link).font(.caption)
                Button("None") { selectedHosts = [] }
                    .buttonStyle(.link).font(.caption)
            }
            hostList
        }
    }

    @ViewBuilder
    private var hostList: some View {
        let rows = VStack(alignment: .leading, spacing: 4) {
            ForEach(model.evidenceList) { host in
                Toggle(isOn: hostBinding(host.id)) {
                    HStack(spacing: 6) {
                        Text(host.displayName)
                        Text(host.kind.label).font(.caption).foregroundStyle(.secondary)
                    }
                }
            }
        }
        // Scroll once the host list gets long; otherwise let it size naturally.
        if model.evidenceList.count > 6 {
            ScrollView { rows.frame(maxWidth: .infinity, alignment: .leading) }
                .frame(height: 150)
        } else {
            rows
        }
    }

    private var reportSection: some View {
        groupBox("Examiner report") {
            Toggle("Markdown (.md)", isOn: $reportMarkdown)
            Toggle("HTML (.html)", isOn: $reportHTML)
            Text("Per-host profile, findings grouped by kill-chain phase with ATT&CK tags, IOC matches, and a findings timeline.")
                .font(.caption).foregroundStyle(.secondary)
            Divider()
            Text("Include severities (report only)").font(.caption).foregroundStyle(.secondary)
            HStack(spacing: 12) {
                // High → low: most relevant first.
                ForEach(Array(Severity.allCases.reversed()), id: \.self) { severity in
                    Toggle(severity.label, isOn: severityBinding(severity))
                }
            }
            .disabled(!wantsReport)
            if wantsReport && reportSeverities.isEmpty {
                Text("Select at least one severity to export the report.")
                    .font(.caption).foregroundStyle(.orange)
            }
        }
    }

    private var dataSection: some View {
        groupBox("Data exports") {
            Text("Raw data for the selected endpoints — not affected by the severity filter.")
                .font(.caption).foregroundStyle(.secondary)
            dataRow("Timeline", count: timelineCount, csv: $timelineCSV, json: $timelineJSON)
            Divider()
            dataRow("Findings", count: findingCount, csv: $findingsCSV, json: $findingsJSON)
            Divider()
            dataRow("IOC matches", count: iocCount, csv: $iocCSV, json: $iocJSON)
        }
    }

    // MARK: - Bindings into the Set states

    private func hostBinding(_ id: UUID) -> Binding<Bool> {
        Binding(get: { selectedHosts.contains(id) },
                set: { selected in
                    if selected { selectedHosts.insert(id) } else { selectedHosts.remove(id) }
                })
    }

    private func severityBinding(_ severity: Severity) -> Binding<Bool> {
        Binding(get: { reportSeverities.contains(severity) },
                set: { selected in
                    if selected { reportSeverities.insert(severity) }
                    else { reportSeverities.remove(severity) }
                })
    }

    // MARK: - Building blocks

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
