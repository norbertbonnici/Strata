import SwiftUI

/// Parsed Windows shortcuts (`.lnk`) for the active scope: file-access evidence
/// with target, timestamps, and any embedded command-line arguments.
struct LnkView: View {
    @EnvironmentObject private var model: AppModel
    @State private var query = ""
    @State private var selectedID: LnkEntry.ID?

    private func filtered(_ entries: [LnkEntry]) -> [LnkEntry] {
        guard !query.isEmpty else { return entries }
        return entries.filter { e in
            e.name.localizedCaseInsensitiveContains(query)
                || (e.targetPath?.localizedCaseInsensitiveContains(query) ?? false)
                || (e.arguments?.localizedCaseInsensitiveContains(query) ?? false)
        }
    }

    var body: some View {
        let entries = model.lnk
        let visible = filtered(entries)
        return Group {
            if entries.isEmpty {
                ContentUnavailableView {
                    Label("No shortcuts parsed yet", systemImage: "arrowshape.turn.up.right")
                } description: {
                    Text(model.files.isEmpty
                         ? "Ingest evidence first, then come back here."
                         : "Click Parse to extract and parse every .lnk in the image.")
                } actions: {
                    #if os(macOS)
                    if !model.files.isEmpty {
                        Button { Task { await model.parseArtifacts() } } label: {
                            Label("Parse artifacts", systemImage: "play.fill")
                        }
                        .disabled(model.isWorking)
                        .help("Parse event logs, registry, and shortcuts, then run all analyzers.")
                    }
                    #endif
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else {
                VStack(spacing: 0) {
                    HStack(spacing: 12) {
                        Spacer()
                        TextField("Filter name / target / arguments...", text: $query)
                            .textFieldStyle(.roundedBorder)
                            .frame(width: 340)
                        #if os(macOS)
                        Button { Task { await model.parseArtifacts() } } label: {
                            Image(systemName: "arrow.clockwise")
                        }
                        .help("Re-parse artifacts, then re-run analyzers")
                        .disabled(model.isWorking)
                        #endif
                    }
                    .padding(8)
                    Divider()
                    split(visible, detail: entries.first { $0.id == selectedID })
                        .frame(maxWidth: .infinity, maxHeight: .infinity)
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .top)
            }
        }
        .navigationTitle(entries.isEmpty ? "Shortcuts" : "Shortcuts - \(visible.count) of \(entries.count)")
    }

    private func table(_ visible: [LnkEntry]) -> some View {
        Table(visible, selection: $selectedID) {
            TableColumn("Shortcut") { e in
                Text(e.name).font(.caption).lineLimit(1).truncationMode(.middle)
            }
            TableColumn("Target") { e in
                Text(e.targetPath ?? "—").font(.caption).lineLimit(1).truncationMode(.middle)
            }
            TableColumn("Arguments") { e in
                Text(e.arguments ?? "").font(.caption).lineLimit(1).truncationMode(.tail)
                    .foregroundStyle(e.arguments == nil ? .secondary : .primary)
            }
            TableColumn("Modified") { e in
                Text(e.targetModified?.formatted(date: .numeric, time: .standard) ?? "—")
                    .font(.caption).monospacedDigit()
            }
        }
        .frame(minWidth: 600, maxHeight: .infinity)
    }

    @ViewBuilder
    private func split(_ visible: [LnkEntry], detail: LnkEntry?) -> some View {
        #if os(macOS)
        HSplitView {
            table(visible)
            LnkDetailView(entry: detail).frame(minWidth: 320, maxHeight: .infinity)
        }
        #else
        HStack(spacing: 0) {
            table(visible)
            Divider()
            LnkDetailView(entry: detail).frame(minWidth: 320, maxHeight: .infinity)
        }
        #endif
    }
}

private struct LnkDetailView: View {
    let entry: LnkEntry?
    var body: some View {
        if let entry {
            ScrollView {
                VStack(alignment: .leading, spacing: 10) {
                    Text(entry.name).font(.headline)
                    if let target = entry.targetPath {
                        LabeledContent("Target") {
                            Text(target).font(.caption.monospaced()).textSelection(.enabled)
                                .frame(maxWidth: .infinity, alignment: .trailing)
                        }
                    }
                    if let args = entry.arguments {
                        LabeledContent("Arguments") {
                            Text(args).font(.caption.monospaced()).textSelection(.enabled)
                                .frame(maxWidth: .infinity, alignment: .trailing)
                        }
                    }
                    if let wd = entry.workingDirectory { LabeledContent("Working dir", value: wd) }
                    if let size = entry.targetSize { LabeledContent("Target size", value: "\(size) bytes") }
                    if let c = entry.targetCreated { LabeledContent("Target created", value: c.formatted(date: .abbreviated, time: .standard)) }
                    if let m = entry.targetModified { LabeledContent("Target modified", value: m.formatted(date: .abbreviated, time: .standard)) }
                    if let a = entry.targetAccessed { LabeledContent("Target accessed", value: a.formatted(date: .abbreviated, time: .standard)) }
                    if let dt = entry.driveType { LabeledContent("Drive type", value: dt) }
                    if let vl = entry.volumeLabel { LabeledContent("Volume label", value: vl) }
                    if let vs = entry.volumeSerial { LabeledContent("Volume serial", value: vs) }
                    if let mid = entry.machineIdentifier { LabeledContent("Created on host", value: mid) }
                    LabeledContent("Shortcut path") {
                        Text(entry.sourceFile).font(.caption.monospaced()).textSelection(.enabled)
                            .frame(maxWidth: .infinity, alignment: .trailing)
                    }
                }
                .padding()
                .frame(maxWidth: .infinity, alignment: .leading)
            }
        } else {
            ContentUnavailableView("Select a shortcut", systemImage: "arrowshape.turn.up.right")
        }
    }
}
