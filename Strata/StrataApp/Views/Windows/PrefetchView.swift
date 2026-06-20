import SwiftUI

/// Parsed Windows Prefetch for the active scope: one row per executable, with
/// run count and last-run time - the headline "what ran, and when" artifact.
/// Mirrors EventsView (filter bar + table/detail split + empty-state parse).
struct PrefetchView: View {
    @EnvironmentObject private var model: AppModel
    @State private var query = ""
    @State private var selectedID: PrefetchEntry.ID?

    private func filtered(_ entries: [PrefetchEntry]) -> [PrefetchEntry] {
        guard !query.isEmpty else { return entries }
        return entries.filter { entry in
            entry.executableName.localizedCaseInsensitiveContains(query)
                || (entry.executablePath?.localizedCaseInsensitiveContains(query) ?? false)
        }
    }

    var body: some View {
        let entries = model.prefetch
        let visible = filtered(entries)
        return Group {
            if entries.isEmpty {
                ContentUnavailableView {
                    Label("No prefetch parsed yet", systemImage: "bolt.badge.clock")
                } description: {
                    Text(model.files.isEmpty
                         ? "Ingest evidence first, then come back here."
                         : "Click Parse to extract and parse every .pf in \\Windows\\Prefetch.")
                } actions: {
                    #if os(macOS)
                    if !model.files.isEmpty {
                        Button {
                            Task { await model.parseArtifacts() }
                        } label: {
                            Label("Parse artifacts", systemImage: "play.fill")
                        }
                        .disabled(model.isWorking)
                        .help("Parse event logs, registry hives, and prefetch, then run all analyzers.")
                    }
                    #endif
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else {
                VStack(spacing: 0) {
                    HStack(spacing: 12) {
                        Spacer()
                        TextField("Filter executable / path...", text: $query)
                            .textFieldStyle(.roundedBorder)
                            .frame(width: 320)
                        #if os(macOS)
                        Button {
                            Task { await model.parseArtifacts() }
                        } label: {
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
        .navigationTitle(entries.isEmpty ? "Prefetch" : "Prefetch - \(visible.count) of \(entries.count)")
    }

    private func table(_ visible: [PrefetchEntry]) -> some View {
        Table(visible, selection: $selectedID) {
            TableColumn("Executable") { e in
                Text(e.executableName).font(.caption).lineLimit(1).truncationMode(.middle)
            }
            TableColumn("Runs") { e in
                Text("\(e.runCount)").monospacedDigit().font(.caption)
            }
            TableColumn("Last Run") { e in
                Text(e.lastRun?.formatted(date: .numeric, time: .standard) ?? "—")
                    .monospacedDigit().font(.caption)
            }
            TableColumn("Path") { e in
                Text(e.executablePath ?? "—").font(.caption).lineLimit(1).truncationMode(.middle)
            }
        }
        .frame(minWidth: 600, maxHeight: .infinity)
    }

    @ViewBuilder
    private func split(_ visible: [PrefetchEntry], detail: PrefetchEntry?) -> some View {
        #if os(macOS)
        HSplitView {
            table(visible)
            PrefetchDetailView(entry: detail)
                .frame(minWidth: 320, maxHeight: .infinity)
        }
        #else
        HStack(spacing: 0) {
            table(visible)
            Divider()
            PrefetchDetailView(entry: detail)
                .frame(minWidth: 320, maxHeight: .infinity)
        }
        #endif
    }
}

private struct PrefetchDetailView: View {
    let entry: PrefetchEntry?
    var body: some View {
        if let entry {
            ScrollView {
                VStack(alignment: .leading, spacing: 10) {
                    Text(entry.executableName).font(.headline)
                    LabeledContent("Run count", value: "\(entry.runCount)")
                    if let path = entry.executablePath {
                        LabeledContent("Path") {
                            Text(path).font(.caption.monospaced()).textSelection(.enabled)
                                .frame(maxWidth: .infinity, alignment: .trailing)
                        }
                    }
                    if let version = entry.formatVersion {
                        LabeledContent("Format version", value: "\(version)")
                    }
                    LabeledContent("Files referenced", value: "\(entry.fileCount)")
                    LabeledContent("Volumes", value: "\(entry.volumeCount)")
                    LabeledContent("Source", value: (entry.sourceFile as NSString).lastPathComponent)
                    Divider()
                    Text("Run times (\(entry.lastRunTimes.count))").font(.headline)
                    if entry.lastRunTimes.isEmpty {
                        Text("No recorded run times.").font(.caption).foregroundStyle(.secondary)
                    } else {
                        ForEach(Array(entry.lastRunTimes.enumerated()), id: \.offset) { _, date in
                            Text(date.formatted(date: .abbreviated, time: .standard))
                                .font(.caption.monospaced())
                        }
                    }
                }
                .padding()
                .frame(maxWidth: .infinity, alignment: .leading)
            }
        } else {
            ContentUnavailableView("Select a prefetch entry", systemImage: "bolt.badge.clock")
        }
    }
}
