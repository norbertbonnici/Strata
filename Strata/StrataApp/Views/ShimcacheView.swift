import SwiftUI

/// AppCompatCache (Shimcache) entries for the active scope: one row per cached
/// path, in cache (most-recent-first) order. Proves presence, not execution.
struct ShimcacheView: View {
    @EnvironmentObject private var model: AppModel
    @State private var query = ""
    @State private var selectedID: ShimcacheEntry.ID?

    private func filtered(_ entries: [ShimcacheEntry]) -> [ShimcacheEntry] {
        guard !query.isEmpty else { return entries }
        return entries.filter { $0.path.localizedCaseInsensitiveContains(query) }
    }

    var body: some View {
        let entries = model.shimcache
        let visible = filtered(entries)
        return Group {
            if entries.isEmpty {
                ContentUnavailableView {
                    Label("No Shimcache parsed yet", systemImage: "clock.arrow.circlepath")
                } description: {
                    Text(model.files.isEmpty
                         ? "Ingest evidence first, then come back here."
                         : "Shimcache is decoded from the SYSTEM hive when you parse the registry.")
                } actions: {
                    #if os(macOS)
                    if !model.files.isEmpty {
                        Button { Task { await model.parseArtifacts() } } label: {
                            Label("Parse artifacts", systemImage: "play.fill")
                        }
                        .disabled(model.isWorking)
                        .help("Parse event logs, registry hives (incl. AppCompatCache), then run all analyzers.")
                    }
                    #endif
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else {
                VStack(spacing: 0) {
                    HStack(spacing: 12) {
                        Text("Presence, not execution")
                            .font(.caption).foregroundStyle(.secondary)
                        Spacer()
                        TextField("Filter path...", text: $query)
                            .textFieldStyle(.roundedBorder)
                            .frame(width: 320)
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
        .navigationTitle(entries.isEmpty ? "Shimcache" : "Shimcache - \(visible.count) of \(entries.count)")
    }

    private func table(_ visible: [ShimcacheEntry]) -> some View {
        Table(visible, selection: $selectedID) {
            TableColumn("#") { e in
                Text("\(e.insertionOrder)").font(.caption).monospacedDigit()
            }
            TableColumn("Name") { e in
                Text(e.name).font(.caption).lineLimit(1).truncationMode(.middle)
            }
            TableColumn("Modified") { e in
                Text(e.lastModified?.formatted(date: .numeric, time: .standard) ?? "—")
                    .font(.caption).monospacedDigit()
            }
            TableColumn("Path") { e in
                Text(e.path).font(.caption).lineLimit(1).truncationMode(.middle)
            }
        }
        .frame(minWidth: 600, maxHeight: .infinity)
    }

    @ViewBuilder
    private func split(_ visible: [ShimcacheEntry], detail: ShimcacheEntry?) -> some View {
        #if os(macOS)
        HSplitView {
            table(visible)
            ShimcacheDetailView(entry: detail).frame(minWidth: 320, maxHeight: .infinity)
        }
        #else
        HStack(spacing: 0) {
            table(visible)
            Divider()
            ShimcacheDetailView(entry: detail).frame(minWidth: 320, maxHeight: .infinity)
        }
        #endif
    }
}

private struct ShimcacheDetailView: View {
    let entry: ShimcacheEntry?
    var body: some View {
        if let entry {
            ScrollView {
                VStack(alignment: .leading, spacing: 10) {
                    Text(entry.name).font(.headline)
                    LabeledContent("Path") {
                        Text(entry.path).font(.caption.monospaced()).textSelection(.enabled)
                            .frame(maxWidth: .infinity, alignment: .trailing)
                    }
                    LabeledContent("Cache position", value: "\(entry.insertionOrder) (0 = most recent)")
                    LabeledContent("File modified",
                                   value: entry.lastModified?.formatted(date: .abbreviated, time: .standard) ?? "—")
                    LabeledContent("Format", value: entry.version.rawValue)
                    Divider()
                    Text("Shimcache proves the file was present / known to the system — NOT that it executed. The modified time is the file's timestamp at cache time (timestomp-susceptible), not a run time.")
                        .font(.caption).foregroundStyle(.secondary)
                }
                .padding()
                .frame(maxWidth: .infinity, alignment: .leading)
            }
        } else {
            ContentUnavailableView("Select a Shimcache entry", systemImage: "clock.arrow.circlepath")
        }
    }
}
