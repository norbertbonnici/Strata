import SwiftUI

/// Parsed JumpList destinations for the active scope: per-application recent /
/// pinned items, with the DestList last-access time, access count, host, and
/// the embedded shortcut's target.
struct JumpListView: View {
    @EnvironmentObject private var model: AppModel
    @State private var query = ""
    @State private var selectedID: JumpListEntry.ID?

    private func filtered(_ entries: [JumpListEntry]) -> [JumpListEntry] {
        guard !query.isEmpty else { return entries }
        return entries.filter { e in
            e.name.localizedCaseInsensitiveContains(query)
                || (e.targetPath?.localizedCaseInsensitiveContains(query) ?? false)
                || (e.application?.localizedCaseInsensitiveContains(query) ?? false)
                || e.appID.localizedCaseInsensitiveContains(query)
        }
    }

    var body: some View {
        let entries = model.jumpList
        let visible = filtered(entries)
        return Group {
            if entries.isEmpty {
                ContentUnavailableView {
                    Label("No JumpLists parsed yet", systemImage: "list.star")
                } description: {
                    Text(model.files.isEmpty
                         ? "Ingest evidence first, then come back here."
                         : "Click Parse to crack every *.automaticDestinations-ms / *.customDestinations-ms.")
                } actions: {
                    #if os(macOS)
                    if !model.files.isEmpty {
                        Button { Task { await model.parseArtifacts() } } label: {
                            Label("Parse artifacts", systemImage: "play.fill")
                        }
                        .disabled(model.isWorking)
                        .help("Parse event logs, registry, shortcuts, and JumpLists, then run all analyzers.")
                    }
                    #endif
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else {
                VStack(spacing: 0) {
                    HStack(spacing: 12) {
                        Spacer()
                        TextField("Filter target / app / AppID...", text: $query)
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
        .navigationTitle(entries.isEmpty ? "JumpLists" : "JumpLists - \(visible.count) of \(entries.count)")
    }

    private func table(_ visible: [JumpListEntry]) -> some View {
        Table(visible, selection: $selectedID) {
            TableColumn("Application") { e in
                Text(e.application ?? e.appID).font(.caption).lineLimit(1).truncationMode(.middle)
            }
            TableColumn("Target") { e in
                Text(e.targetPath ?? "—").font(.caption).lineLimit(1).truncationMode(.middle)
            }
            TableColumn("Last accessed") { e in
                Text(e.lastAccessed?.formatted(date: .numeric, time: .standard) ?? "—")
                    .font(.caption).monospacedDigit()
            }
            TableColumn("Host") { e in
                Text(e.hostname ?? "—").font(.caption).lineLimit(1)
            }
        }
        .frame(minWidth: 600, maxHeight: .infinity)
    }

    @ViewBuilder
    private func split(_ visible: [JumpListEntry], detail: JumpListEntry?) -> some View {
        #if os(macOS)
        HSplitView {
            table(visible)
            JumpListDetailView(entry: detail).frame(minWidth: 320, maxHeight: .infinity)
        }
        #else
        HStack(spacing: 0) {
            table(visible)
            Divider()
            JumpListDetailView(entry: detail).frame(minWidth: 320, maxHeight: .infinity)
        }
        #endif
    }
}

private struct JumpListDetailView: View {
    let entry: JumpListEntry?
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
                    LabeledContent("Application", value: entry.application ?? "Unknown")
                    LabeledContent("AppID", value: entry.appID)
                    LabeledContent("List type", value: entry.listType == .automatic ? "Automatic" : "Custom")
                    if let last = entry.lastAccessed {
                        LabeledContent("Last accessed", value: last.formatted(date: .abbreviated, time: .standard))
                    }
                    if let count = entry.accessCount { LabeledContent("Access count", value: "\(count)") }
                    if let host = entry.hostname { LabeledContent("Recorded on host", value: host) }
                    if let pinned = entry.pinned { LabeledContent("Pinned", value: pinned ? "Yes" : "No") }
                    LabeledContent("Source", value: (entry.sourceFile as NSString).lastPathComponent)
                    if entry.appID.caseInsensitiveCompare(JumpListAppID.remoteDesktop) == .orderedSame {
                        Divider()
                        Text("Remote Desktop (mstsc) jumplist — this destination is a host this machine connected out to (lateral movement).")
                            .font(.caption).foregroundStyle(.secondary)
                    }
                }
                .padding()
                .frame(maxWidth: .infinity, alignment: .leading)
            }
        } else {
            ContentUnavailableView("Select a JumpList entry", systemImage: "list.star")
        }
    }
}
