import SwiftUI

/// Parsed macOS launchd jobs (LaunchAgents / LaunchDaemons) for the active
/// scope - the dominant macOS auto-start / persistence foothold. One row per
/// job, with its domain, the executable it runs, and the boot/login + beacon
/// triggers. Mirrors PrefetchView (filter bar + table/detail split + empty-state
/// parse).
struct LaunchItemsView: View {
    @EnvironmentObject private var model: AppModel
    @State private var query = ""
    @State private var selectedID: LaunchItemEntry.ID?

    private func filtered(_ entries: [LaunchItemEntry]) -> [LaunchItemEntry] {
        guard !query.isEmpty else { return entries }
        return entries.filter { entry in
            entry.label.localizedCaseInsensitiveContains(query)
                || entry.commandLine.localizedCaseInsensitiveContains(query)
                || entry.plistPath.localizedCaseInsensitiveContains(query)
        }
    }

    var body: some View {
        let entries = model.launchItems
        let visible = filtered(entries)
        return Group {
            if entries.isEmpty {
                ContentUnavailableView {
                    Label("No launch items parsed yet", systemImage: "powerplug")
                } description: {
                    Text(model.files.isEmpty
                         ? "Ingest evidence first, then come back here."
                         : "Click Parse to read every launchd .plist in LaunchAgents / LaunchDaemons.")
                } actions: {
                    #if os(macOS)
                    if !model.files.isEmpty {
                        Button {
                            Task { await model.parseMac() }
                        } label: {
                            Label("Parse macOS artifacts", systemImage: "play.fill")
                        }
                        .disabled(model.isWorking)
                        .help("Parse launchd jobs, the quarantine store, and the macOS host info.")
                    }
                    #endif
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else {
                VStack(spacing: 0) {
                    HStack(spacing: 12) {
                        Spacer()
                        TextField("Filter label / command / path...", text: $query)
                            .textFieldStyle(.roundedBorder)
                            .frame(width: 320)
                        #if os(macOS)
                        Button {
                            Task { await model.parseMac() }
                        } label: {
                            Image(systemName: "arrow.clockwise")
                        }
                        .help("Re-parse macOS artifacts")
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
        .navigationTitle(entries.isEmpty ? "Launch Items" : "Launch Items - \(visible.count) of \(entries.count)")
    }

    private func table(_ visible: [LaunchItemEntry]) -> some View {
        Table(visible, selection: $selectedID) {
            TableColumn("Label") { e in
                Text(e.label).font(.caption).lineLimit(1).truncationMode(.middle)
            }
            TableColumn("Domain") { e in
                Text(e.scope.label).font(.caption)
            }
            TableColumn("RunAtLoad") { e in
                Text(e.runAtLoad ? "yes" : "—").font(.caption)
                    .foregroundStyle(e.runAtLoad ? .primary : .secondary)
            }
            TableColumn("Executable") { e in
                Text(e.executable ?? "—").font(.caption).lineLimit(1).truncationMode(.middle)
            }
        }
        .frame(minWidth: 600, maxHeight: .infinity)
    }

    @ViewBuilder
    private func split(_ visible: [LaunchItemEntry], detail: LaunchItemEntry?) -> some View {
        #if os(macOS)
        HSplitView {
            table(visible)
            LaunchItemDetailView(entry: detail)
                .frame(minWidth: 320, maxHeight: .infinity)
        }
        #else
        HStack(spacing: 0) {
            table(visible)
            Divider()
            LaunchItemDetailView(entry: detail)
                .frame(minWidth: 320, maxHeight: .infinity)
        }
        #endif
    }
}

private struct LaunchItemDetailView: View {
    let entry: LaunchItemEntry?
    var body: some View {
        if let entry {
            ScrollView {
                VStack(alignment: .leading, spacing: 10) {
                    Text(entry.label).font(.headline)
                    LabeledContent("Domain", value: entry.scope.label)
                    if let exec = entry.executable {
                        LabeledContent("Executable") {
                            Text(exec).font(.caption.monospaced()).textSelection(.enabled)
                                .frame(maxWidth: .infinity, alignment: .trailing)
                        }
                    }
                    if !entry.commandLine.isEmpty {
                        LabeledContent("Command line") {
                            Text(entry.commandLine).font(.caption.monospaced()).textSelection(.enabled)
                                .frame(maxWidth: .infinity, alignment: .trailing)
                        }
                    }
                    LabeledContent("RunAtLoad", value: entry.runAtLoad ? "yes" : "no")
                    if let interval = entry.startInterval {
                        LabeledContent("StartInterval", value: "\(interval)s")
                    }
                    if !entry.watchPaths.isEmpty {
                        Divider()
                        Text("WatchPaths (\(entry.watchPaths.count))").font(.headline)
                        ForEach(Array(entry.watchPaths.enumerated()), id: \.offset) { _, path in
                            Text(path).font(.caption.monospaced()).textSelection(.enabled)
                        }
                    }
                    Divider()
                    LabeledContent("Source plist") {
                        Text(entry.plistPath).font(.caption.monospaced()).textSelection(.enabled)
                            .frame(maxWidth: .infinity, alignment: .trailing)
                    }
                }
                .padding()
                .frame(maxWidth: .infinity, alignment: .leading)
            }
        } else {
            ContentUnavailableView("Select a launch item", systemImage: "powerplug")
        }
    }
}
