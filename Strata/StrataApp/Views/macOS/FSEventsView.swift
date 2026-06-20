import SwiftUI

/// The macOS FSEvents change history for the active scope - the kernel's
/// coalesced log of filesystem changes (the macOS analogue of the NTFS USN
/// journal). One row per record: the changed path, the coalesced change flags,
/// and the monotonic event ID. FSEvents has no per-record timestamp, so there is
/// no time column and the store is ordered by event ID. Mirrors PrefetchView
/// (filter bar + table/detail split + empty-state parse).
struct FSEventsView: View {
    @EnvironmentObject private var model: AppModel
    @State private var query = ""
    @State private var changesOnly = false
    @State private var selectedID: FSEventRecord.ID?

    private func filtered(_ records: [FSEventRecord]) -> [FSEventRecord] {
        records.filter { r in
            if changesOnly && !(r.wasCreated || r.wasRemoved || r.wasRenamed || r.wasModified) { return false }
            guard !query.isEmpty else { return true }
            return r.path.localizedCaseInsensitiveContains(query)
                || r.flagSummary.localizedCaseInsensitiveContains(query)
        }
    }

    var body: some View {
        let records = model.fsEvents
        let visible = filtered(records)
        return Group {
            if records.isEmpty {
                ContentUnavailableView {
                    Label("No FSEvents parsed yet", systemImage: "doc.on.doc")
                } description: {
                    Text(model.files.isEmpty
                         ? "Ingest evidence first, then come back here."
                         : "Click Parse to inflate and decode every /.fseventsd/ log.")
                } actions: {
                    #if os(macOS)
                    if !model.files.isEmpty {
                        Button {
                            Task { await model.parseMac() }
                        } label: {
                            Label("Parse macOS artifacts", systemImage: "play.fill")
                        }
                        .disabled(model.isWorking)
                        .help("Parse launchd jobs, persistence, quarantine, FSEvents, and the macOS host info.")
                    }
                    #endif
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else {
                VStack(spacing: 0) {
                    HStack(spacing: 12) {
                        let changesToggle = Toggle("Changes only", isOn: $changesOnly)
                            .help("Show only Created / Removed / Renamed / Modified records")
                        #if os(macOS)
                        changesToggle.toggleStyle(.checkbox)
                        #else
                        changesToggle
                        #endif
                        Spacer()
                        TextField("Filter path / flags...", text: $query)
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

                    split(visible, detail: records.first { $0.id == selectedID })
                        .frame(maxWidth: .infinity, maxHeight: .infinity)
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .top)
            }
        }
        .navigationTitle(records.isEmpty ? "FSEvents" : "FSEvents - \(visible.count) of \(records.count)")
    }

    private func table(_ visible: [FSEventRecord]) -> some View {
        Table(visible, selection: $selectedID) {
            TableColumn("Path") { r in
                Text(r.path).font(.caption).lineLimit(1).truncationMode(.middle)
            }
            TableColumn("Type") { r in
                Text(r.isFolder ? "Folder" : (r.isFile ? "File" : "—")).font(.caption)
            }
            TableColumn("Changes") { r in
                Text(r.flagSummary).font(.caption).lineLimit(1).truncationMode(.tail)
            }
            TableColumn("Event ID") { r in
                Text("\(r.eventID)").monospacedDigit().font(.caption)
            }
        }
        .frame(minWidth: 600, maxHeight: .infinity)
    }

    @ViewBuilder
    private func split(_ visible: [FSEventRecord], detail: FSEventRecord?) -> some View {
        #if os(macOS)
        HSplitView {
            table(visible)
            FSEventDetailView(record: detail)
                .frame(minWidth: 320, maxHeight: .infinity)
        }
        #else
        HStack(spacing: 0) {
            table(visible)
            Divider()
            FSEventDetailView(record: detail)
                .frame(minWidth: 320, maxHeight: .infinity)
        }
        #endif
    }
}

private struct FSEventDetailView: View {
    let record: FSEventRecord?
    var body: some View {
        if let record {
            ScrollView {
                VStack(alignment: .leading, spacing: 10) {
                    Text(record.name).font(.headline).textSelection(.enabled)
                    LabeledContent("Path") {
                        Text(record.path).font(.caption.monospaced()).textSelection(.enabled)
                            .frame(maxWidth: .infinity, alignment: .trailing)
                    }
                    LabeledContent("Type", value: record.isFolder ? "Folder" : (record.isFile ? "File" : "Unknown"))
                    LabeledContent("Event ID", value: "\(record.eventID)")
                    if let node = record.nodeID {
                        LabeledContent("Node ID (inode)", value: "\(node)")
                    }
                    LabeledContent("Source", value: (record.sourceFile as NSString).lastPathComponent)
                    Divider()
                    Text("Coalesced changes").font(.headline)
                    if record.flagNames.isEmpty {
                        Text("None").font(.caption).foregroundStyle(.secondary)
                    } else {
                        ForEach(record.flagNames, id: \.self) { flag in
                            Text(flag).font(.caption.monospaced())
                        }
                    }
                    Text("FSEvents records carry no timestamp — only the event ID orders them.")
                        .font(.caption2).foregroundStyle(.secondary).padding(.top, 4)
                }
                .padding()
                .frame(maxWidth: .infinity, alignment: .leading)
            }
        } else {
            ContentUnavailableView("Select an FSEvents record", systemImage: "doc.on.doc")
        }
    }
}
