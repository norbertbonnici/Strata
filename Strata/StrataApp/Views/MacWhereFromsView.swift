import SwiftUI

/// macOS Download Origins: the `kMDItemWhereFroms` download-provenance xattrs —
/// where each downloaded file came from (download URL + referrer), recovered even
/// when the quarantine flag was stripped.
struct MacWhereFromsView: View {
    @EnvironmentObject private var model: AppModel
    @State private var query = ""
    @State private var selectedID: MacWhereFrom.ID?
    @State private var sort = [KeyPathComparator(\MacWhereFrom.fileName)]

    private func filtered(_ items: [MacWhereFrom]) -> [MacWhereFrom] {
        guard !query.isEmpty else { return items }
        return items.filter { e in
            e.path.localizedCaseInsensitiveContains(query)
            || e.urls.contains { $0.localizedCaseInsensitiveContains(query) }
        }
    }

    var body: some View {
        let rows = model.whereFroms
        let visible = filtered(rows).sorted(using: sort)
        return Group {
            if rows.isEmpty {
                ContentUnavailableView {
                    Label("No download origins parsed yet", systemImage: "arrow.down.circle")
                } description: {
                    Text(model.files.isEmpty
                         ? "Ingest a macOS image first, then come back here."
                         : "Click Parse to recover kMDItemWhereFroms xattrs (APFS images only).")
                } actions: {
                    #if os(macOS)
                    if !model.files.isEmpty {
                        Button { Task { await model.parseMac() } } label: {
                            Label("Parse macOS artifacts", systemImage: "play.fill")
                        }
                        .disabled(model.isWorking)
                    }
                    #endif
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else {
                VStack(spacing: 0) {
                    HStack(spacing: 12) {
                        Spacer()
                        TextField("Filter file / URL...", text: $query)
                            .textFieldStyle(.roundedBorder)
                            .frame(width: 320)
                        #if os(macOS)
                        Button { Task { await model.parseMac() } } label: {
                            Image(systemName: "arrow.clockwise")
                        }
                        .help("Re-parse macOS artifacts")
                        .disabled(model.isWorking)
                        #endif
                    }
                    .padding(8)
                    Divider()
                    split(visible, detail: rows.first { $0.id == selectedID })
                        .frame(maxWidth: .infinity, maxHeight: .infinity)
                }
            }
        }
        .navigationTitle(rows.isEmpty ? "Download Origins"
                         : "Download Origins - \(visible.count.formatted()) of \(rows.count.formatted())")
    }

    private func table(_ visible: [MacWhereFrom]) -> some View {
        Table(visible, selection: $selectedID, sortOrder: $sort) {
            TableColumn("File", value: \.fileName) { e in
                Text(e.fileName).font(.callout).lineLimit(1).truncationMode(.middle)
            }
            .width(min: 140, ideal: 200, max: 280)
            TableColumn("Downloaded from") { e in
                Text(e.downloadURL ?? "—").font(.caption).foregroundStyle(.secondary)
                    .lineLimit(1).truncationMode(.middle)
            }
        }
    }

    @ViewBuilder
    private func split(_ visible: [MacWhereFrom], detail: MacWhereFrom?) -> some View {
        #if os(macOS)
        HSplitView {
            table(visible).frame(minWidth: 520, maxHeight: .infinity)
            MacWhereFromDetailView(entry: detail).frame(minWidth: 320, maxHeight: .infinity)
        }
        #else
        table(visible)
        #endif
    }
}

private struct MacWhereFromDetailView: View {
    let entry: MacWhereFrom?

    var body: some View {
        if let e = entry {
            ScrollView {
                VStack(alignment: .leading, spacing: 10) {
                    Text(e.fileName).font(.headline).textSelection(.enabled)
                    if let u = e.downloadURL {
                        LabeledContent("Download URL") {
                            Text(u).font(.callout).textSelection(.enabled)
                                .frame(maxWidth: .infinity, alignment: .trailing)
                        }
                    }
                    if let r = e.referrerURL {
                        LabeledContent("Referrer") {
                            Text(r).font(.callout).textSelection(.enabled)
                                .frame(maxWidth: .infinity, alignment: .trailing)
                        }
                    }
                    if e.urls.count > 2 {
                        Divider()
                        Text("All where-from values").font(.caption).foregroundStyle(.secondary)
                        ForEach(Array(e.urls.enumerated()), id: \.offset) { _, u in
                            Text(u).font(.caption.monospaced()).textSelection(.enabled)
                        }
                    }
                    LabeledContent("Scope", value: e.scope)
                    Divider()
                    LabeledContent("File path") {
                        Text(e.path).font(.caption.monospaced()).textSelection(.enabled)
                            .frame(maxWidth: .infinity, alignment: .trailing)
                    }
                }
                .padding()
                .frame(maxWidth: .infinity, alignment: .leading)
            }
        } else {
            ContentUnavailableView("Select a file", systemImage: "arrow.down.circle")
        }
    }
}
