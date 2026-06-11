import SwiftUI

/// Windows Recycle Bin contents recovered from `$I` index files — what was
/// deleted, its original path, size, and when. Column-sortable + filterable.
struct RecycleBinView: View {
    @EnvironmentObject private var model: AppModel
    @State private var query = ""
    @State private var sort = [KeyPathComparator(\RecycleBinEntry.sortDeleted, order: .reverse)]

    private func filtered(_ rows: [RecycleBinEntry]) -> [RecycleBinEntry] {
        guard !query.isEmpty else { return rows }
        return rows.filter {
            $0.originalPath.localizedCaseInsensitiveContains(query)
                || ($0.sid?.localizedCaseInsensitiveContains(query) ?? false)
        }
    }

    var body: some View {
        let rows = model.recycleBin
        let visible = filtered(rows).sorted(using: sort)
        return Group {
            if rows.isEmpty {
                ContentUnavailableView {
                    Label("No Recycle Bin records parsed yet", systemImage: "trash")
                } description: {
                    Text(model.files.isEmpty
                         ? "Ingest a Windows image first, then come back here."
                         : "Click Parse to recover deleted-file records from $Recycle.Bin.")
                } actions: {
                    #if os(macOS)
                    if !model.files.isEmpty {
                        Button { Task { await model.parseArtifacts() } } label: {
                            Label("Parse artifacts", systemImage: "play.fill")
                        }.disabled(model.isWorking)
                    }
                    #endif
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else {
                VStack(spacing: 0) {
                    HStack { Spacer()
                        TextField("Filter path / SID…", text: $query)
                            .textFieldStyle(.roundedBorder).frame(width: 280)
                    }
                    .padding(8)
                    Divider()
                    Table(visible, sortOrder: $sort) {
                        TableColumn("Deleted", value: \.sortDeleted) { e in
                            Text(e.deletedAt.map { $0.formatted(date: .numeric, time: .standard) } ?? "—")
                                .monospacedDigit()
                        }
                        .width(min: 130, ideal: 150, max: 170)
                        TableColumn("Original path", value: \.originalPath) { e in
                            Text(e.originalPath).font(.caption.monospaced())
                                .lineLimit(1).truncationMode(.middle).help(e.originalPath)
                        }
                        TableColumn("Size", value: \.sizeBytes) { e in
                            Text(ByteCountFormatter.string(fromByteCount: e.sizeBytes, countStyle: .file))
                                .font(.caption.monospacedDigit()).foregroundStyle(.secondary)
                        }
                        .width(min: 70, ideal: 90, max: 120)
                        TableColumn("SID", value: \.sortSID) { e in
                            Text(e.sid ?? "—").font(.caption.monospaced()).foregroundStyle(.secondary)
                                .lineLimit(1).truncationMode(.head)
                        }
                        .width(min: 90, ideal: 130, max: 200)
                    }
                }
            }
        }
        .navigationTitle(rows.isEmpty ? "Recycle Bin" : "Recycle Bin - \(visible.count) of \(rows.count)")
    }
}

/// Non-optional sort keys for the sortable `Table`.
private extension RecycleBinEntry {
    var sortDeleted: Date { deletedAt ?? .distantPast }
    var sortSID: String { sid ?? "" }
}
