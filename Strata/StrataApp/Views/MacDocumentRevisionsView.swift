import SwiftUI

/// macOS document Versions store: each row is a saved generation of a document —
/// the file's edit timeline + a recoverable prior version, even for files no
/// longer on disk.
struct MacDocumentRevisionsView: View {
    @EnvironmentObject private var model: AppModel
    @State private var query = ""
    @State private var selectedID: MacDocumentVersion.ID?
    @State private var sort = [KeyPathComparator(\MacDocumentVersion.sortTime, order: .reverse)]

    private func filtered(_ items: [MacDocumentVersion]) -> [MacDocumentVersion] {
        guard !query.isEmpty else { return items }
        return items.filter { $0.filePath.localizedCaseInsensitiveContains(query) }
    }

    var body: some View {
        let rows = model.documentVersions
        let visible = filtered(rows).sorted(using: sort)
        return Group {
            if rows.isEmpty {
                ContentUnavailableView {
                    Label("No document versions parsed yet", systemImage: "doc.on.doc")
                } description: {
                    Text(model.files.isEmpty
                         ? "Ingest a macOS image first, then come back here."
                         : "Click Parse to read the Versions store (.DocumentRevisions-V100).")
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
                        TextField("Filter path...", text: $query)
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
        .navigationTitle(rows.isEmpty ? "Document Versions"
                         : "Document Versions - \(visible.count.formatted()) of \(rows.count.formatted())")
    }

    private func table(_ visible: [MacDocumentVersion]) -> some View {
        Table(visible, selection: $selectedID, sortOrder: $sort) {
            TableColumn("Version time", value: \.sortTime) { v in
                Text(v.versionTime?.formatted(date: .numeric, time: .standard) ?? "—")
                    .monospacedDigit().font(.caption)
            }
            .width(min: 140, ideal: 160, max: 190)
            TableColumn("Document", value: \.filePath) { v in
                Text(v.filePath).font(.callout).lineLimit(1).truncationMode(.middle)
            }
            TableColumn("Size") { v in
                Text(v.size.map { ByteCountFormatter.string(fromByteCount: $0, countStyle: .file) } ?? "—")
                    .font(.caption.monospacedDigit()).foregroundStyle(.secondary)
            }
            .width(min: 80, ideal: 100, max: 130)
        }
    }

    @ViewBuilder
    private func split(_ visible: [MacDocumentVersion], detail: MacDocumentVersion?) -> some View {
        #if os(macOS)
        HSplitView {
            table(visible).frame(minWidth: 560, maxHeight: .infinity)
            MacDocumentVersionDetailView(version: detail).frame(minWidth: 300, maxHeight: .infinity)
        }
        #else
        table(visible)
        #endif
    }
}

private extension MacDocumentVersion {
    var sortTime: Date { versionTime ?? .distantPast }
}

private struct MacDocumentVersionDetailView: View {
    let version: MacDocumentVersion?

    var body: some View {
        if let version {
            ScrollView {
                VStack(alignment: .leading, spacing: 10) {
                    Text(version.name).font(.headline).textSelection(.enabled)
                    LabeledContent("Version time", value: version.versionTime?.formatted(date: .long, time: .standard) ?? "—")
                    if let s = version.size {
                        LabeledContent("Size", value: ByteCountFormatter.string(fromByteCount: s, countStyle: .file))
                    }
                    LabeledContent("Document") {
                        Text(version.filePath).font(.caption.monospaced()).textSelection(.enabled)
                            .frame(maxWidth: .infinity, alignment: .trailing)
                    }
                    if let g = version.generationPath {
                        LabeledContent("Stored version") {
                            Text(g).font(.caption.monospaced()).textSelection(.enabled)
                                .frame(maxWidth: .infinity, alignment: .trailing)
                        }
                    }
                    Text("A version generation is a recoverable prior copy the OS auto-saved — present "
                         + "even if the document was later deleted.")
                        .font(.caption).foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                    Divider()
                    LabeledContent("Source") {
                        Text(version.sourceFile).font(.caption.monospaced()).textSelection(.enabled)
                            .frame(maxWidth: .infinity, alignment: .trailing)
                    }
                }
                .padding()
                .frame(maxWidth: .infinity, alignment: .leading)
            }
        } else {
            ContentUnavailableView("Select a version", systemImage: "doc.on.doc")
        }
    }
}
