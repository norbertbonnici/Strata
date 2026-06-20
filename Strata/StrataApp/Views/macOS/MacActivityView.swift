import SwiftUI

/// macOS user-activity / deleted-evidence: QuickLook-previewed files (viewed,
/// possibly since deleted) and files in the Trash (deletion intent + time).
struct MacActivityView: View {
    @EnvironmentObject private var model: AppModel
    @State private var query = ""
    @State private var kind: MacActivityItem.Kind?
    @State private var selectedID: MacActivityItem.ID?
    @State private var sort = [KeyPathComparator(\MacActivityItem.sortTime, order: .reverse)]

    private func filtered(_ items: [MacActivityItem]) -> [MacActivityItem] {
        var out = items
        if let kind { out = out.filter { $0.kind == kind } }
        if !query.isEmpty {
            out = out.filter { $0.path.localizedCaseInsensitiveContains(query)
                || ($0.detail?.localizedCaseInsensitiveContains(query) ?? false) }
        }
        return out
    }

    var body: some View {
        let rows = model.userActivity
        let visible = filtered(rows).sorted(using: sort)
        let kinds = Array(Set(rows.map(\.kind))).sorted { $0.label < $1.label }
        return Group {
            if rows.isEmpty {
                ContentUnavailableView {
                    Label("No QuickLook / Trash data parsed yet", systemImage: "eye.trianglebadge.exclamationmark")
                } description: {
                    Text(model.files.isEmpty
                         ? "Ingest a macOS image first, then come back here."
                         : "Click Parse to read the QuickLook thumbnail index + Trash.")
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
                        Picker("Type", selection: $kind) {
                            Text("All").tag(MacActivityItem.Kind?.none)
                            ForEach(kinds, id: \.self) { k in
                                Text(k.label).tag(MacActivityItem.Kind?.some(k))
                            }
                        }
                        .pickerStyle(.menu)
                        .frame(width: 160)
                        Spacer()
                        TextField("Filter path / detail...", text: $query)
                            .textFieldStyle(.roundedBorder)
                            .frame(width: 300)
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
        .navigationTitle(rows.isEmpty ? "QuickLook & Trash"
                         : "QuickLook & Trash - \(visible.count.formatted()) of \(rows.count.formatted())")
    }

    private func table(_ visible: [MacActivityItem]) -> some View {
        Table(visible, selection: $selectedID, sortOrder: $sort) {
            TableColumn("When", value: \.sortTime) { i in
                Text(i.timestamp?.formatted(date: .numeric, time: .standard) ?? "—")
                    .monospacedDigit().font(.caption)
            }
            .width(min: 130, ideal: 150, max: 180)
            TableColumn("Type", value: \.sortKind) { i in
                Text(i.kind.label).font(.caption).foregroundStyle(.secondary)
            }
            .width(min: 80, ideal: 90, max: 110)
            TableColumn("Path", value: \.path) { i in
                Text(i.path).font(.callout).lineLimit(1).truncationMode(.middle)
            }
            TableColumn("Detail") { i in
                Text(i.detail ?? "—").font(.caption).foregroundStyle(.secondary)
            }
            .width(min: 90, ideal: 110, max: 160)
        }
    }

    @ViewBuilder
    private func split(_ visible: [MacActivityItem], detail: MacActivityItem?) -> some View {
        #if os(macOS)
        HSplitView {
            table(visible).frame(minWidth: 560, maxHeight: .infinity)
            MacActivityDetailView(item: detail).frame(minWidth: 300, maxHeight: .infinity)
        }
        #else
        table(visible)
        #endif
    }
}

private extension MacActivityItem {
    var sortTime: Date { timestamp ?? .distantPast }
    var sortKind: String { kind.label }
}

private struct MacActivityDetailView: View {
    let item: MacActivityItem?

    var body: some View {
        if let item {
            ScrollView {
                VStack(alignment: .leading, spacing: 10) {
                    Text(item.name).font(.headline).textSelection(.enabled)
                    LabeledContent("Type", value: item.kind == .quickLook ? "QuickLook (previewed)" : "Trash (deleted)")
                    LabeledContent("When", value: item.timestamp?.formatted(date: .long, time: .standard) ?? "—")
                    if let d = item.detail { LabeledContent("Detail", value: d) }
                    LabeledContent("Path") {
                        Text(item.path).font(.caption.monospaced()).textSelection(.enabled)
                            .frame(maxWidth: .infinity, alignment: .trailing)
                    }
                    if item.kind == .quickLook {
                        Text("A QuickLook entry means the file was previewed — evidence it existed and was "
                             + "viewed, even if it has since been deleted.")
                            .font(.caption).foregroundStyle(.secondary)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                    Divider()
                    LabeledContent("Source") {
                        Text(item.sourceFile).font(.caption.monospaced()).textSelection(.enabled)
                            .frame(maxWidth: .infinity, alignment: .trailing)
                    }
                }
                .padding()
                .frame(maxWidth: .infinity, alignment: .leading)
            }
        } else {
            ContentUnavailableView("Select an item", systemImage: "eye")
        }
    }
}
