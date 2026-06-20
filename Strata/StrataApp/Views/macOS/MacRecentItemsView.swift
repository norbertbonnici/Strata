import SwiftUI

/// Parsed macOS Recent Items / LSSharedFileList stores: recently opened apps,
/// documents, servers, Finder favorites, and sidebar locations.
struct MacRecentItemsView: View {
    @EnvironmentObject private var model: AppModel
    @State private var query = ""
    @State private var kind: MacRecentItem.ListKind?
    @State private var selectedID: MacRecentItem.ID?
    @State private var sort = [KeyPathComparator(\MacRecentItem.sortTime, order: .reverse)]

    private func filtered(_ items: [MacRecentItem]) -> [MacRecentItem] {
        var out = items
        if let kind { out = out.filter { $0.kind == kind } }
        if !query.isEmpty {
            out = out.filter { item in
                item.title.localizedCaseInsensitiveContains(query)
                    || item.value.localizedCaseInsensitiveContains(query)
                    || item.sourceFile.localizedCaseInsensitiveContains(query)
                    || item.scope.localizedCaseInsensitiveContains(query)
            }
        }
        return out
    }

    var body: some View {
        let rows = model.macRecentItems
        let visible = filtered(rows).sorted(using: sort)
        let kinds = Array(Set(rows.map(\.kind))).sorted { $0.label < $1.label }
        return Group {
            if rows.isEmpty {
                ContentUnavailableView {
                    Label("No recent items parsed yet", systemImage: "clock.arrow.circlepath")
                } description: {
                    Text(model.files.isEmpty
                         ? "Ingest a macOS image first, then come back here."
                         : "Click Parse to read Recent Items and LSSharedFileList stores.")
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
                        Picker("Kind", selection: $kind) {
                            Text("All").tag(MacRecentItem.ListKind?.none)
                            ForEach(kinds, id: \.self) { kind in
                                Text(kind.label).tag(MacRecentItem.ListKind?.some(kind))
                            }
                        }
                        .pickerStyle(.menu)
                        .frame(width: 170)

                        Spacer()

                        TextField("Filter title / path / URL...", text: $query)
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
        .navigationTitle(rows.isEmpty ? "Recent Items" : "Recent Items - \(visible.count.formatted()) of \(rows.count.formatted())")
    }

    private func table(_ visible: [MacRecentItem]) -> some View {
        Table(visible, selection: $selectedID, sortOrder: $sort) {
            TableColumn("When", value: \.sortTime) { item in
                Text(item.timestamp?.formatted(date: .numeric, time: .standard) ?? "-")
                    .monospacedDigit()
                    .font(.caption)
            }
            .width(min: 130, ideal: 150, max: 180)

            TableColumn("Kind", value: \.sortKind) { item in
                Text(item.kind.label)
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            .width(min: 90, ideal: 110, max: 140)

            TableColumn("Item", value: \.title) { item in
                Text(item.title)
                    .font(.callout)
                    .lineLimit(1)
                    .truncationMode(.middle)
            }

            TableColumn("Scope", value: \.scope) { item in
                Text(item.scope)
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            .width(min: 70, ideal: 90, max: 120)
        }
    }

    @ViewBuilder
    private func split(_ visible: [MacRecentItem], detail: MacRecentItem?) -> some View {
        #if os(macOS)
        HSplitView {
            table(visible).frame(minWidth: 620, maxHeight: .infinity)
            MacRecentItemDetailView(item: detail).frame(minWidth: 320, maxHeight: .infinity)
        }
        #else
        table(visible)
        #endif
    }
}

private extension MacRecentItem {
    var sortTime: Date { timestamp ?? .distantPast }
    var sortKind: String { kind.label }
}

private struct MacRecentItemDetailView: View {
    let item: MacRecentItem?

    var body: some View {
        if let item {
            ScrollView {
                VStack(alignment: .leading, spacing: 10) {
                    Text(item.title)
                        .font(.headline)
                        .textSelection(.enabled)
                    LabeledContent("Kind", value: item.kind.label)
                    LabeledContent("When", value: item.timestamp?.formatted(date: .long, time: .standard) ?? "-")
                    LabeledContent("Scope", value: item.scope)
                    LabeledContent("Value") {
                        Text(item.value)
                            .font(.caption.monospaced())
                            .textSelection(.enabled)
                            .frame(maxWidth: .infinity, alignment: .trailing)
                    }
                    Divider()
                    LabeledContent("Source store") {
                        Text(item.sourceFile)
                            .font(.caption.monospaced())
                            .textSelection(.enabled)
                            .frame(maxWidth: .infinity, alignment: .trailing)
                    }
                }
                .padding()
                .frame(maxWidth: .infinity, alignment: .leading)
            }
        } else {
            ContentUnavailableView("Select a recent item", systemImage: "clock.arrow.circlepath")
        }
    }
}
