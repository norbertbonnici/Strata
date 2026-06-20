import SwiftUI

/// macOS **KnowledgeC** behavioural timeline — which app was in focus and for
/// how long, screen on/off, media, Safari visits. Sortable/filterable, with a
/// category filter so an examiner can isolate app usage from device state.
struct KnowledgeCView: View {
    @EnvironmentObject private var model: AppModel
    @State private var query = ""
    @State private var category: KnowledgeEntry.Category?
    @State private var selectedID: KnowledgeEntry.ID?
    @State private var sort = [KeyPathComparator(\KnowledgeEntry.sortTime, order: .reverse)]

    private func filtered(_ rows: [KnowledgeEntry]) -> [KnowledgeEntry] {
        var out = rows
        if let category { out = out.filter { $0.category == category } }
        if !query.isEmpty {
            out = out.filter {
                ($0.value?.localizedCaseInsensitiveContains(query) ?? false)
                    || $0.stream.localizedCaseInsensitiveContains(query)
            }
        }
        return out
    }

    var body: some View {
        let rows = model.knowledgeC
        let visible = filtered(rows).sorted(using: sort)
        let categories = Array(Set(rows.map(\.category))).sorted { $0.label < $1.label }
        return Group {
            if rows.isEmpty {
                ContentUnavailableView {
                    Label("No KnowledgeC data parsed yet", systemImage: "brain")
                } description: {
                    Text(model.files.isEmpty
                         ? "Ingest a macOS image first, then come back here."
                         : "Click Parse to read the KnowledgeC activity store.")
                } actions: {
                    #if os(macOS)
                    if !model.files.isEmpty {
                        Button { Task { await model.parseArtifacts() } } label: {
                            Label("Parse artifacts", systemImage: "play.fill")
                        }
                        .disabled(model.isWorking)
                    }
                    #endif
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else {
                VStack(spacing: 0) {
                    HStack(spacing: 12) {
                        Picker("Category", selection: $category) {
                            Text("All").tag(KnowledgeEntry.Category?.none)
                            ForEach(categories, id: \.self) { c in
                                Text(c.label).tag(KnowledgeEntry.Category?.some(c))
                            }
                        }
                        .pickerStyle(.menu).frame(width: 170)
                        Spacer()
                        TextField("Filter app / value...", text: $query)
                            .textFieldStyle(.roundedBorder).frame(width: 260)
                    }
                    .padding(8)
                    Divider()
                    split(visible, detail: rows.first { $0.id == selectedID })
                }
            }
        }
        .navigationTitle(rows.isEmpty ? "KnowledgeC" : "KnowledgeC — \(visible.count.formatted()) of \(rows.count.formatted())")
    }

    private func table(_ visible: [KnowledgeEntry]) -> some View {
        Table(visible, selection: $selectedID, sortOrder: $sort) {
            TableColumn("Start", value: \.sortTime) { e in
                Text(e.startDate.map { $0.formatted(date: .numeric, time: .standard) } ?? "—")
                    .monospacedDigit()
            }
            .width(min: 130, ideal: 150, max: 170)
            TableColumn("Category", value: \.sortCategory) { e in
                Text(e.category.label).font(.caption).foregroundStyle(.secondary)
            }
            .width(min: 80, ideal: 100, max: 130)
            TableColumn("Detail", value: \.summary) { e in
                Text(e.summary).font(.callout).lineLimit(1).truncationMode(.middle)
            }
            TableColumn("Duration") { e in
                Text(e.duration.map { "\(Int($0))s" } ?? "—")
                    .font(.caption.monospacedDigit()).foregroundStyle(.secondary)
            }
            .width(min: 56, ideal: 64, max: 80)
        }
    }

    @ViewBuilder
    private func split(_ visible: [KnowledgeEntry], detail: KnowledgeEntry?) -> some View {
        #if os(macOS)
        HSplitView {
            table(visible).frame(minWidth: 540, maxHeight: .infinity)
            KnowledgeCDetailView(entry: detail).frame(minWidth: 260, maxHeight: .infinity)
        }
        #else
        table(visible)
        #endif
    }
}

private extension KnowledgeEntry {
    var sortTime: Date { startDate ?? .distantPast }
    var sortCategory: String { category.label }
}

private struct KnowledgeCDetailView: View {
    let entry: KnowledgeEntry?
    var body: some View {
        if let entry {
            ScrollView {
                VStack(alignment: .leading, spacing: 10) {
                    Text(entry.category.label).font(.headline)
                    LabeledContent("Detail", value: entry.summary)
                    if let v = entry.value { LabeledContent("Value", value: v) }
                    LabeledContent("Stream", value: entry.stream)
                    if let s = entry.startDate {
                        LabeledContent("Start", value: s.formatted(date: .long, time: .standard))
                    }
                    if let e = entry.endDate {
                        LabeledContent("End", value: e.formatted(date: .long, time: .standard))
                    }
                    if let d = entry.duration { LabeledContent("Duration", value: "\(Int(d)) s") }
                    LabeledContent("Scope", value: entry.scope)
                    LabeledContent("Source") {
                        Text(entry.sourceFile).font(.caption.monospaced()).textSelection(.enabled)
                            .frame(maxWidth: .infinity, alignment: .trailing)
                    }
                }
                .padding()
                .frame(maxWidth: .infinity, alignment: .leading)
            }
        } else {
            ContentUnavailableView("Select a record", systemImage: "brain")
        }
    }
}
