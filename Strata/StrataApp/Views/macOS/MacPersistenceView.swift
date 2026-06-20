import SwiftUI

/// The non-launchd macOS persistence sweep for the active scope - cron,
/// periodic, emond, login/logout hooks, rc scripts, and configuration profiles.
/// One row per mechanism. The launchd jobs live in the separate Launch Items
/// tab. Mirrors PrefetchView (filter bar + table/detail split + empty-state
/// parse).
struct MacPersistenceView: View {
    @EnvironmentObject private var model: AppModel
    @State private var query = ""
    @State private var selectedID: MacPersistenceItem.ID?

    private func filtered(_ items: [MacPersistenceItem]) -> [MacPersistenceItem] {
        guard !query.isEmpty else { return items }
        return items.filter { item in
            item.title.localizedCaseInsensitiveContains(query)
                || item.command.localizedCaseInsensitiveContains(query)
                || item.kind.label.localizedCaseInsensitiveContains(query)
                || item.sourceFile.localizedCaseInsensitiveContains(query)
        }
    }

    var body: some View {
        let items = model.macPersistence
        let visible = filtered(items)
        return Group {
            if items.isEmpty {
                ContentUnavailableView {
                    Label("No persistence parsed yet", systemImage: "calendar.badge.clock")
                } description: {
                    Text(model.files.isEmpty
                         ? "Ingest evidence first, then come back here."
                         : "Click Parse to sweep cron, periodic, emond, hooks, rc scripts, and profiles.")
                } actions: {
                    #if os(macOS)
                    if !model.files.isEmpty {
                        Button {
                            Task { await model.parseMac() }
                        } label: {
                            Label("Parse macOS artifacts", systemImage: "play.fill")
                        }
                        .disabled(model.isWorking)
                        .help("Parse launchd jobs, the persistence sweep, the quarantine store, and the macOS host info.")
                    }
                    #endif
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else {
                VStack(spacing: 0) {
                    HStack(spacing: 12) {
                        Spacer()
                        TextField("Filter kind / command / path...", text: $query)
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

                    split(visible, detail: items.first { $0.id == selectedID })
                        .frame(maxWidth: .infinity, maxHeight: .infinity)
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .top)
            }
        }
        .navigationTitle(items.isEmpty ? "Persistence" : "Persistence - \(visible.count) of \(items.count)")
    }

    private func table(_ visible: [MacPersistenceItem]) -> some View {
        Table(visible, selection: $selectedID) {
            TableColumn("Kind") { i in
                Text(i.kind.label).font(.caption)
            }
            TableColumn("Item") { i in
                Text(i.title).font(.caption).lineLimit(1).truncationMode(.middle)
            }
            TableColumn("Runs as") { i in
                Text(i.user ?? "—").font(.caption)
            }
            TableColumn("Command") { i in
                Text(i.command.isEmpty ? "—" : i.command).font(.caption).lineLimit(1).truncationMode(.middle)
            }
        }
        .frame(minWidth: 600, maxHeight: .infinity)
    }

    @ViewBuilder
    private func split(_ visible: [MacPersistenceItem], detail: MacPersistenceItem?) -> some View {
        #if os(macOS)
        HSplitView {
            table(visible)
            MacPersistenceDetailView(item: detail)
                .frame(minWidth: 320, maxHeight: .infinity)
        }
        #else
        HStack(spacing: 0) {
            table(visible)
            Divider()
            MacPersistenceDetailView(item: detail)
                .frame(minWidth: 320, maxHeight: .infinity)
        }
        #endif
    }
}

private struct MacPersistenceDetailView: View {
    let item: MacPersistenceItem?
    var body: some View {
        if let item {
            ScrollView {
                VStack(alignment: .leading, spacing: 10) {
                    Text(item.title).font(.headline).textSelection(.enabled)
                    LabeledContent("Mechanism", value: item.kind.label)
                    if let schedule = item.schedule {
                        LabeledContent("Schedule", value: schedule)
                    }
                    if let user = item.user {
                        LabeledContent("Runs as", value: user)
                    }
                    if let detail = item.detail, !detail.isEmpty {
                        LabeledContent("Details", value: detail)
                    }
                    if !item.command.isEmpty {
                        LabeledContent("Command") {
                            Text(item.command).font(.caption.monospaced()).textSelection(.enabled)
                                .frame(maxWidth: .infinity, alignment: .trailing)
                        }
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
            ContentUnavailableView("Select a persistence item", systemImage: "calendar.badge.clock")
        }
    }
}
