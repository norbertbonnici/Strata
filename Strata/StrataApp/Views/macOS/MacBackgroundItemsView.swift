import SwiftUI

/// macOS Background Task Management inventory (`.btm`) — registered login items,
/// launch agents, and daemons. Apple's own items are expected; the analyst's
/// interest is the third-party ones (especially in staging paths, or disabled).
struct MacBackgroundItemsView: View {
    @EnvironmentObject private var model: AppModel
    @State private var query = ""
    @State private var thirdPartyOnly = false
    @State private var selectedID: MacBackgroundItem.ID?
    @State private var sort = [KeyPathComparator(\MacBackgroundItem.title, order: .forward)]

    private func filtered(_ items: [MacBackgroundItem]) -> [MacBackgroundItem] {
        var out = items
        if thirdPartyOnly { out = out.filter { !$0.isApple } }
        if !query.isEmpty {
            out = out.filter { e in
                e.title.localizedCaseInsensitiveContains(query)
                    || (e.bundleID?.localizedCaseInsensitiveContains(query) ?? false)
                    || (e.executable?.localizedCaseInsensitiveContains(query) ?? false)
                    || (e.developerName?.localizedCaseInsensitiveContains(query) ?? false)
            }
        }
        return out
    }

    var body: some View {
        let rows = model.backgroundItems
        let visible = filtered(rows).sorted(using: sort)
        return Group {
            if rows.isEmpty {
                ContentUnavailableView {
                    Label("No background items parsed yet", systemImage: "person.badge.clock")
                } description: {
                    Text(model.files.isEmpty
                         ? "Ingest a macOS image first, then come back here."
                         : "Click Parse to read the Background Task Management store (.btm).")
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
                        Toggle("Third-party only", isOn: $thirdPartyOnly)
                            #if os(macOS)
                            .toggleStyle(.checkbox)
                            #endif
                        Spacer()
                        TextField("Filter name / bundle / path...", text: $query)
                            .textFieldStyle(.roundedBorder)
                            .frame(width: 280)
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
        .navigationTitle(rows.isEmpty ? "Background Items"
                         : "Background Items - \(visible.count.formatted()) of \(rows.count.formatted())")
    }

    private func table(_ visible: [MacBackgroundItem]) -> some View {
        Table(visible, selection: $selectedID, sortOrder: $sort) {
            TableColumn("Name", value: \.title) { e in
                HStack(spacing: 6) {
                    if !e.isApple {
                        Image(systemName: "exclamationmark.triangle.fill")
                            .foregroundStyle(.orange).font(.caption)
                    }
                    Text(e.title).font(.callout).lineLimit(1).truncationMode(.middle)
                }
            }
            TableColumn("Type") { e in
                Text(e.typeLabel).font(.caption).foregroundStyle(.secondary)
            }
            .width(min: 90, ideal: 120, max: 160)
            TableColumn("State") { e in
                if let enabled = e.enabled {
                    Text(enabled ? "enabled" : "disabled")
                        .font(.caption).foregroundStyle(enabled ? Color.secondary : Color.orange)
                } else {
                    Text("—").font(.caption).foregroundStyle(.secondary)
                }
            }
            .width(min: 60, ideal: 80, max: 100)
            TableColumn("Identity") { e in
                Text(e.bundleID ?? e.executable ?? "—")
                    .font(.caption.monospaced()).foregroundStyle(.secondary)
                    .lineLimit(1).truncationMode(.middle)
            }
        }
    }

    @ViewBuilder
    private func split(_ visible: [MacBackgroundItem], detail: MacBackgroundItem?) -> some View {
        #if os(macOS)
        HSplitView {
            table(visible).frame(minWidth: 560, maxHeight: .infinity)
            MacBackgroundItemDetailView(item: detail).frame(minWidth: 300, maxHeight: .infinity)
        }
        #else
        table(visible)
        #endif
    }
}

private struct MacBackgroundItemDetailView: View {
    let item: MacBackgroundItem?

    var body: some View {
        if let item {
            ScrollView {
                VStack(alignment: .leading, spacing: 10) {
                    HStack(spacing: 6) {
                        Text(item.title).font(.headline).textSelection(.enabled)
                        if !item.isApple {
                            Text("third-party").font(.caption2)
                                .padding(.horizontal, 6).padding(.vertical, 2)
                                .background(Color.orange.opacity(0.2)).clipShape(Capsule())
                        }
                    }
                    LabeledContent("Type", value: item.typeLabel)
                    if let enabled = item.enabled {
                        LabeledContent("State", value: enabled ? "Enabled" : "Disabled / not active")
                    }
                    if let b = item.bundleID { LabeledContent("Bundle ID", value: b) }
                    if let d = item.developerName, !d.isEmpty { LabeledContent("Developer", value: d) }
                    if let t = item.teamID, !t.isEmpty { LabeledContent("Team ID", value: t) }
                    LabeledContent("Signed by", value: item.isApple ? "Apple" : "third-party")
                    if let e = item.executable {
                        LabeledContent("Executable") {
                            Text(e).font(.caption.monospaced()).textSelection(.enabled)
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
            ContentUnavailableView("Select a background item", systemImage: "person.badge.clock")
        }
    }
}
