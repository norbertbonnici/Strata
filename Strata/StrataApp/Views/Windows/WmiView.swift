import SwiftUI

/// Carved WMI event-subscription persistence (`OBJECTS.DATA`): filter→consumer
/// bindings (with the WQL trigger + command) and any script payloads carved from
/// the repository. Built-in Microsoft subscriptions (BVT/SCM) are marked.
struct WmiView: View {
    @EnvironmentObject private var model: AppModel
    @State private var query = ""
    @State private var hideBenign = true
    @State private var selectedID: WmiPersistenceEntry.ID?

    private func filtered(_ rows: [WmiPersistenceEntry]) -> [WmiPersistenceEntry] {
        var out = rows
        if hideBenign { out = out.filter { !$0.isCommonBenign } }
        guard !query.isEmpty else { return out }
        return out.filter { e in
            e.title.localizedCaseInsensitiveContains(query)
                || (e.command?.localizedCaseInsensitiveContains(query) ?? false)
                || (e.query?.localizedCaseInsensitiveContains(query) ?? false)
                || (e.scriptText?.localizedCaseInsensitiveContains(query) ?? false)
        }
    }

    var body: some View {
        let rows = model.wmi
        let visible = filtered(rows)
        let benignCount = rows.lazy.filter(\.isCommonBenign).count
        return Group {
            if rows.isEmpty {
                ContentUnavailableView {
                    Label("No WMI persistence parsed yet", systemImage: "gearshape.2")
                } description: {
                    Text(model.files.isEmpty
                         ? "Ingest evidence first, then come back here."
                         : "Click Parse to carve the WMI repository (OBJECTS.DATA) for event-subscription persistence.")
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
                        if benignCount > 0 {
                            Toggle("Hide built-in (\(benignCount))", isOn: $hideBenign)
                                .toggleStyle(.switch).controlSize(.small)
                                .help("Hide Microsoft's built-in BVT/SCM subscriptions.")
                        }
                        Spacer()
                        TextField("Filter consumer / command / query / script...", text: $query)
                            .textFieldStyle(.roundedBorder).frame(width: 320)
                    }
                    .padding(8)
                    Divider()
                    split(visible, detail: rows.first { $0.id == selectedID })
                        .frame(maxWidth: .infinity, maxHeight: .infinity)
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .top)
            }
        }
        .navigationTitle(rows.isEmpty ? "WMI" : "WMI - \(visible.count) of \(rows.count)")
    }

    private func table(_ visible: [WmiPersistenceEntry]) -> some View {
        Table(visible, selection: $selectedID) {
            TableColumn("Kind") { e in
                HStack(spacing: 5) {
                    Image(systemName: e.kind == .scriptConsumer ? "curlybraces" : "arrow.triangle.branch")
                        .font(.caption2).foregroundStyle(e.isCommonBenign ? Color.secondary : Color.orange)
                    Text(e.kind.label).font(.caption).foregroundStyle(.secondary)
                }
            }
            TableColumn("Consumer / payload") { e in
                Text(e.consumerName ?? (e.scriptEngine.map { "\($0) script" } ?? "—"))
                    .font(.caption).lineLimit(1)
            }
            TableColumn("Filter") { e in
                Text(e.filterName ?? "—").font(.caption).foregroundStyle(.secondary).lineLimit(1)
            }
            TableColumn("Detail") { e in
                Text(e.detailSummary).font(.caption.monospaced()).lineLimit(1).truncationMode(.middle)
            }
        }
        .frame(minWidth: 600, maxHeight: .infinity)
    }

    @ViewBuilder
    private func split(_ visible: [WmiPersistenceEntry], detail: WmiPersistenceEntry?) -> some View {
        #if os(macOS)
        HSplitView { table(visible); WmiDetailView(entry: detail).frame(minWidth: 320, maxHeight: .infinity) }
        #else
        HStack(spacing: 0) {
            table(visible); Divider(); WmiDetailView(entry: detail).frame(minWidth: 320, maxHeight: .infinity)
        }
        #endif
    }
}

private struct WmiDetailView: View {
    let entry: WmiPersistenceEntry?
    var body: some View {
        if let entry {
            ScrollView {
                VStack(alignment: .leading, spacing: 10) {
                    Text(entry.title).font(.headline).lineLimit(2)
                    if entry.isCommonBenign {
                        Label("Built-in Microsoft subscription (BVT/SCM)", systemImage: "checkmark.seal")
                            .font(.caption).foregroundStyle(.secondary)
                    } else {
                        Label("WMI event-subscription persistence (T1546.003)", systemImage: "exclamationmark.triangle.fill")
                            .font(.caption).foregroundStyle(.orange)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                    LabeledContent("Kind", value: entry.kind.label)
                    if let t = entry.consumerType { LabeledContent("Consumer type", value: t) }
                    if let n = entry.consumerName { LabeledContent("Consumer", value: n) }
                    if let f = entry.filterName { LabeledContent("Filter", value: f) }
                    if let e = entry.scriptEngine { LabeledContent("Script engine", value: e) }
                    if let q = entry.query, !q.isEmpty { block("Trigger (WQL)", q) }
                    if let c = entry.command, !c.isEmpty { block("Command", c) }
                    if let s = entry.scriptText, !s.isEmpty { block("Script", s) }
                    LabeledContent("Source") {
                        Text(entry.sourceFile).font(.caption.monospaced()).textSelection(.enabled)
                            .frame(maxWidth: .infinity, alignment: .trailing)
                    }
                }
                .padding()
                .frame(maxWidth: .infinity, alignment: .leading)
            }
        } else {
            ContentUnavailableView("Select an item", systemImage: "gearshape.2")
        }
    }

    private func block(_ title: String, _ value: String) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(title).font(.caption.bold()).foregroundStyle(.secondary)
            Text(value)
                .font(.system(size: 11, design: .monospaced)).textSelection(.enabled)
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(8)
                .background(.quaternary.opacity(0.4), in: RoundedRectangle(cornerRadius: 6))
        }
    }
}
