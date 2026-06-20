import SwiftUI

/// macOS network / device context: known Wi-Fi networks, DHCP leases, paired
/// Bluetooth devices, Time Machine destinations, and trusted iOS device pairings.
struct MacNetworkView: View {
    @EnvironmentObject private var model: AppModel
    @State private var query = ""
    @State private var kind: MacNetworkItem.Kind?
    @State private var selectedID: MacNetworkItem.ID?
    @State private var sort = [KeyPathComparator(\MacNetworkItem.sortTime, order: .reverse)]

    private func filtered(_ items: [MacNetworkItem]) -> [MacNetworkItem] {
        var out = items
        if let kind { out = out.filter { $0.kind == kind } }
        if !query.isEmpty {
            out = out.filter { i in
                i.name.localizedCaseInsensitiveContains(query)
                    || (i.identifier?.localizedCaseInsensitiveContains(query) ?? false)
                    || (i.detail?.localizedCaseInsensitiveContains(query) ?? false)
            }
        }
        return out
    }

    var body: some View {
        let rows = model.network
        let visible = filtered(rows).sorted(using: sort)
        let kinds = Array(Set(rows.map(\.kind))).sorted { $0.label < $1.label }
        return Group {
            if rows.isEmpty {
                ContentUnavailableView {
                    Label("No network/device data parsed yet", systemImage: "wifi")
                } description: {
                    Text(model.files.isEmpty
                         ? "Ingest a macOS image first, then come back here."
                         : "Click Parse to read Wi-Fi / DHCP / Bluetooth / Time Machine / pairing plists.")
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
                            Text("All").tag(MacNetworkItem.Kind?.none)
                            ForEach(kinds, id: \.self) { k in
                                Text(k.label).tag(MacNetworkItem.Kind?.some(k))
                            }
                        }
                        .pickerStyle(.menu)
                        .frame(width: 190)
                        Spacer()
                        TextField("Filter name / id / detail...", text: $query)
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
        .navigationTitle(rows.isEmpty ? "Network & Devices"
                         : "Network & Devices - \(visible.count.formatted()) of \(rows.count.formatted())")
    }

    private func table(_ visible: [MacNetworkItem]) -> some View {
        Table(visible, selection: $selectedID, sortOrder: $sort) {
            TableColumn("When", value: \.sortTime) { i in
                Text(i.timestamp?.formatted(date: .numeric, time: .standard) ?? "—")
                    .monospacedDigit().font(.caption)
            }
            .width(min: 130, ideal: 150, max: 180)
            TableColumn("Type", value: \.sortKind) { i in
                Text(i.kind.label).font(.caption).foregroundStyle(.secondary)
            }
            .width(min: 110, ideal: 130, max: 160)
            TableColumn("Name", value: \.name) { i in
                Text(i.title).font(.callout).lineLimit(1).truncationMode(.middle)
            }
            TableColumn("Identifier") { i in
                Text(i.identifier ?? "—").font(.caption.monospaced()).foregroundStyle(.secondary)
                    .lineLimit(1).truncationMode(.middle)
            }
        }
    }

    @ViewBuilder
    private func split(_ visible: [MacNetworkItem], detail: MacNetworkItem?) -> some View {
        #if os(macOS)
        HSplitView {
            table(visible).frame(minWidth: 560, maxHeight: .infinity)
            MacNetworkDetailView(item: detail).frame(minWidth: 300, maxHeight: .infinity)
        }
        #else
        table(visible)
        #endif
    }
}

private extension MacNetworkItem {
    var sortTime: Date { timestamp ?? .distantPast }
    var sortKind: String { kind.label }
}

private struct MacNetworkDetailView: View {
    let item: MacNetworkItem?

    var body: some View {
        if let item {
            ScrollView {
                VStack(alignment: .leading, spacing: 10) {
                    Text(item.title).font(.headline).textSelection(.enabled)
                    LabeledContent("Type", value: item.kind.label)
                    if let id = item.identifier {
                        LabeledContent("Identifier") {
                            Text(id).font(.caption.monospaced()).textSelection(.enabled)
                                .frame(maxWidth: .infinity, alignment: .trailing)
                        }
                    }
                    LabeledContent("When", value: item.timestamp?.formatted(date: .long, time: .standard) ?? "—")
                    if let d = item.detail {
                        LabeledContent("Detail") {
                            Text(d).font(.caption).textSelection(.enabled)
                                .frame(maxWidth: .infinity, alignment: .trailing)
                        }
                    }
                    LabeledContent("Scope", value: item.scope)
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
            ContentUnavailableView("Select an item", systemImage: "wifi")
        }
    }
}
