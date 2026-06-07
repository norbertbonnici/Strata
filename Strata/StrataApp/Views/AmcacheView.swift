import SwiftUI

/// Reconstructed Amcache program-presence records for the active scope: one row
/// per binary Amcache knows about, with its recovered SHA-1 and registration
/// time. Mirrors EventsView's filter-bar + table/detail split.
struct AmcacheView: View {
    @EnvironmentObject private var model: AppModel
    @State private var query = ""
    @State private var selectedID: AmcacheEntry.ID?

    private func filtered(_ entries: [AmcacheEntry]) -> [AmcacheEntry] {
        guard !query.isEmpty else { return entries }
        return entries.filter { e in
            e.name.localizedCaseInsensitiveContains(query)
                || (e.fullPath?.localizedCaseInsensitiveContains(query) ?? false)
                || (e.sha1?.localizedCaseInsensitiveContains(query) ?? false)
        }
    }

    var body: some View {
        let entries = model.amcache
        let visible = filtered(entries)
        return Group {
            if entries.isEmpty {
                ContentUnavailableView {
                    Label("No Amcache parsed yet", systemImage: "shippingbox.and.arrow.backward")
                } description: {
                    Text(model.files.isEmpty
                         ? "Ingest evidence first, then come back here."
                         : "Amcache is reconstructed when you parse the registry (Amcache.hve).")
                } actions: {
                    #if os(macOS)
                    if !model.files.isEmpty {
                        Button {
                            Task { await model.parseArtifacts() }
                        } label: {
                            Label("Parse artifacts", systemImage: "play.fill")
                        }
                        .disabled(model.isWorking)
                        .help("Parse event logs, registry hives (incl. Amcache), then run all analyzers.")
                    }
                    #endif
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else {
                VStack(spacing: 0) {
                    HStack(spacing: 12) {
                        Spacer()
                        TextField("Filter name / path / SHA-1...", text: $query)
                            .textFieldStyle(.roundedBorder)
                            .frame(width: 340)
                        #if os(macOS)
                        Button {
                            Task { await model.parseArtifacts() }
                        } label: { Image(systemName: "arrow.clockwise") }
                        .help("Re-parse artifacts, then re-run analyzers")
                        .disabled(model.isWorking)
                        #endif
                    }
                    .padding(8)
                    Divider()
                    split(visible, detail: entries.first { $0.id == selectedID })
                        .frame(maxWidth: .infinity, maxHeight: .infinity)
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .top)
            }
        }
        .navigationTitle(entries.isEmpty ? "Amcache" : "Amcache - \(visible.count) of \(entries.count)")
    }

    private func table(_ visible: [AmcacheEntry]) -> some View {
        Table(visible, selection: $selectedID) {
            TableColumn("Name") { e in
                Text(e.name).font(.caption).lineLimit(1).truncationMode(.middle)
            }
            TableColumn("SHA-1") { e in
                Text(e.sha1 ?? "—").font(.caption.monospaced()).lineLimit(1).truncationMode(.tail)
            }
            TableColumn("Size") { e in
                Text(e.size.map { ByteCountFormatter.string(fromByteCount: $0, countStyle: .file) } ?? "—")
                    .font(.caption).monospacedDigit()
            }
            TableColumn("Registered") { e in
                Text(e.registeredAt?.formatted(date: .numeric, time: .standard) ?? "—")
                    .font(.caption).monospacedDigit()
            }
            TableColumn("Path") { e in
                Text(e.fullPath ?? "—").font(.caption).lineLimit(1).truncationMode(.middle)
            }
        }
        .frame(minWidth: 600, maxHeight: .infinity)
    }

    @ViewBuilder
    private func split(_ visible: [AmcacheEntry], detail: AmcacheEntry?) -> some View {
        #if os(macOS)
        HSplitView {
            table(visible)
            AmcacheDetailView(entry: detail).frame(minWidth: 320, maxHeight: .infinity)
        }
        #else
        HStack(spacing: 0) {
            table(visible)
            Divider()
            AmcacheDetailView(entry: detail).frame(minWidth: 320, maxHeight: .infinity)
        }
        #endif
    }
}

private struct AmcacheDetailView: View {
    let entry: AmcacheEntry?
    var body: some View {
        if let entry {
            ScrollView {
                VStack(alignment: .leading, spacing: 10) {
                    Text(entry.name).font(.headline)
                    if let path = entry.fullPath {
                        LabeledContent("Path") {
                            Text(path).font(.caption.monospaced()).textSelection(.enabled)
                                .frame(maxWidth: .infinity, alignment: .trailing)
                        }
                    }
                    if let sha1 = entry.sha1 {
                        LabeledContent("SHA-1") {
                            Text(sha1).font(.caption.monospaced()).textSelection(.enabled)
                        }
                    }
                    if let size = entry.size {
                        LabeledContent("Size", value: "\(size) bytes")
                    }
                    if let linkDate = entry.linkDate {
                        LabeledContent("PE link date", value: linkDate.formatted(date: .abbreviated, time: .standard))
                    }
                    if let registered = entry.registeredAt {
                        LabeledContent("Registered", value: registered.formatted(date: .abbreviated, time: .standard))
                    }
                    if let product = entry.productName { LabeledContent("Product", value: product) }
                    if let publisher = entry.publisher { LabeledContent("Publisher", value: publisher) }
                    if let bin = entry.binaryType { LabeledContent("Binary type", value: bin) }
                    LabeledContent("Source", value: entry.source == .inventoryApplicationFile
                                   ? "InventoryApplicationFile" : "Root\\File (legacy)")
                    Divider()
                    Text("Amcache proves the file was present/registered on this host — not that it executed.")
                        .font(.caption).foregroundStyle(.secondary)
                }
                .padding()
                .frame(maxWidth: .infinity, alignment: .leading)
            }
        } else {
            ContentUnavailableView("Select an Amcache entry", systemImage: "shippingbox.and.arrow.backward")
        }
    }
}
