import SwiftUI

/// Parsed web-browser history for the active scope: page visits (one row per
/// distinct URL, with visit/typed counts and last-visit time) and downloads,
/// across Chromium-family browsers and Firefox.
struct BrowserHistoryView: View {
    @EnvironmentObject private var model: AppModel
    @State private var query = ""
    @State private var kindFilter: BrowserHistoryEntry.Kind?
    @State private var selectedID: BrowserHistoryEntry.ID?

    private func filtered(_ rows: [BrowserHistoryEntry]) -> [BrowserHistoryEntry] {
        var out = rows
        if let kindFilter { out = out.filter { $0.kind == kindFilter } }
        guard !query.isEmpty else { return out }
        return out.filter { r in
            r.url.localizedCaseInsensitiveContains(query)
                || (r.title?.localizedCaseInsensitiveContains(query) ?? false)
                || (r.targetPath?.localizedCaseInsensitiveContains(query) ?? false)
        }
    }

    var body: some View {
        let rows = model.browserHistory
        let visible = filtered(rows)
        return Group {
            if rows.isEmpty {
                ContentUnavailableView {
                    Label("No browser history parsed yet", systemImage: "globe")
                } description: {
                    Text(model.files.isEmpty
                         ? "Ingest evidence first, then come back here."
                         : "Click Parse to extract and parse browser history (Chrome/Edge/Firefox).")
                } actions: {
                    #if os(macOS)
                    if !model.files.isEmpty {
                        Button { Task { await model.parseArtifacts() } } label: {
                            Label("Parse artifacts", systemImage: "play.fill")
                        }
                        .disabled(model.isWorking)
                        .help("Parse event logs, registry, artifacts, and browser history, then run all analyzers.")
                    }
                    #endif
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else {
                VStack(spacing: 0) {
                    HStack(spacing: 12) {
                        Picker("Kind", selection: $kindFilter) {
                            Text("All").tag(BrowserHistoryEntry.Kind?.none)
                            ForEach(BrowserHistoryEntry.Kind.allCases, id: \.self) { k in
                                Text(k.label).tag(BrowserHistoryEntry.Kind?.some(k))
                            }
                        }
                        .pickerStyle(.menu)
                        .frame(width: 200)
                        Spacer()
                        TextField("Filter URL / title / saved path...", text: $query)
                            .textFieldStyle(.roundedBorder)
                            .frame(width: 300)
                        #if os(macOS)
                        Button { Task { await model.parseArtifacts() } } label: {
                            Image(systemName: "arrow.clockwise")
                        }
                        .help("Re-parse artifacts, then re-run analyzers")
                        .disabled(model.isWorking)
                        #endif
                    }
                    .padding(8)
                    Divider()
                    split(visible, detail: rows.first { $0.id == selectedID })
                        .frame(maxWidth: .infinity, maxHeight: .infinity)
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .top)
            }
        }
        .navigationTitle(rows.isEmpty ? "Browser History" : "Browser History - \(visible.count) of \(rows.count)")
    }

    private func table(_ visible: [BrowserHistoryEntry]) -> some View {
        Table(visible, selection: $selectedID) {
            TableColumn("Browser") { r in
                Text(r.browser.label).font(.caption).foregroundStyle(.secondary)
            }
            TableColumn("Title / URL") { r in
                VStack(alignment: .leading, spacing: 1) {
                    Text(r.displayTitle).font(.caption).lineLimit(1).truncationMode(.middle)
                    Text(r.url).font(.caption2).foregroundStyle(.secondary)
                        .lineLimit(1).truncationMode(.middle)
                }
            }
            TableColumn("Detail") { r in
                Text(r.detailSummary).font(.caption).monospacedDigit().lineLimit(1)
            }
            TableColumn("When") { r in
                Text(r.timestamp?.formatted(date: .numeric, time: .standard) ?? "—")
                    .font(.caption).monospacedDigit()
            }
        }
        .frame(minWidth: 600, maxHeight: .infinity)
    }

    @ViewBuilder
    private func split(_ visible: [BrowserHistoryEntry], detail: BrowserHistoryEntry?) -> some View {
        #if os(macOS)
        HSplitView {
            table(visible)
            BrowserHistoryDetailView(entry: detail).frame(minWidth: 300, maxHeight: .infinity)
        }
        #else
        HStack(spacing: 0) {
            table(visible)
            Divider()
            BrowserHistoryDetailView(entry: detail).frame(minWidth: 300, maxHeight: .infinity)
        }
        #endif
    }
}

private struct BrowserHistoryDetailView: View {
    let entry: BrowserHistoryEntry?
    var body: some View {
        if let entry {
            ScrollView {
                VStack(alignment: .leading, spacing: 10) {
                    Text(entry.displayTitle).font(.headline).lineLimit(3)
                    LabeledContent("Browser", value: entry.browser.label)
                    LabeledContent("Kind", value: entry.kind.label)
                    LabeledContent("URL") {
                        Text(entry.url).font(.caption.monospaced()).textSelection(.enabled)
                            .frame(maxWidth: .infinity, alignment: .trailing)
                    }
                    if let title = entry.title {
                        LabeledContent("Title") {
                            Text(title).font(.caption).textSelection(.enabled)
                                .frame(maxWidth: .infinity, alignment: .trailing)
                        }
                    }
                    if let t = entry.timestamp {
                        LabeledContent("Timestamp", value: t.formatted(date: .abbreviated, time: .standard))
                    }
                    if let v = entry.visitCount { LabeledContent("Visits", value: "\(v)") }
                    if let typed = entry.typedCount, typed > 0 {
                        LabeledContent("Typed", value: "\(typed)×")
                    }
                    if let target = entry.targetPath {
                        LabeledContent("Saved to") {
                            Text(target).font(.caption.monospaced()).textSelection(.enabled)
                                .frame(maxWidth: .infinity, alignment: .trailing)
                        }
                    }
                    if let r = entry.receivedBytes {
                        LabeledContent("Received", value: BrowserHistoryEntry.humanBytes(r))
                    }
                    if let total = entry.totalBytes, total > 0 {
                        LabeledContent("Total size", value: BrowserHistoryEntry.humanBytes(total))
                    }
                    if let ref = entry.referrer {
                        LabeledContent("From page") {
                            Text(ref).font(.caption.monospaced()).textSelection(.enabled)
                                .frame(maxWidth: .infinity, alignment: .trailing)
                        }
                    }
                    if let profile = entry.userProfile {
                        LabeledContent("Profile", value: profile)
                    }
                    LabeledContent("Source") {
                        Text(entry.sourceFile).font(.caption.monospaced()).textSelection(.enabled)
                            .frame(maxWidth: .infinity, alignment: .trailing)
                    }
                }
                .padding()
                .frame(maxWidth: .infinity, alignment: .leading)
            }
        } else {
            ContentUnavailableView("Select a row", systemImage: "globe")
        }
    }
}
