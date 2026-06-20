import SwiftUI

/// Cross-artifact global search (roadmap #6). One query box over the active
/// scope's files, events, registry values, timeline, and findings, ranked by
/// `SearchEngine`. The scan runs off-main (the collections can be ~1M rows) and
/// re-derives only when the debounced query or the case data changes.
struct GlobalSearchView: View {
    @EnvironmentObject private var model: AppModel
    @State private var query = ""
    @State private var hits: [SearchHit] = []
    @State private var isSearching = false
    @State private var kindFilter: SearchHit.Kind?

    private struct Key: Equatable { let q: String; let version: Int }
    private var key: Key { Key(q: query, version: model.dataVersion) }

    private var shown: [SearchHit] {
        guard let kindFilter else { return hits }
        return hits.filter { $0.kind == kindFilter }
    }

    var body: some View {
        VStack(spacing: 0) {
            HStack(spacing: 8) {
                Image(systemName: "magnifyingglass").foregroundStyle(.secondary)
                TextField("Search files, events, registry, timeline, findings…", text: $query)
                    .textFieldStyle(.plain)
                    .font(.body)
                if isSearching { ProgressView().controlSize(.small) }
                if !query.isEmpty {
                    Button { query = "" } label: { Image(systemName: "xmark.circle.fill") }
                        .buttonStyle(.borderless).foregroundStyle(.secondary)
                }
            }
            .padding(10)
            Divider()
            if !hits.isEmpty {
                HStack(spacing: 6) {
                    kindChip(nil, "All \(hits.count)")
                    ForEach(SearchHit.Kind.allCases, id: \.self) { k in
                        let n = hits.filter { $0.kind == k }.count
                        if n > 0 { kindChip(k, "\(k.label) \(n)") }
                    }
                    Spacer()
                }
                .padding(.horizontal, 10).padding(.vertical, 6)
                Divider()
            }
            content
        }
        .navigationTitle(query.isEmpty ? "Search" : "Search — \(shown.count) result\(shown.count == 1 ? "" : "s")")
        .task(id: key) { await runSearch() }
    }

    @ViewBuilder
    private var content: some View {
        if model.currentCase == nil {
            ContentUnavailableView("Open a case", systemImage: "magnifyingglass",
                description: Text("Global search runs across a loaded case."))
        } else if query.trimmingCharacters(in: .whitespaces).count < 2 {
            ContentUnavailableView("Type to search", systemImage: "magnifyingglass",
                description: Text("At least two characters. Searches file paths, event payloads, registry keys/values, timeline detail, and findings."))
        } else if shown.isEmpty && !isSearching {
            ContentUnavailableView.search(text: query)
        } else {
            List(shown) { hit in
                HStack(alignment: .top, spacing: 10) {
                    Image(systemName: icon(hit.kind)).foregroundStyle(color(hit.kind)).frame(width: 18)
                    VStack(alignment: .leading, spacing: 2) {
                        HStack(spacing: 6) {
                            Text(hit.title).font(.callout.bold()).lineLimit(1)
                            Text(hit.kind.label).font(.caption2)
                                .padding(.horizontal, 5).padding(.vertical, 1)
                                .background(color(hit.kind).opacity(0.18), in: Capsule())
                                .foregroundStyle(color(hit.kind))
                        }
                        if !hit.subtitle.isEmpty {
                            Text(hit.subtitle).font(.caption).foregroundStyle(.secondary).lineLimit(1)
                        }
                        if !hit.snippet.isEmpty {
                            Text(hit.snippet).font(.caption.monospaced()).foregroundStyle(.secondary)
                                .lineLimit(2).truncationMode(.middle)
                        }
                    }
                    Spacer()
                }
                .padding(.vertical, 2)
            }
            #if os(macOS)
            .listStyle(.inset(alternatesRowBackgrounds: true))
            #endif
        }
    }

    private func kindChip(_ k: SearchHit.Kind?, _ label: String) -> some View {
        Button { kindFilter = k } label: {
            Text(label).font(.caption2)
                .padding(.horizontal, 8).padding(.vertical, 3)
                .background((kindFilter == k ? Color.accentColor : Color.secondary).opacity(0.18), in: Capsule())
        }
        .buttonStyle(.plain)
    }

    private func runSearch() async {
        let q = query.trimmingCharacters(in: .whitespaces)
        guard q.count >= 2 else { hits = []; return }
        isSearching = true
        defer { isSearching = false }
        // Snapshot the scoped collections, then rank off-main.
        let files = model.files, events = model.events, registry = model.registryValues
        let timeline = model.timeline, findings = model.findings
        let results = await Task.detached(priority: .userInitiated) {
            SearchEngine.search(query: q, files: files, events: events,
                                registry: registry, timeline: timeline, findings: findings)
        }.value
        if Task.isCancelled { return }
        hits = results
    }

    private func icon(_ k: SearchHit.Kind) -> String {
        switch k {
        case .file: return "doc"; case .event: return "doc.text.magnifyingglass"
        case .registry: return "list.bullet.indent"; case .timeline: return "clock"
        case .finding: return "exclamationmark.triangle"
        }
    }
    private func color(_ k: SearchHit.Kind) -> Color {
        switch k {
        case .file: return .blue; case .event: return .purple; case .registry: return .teal
        case .timeline: return .orange; case .finding: return .red
        }
    }
}
