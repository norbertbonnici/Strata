import SwiftUI

/// Regedit-style registry explorer: a key tree (grouped by hive) on the left,
/// the selected key's values on the right. Structurally mirrors
/// `EvidenceTreeView` — snapshot once, keep the tree in `@State`, and rebuild
/// off the main render path (on appear / data change / search), never in `body`.
struct RegistryView: View {
    @EnvironmentObject private var model: AppModel
    @State private var tree: [RegistryNode] = []
    @State private var selectedKey: RegistryNode?
    @State private var search: String = ""
    /// Flat search matches, recomputed off `body` (the value set can be tens of
    /// thousands of rows, so filtering per keystroke must not run in render).
    @State private var searchResults: [RegistryValue] = []

    private var isSearching: Bool {
        !search.trimmingCharacters(in: .whitespaces).isEmpty
    }

    var body: some View {
        let values = model.registryValues          // cached snapshot
        return Group {
            if values.isEmpty {
                ContentUnavailableView(
                    "No registry parsed",
                    systemImage: "list.bullet.indent",
                    description: Text("Parse this case's registry hives to browse keys and values here."))
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else {
                VStack(spacing: 0) {
                    header(valueCount: values.count)
                    Divider()
                    registrySplit
                        .frame(maxWidth: .infinity, maxHeight: .infinity)
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .top)
            }
        }
        .navigationTitle("Registry")
        .onAppear { rebuildTree() }
        .onChange(of: model.dataVersion) {
            rebuildTree()
            recomputeSearch()
            // Re-resolve the selection against the fresh tree: the value-type
            // node could otherwise dangle at the old host/scope.
            if let sel = selectedKey {
                selectedKey = Self.findNode(id: sel.id, in: tree)
            }
        }
        .onChange(of: search) { recomputeSearch() }
    }

    private func header(valueCount: Int) -> some View {
        HStack(spacing: 10) {
            Image(systemName: "magnifyingglass").foregroundStyle(.secondary)
            TextField("Search keys, values, data", text: $search)
                .textFieldStyle(.roundedBorder)
                .frame(maxWidth: 320)
            if isSearching {
                Button { search = "" } label: { Image(systemName: "xmark.circle.fill") }
                    .buttonStyle(.plain)
                    .foregroundStyle(.secondary)
                    .help("Clear search")
            }
            Spacer()
            Text("\(tree.count) hive\(tree.count == 1 ? "" : "s") · \(valueCount.formatted()) values")
                .font(.caption).foregroundStyle(.secondary)
        }
        .padding(.horizontal, 12).padding(.vertical, 6)
    }

    private func rebuildTree() {
        tree = RegistryNode.buildTree(from: model.registryValues)
    }

    private func recomputeSearch() {
        guard isSearching else { searchResults = []; return }
        searchResults = model.registryValues
            .filter { $0.matches(search) }
            .sorted {
                let p = $0.fullPath.localizedStandardCompare($1.fullPath)
                if p != .orderedSame { return p == .orderedAscending }
                return $0.name.localizedStandardCompare($1.name) == .orderedAscending
            }
    }

    @ViewBuilder private var registrySplit: some View {
        #if os(macOS)
        HSplitView {
            keyPane.frame(minWidth: 320, maxHeight: .infinity)
            RegistryValuePane(key: selectedKey).frame(minWidth: 320, maxHeight: .infinity)
        }
        #else
        HStack(spacing: 0) {
            keyPane
            Divider()
            RegistryValuePane(key: selectedKey).frame(minWidth: 280, maxHeight: .infinity)
        }
        #endif
    }

    @ViewBuilder private var keyPane: some View {
        if isSearching { searchList } else { keyTree }
    }

    private var keyTree: some View {
        List {
            OutlineGroup(tree, children: \.children) { node in
                HStack {
                    Image(systemName: node.isHive ? "externaldrive" : "folder")
                        .foregroundStyle(node.isHive ? Color.accentColor : .secondary)
                    Text(node.name)
                        .fontWeight(node.isHive ? .semibold : .regular)
                        .lineLimit(1).truncationMode(.middle)
                    Spacer()
                    if !node.values.isEmpty {
                        Text("\(node.values.count)")
                            .font(.caption).foregroundStyle(.secondary)
                    }
                }
                .contentShape(Rectangle())
                .onTapGesture { selectedKey = node }
            }
        }
    }

    /// Search mode: a flat, immediately-visible list of matching values (no
    /// manual tree expansion). Tapping a result selects its owning key so the
    /// right pane shows it in the context of its sibling values.
    private var searchList: some View {
        List(searchResults) { value in
            VStack(alignment: .leading, spacing: 2) {
                Text(value.name.isEmpty ? "(default)" : value.name)
                    .fontWeight(.medium)
                    .lineLimit(1).truncationMode(.middle)
                Text(value.fullPath)
                    .font(.caption).foregroundStyle(.secondary)
                    .lineLimit(1).truncationMode(.middle)
            }
            .contentShape(Rectangle())
            .onTapGesture { selectedKey = Self.findNode(id: keyID(for: value), in: tree) }
        }
        .overlay {
            if searchResults.isEmpty { ContentUnavailableView.search(text: search) }
        }
    }

    /// The node id of the key that owns `value`: "hive:<H>" when the value sits
    /// at the hive root, else "<H>\<components>" — matching how
    /// `RegistryNode.buildHive` ids its key nodes.
    private func keyID(for value: RegistryValue) -> String {
        let comps = value.path.components(separatedBy: "\\").filter { !$0.isEmpty }
        return comps.isEmpty ? "hive:\(value.hive)" : ([value.hive] + comps).joined(separator: "\\")
    }

    /// Depth-first lookup of a node by id within a freshly built tree.
    private static func findNode(id: String, in nodes: [RegistryNode]) -> RegistryNode? {
        for node in nodes {
            if node.id == id { return node }
            if let kids = node.children, let hit = findNode(id: id, in: kids) { return hit }
        }
        return nil
    }
}

// MARK: - Value pane

/// Right-hand pane: the selected key's full path + last-written header, then
/// one row per value (name, type badge, decoded data).
private struct RegistryValuePane: View {
    let key: RegistryNode?

    var body: some View {
        if let key {
            ScrollView {
                VStack(alignment: .leading, spacing: 0) {
                    VStack(alignment: .leading, spacing: 6) {
                        Text(key.displayPath)
                            .font(.system(.headline, design: .monospaced))
                            .textSelection(.enabled)
                            .frame(maxWidth: .infinity, alignment: .leading)
                        HStack(spacing: 12) {
                            if let lw = key.lastWritten {
                                Label(lw.formatted(date: .abbreviated, time: .standard),
                                      systemImage: "clock")
                                    .font(.caption).foregroundStyle(.secondary)
                            }
                            Text("\(key.values.count) value\(key.values.count == 1 ? "" : "s")")
                                .font(.caption).foregroundStyle(.secondary)
                        }
                    }
                    .padding()
                    Divider()
                    if key.values.isEmpty {
                        Text("This key has no values.")
                            .font(.callout).foregroundStyle(.secondary)
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .padding()
                    } else {
                        ForEach(key.values) { value in
                            RegistryValueRow(value: value)
                            Divider()
                        }
                    }
                }
                .frame(maxWidth: .infinity, alignment: .leading)
            }
        } else {
            ContentUnavailableView("Select a key", systemImage: "list.bullet.indent",
                description: Text("Choose a registry key to see its values."))
        }
    }
}

private struct RegistryValueRow: View {
    let value: RegistryValue

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack(spacing: 8) {
                Text(value.name.isEmpty ? "(default)" : value.name)
                    .fontWeight(.medium)
                    .foregroundStyle(value.name.isEmpty ? .secondary : .primary)
                    .textSelection(.enabled)
                Text(value.typeBadge)
                    .font(.caption2)
                    .padding(.horizontal, 5).padding(.vertical, 1)
                    .background(.secondary.opacity(0.15), in: Capsule())
                    .foregroundStyle(.secondary)
                Spacer()
            }
            Text(value.decodedData.isEmpty ? "(empty)" : value.decodedData)
                .font(.system(.callout, design: .monospaced))
                .foregroundStyle(value.decodedData.isEmpty ? .secondary : .primary)
                .textSelection(.enabled)
                .lineLimit(6)
                .truncationMode(.tail)
                .frame(maxWidth: .infinity, alignment: .leading)
        }
        .padding(.horizontal, 12).padding(.vertical, 8)
    }
}
