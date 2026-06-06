import SwiftUI

struct EvidenceTreeView: View {
    @EnvironmentObject private var model: AppModel
    @State private var selection: FileEntry?
    @State private var showDeleted = false
    /// Memoized tree, rebuilt off the main thread when the file set or the
    /// deleted toggle changes. Rebuilding it inside body re-allocated and
    /// re-sorted the whole node graph on every unrelated state change.
    @State private var tree: [FileNode] = []

    private struct TreeKey: Equatable { let version: Int; let showDeleted: Bool }

    var body: some View {
        // Snapshot once (cached) for the header counts.
        let allFiles = model.files
        let visibleCount = showDeleted ? allFiles.count
                                       : allFiles.lazy.filter { !$0.isDeleted }.count
        let hidden = showDeleted ? 0 : allFiles.count - visibleCount
        return Group {
            if allFiles.isEmpty {
                ContentUnavailableView("No files loaded", systemImage: "folder",
                    description: Text("Open an E01 or KAPE .vhd to enumerate the file system."))
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else {
                VStack(spacing: 0) {
                    HStack(spacing: 12) {
                        Toggle("Show deleted / unallocated", isOn: $showDeleted)
                            .toggleStyle(.switch)
                            .controlSize(.small)
                        if hidden > 0 {
                            Text("\(hidden) hidden")
                                .font(.caption).foregroundStyle(.secondary)
                        }
                        Spacer()
                        Text("\(visibleCount) files")
                            .font(.caption).foregroundStyle(.secondary)
                    }
                    .padding(.horizontal, 12).padding(.vertical, 6)
                    Divider()
                    evidenceSplit
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .top)
            }
        }
        .navigationTitle("Evidence")
        .task(id: TreeKey(version: model.dataVersion, showDeleted: showDeleted)) {
            await rebuildTree()
        }
        .onChange(of: model.dataVersion) {
            // Drop or refresh a stale selection when the file set / scope changes
            // (the value-type FileEntry could otherwise point at another host).
            if let sel = selection {
                selection = model.files.first { $0.id == sel.id }
            }
        }
    }

    private func rebuildTree() async {
        let files = showDeleted ? model.files : model.files.filter { !$0.isDeleted }
        let built = await Task.detached(priority: .userInitiated) {
            FileNode.buildTree(from: files)
        }.value
        if Task.isCancelled { return }
        tree = built
    }

    private func byteString(_ bytes: Int64) -> String {
        ByteCountFormatter.string(fromByteCount: bytes, countStyle: .file)
    }

    private var evidenceTree: some View {
        List {
            OutlineGroup(tree, children: \.children) { node in
                HStack {
                    Image(systemName: (node.entry?.isDirectory ?? true) ? "folder" : "doc")
                        .foregroundStyle(.secondary)
                    Text(node.name)
                    if node.entry?.isDeleted == true {
                        Text("deleted").font(.caption2)
                            .padding(.horizontal, 5).padding(.vertical, 1)
                            .background(.red.opacity(0.2), in: Capsule())
                            .foregroundStyle(.red)
                    }
                    Spacer()
                    if let entry = node.entry, entry.isDirectory == false {
                        Text(byteString(entry.size)).font(.caption).foregroundStyle(.secondary)
                    }
                }
                .contentShape(Rectangle())
                .onTapGesture { if let e = node.entry { selection = e } }
            }
        }
        .frame(minWidth: 360, maxHeight: .infinity)
    }

    @ViewBuilder
    private var evidenceSplit: some View {
        #if os(macOS)
        HSplitView {
            evidenceTree
            FileDetailView(entry: selection).frame(minWidth: 280, maxHeight: .infinity)
        }
        #else
        HStack(spacing: 0) {
            evidenceTree
            Divider()
            FileDetailView(entry: selection).frame(minWidth: 280, maxHeight: .infinity)
        }
        #endif
    }
}

private struct FileDetailView: View {
    let entry: FileEntry?
    var body: some View {
        if let entry {
            ScrollView {
                VStack(alignment: .leading, spacing: 10) {
                    Text(entry.name).font(.headline)
                    LabeledContent("Path", value: entry.fullPath)
                    if let addr = entry.metaAddr { LabeledContent("MFT entry", value: "\(addr)") }
                    LabeledContent("Size", value: "\(entry.size) bytes")
                    LabeledContent("Deleted", value: entry.isDeleted ? "Yes" : "No")
                    Divider()
                    row("Created (B)", entry.created)
                    row("Modified (M)", entry.modified)
                    row("Accessed (A)", entry.accessed)
                    row("MFT changed (C)", entry.changed)
                }
                .padding()
                .frame(maxWidth: .infinity, alignment: .leading)
            }
        } else {
            ContentUnavailableView("Select a file", systemImage: "doc.text.magnifyingglass")
        }
    }

    private func row(_ label: String, _ date: Date?) -> some View {
        LabeledContent(label,
            value: date.map { $0.formatted(date: .abbreviated, time: .standard) } ?? "-")
    }
}

/// Tree node built from flat FileEntry paths, for OutlineGroup. `nonisolated`
/// + Sendable so the (pure) builder can run off the main actor.
nonisolated struct FileNode: Identifiable, Sendable {
    let id: String        // full path
    let name: String
    var entry: FileEntry?
    var children: [FileNode]?

    static func buildTree(from files: [FileEntry]) -> [FileNode] {
        final class Box {
            var node: FileNode
            var kids: [String: Box] = [:]
            init(_ n: FileNode) { node = n }
        }
        let root = Box(FileNode(id: "/", name: "/", entry: nil, children: nil))

        for file in files {
            let components = (file.fullPath as NSString)
                .pathComponents.filter { $0 != "/" && !$0.isEmpty }
            var cursor = root
            var path = ""
            for (index, comp) in components.enumerated() {
                path += "/" + comp
                let isLast = index == components.count - 1
                if isLast && !file.isDirectory {
                    // File leaf: key by the file's unique obj_id so same-name
                    // siblings (NTFS ADS, or a deleted + live entry at one path
                    // - exactly what "Show deleted" surfaces) both survive
                    // instead of the first silently clobbering the second.
                    let key = "\u{0}\(file.id)"
                    cursor.kids[key] = Box(FileNode(id: "\(path)\u{0}\(file.id)",
                                                    name: comp, entry: file, children: nil))
                } else {
                    // Directory component: merge by name so the subtree is
                    // shared. A directory entry attaches its metadata to the
                    // (possibly already-created) named node.
                    if let existing = cursor.kids[comp] {
                        if isLast, existing.node.entry == nil { existing.node.entry = file }
                        cursor = existing
                    } else {
                        let box = Box(FileNode(id: path, name: comp,
                                               entry: isLast ? file : nil, children: nil))
                        cursor.kids[comp] = box
                        cursor = box
                    }
                }
            }
        }

        func materialize(_ box: Box) -> FileNode {
            var node = box.node
            if !box.kids.isEmpty {
                node.children = box.kids.values.map(materialize)
                    .sorted { $0.name.localizedStandardCompare($1.name) == .orderedAscending }
            }
            return node
        }
        return root.kids.values.map(materialize)
            .sorted { $0.name.localizedStandardCompare($1.name) == .orderedAscending }
    }
}
