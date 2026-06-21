import SwiftUI

struct EvidenceTreeView: View {
    @EnvironmentObject private var model: AppModel
    @State private var selection: FileEntry?
    @State private var showDeleted = false
    /// TSK emits a `<name>-slack` pseudo-entry per allocated cluster's trailing
    /// slack (1980-epoch timestamps); hide them by default, matching Timeline.
    @State private var hideSlack = true

    /// Files the current filters keep: deleted/unallocated and slack toggles.
    private func isVisible(_ f: FileEntry) -> Bool {
        (showDeleted || !f.isDeleted) &&
        (!hideSlack || !TimelineBuilder.isSlackEntry(f))
    }
    /// Memoized tree, rebuilt off the main thread when the file set or the
    /// deleted toggle changes. Rebuilding it inside body re-allocated and
    /// re-sorted the whole node graph on every unrelated state change.
    @State private var tree: [FileNode] = []

    var body: some View {
        // Snapshot once (cached) for the header counts.
        let allFiles = model.files
        let shownCount = allFiles.lazy.filter(isVisible).count
        let hidden = allFiles.count - shownCount
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
                        Toggle("Hide slack", isOn: $hideSlack)
                            .toggleStyle(.switch)
                            .controlSize(.small)
                            .help("Hide TSK *-slack pseudo-entries (slack-space rows with 1980 epoch timestamps).")
                        if hidden > 0 {
                            Text("\(hidden) hidden")
                                .font(.caption).foregroundStyle(.secondary)
                        }
                        Spacer()
                        Text("\(shownCount) files")
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
        // Rebuild synchronously on appear and when the data/scope or the deleted
        // toggle changes - NOT in body (which would rebuild every render) and
        // NOT via a detached task (whose cancellation on a tab switch could
        // leave the tree empty). buildTree is O(files) but only runs on change.
        .onAppear { rebuildTree() }
        .onChange(of: model.dataVersion) {
            rebuildTree()
            // Drop or refresh a stale selection when the file set / scope changes
            // (the value-type FileEntry could otherwise point at another host).
            if let sel = selection {
                selection = model.files.first { $0.id == sel.id }
            }
        }
        .onChange(of: showDeleted) { rebuildTree() }
        .onChange(of: hideSlack) { rebuildTree() }
    }

    private func rebuildTree() {
        // The file tree is inherently per-host: a host's volumes are numbered by
        // TSK fs_obj_id starting at 2, so two hosts' volume ids collide. The
        // rolled-up `model.files`/`model.volumes` (combined "All" scope) would
        // therefore merge - and crash - the volume layer. When more than one host
        // is in scope, give each its own top-level node built from ITS OWN files
        // + volumes; a single host (or a scoped view) skips the host layer.
        let hosts = model.activeEvidenceID
            .map { id in model.evidenceList.filter { $0.id == id } } ?? model.evidenceList

        guard hosts.count > 1 else {
            let files = model.files.filter(isVisible)
            tree = FileNode.buildTree(from: files, volumes: model.volumes)
            return
        }

        tree = hosts.compactMap { host in
            let (allFiles, volumes) = model.hostFileTree(host.id)
            let files = allFiles.filter(isVisible)
            guard !files.isEmpty else { return nil }
            return FileNode(id: "host:\(host.id)",
                            name: "\(host.displayName) — \(files.count.formatted()) files",
                            entry: nil,
                            children: FileNode.buildTree(from: files, volumes: volumes),
                            isHost: true)
        }
    }

    private func byteString(_ bytes: Int64) -> String {
        ByteCountFormatter.string(fromByteCount: bytes, countStyle: .file)
    }

    private var evidenceTree: some View {
        List {
            OutlineGroup(tree, children: \.children) { node in
                HStack {
                    Image(systemName: node.isHost ? "desktopcomputer"
                          : node.isVolume ? "internaldrive"
                          : ((node.entry?.isDirectory ?? true) ? "folder" : "doc"))
                        .foregroundStyle(node.isHost || node.isVolume ? Color.accentColor : .secondary)
                    Text(node.name)
                        .fontWeight(node.isHost || node.isVolume ? .semibold : .regular)
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
    let id: String        // full path, or "vol:<fsID>" for a volume node, or "host:<uuid>"
    let name: String
    var entry: FileEntry?
    var children: [FileNode]?
    var isVolume = false
    var isHost = false

    /// Build the evidence tree. When the files span more than one filesystem
    /// (the usual case for a disk image: EFI FAT + main NTFS + recovery NTFS),
    /// the top level is one node per volume - so same-named volume metadata
    /// ($MFT, $LogFile, ...) no longer looks like duplicates. A single volume or
    /// a loose folder (no fsID) skips the volume layer entirely.
    static func buildTree(from files: [FileEntry], volumes: [VolumeInfo] = []) -> [FileNode] {
        let fsIDs = Set(files.compactMap { $0.fsID })
        guard fsIDs.count > 1 else { return buildSubtree(from: files) }

        // De-dup on volume id for BOTH maps: a combined multi-host scope can hand
        // us several hosts' volume lists whose TSK fs_obj_ids collide (each host
        // restarts at 2). `uniqueKeysWithValues` would TRAP on the duplicate, so
        // keep the first like `labels` does. (The view also groups by host above,
        // so within one host these ids are already distinct - this is defensive.)
        let labels = Dictionary(volumes.map { ($0.id, $0.label) }, uniquingKeysWith: { a, _ in a })
        let order  = Dictionary(volumes.enumerated().map { ($1.id, $0) }, uniquingKeysWith: { a, _ in a })
        var byFS: [Int64: [FileEntry]] = [:]
        var unassigned: [FileEntry] = []
        for file in files {
            if let fs = file.fsID { byFS[fs, default: []].append(file) } else { unassigned.append(file) }
        }
        var roots: [FileNode] = byFS.keys
            .sorted { (order[$0] ?? Int.max, $0) < (order[$1] ?? Int.max, $1) }   // by image offset
            .map { fs in
                let label = labels[fs] ?? "Volume \(fs)"
                let count = (byFS[fs]?.count ?? 0).formatted()
                return FileNode(id: "vol:\(fs)", name: "\(label) — \(count) files",
                                entry: nil, children: buildSubtree(from: byFS[fs] ?? []),
                                isVolume: true)
            }
        if !unassigned.isEmpty {
            roots.append(FileNode(id: "vol:none",
                                  name: "Unassigned — \(unassigned.count.formatted()) files",
                                  entry: nil, children: buildSubtree(from: unassigned), isVolume: true))
        }
        return roots
    }

    private static func buildSubtree(from files: [FileEntry]) -> [FileNode] {
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
                    // instead of the first silently clobbering the second. The
                    // dict key uses a NUL (can't appear in a path component); the
                    // OutlineGroup-facing node id avoids NUL (SwiftUI ids should
                    // be plain) while staying unique via the obj_id suffix.
                    let key = "\u{0}\(file.id)"
                    cursor.kids[key] = Box(FileNode(id: "\(path)#\(file.id)",
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
