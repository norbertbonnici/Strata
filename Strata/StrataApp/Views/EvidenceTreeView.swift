import SwiftUI

struct EvidenceTreeView: View {
    @EnvironmentObject private var model: AppModel
    @State private var selection: FileEntry?
    @State private var showDeleted = false

    private var visibleFiles: [FileEntry] {
        showDeleted ? model.files : model.files.filter { !$0.isDeleted }
    }

    private var tree: [FileNode] { FileNode.buildTree(from: visibleFiles) }

    private var hiddenCount: Int {
        showDeleted ? 0 : model.files.count - visibleFiles.count
    }

    var body: some View {
        Group {
            if model.files.isEmpty {
                ContentUnavailableView("No files loaded", systemImage: "folder",
                    description: Text("Open an E01 or KAPE .vhd to enumerate the file system."))
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else {
                VStack(spacing: 0) {
                    HStack(spacing: 12) {
                        Toggle("Show deleted / unallocated", isOn: $showDeleted)
                            .toggleStyle(.switch)
                            .controlSize(.small)
                        if hiddenCount > 0 {
                            Text("\(hiddenCount) hidden")
                                .font(.caption).foregroundStyle(.secondary)
                        }
                        Spacer()
                        Text("\(visibleFiles.count) files")
                            .font(.caption).foregroundStyle(.secondary)
                    }
                    .padding(.horizontal, 12).padding(.vertical, 6)
                    Divider()
                    HSplitView {
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
                    .frame(minWidth: 360)

                        FileDetailView(entry: selection).frame(minWidth: 280)
                    }
                }
            }
        }
        .navigationTitle("Evidence")
    }

    private func byteString(_ bytes: Int64) -> String {
        ByteCountFormatter.string(fromByteCount: bytes, countStyle: .file)
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

/// Tree node built from flat FileEntry paths, for OutlineGroup.
struct FileNode: Identifiable {
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
                if let existing = cursor.kids[comp] {
                    cursor = existing
                } else {
                    let isLeaf = index == components.count - 1
                    let box = Box(FileNode(id: path, name: comp,
                                           entry: isLeaf ? file : nil, children: nil))
                    cursor.kids[comp] = box
                    cursor = box
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
