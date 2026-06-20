import Foundation

/// Tree node built from flat `MftEntry` paths, for an `OutlineGroup` — the MFT
/// analogue of `FileNode`. Pure + `Sendable` so the builder runs off-main.
///
/// The top level is one node per **volume** (a multi-NTFS image — system +
/// recovery — has one `$MFT` per volume, so identical paths must not merge); a
/// single-volume case skips that layer. Beneath, records nest by their resolved
/// `$FN` path.
public nonisolated struct MftNode: Identifiable, Sendable {
    public let id: String          // path (+ record for file leaves), or "vol:<label>"
    public let name: String
    public var entry: MftEntry?
    public var children: [MftNode]?
    public var isVolume = false

    public static func buildTree(from entries: [MftEntry]) -> [MftNode] {
        let named = entries.filter { $0.fileName != nil }
        let volumes = orderedDistinct(named.map(\.volume))
        guard volumes.count > 1 else { return buildSubtree(from: named) }
        return volumes.map { vol in
            let kids = named.filter { $0.volume == vol }
            return MftNode(id: "vol:\(vol)", name: "\(vol) — \(kids.count.formatted()) records",
                           entry: nil, children: buildSubtree(from: kids), isVolume: true)
        }
    }

    private static func buildSubtree(from entries: [MftEntry]) -> [MftNode] {
        final class Box {
            var node: MftNode
            var kids: [String: Box] = [:]
            init(_ n: MftNode) { node = n }
        }
        let root = Box(MftNode(id: "/", name: "\\", entry: nil, children: nil))

        for e in entries {
            let components = (e.fullPath ?? e.fileName ?? "")
                .split(separator: "\\").map(String.init)
            // The root directory ("\") attaches its metadata to the root node.
            guard !components.isEmpty else {
                if root.node.entry == nil { root.node.entry = e }
                continue
            }
            var cursor = root
            var path = ""
            for (index, comp) in components.enumerated() {
                path += "\\" + comp
                let isLast = index == components.count - 1
                if isLast && !e.isDirectory {
                    // File leaf keyed by the record number so same-name siblings
                    // (and a deleted + live entry at one path) both survive.
                    let key = "\u{0}\(e.recordNumber)"
                    cursor.kids[key] = Box(MftNode(id: "\(path)#\(e.recordNumber)",
                                                   name: comp, entry: e, children: nil))
                } else if let existing = cursor.kids[comp] {
                    if isLast, existing.node.entry == nil { existing.node.entry = e }
                    cursor = existing
                } else {
                    let box = Box(MftNode(id: path, name: comp,
                                          entry: isLast ? e : nil, children: nil))
                    cursor.kids[comp] = box
                    cursor = box
                }
            }
        }

        func materialize(_ box: Box) -> MftNode {
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

    private static func orderedDistinct(_ xs: [String]) -> [String] {
        var seen = Set<String>()
        return xs.filter { seen.insert($0).inserted }
    }
}
