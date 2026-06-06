import Testing
import Foundation
@testable import Strata

/// Regression tests for the pure view-layer logic the code review flagged:
/// the filesystem path normalization (trailing-slash navigation bug) and the
/// evidence-tree builder's same-name collision handling.
struct ViewLogicTests {

    // MARK: - Path normalization (FilesystemDrillView navigation)

    @Test func normalizeDirPathStripsTrailingSlashAndRoot() {
        #expect(FileEntry.normalizeDirPath("/Windows/") == "/Windows")   // TSK convention
        #expect(FileEntry.normalizeDirPath("/Windows") == "/Windows")    // KAPE convention
        #expect(FileEntry.normalizeDirPath("/Windows/System32/") == "/Windows/System32")
        #expect(FileEntry.normalizeDirPath("/") == "")
        #expect(FileEntry.normalizeDirPath("") == "")
    }

    /// The original bug: a TSK-backed entry (trailing-slash parentPath) never
    /// matched a reconstructed path, so every subfolder rendered empty. Both
    /// ingest conventions must navigate identically now.
    @Test func childMatchingWorksForBothIngestConventions() {
        let tsk  = file(name: "cmd.exe", parent: "/Windows/System32/")   // trailing slash
        let kape = file(name: "calc.exe", parent: "/Windows/System32")   // no slash
        let other = file(name: "boot.ini", parent: "/")

        let here = FileEntry.normalizeDirPath("/Windows/System32")
        let kids = [tsk, kape, other].filter {
            FileEntry.normalizeDirPath($0.parentPath) == here
        }
        #expect(Set(kids.map(\.name)) == ["cmd.exe", "calc.exe"])
    }

    @Test func rootChildrenMatch() {
        let atRoot = file(name: "pagefile.sys", parent: "/")
        let nested = file(name: "cmd.exe", parent: "/Windows/System32/")
        let here = FileEntry.normalizeDirPath("")   // root
        let kids = [atRoot, nested].filter { FileEntry.normalizeDirPath($0.parentPath) == here }
        #expect(kids.map(\.name) == ["pagefile.sys"])
    }

    // MARK: - FileNode tree collision (EvidenceTreeView)

    /// A deleted and a live file at the same path must BOTH survive in the tree
    /// (keyed by obj_id), not collapse to one - "Show deleted" exists to surface
    /// exactly that pairing.
    @Test func sameNameSiblingsBothSurviveInTree() {
        let live    = file(id: 1, name: "evil.exe", parent: "/Windows/Temp/", deleted: false)
        let deleted = file(id: 2, name: "evil.exe", parent: "/Windows/Temp/", deleted: true)

        let leaves = Self.leaves(of: FileNode.buildTree(from: [live, deleted]))
        let evil = leaves.filter { $0.name == "evil.exe" }
        #expect(evil.count == 2)                              // neither dropped
        #expect(Set(evil.map(\.id)).count == 2)              // unique node ids
        #expect(Set(evil.compactMap { $0.entry?.isDeleted }) == [true, false])
    }

    @Test func directoriesStillMergeByName() {
        // A directory entry plus a file inside it should yield ONE "Temp" node
        // that both carries its own metadata and hosts the child.
        let dir   = file(id: 1, name: "Temp", parent: "/Windows/", isDirectory: true)
        let child = file(id: 2, name: "a.txt", parent: "/Windows/Temp/")
        let roots = FileNode.buildTree(from: [dir, child])

        let windows = roots.first { $0.name == "Windows" }
        let temp = windows?.children?.first { $0.name == "Temp" }
        #expect(temp != nil)
        #expect(temp?.entry?.isDirectory == true)            // dir metadata attached
        #expect(temp?.children?.contains { $0.name == "a.txt" } == true)
        #expect((windows?.children?.filter { $0.name == "Temp" }.count ?? 0) == 1)  // not duplicated
    }

    // MARK: - Volume grouping (multi-filesystem images)

    /// A disk image with several filesystems must group the tree by volume so
    /// each volume's metadata ($MFT, ...) lives under its own node instead of
    /// colliding at the root.
    @Test func multipleFilesystemsGroupIntoVolumeNodes() {
        let main = file(id: 1, name: "$MFT", parent: "/", fs: 462)
        let recov = file(id: 2, name: "$MFT", parent: "/", fs: 563419)
        let volumes = [
            VolumeInfo(id: 462,    fsType: "NTFS", offsetBytes: 100, sizeBytes: 1000),
            VolumeInfo(id: 563419, fsType: "NTFS", offsetBytes: 200, sizeBytes: 50),
        ]
        let roots = FileNode.buildTree(from: [main, recov], volumes: volumes)
        let allVolumes = roots.allSatisfy(\.isVolume)
        let eachHasMFT = roots.allSatisfy { node in
            (node.children ?? []).contains { $0.name == "$MFT" }
        }
        #expect(roots.count == 2)
        #expect(allVolumes)
        #expect(roots.first?.id == "vol:462")   // ordered by image offset
        #expect(eachHasMFT)
    }

    @Test func singleFilesystemSkipsVolumeLayer() {
        let f = file(id: 1, name: "cmd.exe", parent: "/Windows/", fs: 462)
        let roots = FileNode.buildTree(
            from: [f],
            volumes: [VolumeInfo(id: 462, fsType: "NTFS", offsetBytes: 0, sizeBytes: 0)])
        let hasWindows = roots.contains { $0.name == "Windows" }
        #expect(roots.first?.isVolume == false)        // no volume wrapper for one fs
        #expect(hasWindows)
    }

    // MARK: - Helpers

    private func file(id: Int64 = 0, name: String, parent: String,
                      isDirectory: Bool = false, deleted: Bool = false,
                      fs: Int64? = nil) -> FileEntry {
        FileEntry(id: id, metaAddr: nil, name: name, parentPath: parent,
                  size: 0, isDirectory: isDirectory, isDeleted: deleted,
                  modified: nil, accessed: nil, changed: nil, created: nil, fsID: fs)
    }

    private static func leaves(of nodes: [FileNode]) -> [FileNode] {
        nodes.flatMap { node -> [FileNode] in
            if let kids = node.children, !kids.isEmpty { return leaves(of: kids) }
            return [node]
        }
    }
}
