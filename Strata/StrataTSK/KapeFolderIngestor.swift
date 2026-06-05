import Foundation

/// Direct-artifact ingestion for a loose KAPE / triage folder - a directory
/// tree of collected files with no image container. TSK can't read a
/// directory, so instead of `tsk_loaddb` we walk the folder ourselves and
/// project it into the same `[FileEntry]` model the image path produces. The
/// rest of the pipeline (timeline, evtx / registry discovery, analyzers) is
/// then identical, because discovery keys off path suffixes and `diskURL`
/// rather than anything TSK-specific.
///
/// MACB fidelity is intentionally limited. A loose collection lives on the
/// analyst's own filesystem, which preserves the source *modification* time
/// (KAPE copies it through) but stamps a fresh *creation* time when it writes
/// each file; there is no trustworthy NTFS access / MFT-change time to recover
/// from a plain copy. We surface modified + created and leave accessed /
/// changed nil rather than invent values. Recovering true NTFS MACB would mean
/// parsing a collected `$MFT`, which is future work.
public nonisolated struct KapeFolderIngestor: Sendable {
    public init() {}

    private static let resourceKeys: [URLResourceKey] = [
        .isDirectoryKey, .fileSizeKey, .creationDateKey, .contentModificationDateKey,
    ]

    /// Recursively enumerate `root`, one FileEntry per file and directory.
    /// Unreadable entries are skipped so a single permission error doesn't
    /// abort the walk. `id` is a synthetic per-folder counter - loose entries
    /// never round-trip through TSK, so it only needs to be locally unique for
    /// timeline grouping.
    public func ingest(folderAt root: URL) -> [FileEntry] {
        let fm = FileManager.default
        let standardizedRoot = root.standardizedFileURL
        let rootPath = standardizedRoot.path
        let keys = Set(Self.resourceKeys)

        guard let enumerator = fm.enumerator(
            at: standardizedRoot,
            includingPropertiesForKeys: Self.resourceKeys,
            options: [],
            errorHandler: { _, _ in true }   // skip the offending item, keep walking
        ) else { return [] }

        var entries: [FileEntry] = []
        var nextID: Int64 = 1
        for case let url as URL in enumerator {
            let name = url.lastPathComponent
            // Drop macOS cruft that can appear if the folder was browsed in
            // Finder; it isn't part of the collected Windows artifact set.
            if name == ".DS_Store" { continue }

            let values = try? url.resourceValues(forKeys: keys)
            let isDir = values?.isDirectory ?? false
            let (parentPath, leaf) = Self.relativeComponents(of: url, underRoot: rootPath)
            entries.append(FileEntry(
                id: nextID,
                metaAddr: nil,
                name: leaf,
                parentPath: parentPath,
                size: isDir ? 0 : Int64(values?.fileSize ?? 0),
                isDirectory: isDir,
                isDeleted: false,
                modified: values?.contentModificationDate,
                accessed: nil,
                changed: nil,
                created: values?.creationDate,
                diskURL: url))
            nextID += 1
        }
        return entries
    }

    /// Split a file URL into ("/parent/dir", "name") relative to the chosen
    /// root. Mirroring the source layout (e.g. "/C/Windows/System32/config",
    /// "SYSTEM") is what lets the existing suffix-based hive / evtx discovery
    /// keep working regardless of KAPE's drive-letter or machine-name prefix.
    static func relativeComponents(of url: URL, underRoot rootPath: String)
        -> (parentPath: String, name: String)
    {
        let full = url.standardizedFileURL.path
        var rel = full.hasPrefix(rootPath) ? String(full.dropFirst(rootPath.count)) : full
        if !rel.hasPrefix("/") { rel = "/" + rel }
        let nsRel = rel as NSString
        let name = nsRel.lastPathComponent
        let parent = nsRel.deletingLastPathComponent
        return (parent.isEmpty ? "/" : parent, name)
    }
}
