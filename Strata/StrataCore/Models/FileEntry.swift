import Foundation

/// A single file-system object surfaced from the TSK SQLite database.
/// Mirrors the `tsk_files` columns that matter for enumeration + timeline.
public nonisolated struct FileEntry: Identifiable, Hashable, Sendable {
    public let id: Int64          // tsk_files.obj_id
    public let metaAddr: Int64?   // MFT entry / inode number
    public let fsID: Int64?       // tsk_files.fs_obj_id - which filesystem/volume; nil for loose folders
    public let name: String
    public let parentPath: String // e.g. "/Windows/System32/"
    public let size: Int64
    public let isDirectory: Bool
    public let isDeleted: Bool

    // MACB timestamps (epoch -> Date). nil when TSK recorded 0.
    public let modified: Date?    // mtime  (M)
    public let accessed: Date?    // atime  (A)
    public let changed: Date?     // ctime  (C) - MFT entry modified
    public let created: Date?     // crtime (B) - born

    /// Real on-disk location of this file's content, when it is directly
    /// readable without TSK. Populated for loose KAPE/triage folders (the
    /// artifacts already live on the analyst's filesystem); nil for image-
    /// backed entries, whose bytes must be pulled out with `icat`.
    public let diskURL: URL?

    public init(id: Int64, metaAddr: Int64?, name: String, parentPath: String,
                size: Int64, isDirectory: Bool, isDeleted: Bool,
                modified: Date?, accessed: Date?, changed: Date?, created: Date?,
                fsID: Int64? = nil, diskURL: URL? = nil) {
        self.id = id; self.metaAddr = metaAddr; self.name = name
        self.parentPath = parentPath; self.size = size
        self.isDirectory = isDirectory; self.isDeleted = isDeleted
        self.modified = modified; self.accessed = accessed
        self.changed = changed; self.created = created
        self.fsID = fsID; self.diskURL = diskURL
    }

    /// Full reconstructed path, e.g. "/Windows/System32/cmd.exe".
    public var fullPath: String {
        let base = parentPath.hasSuffix("/") ? parentPath : parentPath + "/"
        return base + name
    }

    public var fileExtension: String {
        (name as NSString).pathExtension.lowercased()
    }

    /// Normalize a directory path for "is child of" comparison: strip a trailing
    /// slash and represent root as "". TSK records parentPath WITH a trailing
    /// slash ("/Windows/"); the KAPE walk records it WITHOUT ("/Windows"). The
    /// iOS filesystem browser compares a reconstructed path against parentPath,
    /// so both sides must be normalized or image-backed cases show empty folders.
    public static func normalizeDirPath(_ path: String) -> String {
        if path == "/" || path.isEmpty { return "" }
        return path.hasSuffix("/") ? String(path.dropLast()) : path
    }
}
