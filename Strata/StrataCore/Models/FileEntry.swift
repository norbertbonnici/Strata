import Foundation

/// A single file-system object surfaced from the TSK SQLite database.
/// Mirrors the `tsk_files` columns that matter for enumeration + timeline.
public nonisolated struct FileEntry: Identifiable, Hashable, Sendable {
    public let id: Int64          // tsk_files.obj_id
    public let metaAddr: Int64?   // MFT entry / inode number
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

    public init(id: Int64, metaAddr: Int64?, name: String, parentPath: String,
                size: Int64, isDirectory: Bool, isDeleted: Bool,
                modified: Date?, accessed: Date?, changed: Date?, created: Date?) {
        self.id = id; self.metaAddr = metaAddr; self.name = name
        self.parentPath = parentPath; self.size = size
        self.isDirectory = isDirectory; self.isDeleted = isDeleted
        self.modified = modified; self.accessed = accessed
        self.changed = changed; self.created = created
    }

    /// Full reconstructed path, e.g. "/Windows/System32/cmd.exe".
    public var fullPath: String {
        let base = parentPath.hasSuffix("/") ? parentPath : parentPath + "/"
        return base + name
    }

    public var fileExtension: String {
        (name as NSString).pathExtension.lowercased()
    }
}
