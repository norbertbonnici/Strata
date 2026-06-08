import Foundation
import GRDB

/// Read-only access to a TSK SQLite database produced by tsk_loaddb.
/// Queries TSK's own schema (notably `tsk_files`) and maps rows to FileEntry.
public nonisolated struct TSKDatabase {
    private let dbQueue: DatabaseQueue

    // TSK_FS_META_FLAG / TSK_FS_NAME_FLAG bit for "unallocated" (deleted).
    private static let unallocFlag = 2
    // TSK_FS_META_TYPE_DIR.
    private static let dirMetaType = 2

    public init(path: URL) throws {
        guard FileManager.default.fileExists(atPath: path.path) else {
            throw TSKError.databaseUnavailable(path)
        }
        var config = Configuration()
        config.readonly = true
        self.dbQueue = try DatabaseQueue(path: path.path, configuration: config)
    }

    public func fileCount() throws -> Int {
        try dbQueue.read { db in
            try Int.fetchOne(db, sql: "SELECT COUNT(*) FROM tsk_files") ?? 0
        }
    }

    /// Fetch file entries (directories included so the UI can build a tree).
    public func fetchFiles(limit: Int? = nil, offset: Int = 0) throws -> [FileEntry] {
        let limitClause = limit.map { "LIMIT \($0) OFFSET \(offset)" } ?? ""
        let sql = """
            SELECT obj_id, meta_addr, fs_obj_id, name, parent_path, size,
                   meta_type, meta_flags, dir_flags,
                   crtime, mtime, atime, ctime
            FROM tsk_files
            WHERE name NOT IN ('.', '..')
            ORDER BY parent_path, name
            \(limitClause)
            """
        return try dbQueue.read { db in
            try Row.fetchAll(db, sql: sql).map(Self.makeEntry)
        }
    }

    /// The filesystems/volumes in the image. A disk image holds several (EFI
    /// FAT + main NTFS + recovery NTFS, ...), each with its own metadata files,
    /// so the UI groups the file tree by these.
    public func fetchVolumes() throws -> [VolumeInfo] {
        let sql = """
            SELECT obj_id, fs_type, img_offset, block_size, block_count
            FROM tsk_fs_info
            ORDER BY img_offset
            """
        return try dbQueue.read { db in
            try Row.fetchAll(db, sql: sql).map { row in
                let blockSize: Int64 = row["block_size"] ?? 0
                let blockCount: Int64 = row["block_count"] ?? 0
                return VolumeInfo(id: row["obj_id"] ?? 0,
                                  fsType: VolumeInfo.fsTypeName(row["fs_type"] ?? 0),
                                  offsetBytes: row["img_offset"] ?? 0,
                                  sizeBytes: blockSize * blockCount)
            }
        }
    }

    private static func makeEntry(_ row: Row) -> FileEntry {
        let metaFlags: Int = row["meta_flags"] ?? 0
        let dirFlags: Int = row["dir_flags"] ?? 0
        let metaType: Int = row["meta_type"] ?? 0
        let deleted = (metaFlags & unallocFlag) != 0 || (dirFlags & unallocFlag) != 0

        return FileEntry(
            id: row["obj_id"] ?? 0,
            metaAddr: row["meta_addr"],
            name: row["name"] ?? "",
            parentPath: row["parent_path"] ?? "/",
            size: row["size"] ?? 0,
            isDirectory: metaType == dirMetaType,
            isDeleted: deleted,
            modified: Self.date(row["mtime"]),
            accessed: Self.date(row["atime"]),
            changed: Self.date(row["ctime"]),
            created: Self.date(row["crtime"]),
            fsID: row["fs_obj_id"]
        )
    }

    /// Look up the partition's image offset (in sectors) and the file's
    /// meta_addr (NTFS MFT entry) for a single tsk_files row. icat needs both
    /// to extract the content out of a multi-partition image.
    public func fetchExtractInfo(forFileID id: Int64)
        throws -> (imageOffsetSectors: Int64, metaAddr: Int64)?
    {
        let sql = """
            SELECT fs.img_offset, f.meta_addr
            FROM tsk_files f
            JOIN tsk_fs_info fs ON f.fs_obj_id = fs.obj_id
            WHERE f.obj_id = ?
            """
        return try dbQueue.read { db in
            guard let row = try Row.fetchOne(db, sql: sql, arguments: [id]) else { return nil }
            let bytes: Int64 = row["img_offset"] ?? 0
            let metaAddr: Int64 = row["meta_addr"] ?? 0
            // TSK img_offset is bytes; icat -o expects sectors. 512 is the
            // standard sector size for everything we've seen so far.
            return (imageOffsetSectors: bytes / 512, metaAddr: metaAddr)
        }
    }

    /// Like `fetchExtractInfo`, but also returns the file's NTFS attribute
    /// type + id so a *named* alternate data stream (e.g. `$UsnJrnl:$J`) can be
    /// extracted - icat needs the `meta-type-id` address form, since the bare
    /// meta_addr selects only the (often empty) default `$DATA` stream.
    public func fetchAttrExtractInfo(forFileID id: Int64)
        throws -> (imageOffsetSectors: Int64, metaAddr: Int64, attrType: Int64, attrId: Int64)?
    {
        let sql = """
            SELECT fs.img_offset, f.meta_addr, f.attr_type, f.attr_id
            FROM tsk_files f
            JOIN tsk_fs_info fs ON f.fs_obj_id = fs.obj_id
            WHERE f.obj_id = ?
            """
        return try dbQueue.read { db in
            guard let row = try Row.fetchOne(db, sql: sql, arguments: [id]) else { return nil }
            let bytes: Int64 = row["img_offset"] ?? 0
            return (imageOffsetSectors: bytes / 512,
                    metaAddr: row["meta_addr"] ?? 0,
                    attrType: row["attr_type"] ?? 128,
                    attrId: row["attr_id"] ?? 0)
        }
    }

    /// TSK stores epoch seconds; 0 (or negative) means "no timestamp recorded".
    private static func date(_ value: Int64?) -> Date? {
        guard let value, value > 0 else { return nil }
        return Date(timeIntervalSince1970: TimeInterval(value))
    }
}
