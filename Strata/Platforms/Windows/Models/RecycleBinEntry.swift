import Foundation

/// A single deleted file recovered from a Windows `$Recycle.Bin\<SID>\$I*`
/// index file. The `$I` record records the deleted file's **original path**,
/// its **original size**, and the **deletion timestamp** — the deleted bytes
/// themselves live in the paired `$R` file (not parsed here).
///
/// Pure value type; parse-time identity (`id`) is a fresh UUID — RecycleBin has
/// no stable-key timeline splice requirement, so a content-derived key is not
/// needed.
public nonisolated struct RecycleBinEntry: Identifiable, Hashable, Sendable, Codable {
    public let id: UUID
    /// Recovered original full path of the deleted file,
    /// e.g. `C:\Users\bob\Desktop\mimikatz.exe`.
    public let originalPath: String
    /// Deletion time, from the FILETIME at offset 16 (lossy `Date`); nil when
    /// the stored tick value was 0 or implausible.
    public let deletedAt: Date?
    /// Original file size in bytes (offset-8 uint64), clamped to `Int64`.
    public let sizeBytes: Int64
    /// The `$I`/`$R` recycled-name id, e.g. `$IXXXXXX.ext` or the bare id token.
    public let recycledName: String
    /// Owning user SID, parsed from the parent folder name `\$Recycle.Bin\<SID>\`;
    /// nil when unknown.
    public let sid: String?
    /// Path of the `$I` index file this entry came from (evidence path).
    public let sourceFile: String

    public init(id: UUID = UUID(), originalPath: String, deletedAt: Date?,
                sizeBytes: Int64, recycledName: String, sid: String?,
                sourceFile: String) {
        self.id = id
        self.originalPath = originalPath
        self.deletedAt = deletedAt
        self.sizeBytes = sizeBytes
        self.recycledName = recycledName
        self.sid = sid
        self.sourceFile = sourceFile
    }

    /// Final path component of `originalPath`, splitting on both Windows `\` and
    /// POSIX `/` separators.
    public var fileName: String {
        let parts = originalPath.split(whereSeparator: { $0 == "\\" || $0 == "/" })
        return parts.last.map(String.init) ?? originalPath
    }

    /// Lowercased extension of `fileName` (empty when there is none).
    public var fileExtension: String {
        (fileName as NSString).pathExtension.lowercased()
    }
}
