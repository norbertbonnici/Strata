import Foundation

/// One saved **document version** recovered from the macOS Versions store
/// (`/.DocumentRevisions-V100/db-V1/db.sqlite`). Each row is a generation the OS
/// auto-saved for a document — so this reconstructs the **edit timeline** of a
/// file and points at a recoverable prior version, **even for files no longer on
/// disk**.
///
/// Pure / `Sendable` / no I/O — the macOS-only `DocumentRevisionsParser` reads
/// the SQLite store via GRDB and builds these. This is investigative
/// recovery/context (no detection rule), like the host-info artifacts.
public nonisolated struct MacDocumentVersion: Identifiable, Hashable, Sendable, Codable {
    public let id: UUID
    /// Original document path the version belongs to.
    public let filePath: String
    /// When this generation was saved.
    public let versionTime: Date?
    /// Stored generation size in bytes, when recorded.
    public let size: Int64?
    /// Relative path to the stored version blob under the Versions store.
    public let generationPath: String?
    public let scope: String
    public let sourceFile: String

    public init(id: UUID = UUID(), filePath: String, versionTime: Date? = nil,
                size: Int64? = nil, generationPath: String? = nil,
                scope: String, sourceFile: String) {
        self.id = id
        self.filePath = filePath
        self.versionTime = versionTime
        self.size = size
        self.generationPath = generationPath
        self.scope = scope
        self.sourceFile = sourceFile
    }

    public var timestamp: Date? { versionTime }
    public var name: String { (filePath as NSString).lastPathComponent }
    public var timelineSummary: String { "[Doc Version] \(filePath)" }
}
