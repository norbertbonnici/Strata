import Foundation

/// A rule match against one file from an evidence source.
public nonisolated struct YaraMatch: Identifiable, Hashable, Sendable, Codable {
    public let rule: String
    public let evidenceID: UUID
    public let path: String
    public let fileID: Int64
    public let fileSize: Int64
    public let scannedAt: Date

    public var id: String { "\(evidenceID)\u{0}\(rule)\u{0}\(fileID)\u{0}\(path)" }

    public init(rule: String, evidenceID: UUID, path: String, fileID: Int64, fileSize: Int64,
                scannedAt: Date = Date()) {
        self.rule = rule
        self.evidenceID = evidenceID
        self.path = path
        self.fileID = fileID
        self.fileSize = fileSize
        self.scannedAt = scannedAt
    }
}
