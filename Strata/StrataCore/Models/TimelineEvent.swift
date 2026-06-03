import Foundation

/// One of the four NTFS Standard-Information timestamps, in `mactime` order.
public enum MACBKind: String, CaseIterable, Sendable, Codable {
    case modified = "M"
    case accessed = "A"
    case changed  = "C"   // MFT entry modified
    case born     = "B"   // created

    public var label: String {
        switch self {
        case .modified: return "Modified"
        case .accessed: return "Accessed"
        case .changed:  return "MFT changed"
        case .born:     return "Created"
        }
    }
}

/// A single point on the timeline: one timestamp of one file.
/// Each FileEntry expands into up to four of these (the mactime model).
public struct TimelineEvent: Identifiable, Hashable, Sendable {
    public let id: UUID
    public let date: Date
    public let kind: MACBKind
    public let fileID: Int64
    public let path: String
    public let size: Int64
    public let isDeleted: Bool

    public init(date: Date, kind: MACBKind, fileID: Int64,
                path: String, size: Int64, isDeleted: Bool) {
        self.id = UUID()
        self.date = date; self.kind = kind; self.fileID = fileID
        self.path = path; self.size = size; self.isDeleted = isDeleted
    }
}
