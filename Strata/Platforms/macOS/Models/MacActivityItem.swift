import Foundation

/// One macOS user-activity / deleted-evidence item:
///
///  - **QuickLook** — a file that was *previewed* (the QuickLook thumbnail index
///    records it), which is evidence the file existed and was viewed **even if it
///    has since been deleted**.
///  - **Trash** — a file currently sitting in the Trash, i.e. deletion intent +
///    the time it was moved there.
///
/// Pure / `Sendable` / no I/O (the macOS-only parsers build these): QuickLook
/// comes from `index.sqlite` via GRDB; Trash from the file tree (`/.Trash`).
public nonisolated struct MacActivityItem: Identifiable, Hashable, Sendable, Codable {
    public enum Kind: String, CaseIterable, Sendable, Codable {
        case quickLook
        case trash

        public var label: String {
            switch self {
            case .quickLook: return "QuickLook"
            case .trash:     return "Trash"
            }
        }
    }

    public let id: UUID
    public let kind: Kind
    /// Full path of the file (the viewed file for QuickLook; the in-Trash path).
    public let path: String
    /// Last preview time (QuickLook) / time moved to Trash (changed time).
    public let timestamp: Date?
    /// Extra context: "viewed N×" / file size.
    public let detail: String?
    public let scope: String
    public let sourceFile: String

    public init(id: UUID = UUID(), kind: Kind, path: String, timestamp: Date? = nil,
                detail: String? = nil, scope: String, sourceFile: String) {
        self.id = id
        self.kind = kind
        self.path = path
        self.timestamp = timestamp
        self.detail = detail
        self.scope = scope
        self.sourceFile = sourceFile
    }

    public var name: String { (path as NSString).lastPathComponent }

    public var timelineSummary: String {
        "[\(kind.label)] \(path)" + (detail.map { " — \($0)" } ?? "")
    }
}
