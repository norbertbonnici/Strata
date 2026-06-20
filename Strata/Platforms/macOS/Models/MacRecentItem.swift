import Foundation

/// One recovered item from macOS recent-item stores such as
/// `com.apple.LSSharedFileList.*.sfl2`, Finder sidebar/favorites lists, and
/// related LaunchServices recent-object plists.
///
/// These stores are user-behaviour evidence: recently opened apps/documents,
/// mounted servers, and Finder locations. The backing formats drift between
/// macOS releases and are often keyed archives, so the parser keeps the model
/// deliberately small and records the best stable display value recovered from
/// each item.
public nonisolated struct MacRecentItem: Identifiable, Hashable, Sendable, Codable {
    public enum ListKind: String, Sendable, Codable {
        case applications
        case documents
        case servers
        case hosts
        case volumes
        case favorites
        case other

        public var label: String {
            switch self {
            case .applications: return "Applications"
            case .documents: return "Documents"
            case .servers: return "Servers"
            case .hosts: return "Hosts"
            case .volumes: return "Volumes"
            case .favorites: return "Favorites"
            case .other: return "Recent Items"
            }
        }
    }

    public let id: UUID
    public let kind: ListKind
    public let title: String
    public let value: String
    public let timestamp: Date?
    public let scope: String
    public let sourceFile: String

    public init(id: UUID = UUID(), kind: ListKind, title: String, value: String,
                timestamp: Date?, scope: String, sourceFile: String) {
        self.id = id
        self.kind = kind
        self.title = title
        self.value = value
        self.timestamp = timestamp
        self.scope = scope
        self.sourceFile = sourceFile
    }

    public var timelineSummary: String {
        "\(kind.label): \(title)"
    }
}
