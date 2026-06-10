import Foundation

/// One package-manager action (install / remove / upgrade …) from a system
/// package log. The "what was added or removed, and when" timeline - attackers
/// install tooling (nmap, socat, netcat) and responders/cleaners remove
/// packages, so this is high-value context and, for offensive tooling, a
/// detection in its own right. Persisted per host as `packages.json`, spliced
/// onto the timeline.
public nonisolated struct PackageEvent: Identifiable, Hashable, Sendable, Codable {
    public enum Action: String, Codable, Sendable, CaseIterable {
        case install, remove, upgrade, purge, reinstall, downgrade

        public var label: String { rawValue.capitalized }

        /// Removal-family actions (anti-forensic / cleanup signal).
        public var isRemoval: Bool { self == .remove || self == .purge }
    }

    public enum Manager: String, Codable, Sendable {
        case dpkg, apt, yum, dnf

        public var label: String {
            switch self {
            case .dpkg: return "dpkg"
            case .apt:  return "apt"
            case .yum:  return "yum"
            case .dnf:  return "dnf"
            }
        }
    }

    public let id: UUID
    public let timestamp: Date?
    public let action: Action
    public let package: String
    public let version: String?
    public let manager: Manager
    public let sourceFile: String

    public init(id: UUID = UUID(), timestamp: Date?, action: Action, package: String,
                version: String? = nil, manager: Manager, sourceFile: String) {
        self.id = id
        self.timestamp = timestamp
        self.action = action
        self.package = package
        self.version = version
        self.manager = manager
        self.sourceFile = sourceFile
    }
}
