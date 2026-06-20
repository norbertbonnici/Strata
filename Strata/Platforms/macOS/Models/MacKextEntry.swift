import Foundation

/// A macOS **kernel extension** (`.kext`) or modern **System Extension**
/// (DriverKit / Network / Endpoint-Security extension). Both load third-party
/// code into a privileged context, so a non-Apple one is a high-signal
/// persistence / rootkit vector (ATT&CK T1547.006).
///
/// No reliable per-item timestamp lives in a kext `Info.plist` or the System
/// Extensions `db.plist`, so this carries no timeline projection.
public nonisolated struct MacKextEntry: Identifiable, Hashable, Sendable, Codable {
    public enum Kind: String, CaseIterable, Sendable, Codable {
        case kext
        case systemExtension

        public var label: String {
            switch self {
            case .kext: return "Kernel Extension"
            case .systemExtension: return "System Extension"
            }
        }
    }

    public let id: UUID
    public let kind: Kind
    public let bundleID: String
    public let name: String
    public let version: String?
    /// Developer Team ID (System Extensions db); nil for a plain kext Info.plist.
    public let teamID: String?
    /// On-disk bundle path, when recorded.
    public let path: String?
    /// System Extension activation state (enabled/activated); nil for kexts.
    public let enabled: Bool?
    public let scope: String
    public let sourceFile: String

    public init(id: UUID = UUID(), kind: Kind, bundleID: String, name: String,
                version: String? = nil, teamID: String? = nil, path: String? = nil,
                enabled: Bool? = nil, scope: String, sourceFile: String) {
        self.id = id
        self.kind = kind
        self.bundleID = bundleID
        self.name = name
        self.version = version
        self.teamID = teamID
        self.path = path
        self.enabled = enabled
        self.scope = scope
        self.sourceFile = sourceFile
    }

    /// Apple-shipped extensions are expected; third-party ones are the signal.
    public var isApple: Bool {
        bundleID.lowercased().hasPrefix("com.apple.")
    }

    public var title: String { name.isEmpty ? bundleID : name }
}
