import Foundation

/// One macOS **system-configuration / security-posture** setting recovered from a
/// preference plist (or a service-state file). This is the static *capability*
/// half of the picture — "the firewall is off", "SSH remote login is enabled",
/// "auto-login is configured" — complementing the event artifacts (unified log,
/// auth) that show a control was actually *used*.
///
/// Pure / `Sendable` / `Codable` (crosses the off-main parse boundary and is
/// persisted to JSON). The macOS-only `MacConfigParser` reads the curated set of
/// preference domains no other parser covers; `MacConfigAnalyzer` projects the
/// flagged settings into ATT&CK findings.
public nonisolated struct MacConfigSetting: Identifiable, Hashable, Sendable, Codable {
    public enum Category: String, Sendable, Codable, CaseIterable {
        case firewall, screenLock, softwareUpdate, gatekeeper, fileVault
        case remoteAccess, sharing, loginWindow, account

        public nonisolated var label: String {
            switch self {
            case .firewall:       return "Firewall"
            case .screenLock:     return "Screen Lock"
            case .softwareUpdate: return "Software Update"
            case .gatekeeper:     return "Gatekeeper"
            case .fileVault:      return "FileVault"
            case .remoteAccess:   return "Remote Access"
            case .sharing:        return "File Sharing"
            case .loginWindow:    return "Login Window"
            case .account:        return "Accounts"
            }
        }
    }

    /// Display/severity hint for the value. `none` = informational inventory;
    /// the analyzer emits a Finding for everything above `none`.
    public enum Risk: String, Sendable, Codable { case none, low, medium, high }

    public let id: UUID
    public let category: Category
    /// Stable identifier for the setting, e.g. `firewall.globalstate`.
    public let key: String
    /// Human setting name, e.g. "Application Firewall".
    public let name: String
    /// The decoded value, stringified.
    public let value: String
    /// Plain-English meaning, e.g. "Firewall is OFF (all incoming allowed)".
    public let interpretation: String
    public let risk: Risk
    public let attackID: String?
    public let attackName: String?
    /// Preference domain / bundle id, e.g. "com.apple.alf".
    public let domain: String?
    /// "system" or a username.
    public let scope: String
    public let sourceFile: String

    public init(id: UUID = UUID(), category: Category, key: String, name: String,
                value: String, interpretation: String, risk: Risk = .none,
                attackID: String? = nil, attackName: String? = nil,
                domain: String? = nil, scope: String, sourceFile: String) {
        self.id = id
        self.category = category
        self.key = key
        self.name = name
        self.value = value
        self.interpretation = interpretation
        self.risk = risk
        self.attackID = attackID
        self.attackName = attackName
        self.domain = domain
        self.scope = scope
        self.sourceFile = sourceFile
    }

    public var isFlagged: Bool { risk != .none }
    public var title: String { name }
    public var detailSummary: String { interpretation }
}
