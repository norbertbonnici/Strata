import Foundation

/// One row of the macOS **TCC** (Transparency, Consent, and Control) database's
/// `access` table — a record that an app/binary was granted (or denied) a
/// privacy-sensitive capability: Camera, Microphone, Screen Recording,
/// Accessibility, Full Disk Access, Automation, Input Monitoring, etc.
///
/// Forensically high-value: an attacker tool that obtained **Accessibility**
/// (keystroke injection / UI control), **Screen Recording**, or **Full Disk
/// Access** shows up here with the grant's `last_modified` time. Lives in the
/// system `TCC.db` (`/Library/Application Support/com.apple.TCC/`) and a per-user
/// one (`~/Library/Application Support/com.apple.TCC/`).
public nonisolated struct TCCAccess: Identifiable, Hashable, Sendable, Codable {
    public let id: UUID
    /// The raw TCC service key (e.g. `kTCCServiceAccessibility`).
    public let service: String
    /// The client — a bundle identifier (`client_type` 0) or an executable path
    /// (`client_type` 1).
    public let client: String
    public let clientType: Int
    /// Authorisation result.
    public let authValue: AuthValue
    /// TCC's reason code for the decision (`auth_reason`).
    public let authReason: Int
    /// When the grant was created/last changed.
    public let lastModified: Date?
    /// `system` or the owning user (the TCC.db's location).
    public let scope: String
    public let sourceFile: String

    public enum AuthValue: Int, Sendable, Codable {
        case denied = 0, unknown = 1, allowed = 2, limited = 3
        public var label: String {
            switch self {
            case .denied:  return "Denied"
            case .unknown: return "Unknown"
            case .allowed: return "Allowed"
            case .limited: return "Limited"
            }
        }
    }

    public init(id: UUID = UUID(), service: String, client: String, clientType: Int,
                authValue: AuthValue, authReason: Int, lastModified: Date?,
                scope: String, sourceFile: String) {
        self.id = id
        self.service = service; self.client = client; self.clientType = clientType
        self.authValue = authValue; self.authReason = authReason
        self.lastModified = lastModified; self.scope = scope; self.sourceFile = sourceFile
    }

    /// A friendly name for the System-Settings privacy pane the service maps to.
    public var serviceLabel: String {
        TCCAccess.serviceLabels[service] ?? service.replacingOccurrences(of: "kTCCService", with: "")
    }

    /// The client's leaf name (bundle id as-is, or the path's last component).
    public var clientLabel: String {
        clientType == 1 ? (client as NSString).lastPathComponent : client
    }

    /// True for the high-impact capabilities an attacker covets — the ones the
    /// analyzer flags when granted to a non-Apple client.
    public var isSensitive: Bool { TCCAccess.sensitiveServices.contains(service) }

    static let sensitiveServices: Set<String> = [
        "kTCCServiceAccessibility", "kTCCServiceScreenCapture", "kTCCServicePostEvent",
        "kTCCServiceListenEvent", "kTCCServiceSystemPolicyAllFiles", "kTCCServiceCamera",
        "kTCCServiceMicrophone", "kTCCServiceAppleEvents", "kTCCServiceSystemPolicySysAdminFiles",
    ]

    static let serviceLabels: [String: String] = [
        "kTCCServiceCamera": "Camera",
        "kTCCServiceMicrophone": "Microphone",
        "kTCCServiceScreenCapture": "Screen Recording",
        "kTCCServiceAccessibility": "Accessibility",
        "kTCCServicePostEvent": "Send Keystrokes (PostEvent)",
        "kTCCServiceListenEvent": "Input Monitoring",
        "kTCCServiceAppleEvents": "Automation (AppleEvents)",
        "kTCCServiceSystemPolicyAllFiles": "Full Disk Access",
        "kTCCServiceSystemPolicySysAdminFiles": "Admin Files",
        "kTCCServiceSystemPolicyDesktopFolder": "Desktop Folder",
        "kTCCServiceSystemPolicyDocumentsFolder": "Documents Folder",
        "kTCCServiceSystemPolicyDownloadsFolder": "Downloads Folder",
        "kTCCServiceSystemPolicyNetworkVolumes": "Network Volumes",
        "kTCCServiceSystemPolicyRemovableVolumes": "Removable Volumes",
        "kTCCServiceDeveloperTool": "Developer Tool",
        "kTCCServiceContactsFull": "Contacts",
        "kTCCServiceContactsLimited": "Contacts (Limited)",
        "kTCCServiceCalendar": "Calendar",
        "kTCCServiceReminders": "Reminders",
        "kTCCServicePhotos": "Photos",
        "kTCCServiceMediaLibrary": "Media Library",
        "kTCCServiceLocation": "Location",
        "kTCCServiceBluetoothAlways": "Bluetooth",
        "kTCCServiceUbiquity": "iCloud",
        "kTCCServiceFileProviderDomain": "File Provider",
    ]
}
