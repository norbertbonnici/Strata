import Foundation

/// One recovered macOS **network / device** context item — a known Wi-Fi network,
/// a DHCP lease, a paired Bluetooth device, a Time Machine destination, or a
/// trusted iOS device pairing.
///
/// These are host-context evidence: where the Mac has been (SSID/BSSID history →
/// geolocation), what IPs/networks it used, which peripherals + phones it paired
/// with, and where it backed up (a data-egress target). The backing plists drift
/// across macOS releases, so the parser stays lenient and records the best stable
/// (name, identifier, timestamp) it can recover per item.
public nonisolated struct MacNetworkItem: Identifiable, Hashable, Sendable, Codable {
    public enum Kind: String, CaseIterable, Sendable, Codable {
        case wifiNetwork
        case dhcpLease
        case bluetoothDevice
        case timeMachine
        case devicePairing

        public var label: String {
            switch self {
            case .wifiNetwork:     return "Wi-Fi Network"
            case .dhcpLease:       return "DHCP Lease"
            case .bluetoothDevice: return "Bluetooth Device"
            case .timeMachine:     return "Time Machine"
            case .devicePairing:   return "Device Pairing"
            }
        }
    }

    public let id: UUID
    public let kind: Kind
    /// SSID / device name / backup volume / paired-device UDID.
    public let name: String
    /// BSSID / MAC / IP address / backup NetworkURL — the secondary identifier.
    public let identifier: String?
    /// Best timestamp for the item (last joined / lease start / last seen / last backup).
    public let timestamp: Date?
    /// Extra context (security type, router MAC, device class, bytes, …).
    public let detail: String?
    public let scope: String
    public let sourceFile: String

    public init(id: UUID = UUID(), kind: Kind, name: String, identifier: String? = nil,
                timestamp: Date? = nil, detail: String? = nil, scope: String, sourceFile: String) {
        self.id = id
        self.kind = kind
        self.name = name
        self.identifier = identifier
        self.timestamp = timestamp
        self.detail = detail
        self.scope = scope
        self.sourceFile = sourceFile
    }

    public var title: String { name.isEmpty ? (identifier ?? kind.label) : name }

    public var timelineSummary: String {
        "[\(kind.label)] \(title)" + (identifier.map { " (\($0))" } ?? "")
    }
}
