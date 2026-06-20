//
//  MacNetworkTests.swift
//  StrataTests
//
//  Covers the macOS network/device parser (Wi-Fi legacy + modern, DHCP lease,
//  Bluetooth, Time Machine, lockdown pairing) over synthetic plists, plus the
//  Time-Machine-network-destination analyzer.
//

import Testing
import Foundation
@testable import Strata

struct MacNetworkTests {

    private func plist(_ obj: Any) -> Data {
        try! PropertyListSerialization.data(fromPropertyList: obj, format: .binary, options: 0)
    }
    private func parse(_ obj: Any, _ source: String) -> [MacNetworkItem] {
        MacNetworkParser.parse(data: plist(obj), sourceFile: source, scope: "x")
    }

    // MARK: - Wi-Fi

    @Test func parsesLegacyAirportKnownNetworks() {
        let d: [String: Any] = ["KnownNetworks": [
            "uuid-1": ["SSIDString": "CorpWiFi", "SecurityType": "WPA2 Personal",
                       "LastConnected": Date(timeIntervalSince1970: 1_700_000_000)],
        ]]
        let out = parse(d, "/Library/Preferences/SystemConfiguration/com.apple.airport.preferences.plist")
        #expect(out.count == 1)
        #expect(out[0].kind == .wifiNetwork)
        #expect(out[0].name == "CorpWiFi")
        #expect(out[0].timestamp != nil)
        #expect(out[0].detail?.contains("WPA2") == true)
    }

    @Test func parsesModernKnownNetworks() {
        let d: [String: Any] = [
            "wifi.ssid.HomeNet": ["SSID": Data("HomeNet".utf8),
                                  "JoinedByUserAt": Date(timeIntervalSince1970: 1_699_000_000)],
        ]
        let out = parse(d, "/Library/Preferences/com.apple.wifi.known-networks.plist")
        #expect(out.first?.name == "HomeNet")
        #expect(out.first?.timestamp != nil)
    }

    // MARK: - DHCP

    @Test func parsesDHCPLease() {
        let d: [String: Any] = [
            "IPAddress": "192.168.1.50",
            "RouterIPAddress": "192.168.1.1",
            "RouterHardwareAddress": Data([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]),
            "LeaseStartDate": Date(timeIntervalSince1970: 1_700_000_000),
            "SSID": Data("CoffeeShop".utf8),
        ]
        let out = parse(d, "/private/var/db/dhcpclient/leases/en0-1,aa:bb:cc:dd:ee:ff")
        #expect(out.count == 1)
        #expect(out[0].kind == .dhcpLease)
        #expect(out[0].name == "192.168.1.50")
        #expect(out[0].detail?.contains("aa:bb:cc:dd:ee:ff") == true)
        #expect(out[0].detail?.contains("CoffeeShop") == true)
    }

    // MARK: - Bluetooth

    @Test func parsesBluetoothDeviceCache() {
        let d: [String: Any] = [
            "DeviceCache": ["aa-bb-cc-dd-ee-ff": ["Name": "Magic Keyboard",
                                                  "LastNameUpdate": Date(timeIntervalSince1970: 1_700_000_000)]],
            "PairedDevices": ["aa-bb-cc-dd-ee-ff"],
        ]
        let out = parse(d, "/Library/Preferences/com.apple.Bluetooth.plist")
        #expect(out.count == 1)
        #expect(out[0].kind == .bluetoothDevice)
        #expect(out[0].name == "Magic Keyboard")
        #expect(out[0].identifier == "aa-bb-cc-dd-ee-ff")
        #expect(out[0].detail?.contains("paired") == true)
    }

    // MARK: - Time Machine

    @Test func parsesTimeMachineNetworkDestination() {
        let d: [String: Any] = ["Destinations": [
            ["DestinationID": "ABC", "NetworkURL": "smb://10.0.0.9/Backups",
             "BytesUsed": 5_000_000_000 as Int64,
             "SnapshotDates": [Date(timeIntervalSince1970: 1_699_000_000), Date(timeIntervalSince1970: 1_700_000_000)]],
        ]]
        let out = parse(d, "/Library/Preferences/com.apple.TimeMachine.plist")
        #expect(out.count == 1)
        #expect(out[0].kind == .timeMachine)
        #expect(out[0].identifier == "smb://10.0.0.9/Backups")
        // newest snapshot wins
        #expect(out[0].timestamp == Date(timeIntervalSince1970: 1_700_000_000))
    }

    // MARK: - Pairing

    @Test func parsesLockdownPairing() {
        let udid = "00008110-001234567890ABCD"
        let d: [String: Any] = ["WiFiMACAddress": "aa:bb:cc:11:22:33", "HostID": "ABCDEF0123456789"]
        let out = parse(d, "/private/var/db/lockdown/\(udid).plist")
        #expect(out.count == 1)
        #expect(out[0].kind == .devicePairing)
        #expect(out[0].name == udid)
        #expect(out[0].identifier == "aa:bb:cc:11:22:33")
    }

    @Test func skipsNonPairingLockdownPlist() {
        let out = parse(["x": 1], "/private/var/db/lockdown/com.apple.lockdownd.plist")
        #expect(out.isEmpty)
    }

    // MARK: - Analyzer

    private func tm(networkURL: String?) -> MacNetworkItem {
        MacNetworkItem(kind: .timeMachine, name: "Backups", identifier: networkURL,
                       timestamp: Date(timeIntervalSince1970: 1_700_000_000), scope: "x",
                       sourceFile: "/Library/Preferences/com.apple.TimeMachine.plist")
    }

    @Test func flagsNetworkedTimeMachine() {
        let findings = MacNetworkAnalyzer().analyze([tm(networkURL: "smb://nas.local/Backups")])
        #expect(findings.count == 1)
        #expect(findings[0].technique?.attackID == "T1074")
        #expect(findings[0].severity == .medium)
    }

    @Test func rawIPTimeMachineIsHigh() {
        let findings = MacNetworkAnalyzer().analyze([tm(networkURL: "smb://10.0.0.9/Backups")])
        #expect(findings.first?.severity == .high)
    }

    @Test func ignoresLocalTimeMachineAndOtherKinds() {
        let findings = MacNetworkAnalyzer().analyze([
            tm(networkURL: nil),  // local disk — identifier nil
            MacNetworkItem(kind: .wifiNetwork, name: "CorpWiFi", scope: "x", sourceFile: "/x"),
        ])
        #expect(findings.isEmpty)
    }

    @Test func emptyInputNoFindings() {
        #expect(MacNetworkAnalyzer().analyze([]).isEmpty)
    }
}
