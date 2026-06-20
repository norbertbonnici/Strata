import Foundation

/// Parses macOS **network / device** context plists into `[MacNetworkItem]`,
/// dispatching by the source path:
///
///  - Wi-Fi: `com.apple.airport.preferences.plist` (legacy `KnownNetworks`) +
///    `com.apple.wifi.known-networks.plist` (Ventura/Sonoma).
///  - DHCP: `/private/var/db/dhcpclient/leases/*` (per-interface binary plists).
///  - Bluetooth: `com.apple.Bluetooth.plist` (`DeviceCache`).
///  - Time Machine: `com.apple.TimeMachine.plist` (`Destinations`).
///  - Device pairing: `/var/db/lockdown/<UDID>.plist` trust records.
///
/// All parsing is lenient (the layouts drift across releases): a missing key just
/// means a nil field, never a throw. `<date>` plist values decode to `Date`
/// directly; numeric dates are treated as CFAbsoluteTime / Unix by magnitude.
public enum MacNetworkParser {

    public static func parse(data: Data, sourceFile: String, scope: String) -> [MacNetworkItem] {
        let lower = sourceFile.lowercased()
        let name = (sourceFile as NSString).lastPathComponent.lowercased()
        if lower.contains("/dhcpclient/leases/") {
            return parseDHCP(data, sourceFile: sourceFile, scope: scope)
        }
        if name == "com.apple.bluetooth.plist" {
            return parseBluetooth(data, sourceFile: sourceFile, scope: scope)
        }
        if name == "com.apple.timemachine.plist" {
            return parseTimeMachine(data, sourceFile: sourceFile, scope: scope)
        }
        if name.contains("wifi.known-networks") || name.contains("airport.preferences") {
            return parseWifi(data, sourceFile: sourceFile, scope: scope)
        }
        if lower.contains("/lockdown/") {
            return parsePairing(data, sourceFile: sourceFile, scope: scope)
        }
        return []
    }

    // MARK: - Wi-Fi

    private static func parseWifi(_ data: Data, sourceFile: String, scope: String) -> [MacNetworkItem] {
        guard let root = plistDict(data) else { return [] }
        var out: [MacNetworkItem] = []
        // Legacy airport: { KnownNetworks: { <uuid>: {SSIDString, SecurityType, LastConnected, ...} } }
        // Modern: top-level dict keyed by "wifi.ssid.<…>" → {SSID(data), AddedAt, JoinedByUserAt, …}.
        let networks = (root["KnownNetworks"] as? [String: Any]) ?? root
        for (key, value) in networks {
            guard let net = dict(value) else { continue }
            let ssid = (net["SSIDString"] as? String)
                ?? string(fromData: net["SSID"])
                ?? ssid(fromKey: key)
            guard let ssid, !ssid.isEmpty else { continue }
            let when = firstDate(net, ["LastConnected", "JoinedByUserAt", "LastAutoJoinedAt",
                                       "AddedAt", "UpdatedAt", "_timeStamp"])
            var bits: [String] = []
            if let sec = net["SecurityType"] as? String { bits.append(sec) }
            if let bssid = (net["BSSID"] as? String) ?? string(fromData: net["BSSID"]) { bits.append("BSSID \(bssid)") }
            out.append(MacNetworkItem(kind: .wifiNetwork, name: ssid, identifier: nil,
                                      timestamp: when, detail: bits.isEmpty ? nil : bits.joined(separator: " · "),
                                      scope: scope, sourceFile: sourceFile))
        }
        return dedup(out)
    }

    private static func ssid(fromKey key: String) -> String? {
        // "wifi.ssid.MyNet" / "wifi.network.ssid.MyNet" → "MyNet".
        if let r = key.range(of: ".ssid.") { return String(key[r.upperBound...]) }
        return key.hasPrefix("wifi.") ? nil : key
    }

    // MARK: - DHCP

    private static func parseDHCP(_ data: Data, sourceFile: String, scope: String) -> [MacNetworkItem] {
        guard let d = plistDict(data) else { return [] }
        let ip = (d["IPAddress"] as? String)
        let routerMAC = string(fromData: d["RouterHardwareAddress"]) ?? (d["RouterHardwareAddress"] as? String)
        let ssid = string(fromData: d["SSID"]) ?? (d["SSID"] as? String)
        let when = firstDate(d, ["LeaseStartDate", "LeaseStart"])
        guard ip != nil || routerMAC != nil else { return [] }
        var bits: [String] = []
        if let router = d["RouterIPAddress"] as? String { bits.append("router \(router)") }
        if let routerMAC { bits.append("router MAC \(routerMAC)") }
        if let ssid { bits.append("SSID \(ssid)") }
        let iface = (sourceFile as NSString).lastPathComponent
        return [MacNetworkItem(kind: .dhcpLease, name: ip ?? iface, identifier: iface,
                               timestamp: when, detail: bits.isEmpty ? nil : bits.joined(separator: " · "),
                               scope: scope, sourceFile: sourceFile)]
    }

    // MARK: - Bluetooth

    private static func parseBluetooth(_ data: Data, sourceFile: String, scope: String) -> [MacNetworkItem] {
        guard let root = plistDict(data) else { return [] }
        let cache = (root["DeviceCache"] as? [String: Any]) ?? [:]
        let paired = Set((root["PairedDevices"] as? [String])?.map { $0.lowercased() } ?? [])
        var out: [MacNetworkItem] = []
        for (mac, value) in cache {
            guard let dev = dict(value) else { continue }
            let name = (dev["Name"] as? String) ?? (dev["displayName"] as? String) ?? mac
            let when = firstDate(dev, ["LastNameUpdate", "LastServicesUpdate", "LastInquiryUpdate"])
            var bits: [String] = []
            if paired.contains(mac.lowercased()) { bits.append("paired") }
            if let cls = dev["ClassOfDevice"] as? NSNumber { bits.append("class 0x\(String(cls.intValue, radix: 16))") }
            out.append(MacNetworkItem(kind: .bluetoothDevice, name: name, identifier: mac,
                                      timestamp: when, detail: bits.isEmpty ? nil : bits.joined(separator: " · "),
                                      scope: scope, sourceFile: sourceFile))
        }
        return dedup(out)
    }

    // MARK: - Time Machine

    private static func parseTimeMachine(_ data: Data, sourceFile: String, scope: String) -> [MacNetworkItem] {
        guard let root = plistDict(data) else { return [] }
        guard let dests = root["Destinations"] as? [Any] else { return [] }
        var out: [MacNetworkItem] = []
        for value in dests {
            guard let dest = dict(value) else { continue }
            let networkURL = dest["NetworkURL"] as? String
            let volume = (dest["LastKnownVolumeName"] as? String) ?? (dest["LastKnownEncryptionState"] as? String)
            let name = volume ?? networkURL ?? (dest["DestinationID"] as? String) ?? "Backup"
            let when = newestDate(dest["SnapshotDates"]) ?? firstDate(dest, ["BACKUP_COMPLETED_DATE", "RESULT"])
            var bits: [String] = []
            if let bytes = dest["BytesUsed"] as? NSNumber { bits.append("\(ByteCountFormatter.string(fromByteCount: bytes.int64Value, countStyle: .file)) used") }
            if networkURL != nil { bits.append("network backup") }
            out.append(MacNetworkItem(kind: .timeMachine, name: name, identifier: networkURL,
                                      timestamp: when, detail: bits.isEmpty ? nil : bits.joined(separator: " · "),
                                      scope: scope, sourceFile: sourceFile))
        }
        return out
    }

    // MARK: - Device pairing (lockdown)

    private static func parsePairing(_ data: Data, sourceFile: String, scope: String) -> [MacNetworkItem] {
        let udid = ((sourceFile as NSString).lastPathComponent as NSString).deletingPathExtension
        // Skip the non-pairing lockdown plists.
        guard udid.count >= 16, !udid.lowercased().hasPrefix("com.apple") else { return [] }
        let d = plistDict(data) ?? [:]
        let wifiMAC = string(fromData: d["WiFiMACAddress"]) ?? (d["WiFiMACAddress"] as? String)
        let name = (d["DeviceName"] as? String) ?? udid
        var bits: [String] = []
        if d["EscrowBag"] != nil { bits.append("escrow bag present") }
        if let host = d["HostID"] as? String { bits.append("host \(host.prefix(8))…") }
        return [MacNetworkItem(kind: .devicePairing, name: name, identifier: wifiMAC ?? udid,
                               timestamp: nil, detail: bits.isEmpty ? nil : bits.joined(separator: " · "),
                               scope: scope, sourceFile: sourceFile)]
    }

    // MARK: - Helpers

    private static func plistDict(_ data: Data) -> [String: Any]? {
        (try? PropertyListSerialization.propertyList(from: data, options: [], format: nil)) as? [String: Any]
    }
    private static func dict(_ any: Any) -> [String: Any]? {
        if let d = any as? [String: Any] { return d }
        if let ns = any as? NSDictionary {
            var s: [String: Any] = [:]; for (k, v) in ns where k is String { s[k as! String] = v }; return s
        }
        return nil
    }
    private static func string(fromData any: Any?) -> String? {
        guard let data = any as? Data, !data.isEmpty else { return nil }
        // SSID is UTF-8 text; a MAC/BSSID blob renders as colon-hex.
        if let s = String(data: data, encoding: .utf8), s.allSatisfy({ !$0.isNewline && ($0.isASCII) }), !s.isEmpty {
            return s
        }
        return data.map { String(format: "%02x", $0) }.joined(separator: ":")
    }
    private static func firstDate(_ d: [String: Any], _ keys: [String]) -> Date? {
        for k in keys { if let date = dateValue(d[k]) { return date } }
        return nil
    }
    private static func newestDate(_ any: Any?) -> Date? {
        guard let arr = any as? [Any] else { return dateValue(any) }
        return arr.compactMap(dateValue).max()
    }
    private static func dateValue(_ any: Any?) -> Date? {
        if let d = any as? Date { return d }
        if let n = any as? NSNumber {
            let v = n.doubleValue
            guard v > 0 else { return nil }
            return v > 1_000_000_000 ? Date(timeIntervalSince1970: v) : Date(timeIntervalSinceReferenceDate: v)
        }
        return nil
    }
    private static func dedup(_ items: [MacNetworkItem]) -> [MacNetworkItem] {
        var seen = Set<String>(); var out: [MacNetworkItem] = []
        for i in items {
            let key = "\(i.kind.rawValue)|\(i.name)|\(i.identifier ?? "")"
            if seen.insert(key).inserted { out.append(i) }
        }
        return out.sorted {
            if ($0.timestamp ?? .distantPast) != ($1.timestamp ?? .distantPast) {
                return ($0.timestamp ?? .distantPast) > ($1.timestamp ?? .distantPast)
            }
            return $0.name.localizedCaseInsensitiveCompare($1.name) == .orderedAscending
        }
    }
}
