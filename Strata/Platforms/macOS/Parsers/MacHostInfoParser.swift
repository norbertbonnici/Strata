import Foundation

/// Builds a `MacHostInfo` from the handful of small files that identify a macOS
/// host - the macOS counterpart of `LinuxHostInfoParser`. Each `apply…`
/// function folds one source into an `inout MacHostInfo`; feed it whatever was
/// found. Pure and cross-platform (no I/O): the caller hands us the raw bytes
/// (extracted via icat for images, or read in place for a loose collection).
///
/// All four primary sources are property lists - `PropertyListSerialization`
/// transparently decodes both the XML and binary encodings macOS mixes.
public enum MacHostInfoParser {

    /// `/System/Library/CoreServices/SystemVersion.plist`: the OS name, version
    /// and build. `ProductUserVisibleVersion` is preferred over
    /// `ProductVersion` when present (they differ on some seed builds).
    public static func applySystemVersion(_ data: Data, to info: inout MacHostInfo) {
        guard let dict = dictionary(data) else { return }
        info.productName = string(dict["ProductName"]) ?? info.productName
        info.productVersion = string(dict["ProductUserVisibleVersion"])
            ?? string(dict["ProductVersion"]) ?? info.productVersion
        info.buildVersion = string(dict["ProductBuildVersion"]) ?? info.buildVersion
    }

    /// SystemConfiguration `preferences.plist`
    /// (`/Library/Preferences/SystemConfiguration/preferences.plist`): the
    /// user-facing `ComputerName` and the Bonjour `LocalHostName`, nested under
    /// `System.System` and `System.Network.HostNames` respectively. Also a
    /// best-effort sweep for statically-configured IPv4 addresses.
    public static func applyPreferences(_ data: Data, to info: inout MacHostInfo) {
        guard let root = dictionary(data) else { return }
        let system = (root["System"] as? [String: Any]) ?? [:]
        if let inner = system["System"] as? [String: Any] {
            info.computerName = string(inner["ComputerName"]) ?? info.computerName
        }
        if let network = system["Network"] as? [String: Any],
           let hostNames = network["HostNames"] as? [String: Any] {
            info.localHostName = string(hostNames["LocalHostName"]) ?? info.localHostName
        }
        mergeIPs(collectIPv4(in: root), into: &info)
    }

    /// SystemConfiguration `NetworkInterfaces.plist`: a separate best-effort
    /// IPv4 sweep for hosts whose addresses live there rather than in
    /// `preferences.plist`.
    public static func applyNetworkInterfaces(_ data: Data, to info: inout MacHostInfo) {
        guard let root = dictionary(data) else { return }
        mergeIPs(collectIPv4(in: root), into: &info)
    }

    /// One dslocal user plist
    /// (`/private/var/db/dslocal/nodes/Default/users/<name>.plist`). Every
    /// attribute is stored as a single-element array - we unwrap the first
    /// element. UID is a numeric string. Accounts are appended (the caller
    /// applies one plist per user).
    public static func applyUserPlist(_ data: Data, to info: inout MacHostInfo) {
        guard let dict = dictionary(data) else { return }
        guard let name = firstArrayString(dict["name"]),
              let uidString = firstArrayString(dict["uid"]),
              let uid = Int(uidString) else { return }
        let home = firstArrayString(dict["home"]) ?? ""
        let shell = firstArrayString(dict["shell"]) ?? ""
        let user = MacUser(name: name, uid: uid, home: home, shell: shell)
        if !info.users.contains(user) { info.users.append(user) }
    }

    /// Derive the timezone from the `/etc/localtime` symlink target (or any
    /// zoneinfo path), e.g. `…/zoneinfo/Europe/Malta` → `Europe/Malta`.
    public static func applyTimezone(fromZoneinfoPath path: String, to info: inout MacHostInfo) {
        guard let range = path.range(of: "zoneinfo/") else { return }
        let zone = String(path[range.upperBound...]).trimmingCharacters(in: .whitespacesAndNewlines)
        if !zone.isEmpty { info.timeZone = zone }
    }

    /// Append host IPs to `info`, preserving discovery order and deduping.
    public static func mergeIPs(_ ips: [String], into info: inout MacHostInfo) {
        for ip in ips where !info.ipAddresses.contains(ip) {
            info.ipAddresses.append(ip)
        }
    }

    // MARK: - Plist helpers

    private static func dictionary(_ data: Data) -> [String: Any]? {
        (try? PropertyListSerialization.propertyList(from: data, options: [], format: nil))
            as? [String: Any]
    }

    private static func string(_ value: Any?) -> String? {
        guard let s = value as? String else { return nil }
        let t = s.trimmingCharacters(in: .whitespacesAndNewlines)
        return t.isEmpty ? nil : t
    }

    /// dslocal stores each attribute as `[<value>]`; pull the first string.
    private static func firstArrayString(_ value: Any?) -> String? {
        if let arr = value as? [Any] { return string(arr.first) }
        return string(value)
    }

    /// Best-effort recursive sweep of a SystemConfiguration plist for routable
    /// IPv4 host addresses. SystemConfiguration nests them under various keys
    /// (`Addresses`, `IPAddress`, per-service dictionaries), so rather than
    /// hard-code the schema we collect every dotted-quad string and filter out
    /// the non-host ranges (unspecified / loopback / link-local).
    static func collectIPv4(in object: Any) -> [String] {
        var found: [String] = []
        func walk(_ node: Any) {
            switch node {
            case let dict as [String: Any]:
                for value in dict.values { walk(value) }
            case let array as [Any]:
                for value in array { walk(value) }
            case let s as String:
                if isRoutableIPv4(s) { found.append(s) }
            default:
                break
            }
        }
        walk(object)
        // Dedup, preserve order.
        var seen = Set<String>()
        return found.filter { seen.insert($0).inserted }
    }

    /// True for a dotted-quad IPv4 that names a real host (not 0.0.0.0,
    /// 127.x loopback, or 169.254.x link-local).
    static func isRoutableIPv4(_ s: String) -> Bool {
        let parts = s.split(separator: ".", omittingEmptySubsequences: false)
        guard parts.count == 4 else { return false }
        var octets: [Int] = []
        for part in parts {
            guard let n = Int(part), (0...255).contains(n) else { return false }
            octets.append(n)
        }
        if octets == [0, 0, 0, 0] { return false }
        if octets[0] == 127 { return false }
        if octets[0] == 169 && octets[1] == 254 { return false }
        return true
    }
}
