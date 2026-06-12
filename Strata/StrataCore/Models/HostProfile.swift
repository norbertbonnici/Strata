import Foundation

/// Snapshot of a host's identity and configuration, derived from registry
/// values that `parseRegistry()` already extracted. Nothing is persisted -
/// the registry is the source of truth, this struct is just a typed
/// projection over it.
public nonisolated struct HostProfile: Sendable {
    public var hostname: String?
    public var domain: String?
    public var osProductName: String?     // "Windows 10 Pro"
    public var osDisplayVersion: String?  // "22H2"
    public var osBuild: String?           // "19045.4291"
    public var installDate: Date?
    public var lastShutdown: Date?
    public var primaryUser: String?
    public var timeZone: String?
    public var ipAddresses: [String] = []

    public init() {}

    public var hasAnyData: Bool {
        hostname != nil || domain != nil || osProductName != nil ||
        osBuild != nil || installDate != nil || lastShutdown != nil ||
        primaryUser != nil || timeZone != nil || !ipAddresses.isEmpty
    }

    /// Single-line OS string for header rendering. Returns nil when none of
    /// the OS fields are populated.
    public var osSummary: String? {
        var parts: [String] = []
        if let osProductName { parts.append(osProductName) }
        if let osDisplayVersion { parts.append(osDisplayVersion) }
        if let osBuild { parts.append("Build \(osBuild)") }
        let joined = parts.joined(separator: " ")
        return joined.isEmpty ? nil : joined
    }

    /// Build a profile from Linux host-info files (`os-release`, `hostname`,
    /// `passwd`, `timezone`) - the Linux counterpart of the registry walk
    /// below. PRETTY_NAME already carries the version ("Ubuntu 22.04.4 LTS"),
    /// so it maps onto `osProductName` alone. The primary user is the
    /// lowest-UID human account (UID ≥ 1000) with a real login shell.
    public static func derive(fromLinux info: LinuxHostInfo) -> HostProfile {
        var profile = HostProfile()
        profile.hostname = info.hostname
        profile.osProductName = info.prettyName ?? info.osID
        profile.timeZone = info.timeZone
        profile.ipAddresses = info.ipAddresses
        profile.primaryUser = info.users
            .filter { $0.uid >= 1000 && $0.uid < 65_000 && $0.hasLoginShell }
            .min { $0.uid < $1.uid }?
            .name
        return profile
    }

    /// Build a profile from the macOS host-info files (`SystemVersion.plist`,
    /// the SystemConfiguration `preferences.plist`, dslocal user plists, the
    /// timezone) - the macOS counterpart of the Linux derivation above.
    /// `computerName` is the user-facing host label; `localHostName` is the
    /// fallback. The primary user is the lowest-UID human account (macOS starts
    /// human UIDs at 501) with a real login shell.
    public static func derive(fromMac info: MacHostInfo) -> HostProfile {
        var profile = HostProfile()
        profile.hostname = info.computerName ?? info.localHostName
        profile.osProductName = info.productName
        profile.osDisplayVersion = info.productVersion
        profile.osBuild = info.buildVersion
        profile.timeZone = info.timeZone
        profile.ipAddresses = info.ipAddresses
        profile.primaryUser = info.users
            .filter { $0.uid >= 501 && $0.uid < 65_000 && $0.hasLoginShell }
            .min { $0.uid < $1.uid }?
            .name
        return profile
    }

    /// Walk a registry-value list and pull the well-known identity / config
    /// values. Missing values stay nil - we never invent defaults.
    public static func derive(from values: [RegistryValue]) -> HostProfile {
        var profile = HostProfile()
        var ipSeen = Set<String>()

        for value in values {
            let hive = value.hive.uppercased()
            let path = value.path
            let name = value.name

            if hive.contains("SYSTEM") {
                deriveSystem(value: value, path: path, name: name,
                             profile: &profile, ipSeen: &ipSeen)
            } else if hive.contains("SOFTWARE") {
                deriveSoftware(value: value, path: path, name: name,
                               profile: &profile)
            }
        }
        return profile
    }

    private static func deriveSystem(value: RegistryValue, path: String,
                                     name: String, profile: inout HostProfile,
                                     ipSeen: inout Set<String>) {
        if pathMatches(path, key: "Control\\ComputerName\\ComputerName"),
           name.caseInsensitiveCompare("ComputerName") == .orderedSame {
            profile.hostname = nonEmpty(value.data) ?? profile.hostname
            return
        }
        if pathMatches(path, key: "Control\\ComputerName\\ActiveComputerName"),
           name.caseInsensitiveCompare("ComputerName") == .orderedSame,
           profile.hostname == nil {
            profile.hostname = nonEmpty(value.data)
            return
        }
        if pathMatches(path, key: "Services\\Tcpip\\Parameters") {
            if name.caseInsensitiveCompare("Domain") == .orderedSame {
                profile.domain = nonEmpty(value.data) ?? profile.domain
            } else if name.caseInsensitiveCompare("NV Domain") == .orderedSame,
                      profile.domain == nil {
                profile.domain = nonEmpty(value.data)
            }
            return
        }
        if path.localizedCaseInsensitiveContains("Services\\Tcpip\\Parameters\\Interfaces\\") {
            // Walk every interface; IPAddress (static) and DhcpIPAddress
            // (DHCP-assigned) are the two we care about. Both can be
            // REG_MULTI_SZ - splitIPs handles multi-value strings.
            if ["IPAddress", "DhcpIPAddress"].contains(where: {
                name.caseInsensitiveCompare($0) == .orderedSame
            }) {
                for ip in splitIPs(value.data) where !ip.isEmpty && ip != "0.0.0.0" {
                    if ipSeen.insert(ip).inserted {
                        profile.ipAddresses.append(ip)
                    }
                }
            }
            return
        }
        if pathMatches(path, key: "Control\\TimeZoneInformation"),
           name.caseInsensitiveCompare("TimeZoneKeyName") == .orderedSame {
            profile.timeZone = nonEmpty(value.data)
            return
        }
        if pathMatches(path, key: "Control\\Windows"),
           name.caseInsensitiveCompare("ShutdownTime") == .orderedSame {
            profile.lastShutdown = parseFiletime(hex: value.data)
            return
        }
    }

    private static func deriveSoftware(value: RegistryValue, path: String,
                                       name: String, profile: inout HostProfile) {
        if pathMatches(path, key: "Microsoft\\Windows NT\\CurrentVersion\\Authentication\\LogonUI") {
            if name.caseInsensitiveCompare("LastLoggedOnUser") == .orderedSame {
                profile.primaryUser = nonEmpty(value.data) ?? profile.primaryUser
            } else if name.caseInsensitiveCompare("LastLoggedOnSAMUser") == .orderedSame,
                      profile.primaryUser == nil {
                profile.primaryUser = nonEmpty(value.data)
            }
            return
        }
        // Restrict to the exact CurrentVersion key. Many third-party packages
        // (InstallShield, AppCompatFlags subkeys, etc.) plant their own
        // ProductName under deeper paths; a contains-match would let those
        // overwrite the real Windows values.
        guard pathMatches(path, key: "Microsoft\\Windows NT\\CurrentVersion") else { return }
        switch name {
        case "ProductName":
            profile.osProductName = nonEmpty(value.data)
        case "DisplayVersion":
            profile.osDisplayVersion = nonEmpty(value.data)
        case "ReleaseId":
            if profile.osDisplayVersion == nil {
                profile.osDisplayVersion = nonEmpty(value.data)
            }
        case "CurrentBuild", "CurrentBuildNumber":
            let trimmed = value.data.trimmingCharacters(in: .whitespaces)
            if !trimmed.isEmpty, profile.osBuild == nil {
                profile.osBuild = trimmed
            }
        case "UBR":
            let trimmed = value.data.trimmingCharacters(in: .whitespaces)
            if !trimmed.isEmpty, let existing = profile.osBuild, !existing.contains(".") {
                profile.osBuild = "\(existing).\(trimmed)"
            }
        case "InstallDate":
            // REG_DWORD seconds since the Unix epoch.
            let trimmed = value.data.trimmingCharacters(in: .whitespaces)
            if let seconds = UInt32(trimmed) {
                profile.installDate = Date(timeIntervalSince1970: TimeInterval(seconds))
            }
        default:
            break
        }
    }

    /// True when `path` is exactly `key` or ends with `\key` (or `/key`).
    /// We need an end-anchored match because regfexport renders keys with a
    /// hive-relative prefix (e.g. "ControlSet001\..." or "\Microsoft\...")
    /// and we don't want subkey paths to slip through a contains-style match.
    private static func pathMatches(_ path: String, key: String) -> Bool {
        let lower = path.lowercased()
        let target = key.lowercased()
        if lower == target { return true }
        if lower.hasSuffix("\\" + target) { return true }
        if lower.hasSuffix("/" + target) { return true }
        return false
    }

    private static func nonEmpty(_ s: String) -> String? {
        let t = s.trimmingCharacters(in: .whitespacesAndNewlines)
        return t.isEmpty ? nil : t
    }

    private static func splitIPs(_ data: String) -> [String] {
        data.components(separatedBy: CharacterSet(charactersIn: " ,\n\t"))
            .map { $0.trimmingCharacters(in: .whitespaces) }
            .filter { !$0.isEmpty }
    }

    /// Decode a Windows FILETIME (100-nanosecond intervals since 1601-01-01
    /// UTC, little-endian 64-bit) from a hex string. regfexport renders
    /// REG_BINARY as ASCII hex; we strip non-hex characters, take the first
    /// 16 chars (8 bytes), and treat the result as little-endian.
    /// Returns nil if the decoded date isn't plausibly recent, since that
    /// usually means we mis-parsed an offset-prefixed dump line.
    private static func parseFiletime(hex: String) -> Date? {
        let allowed = CharacterSet(charactersIn: "0123456789abcdefABCDEF")
        let hexOnly = hex.unicodeScalars.filter { allowed.contains($0) }
        let chars = Array(String(String.UnicodeScalarView(hexOnly)))
        guard chars.count >= 16 else { return nil }
        var bytes: [UInt8] = []
        var i = 0
        while i < 16 {
            guard let byte = UInt8(String(chars[i..<i+2]), radix: 16) else { return nil }
            bytes.append(byte)
            i += 2
        }
        var filetime: UInt64 = 0
        for index in 0..<8 {
            filetime |= UInt64(bytes[index]) << (8 * index)
        }
        let secondsSince1601 = Double(filetime) / 10_000_000.0
        let secondsSince1970 = secondsSince1601 - 11_644_473_600
        let date = Date(timeIntervalSince1970: secondsSince1970)
        // Sanity gate: anything outside [2000, 2200] is almost certainly a
        // mis-parsed offset prefix, not a real shutdown timestamp.
        let lower = Date(timeIntervalSince1970: 946_684_800)   // 2000-01-01
        let upper = Date(timeIntervalSince1970: 7_258_118_400) // 2200-01-01
        guard date > lower && date < upper else { return nil }
        return date
    }
}
