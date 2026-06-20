import Foundation

/// HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR\<vendor+product>\<serial> is
/// Windows' record of every USB mass-storage device that's ever been plugged
/// in. For DFIR purposes the existence of an entry tells you the device
/// touched this host; the timestamp tells you (approximately) when. Each
/// gets surfaced as an `info` finding by default - the user decides which
/// connections are interesting, since "John Doe's USB stick" looks the same
/// as "attacker's USB stick" in the registry.
///
/// ATT&CK T1091 Replication Through Removable Media (when used for delivery)
/// or T1052.001 Exfiltration over USB (when used for staging).
/// Kill-chain phase: Delivery (conservative default).
public nonisolated struct USBHistoryAnalyzer: Analyzer {
    public let name = "USB History"
    public init() {}

    private static let pathFragments = [
        "ControlSet001\\Enum\\USBSTOR\\",
        "ControlSet002\\Enum\\USBSTOR\\",
        "CurrentControlSet\\Enum\\USBSTOR\\",
    ]

    public func analyze(context: AnalysisContext) -> [Finding] {
        // A single device has many sub-values (FriendlyName, DeviceDesc,
        // Service, ContainerID...). We collapse by key path so one device
        // produces one finding, picking the best label we can find.
        var byKey: [String: [RegistryValue]] = [:]
        for value in context.registryValues {
            guard value.hive.uppercased().contains("SYSTEM"),
                  Self.pathFragments.contains(where: { value.path.contains($0) })
            else { continue }
            // Only keep entries that look like a *serial* level (4 backslashes
            // past the USBSTOR root means we're at a serial), not the parent.
            let depth = value.path.filter { $0 == "\\" }.count
            guard depth >= 5 else { continue }
            byKey[value.path, default: []].append(value)
        }

        return byKey.compactMap { (path, values) -> Finding? in
            let friendly = values.first(where: { $0.name == "FriendlyName" })?.data
            let devDesc  = values.first(where: { $0.name == "DeviceDesc" })?.data
            let serial   = Self.serial(from: path)
            let label    = friendly ?? devDesc ?? serial ?? "(unknown device)"
            let lastWritten = values.compactMap(\.lastWritten).max()

            var bullets: [String] = ["Device: \(label)"]
            if let serial { bullets.append("Serial: \(serial)") }
            if let devDesc, devDesc != label { bullets.append("Desc: \(devDesc)") }
            if let lastWritten { bullets.append("Last seen: \(lastWritten.formatted())") }
            bullets.append("Key: \(path)")

            return Finding(
                title: "USB device connected: \(label)",
                detail: bullets.joined(separator: "\n"),
                severity: .info,
                phase: .delivery,
                technique: AttackTechnique(attackID: "T1091",
                                            name: "Replication Through Removable Media"),
                timestamp: lastWritten,
                evidencePaths: [path])
        }
    }

    /// The serial number sits at the tail of the path, after the
    /// vendor+product key. Pull it out so the finding label has something
    /// readable when FriendlyName / DeviceDesc are missing.
    private static func serial(from path: String) -> String? {
        path.split(separator: "\\").last.map(String.init)
    }
}
