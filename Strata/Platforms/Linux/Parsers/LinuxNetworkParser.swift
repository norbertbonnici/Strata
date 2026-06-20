import Foundation

/// Recovers a Linux host's IPv4 addresses from two kinds of source:
///  - **static config** — netplan YAML (`/etc/netplan/*.yaml`) and ifupdown
///    (`/etc/network/interfaces`), and
///  - **runtime lease** — the NetworkManager / systemd-networkd / dhclient /
///    avahi lines already parsed into the journal, which is the only place a
///    DHCP host's address is recorded (the common case for a VM image).
///
/// Pure - strings in, addresses out - so it unit-tests without fixtures and
/// runs off the main actor.
public nonisolated enum LinuxNetworkParser {

    // MARK: - Static configuration

    /// Netplan YAML interface addresses. Interface addresses carry a CIDR suffix
    /// (`addresses: [192.168.1.10/24]` or a `- 192.168.1.10/24` list item);
    /// gateways and nameservers don't, so a CIDR-suffixed IPv4 is a reliable
    /// interface-address signal that needs no YAML parse.
    public static func parseNetplan(_ text: String) -> [String] {
        cidrIPv4s(in: text)
    }

    /// `/etc/network/interfaces` (ifupdown): the value of each `address …` line
    /// (CIDR suffix stripped if present).
    public static func parseInterfaces(_ text: String) -> [String] {
        var out: [String] = []
        for raw in text.split(separator: "\n", omittingEmptySubsequences: true) {
            let line = raw.trimmingCharacters(in: .whitespaces)
            let lower = line.lowercased()
            guard lower.hasPrefix("address ") || lower.hasPrefix("address\t") else { continue }
            let value = line.dropFirst("address".count).trimmingCharacters(in: .whitespaces)
            let ip = value.split(whereSeparator: { $0 == "/" || $0 == " " }).first.map(String.init) ?? value
            if isHostIPv4(ip) { out.append(ip) }
        }
        return out
    }

    // MARK: - Runtime lease (journal)

    /// Keywords that mark a journal line as carrying an *assigned* host address
    /// (rather than a peer/route/DNS address mentioned in passing).
    private static let leaseTriggers = [
        "new lease", "dhcpv4 address", "dhcp4", "dhcp6",
        "bound to", "leased", "ip_address", "address record for",
    ]

    /// Any DHCP-leased / assigned host IPv4 in a single journal message.
    /// Matches NetworkManager (`dhcp4 (ens18): … new lease, address=192.168.5.160`),
    /// systemd-networkd (`DHCPv4 address 10.0.0.5/24 via …`), dhclient
    /// (`bound to 10.0.0.5`), and avahi (`Registering new address record for
    /// 192.168.5.160 on ens18.IPv4`), with loopback / link-local filtered out.
    public static func leaseAddresses(inMessage message: String) -> [String] {
        let lower = message.lowercased()
        guard leaseTriggers.contains(where: { lower.contains($0) }) else { return [] }
        return ipv4s(in: message).filter(isHostIPv4)
    }

    // MARK: - Primitives

    /// All dotted-quad IPv4 tokens in `text` (each octet validated ≤ 255).
    static func ipv4s(in text: String) -> [String] {
        var out: [String] = []
        let scalars = Array(text.unicodeScalars)
        var i = 0
        while i < scalars.count {
            // Token boundary: a run of digits-and-dots not preceded by digit/dot.
            if isDigit(scalars[i]), i == 0 || !(isDigit(scalars[i - 1]) || scalars[i - 1] == ".") {
                var j = i
                while j < scalars.count, isDigit(scalars[j]) || scalars[j] == "." { j += 1 }
                // Not followed by another dot+digit (avoids swallowing a CIDR's
                // mask as a fifth octet - the slash already broke the run).
                let token = String(String.UnicodeScalarView(scalars[i..<j]))
                if let ip = normalizedIPv4(token) { out.append(ip) }
                i = j
            } else {
                i += 1
            }
        }
        return out
    }

    /// IPv4 addresses in `text` that are immediately followed by a `/<mask>`
    /// CIDR suffix.
    static func cidrIPv4s(in text: String) -> [String] {
        var out: [String] = []
        for raw in text.split(whereSeparator: { " \t\n\r,[]'\"".unicodeScalars.contains($0.unicodeScalars.first!) }) {
            guard let slash = raw.firstIndex(of: "/") else { continue }
            let ipPart = String(raw[..<slash])
            let maskPart = raw[raw.index(after: slash)...]
            guard !maskPart.isEmpty, maskPart.allSatisfy(\.isNumber),
                  let ip = normalizedIPv4(ipPart), isHostIPv4(ip) else { continue }
            out.append(ip)
        }
        return out
    }

    private static func isDigit(_ s: Unicode.Scalar) -> Bool { s >= "0" && s <= "9" }

    /// Validate a dotted-quad string and return it canonicalised, or nil.
    private static func normalizedIPv4(_ token: String) -> String? {
        let parts = token.split(separator: ".", omittingEmptySubsequences: false)
        guard parts.count == 4 else { return nil }
        var octets: [Int] = []
        for p in parts {
            guard !p.isEmpty, p.count <= 3, p.allSatisfy(\.isNumber), let v = Int(p), v <= 255 else { return nil }
            octets.append(v)
        }
        return octets.map(String.init).joined(separator: ".")
    }

    /// A "real" host address: a valid IPv4 that isn't loopback, link-local,
    /// unspecified, broadcast, multicast, or an obvious netmask.
    static func isHostIPv4(_ ip: String) -> Bool {
        guard let canonical = normalizedIPv4(ip) else { return false }
        let o = canonical.split(separator: ".").compactMap { Int($0) }
        guard o.count == 4 else { return false }
        if o[0] == 0 || o[0] == 127 { return false }            // unspecified / loopback
        if o[0] == 169 && o[1] == 254 { return false }          // APIPA link-local
        if o[0] >= 224 { return false }                         // multicast + reserved
        if canonical == "255.255.255.255" { return false }      // broadcast
        if o[0] == 255 { return false }                         // netmask-shaped
        return true
    }
}
