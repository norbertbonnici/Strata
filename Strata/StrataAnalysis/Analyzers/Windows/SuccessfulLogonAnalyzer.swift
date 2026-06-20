import Foundation

/// Security 4624 = successful logon. LogonType 10 is RemoteInteractive = RDP.
/// Successful RDP from a non-RFC1918 / non-loopback / non-link-local address
/// means somebody walked in through the front door from the Internet, which
/// is almost never legitimate on a workstation.
///
/// ATT&CK T1133 External Remote Services + T1078 Valid Accounts.
/// Kill-chain phase: Delivery (treating Initial Access as Delivery in the
/// Lockheed model).
public nonisolated struct SuccessfulLogonAnalyzer: Analyzer {
    public let name = "External RDP Logon"
    public init() {}

    public func analyze(context: AnalysisContext) -> [Finding] {
        context.events.compactMap { event -> Finding? in
            guard event.eventID == 4624,
                  event.data("LogonType") == "10"
            else { return nil }

            let ip = event.data("IpAddress") ?? ""
            guard Self.isExternal(ip) else { return nil }

            let user   = event.data("TargetUserName") ?? "(unknown)"
            let domain = event.data("TargetDomainName") ?? ""
            let host   = domain.isEmpty ? user : "\(domain)\\\(user)"
            return Finding(
                title: "RDP logon from external IP \(ip) as \(host)",
                detail: "LogonType 10 (RemoteInteractive) succeeded from \(ip) at \(event.writtenAt.formatted()). RDP from outside RFC1918 space is almost always either misconfiguration or hands-on-keyboard activity.",
                severity: .high,
                phase: .delivery,
                technique: AttackTechnique(attackID: "T1133",
                                            name: "External Remote Services"),
                timestamp: event.writtenAt,
                evidencePaths: [event.sourceFile])
        }
    }

    /// External = not RFC1918, not loopback, not link-local, not unknown.
    /// Done with prefix matching to avoid pulling in a full IP-parsing library
    /// for what amounts to ~6 prefix checks.
    private static func isExternal(_ ip: String) -> Bool {
        guard !ip.isEmpty, ip != "-", ip != "::1", ip != "0.0.0.0" else { return false }
        if ip.hasPrefix("127.") { return false }
        if ip.hasPrefix("10.")  { return false }
        if ip.hasPrefix("192.168.") { return false }
        if ip.hasPrefix("169.254.") { return false }   // link-local
        if ip.hasPrefix("fe80:") || ip.hasPrefix("FE80:") { return false }
        // 172.16.0.0/12
        if ip.hasPrefix("172.") {
            let parts = ip.split(separator: ".")
            if parts.count >= 2, let second = Int(parts[1]),
               (16...31).contains(second) { return false }
        }
        return true
    }
}
