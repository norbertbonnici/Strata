import Foundation

/// Detection over the package-manager history. The install/remove record is
/// mostly timeline context, but two patterns are real signals: an attacker
/// installing offensive/dual-use tooling on a compromised host, and a burst of
/// package *removals* (cleanup / anti-forensics).
public nonisolated struct PackageAnalyzer: Analyzer {
    public let name = "Package History"
    public init() {}

    /// Packages whose install on a server is a strong post-compromise tell -
    /// offensive tools, tunnelers, and dual-use network/recon utilities rarely
    /// installed on a production box after build time. Keyed by exact name.
    private static let offensive: Set<String> = [
        "nmap", "masscan", "zmap", "netcat", "netcat-traditional", "netcat-openbsd",
        "ncat", "socat", "hydra", "john", "hashcat", "medusa", "nikto", "sqlmap",
        "metasploit-framework", "responder", "proxychains", "proxychains-ng",
        "chisel", "ngrok", "frpc", "frps", "tor", "wireguard", "openvpn",
        "tcpdump", "tshark", "ettercap", "aircrack-ng", "gcc", "make",
    ]

    /// Removal burst threshold (one cleanup run removing many packages).
    private static let removalBurst = 15

    public func analyze(context: AnalysisContext) -> [Finding] {
        guard !context.packages.isEmpty else { return [] }
        var findings: [Finding] = []

        for event in context.packages where event.action == .install || event.action == .reinstall {
            guard Self.offensive.contains(event.package.lowercased()) else { continue }
            // Compilers are common on dev boxes - keep them low, real tooling medium.
            let isBuildTool = event.package == "gcc" || event.package == "make"
            findings.append(Finding(
                title: "Offensive/dual-use package installed: \(event.package)",
                detail: "\(event.manager.label) \(event.action.label) of \(event.package)"
                    + (event.version.map { " \($0)" } ?? "")
                    + " — attacker tooling / recon utility, uncommon to install on a server post-build.",
                severity: isBuildTool ? .low : .medium,
                phase: .installation,
                technique: AttackTechnique(attackID: "T1588.002", name: "Obtain Capabilities: Tool"),
                timestamp: event.timestamp,
                evidencePaths: [event.sourceFile]))
        }

        // Removal burst: many removals sharing a timestamp (one apt/yum run).
        var byMinute: [String: [PackageEvent]] = [:]
        for event in context.packages where event.action.isRemoval {
            let bucket = event.timestamp.map { String(Int($0.timeIntervalSince1970 / 60)) } ?? "none"
            byMinute[bucket, default: []].append(event)
        }
        for (_, group) in byMinute where group.count >= Self.removalBurst {
            let sample = group.prefix(8).map(\.package).joined(separator: ", ")
            findings.append(Finding(
                title: "Mass package removal (\(group.count) packages)",
                detail: "\(group.count) packages removed in one run (\(sample)…) — possible cleanup / "
                    + "anti-forensic activity or system tampering.",
                severity: .medium,
                phase: .actionsOnObjectives,
                technique: AttackTechnique(attackID: "T1070", name: "Indicator Removal"),
                timestamp: group.compactMap(\.timestamp).max(),
                evidencePaths: [group.first?.sourceFile ?? ""]))
        }

        return findings
    }
}
