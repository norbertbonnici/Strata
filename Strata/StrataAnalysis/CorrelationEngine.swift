import Foundation

/// A compact, per-host projection of the case-relevant facts the cross-host
/// correlator needs. The ingest/analysis layer fills one of these per analysed
/// host (from its `IOCMatch` set, host profile, and `LateralGraph` source
/// nodes) and hands the array to `CorrelationEngine.correlate`. Pure value
/// type so the correlation can run off the main actor like the analyzers.
public nonisolated struct HostSummary: Sendable, Hashable {
    /// The host's stable identity in the `.strata` case (the per-host UUID).
    public let hostID: UUID
    /// Display name for the host, when known (registry/Linux host profile).
    /// Falls back to a shortened UUID in finding text when nil.
    public let hostname: String?
    /// Every IOC the case's IOC matcher hit on this host.
    public let iocMatches: [IOCMatch]
    /// Local + domain user accounts seen active on this host (logons, SAM,
    /// `/etc/passwd`, shell history owners…). Raw, un-normalised names.
    public let users: [String]
    /// Source IPs/workstations that authenticated *to* this host over a remote
    /// logon (Windows 4624/4625 type 3/10, sshd "Accepted/Failed from <ip>"…).
    /// These are the origins of inbound remote sessions — the pivot signal.
    public let remoteLogonSourceIPs: [String]

    public init(hostID: UUID, hostname: String? = nil,
                iocMatches: [IOCMatch] = [], users: [String] = [],
                remoteLogonSourceIPs: [String] = []) {
        self.hostID = hostID
        self.hostname = hostname
        self.iocMatches = iocMatches
        self.users = users
        self.remoteLogonSourceIPs = remoteLogonSourceIPs
    }

    /// Human label for finding text — the hostname, else a short UUID prefix so
    /// two unnamed hosts are still distinguishable.
    public var displayName: String {
        if let hostname, !hostname.trimmingCharacters(in: .whitespaces).isEmpty {
            return hostname
        }
        return "host \(hostID.uuidString.prefix(8))"
    }
}

/// Case-wide multi-host correlation (roadmap #8). A pure function from a set of
/// per-host summaries to cross-host `Finding`s. It looks for three classes of
/// signal that only surface when you line several hosts up side by side:
///
///  - **Shared indicator spread** — the *same* IOC value matched on ≥2 hosts.
///    One C2 domain / dropper hash appearing across the estate is a campaign,
///    not an isolated hit.
///  - **Source-IP pivot** — the *same* origin IP authenticated to ≥2 hosts.
///    A single workstation/IP fanning out inbound remote logons is the classic
///    lateral-movement pivot.
///  - **Credential reuse** — the *same* non-built-in account is active on ≥2
///    hosts. Reused local/domain creds are how an attacker spreads.
///
/// Nothing here re-derives per-host facts; it only joins the already-computed
/// summaries, so it is cheap and order-independent. Single-host facts never
/// produce a finding — by construction the join key must span ≥2 distinct
/// `hostID`s. Severity scales with the number of hosts involved.
public nonisolated struct CorrelationEngine: Sendable {
    public init() {}

    // MARK: ATT&CK techniques

    /// Lateral movement via valid accounts — the umbrella for credential reuse
    /// and pivoting across hosts with the same identity.
    private static let validAccounts = AttackTechnique(
        attackID: "T1078", name: "Valid Accounts")
    /// Remote Services — a single origin reaching multiple hosts.
    private static let remoteServices = AttackTechnique(
        attackID: "T1021", name: "Remote Services")
    /// The shared-indicator case is a malware/tooling footprint; tag it with the
    /// generic "Ingress Tool Transfer" technique, the closest single-ID fit for
    /// "the same artefact landed on several machines."
    private static let ingressToolTransfer = AttackTechnique(
        attackID: "T1105", name: "Ingress Tool Transfer")

    // MARK: Built-in / machine accounts

    /// Accounts that are present on *every* host by default, so seeing them on
    /// two hosts is meaningless. Lowercased; matched after trimming a trailing
    /// `$` (machine accounts) and any `DOMAIN\` / `host\` prefix. We also drop
    /// the auto-numbered window-manager/font-driver accounts (`DWM-1`, `UMFD-2`)
    /// and any account ending in `$` (computer accounts).
    private static let builtinUsers: Set<String> = [
        // Windows well-known principals
        "system", "local system", "localsystem",
        "local service", "network service",
        "administrator", "guest", "defaultaccount", "wdagutilityaccount",
        "anonymous logon", "iusr", "krbtgt",
        // Linux system accounts (a representative core set; UID-based filtering
        // happens upstream, this is the name-based backstop)
        "root", "daemon", "bin", "sys", "sync", "games", "man", "lp", "mail",
        "news", "uucp", "proxy", "www-data", "backup", "list", "irc", "gnats",
        "nobody", "systemd-network", "systemd-resolve", "systemd-timesync",
        "messagebus", "syslog", "_apt", "tss", "uuidd", "tcpdump", "landscape",
        "pollinate", "sshd", "ftp", "dnsmasq", "usbmux",
    ]

    /// True when `raw` is a built-in/machine account that shouldn't drive a
    /// credential-reuse finding. Strips a `DOMAIN\` (or `host\`) prefix and a
    /// trailing `$`, then checks the well-known set; any residual `$`-suffixed
    /// name (computer account) is also treated as built-in.
    static func isBuiltinUser(_ raw: String) -> Bool {
        var name = raw.trimmingCharacters(in: .whitespaces).lowercased()
        if name.isEmpty || name == "-" { return true }
        if let slash = name.lastIndex(of: "\\") {
            name = String(name[name.index(after: slash)...])
        }
        if name.hasSuffix("$") { return true }              // computer account
        if name.hasPrefix("dwm-") || name.hasPrefix("umfd-") { return true }
        return builtinUsers.contains(name)
    }

    /// Normalised key for joining a user across hosts: domain/host prefix
    /// stripped, lowercased. So `CORP\jsmith`, `jsmith`, and `WS01\jsmith`
    /// collapse to one identity. (Intentionally lossy — cross-host reuse of a
    /// *name* is the signal, regardless of which domain qualified it.)
    static func userKey(_ raw: String) -> String {
        var name = raw.trimmingCharacters(in: .whitespaces).lowercased()
        if let slash = name.lastIndex(of: "\\") {
            name = String(name[name.index(after: slash)...])
        }
        return name
    }

    /// Severity for a cross-host finding given how many hosts share the key.
    /// 2 hosts ⇒ medium, 3 ⇒ high, ≥4 ⇒ critical. (Caller guarantees ≥2.)
    private static func severity(forHostCount n: Int) -> Severity {
        switch n {
        case ...2: return .medium
        case 3:    return .high
        default:   return .critical
        }
    }

    // MARK: Correlate

    public static func correlate(_ summaries: [HostSummary]) -> [Finding] {
        // A single host can't exhibit *cross*-host correlation.
        guard summaries.count >= 2 else { return [] }
        var findings: [Finding] = []
        findings.append(contentsOf: sharedIndicatorFindings(summaries))
        findings.append(contentsOf: sourceIPPivotFindings(summaries))
        findings.append(contentsOf: credentialReuseFindings(summaries))
        return findings
    }

    // MARK: (a) Shared indicator across hosts

    /// The same IOC *value* matched on ≥2 distinct hosts. Keyed case-insensitively
    /// on the indicator value; the kind is taken from the first match (a value is
    /// one kind). We also surface the *earliest* match timestamp for the timeline.
    private static func sharedIndicatorFindings(_ summaries: [HostSummary]) -> [Finding] {
        // value(lower) -> (kind, displayName, set of hostIDs, set of hostLabels, earliest ts)
        struct Agg {
            var kind: IOCKind
            var displayValue: String
            var hostIDs: Set<UUID> = []
            var hostLabels: Set<String> = []
            var earliest: Date?
        }
        var byValue: [String: Agg] = [:]

        for host in summaries {
            // De-dup the indicator values *within* a host first, so 50 hits of
            // one domain on one host doesn't masquerade as spread.
            var seenOnHost = Set<String>()
            for match in host.iocMatches {
                let key = match.iocValue.lowercased()
                guard !key.isEmpty else { continue }
                seenOnHost.insert(key)
                if byValue[key] == nil {
                    byValue[key] = Agg(kind: match.iocKind, displayValue: match.iocValue)
                }
                if let ts = match.timestamp {
                    if let cur = byValue[key]!.earliest { byValue[key]!.earliest = min(cur, ts) }
                    else { byValue[key]!.earliest = ts }
                }
            }
            for key in seenOnHost {
                byValue[key]?.hostIDs.insert(host.hostID)
                byValue[key]?.hostLabels.insert(host.displayName)
            }
        }

        var out: [Finding] = []
        for (_, agg) in byValue where agg.hostIDs.count >= 2 {
            let hosts = agg.hostLabels.sorted()
            let n = agg.hostIDs.count
            out.append(Finding(
                title: "Shared indicator across \(n) hosts: \(agg.kind.label) \(agg.displayValue)",
                detail: "The \(agg.kind.label.lowercased()) indicator `\(agg.displayValue)` "
                    + "matched on \(n) hosts: \(hosts.joined(separator: ", ")). "
                    + "The same indicator across multiple hosts indicates campaign-wide "
                    + "activity (shared C2, dropper, or tooling) rather than an isolated hit.",
                severity: severity(forHostCount: n),
                phase: .commandAndControl,
                technique: ingressToolTransfer,
                timestamp: agg.earliest,
                evidencePaths: hosts))
        }
        return out.sorted { $0.title < $1.title }
    }

    // MARK: (b) Source-IP pivot across hosts

    /// The same inbound remote-logon source IP authenticated to ≥2 hosts — a
    /// single origin fanning out, the lateral-movement pivot. Loopback/empty
    /// origins are dropped (they aren't a remote source).
    private static func sourceIPPivotFindings(_ summaries: [HostSummary]) -> [Finding] {
        struct Agg { var hostIDs: Set<UUID> = []; var hostLabels: Set<String> = [] }
        var byIP: [String: Agg] = [:]

        for host in summaries {
            var seenOnHost = Set<String>()
            for rawIP in host.remoteLogonSourceIPs {
                let ip = rawIP.trimmingCharacters(in: .whitespaces)
                guard isRoutableSource(ip) else { continue }
                seenOnHost.insert(ip)
            }
            for ip in seenOnHost {
                byIP[ip, default: Agg()].hostIDs.insert(host.hostID)
                byIP[ip, default: Agg()].hostLabels.insert(host.displayName)
            }
        }

        var out: [Finding] = []
        for (ip, agg) in byIP where agg.hostIDs.count >= 2 {
            let hosts = agg.hostLabels.sorted()
            let n = agg.hostIDs.count
            out.append(Finding(
                title: "Source \(ip) authenticated to \(n) hosts (lateral pivot)",
                detail: "The remote-logon source `\(ip)` authenticated to \(n) hosts: "
                    + "\(hosts.joined(separator: ", ")). One origin reaching multiple "
                    + "hosts over remote logon is the classic lateral-movement pivot — "
                    + "review the sessions from this source on each host.",
                severity: severity(forHostCount: n),
                phase: .exploitation,
                technique: remoteServices,
                timestamp: nil,
                evidencePaths: hosts))
        }
        return out.sorted { $0.title < $1.title }
    }

    /// True for an IP we'd treat as a meaningful remote *source*: non-empty,
    /// not a placeholder, not loopback. We deliberately keep RFC1918 ranges —
    /// internal lateral movement is exactly what we want to catch.
    private static func isRoutableSource(_ ip: String) -> Bool {
        guard !ip.isEmpty, ip != "-", ip != "::", ip != "::1",
              ip != "0.0.0.0", ip != "127.0.0.1",
              !ip.hasPrefix("127.") else { return false }
        return true
    }

    // MARK: (c) Credential reuse across hosts

    /// The same non-built-in user account active on ≥2 hosts. Keyed on the
    /// domain-stripped, lowercased name so `CORP\jsmith` and `jsmith` collapse.
    private static func credentialReuseFindings(_ summaries: [HostSummary]) -> [Finding] {
        // key -> (displayName, hostIDs, hostLabels)
        struct Agg { var display: String; var hostIDs: Set<UUID> = []; var hostLabels: Set<String> = [] }
        var byUser: [String: Agg] = [:]

        for host in summaries {
            var seenOnHost = Set<String>()
            for rawUser in host.users {
                guard !isBuiltinUser(rawUser) else { continue }
                let key = userKey(rawUser)
                guard !key.isEmpty else { continue }
                if byUser[key] == nil {
                    byUser[key] = Agg(display: rawUser.trimmingCharacters(in: .whitespaces))
                }
                seenOnHost.insert(key)
            }
            for key in seenOnHost {
                byUser[key]?.hostIDs.insert(host.hostID)
                byUser[key]?.hostLabels.insert(host.displayName)
            }
        }

        var out: [Finding] = []
        for (_, agg) in byUser where agg.hostIDs.count >= 2 {
            let hosts = agg.hostLabels.sorted()
            let n = agg.hostIDs.count
            out.append(Finding(
                title: "Account `\(agg.display)` active on \(n) hosts (credential reuse)",
                detail: "The account `\(agg.display)` is present/active on \(n) hosts: "
                    + "\(hosts.joined(separator: ", ")). A non-built-in account reused "
                    + "across multiple hosts indicates credential reuse or a shared "
                    + "identity an attacker is leveraging to move laterally.",
                severity: severity(forHostCount: n),
                phase: .exploitation,
                technique: validAccounts,
                timestamp: nil,
                evidencePaths: hosts))
        }
        return out.sorted { $0.title < $1.title }
    }
}
