import Foundation

/// Active Directory / Kerberos reconnaissance and credential roasting.
///
/// All three signals are pre-objective: the attacker is mapping the domain and
/// harvesting roastable hashes before lateral movement. They cluster in
/// .reconnaissance.
///
///  1. **Kerberoasting (T1558.003).** Security 4769 (Kerberos service-ticket
///     request) with RC4 encryption (`TicketEncryptionType` 0x17) is the classic
///     roasting fingerprint - the attacker downgrades to RC4 so the returned
///     ticket is offline-crackable. A *single* 0x17/4769 is noisy (legacy apps,
///     SQL SPNs), so we only fire on a **burst**: one account requesting tickets
///     for many *distinct* service names in a short window. That sequence is what
///     Rubeus/GetUserSPNs produce and is hard to explain benignly.
///  2. **AS-REP roasting (T1558.004).** Security 4768 (TGT request) with
///     `PreAuthType=0` means the target account has Kerberos pre-auth disabled,
///     so the KDC returns an AS-REP whose encrypted portion is offline-crackable
///     without any credential. Pre-auth is on by default, so PreAuthType=0 on a
///     real user account is itself the finding (no burst needed) - but we still
///     gate RC4 (0x17) to stay off the ordinary computer-account / smart-card
///     noise that can legitimately carry other pre-auth types.
///  3. **Discovery command bursts (T1087 / T1018 / T1046).** 4688 / Sysmon 1
///     process-creation hitting the canonical domain-enumeration toolkit
///     (`net group /domain`, `nltest /dclist`, `dsquery`, `Get-ADUser`, ...).
///     Any one of these alone is benign admin activity; several *distinct* ones
///     from one host inside a few minutes is the hallmark of an operator (or a
///     BloodHound/SharpHound collector) walking the directory.
///
/// Read-only over `context.events`. Reserve .high for the roasting bursts;
/// discovery clusters are .medium (suggestive, not conclusive).
public nonisolated struct ADReconAnalyzer: Analyzer {
    public let name = "AD / Kerberos Reconnaissance"
    public init() {}

    // RC4-HMAC ticket encryption - the downgrade roasting tools force. The
    // field is hex in the EVTX payload; compare case-insensitively.
    private static let rc4EncTypes: Set<String> = ["0x17", "0x18"]

    // Kerberoasting burst gates: one account requesting tickets for this many
    // distinct service names inside the window crosses from noise to signal.
    private static let roastWindow: TimeInterval = 600        // 10 minutes
    private static let roastDistinctServices = 6

    // Discovery-cluster gates: this many *distinct* enumeration commands from
    // one host inside the window. Single tools are benign admin activity.
    private static let discoWindow: TimeInterval = 300        // 5 minutes
    private static let discoDistinctCommands = 3

    public func analyze(context: AnalysisContext) -> [Finding] {
        var findings: [Finding] = []
        findings += kerberoasting(context.events)
        findings += asRepRoasting(context.events)
        findings += discoveryBursts(context.events)
        return findings
    }

    // MARK: - Kerberoasting (T1558.003)

    /// Group RC4 4769 service-ticket requests by the requesting account, then
    /// slide a window looking for many distinct SPNs requested at once.
    private func kerberoasting(_ events: [EventLogRecord]) -> [Finding] {
        let tickets = events
            .filter { $0.eventID == 4769 && isSecurity($0) }
            .filter { Self.rc4EncTypes.contains(encType(of: $0)) }
            // Skip machine accounts (ServiceName ending in `$`) and the krbtgt/
            // machine *requestor*: roasting targets user-context SPNs requested
            // by a user. The account ending in `$` is a computer logon, which
            // legitimately pulls RC4 tickets in bulk.
            .filter { account(of: $0).hasSuffix("$") == false }
            .filter { serviceName(of: $0).isEmpty == false }
            .sorted { $0.writtenAt < $1.writtenAt }

        let byAccount = Dictionary(grouping: tickets) { account(of: $0) }
        var findings: [Finding] = []
        for (acct, hits) in byAccount where acct != "<unknown>" {
            guard let burst = firstServiceBurst(in: hits) else { continue }
            let services = orderedDistinct(burst.map { serviceName(of: $0) })
            let sample = services.prefix(10).joined(separator: ", ")
            findings.append(Finding(
                title: "Kerberoasting burst by \(acct): \(services.count) service tickets (RC4)",
                detail: """
                Account \(acct) requested RC4 (0x17) Kerberos service tickets for \(services.count) distinct \
                services within \(Int(Self.roastWindow / 60))m - the offline-cracking pattern of Rubeus / \
                GetUserSPNs (Kerberoasting).
                Window: \(burst.first!.writtenAt.formatted()) -> \(burst.last!.writtenAt.formatted()).
                Services: \(sample)\(services.count > 10 ? ", ..." : "")
                """,
                severity: .high,
                phase: .reconnaissance,
                technique: AttackTechnique(attackID: "T1558.003",
                                            name: "Steal or Forge Kerberos Tickets: Kerberoasting"),
                timestamp: burst.first?.writtenAt,
                evidencePaths: Array(Set(burst.map { $0.sourceFile }))))
        }
        return findings
    }

    /// First window in this account's RC4 4769 stream that names enough
    /// distinct services to count as a roast.
    private func firstServiceBurst(in hits: [EventLogRecord]) -> [EventLogRecord]? {
        guard hits.count >= Self.roastDistinctServices else { return nil }
        var start = 0
        for end in 0..<hits.count {
            while hits[end].writtenAt.timeIntervalSince(hits[start].writtenAt) > Self.roastWindow {
                start += 1
            }
            let slice = Array(hits[start...end])
            let services = Set(slice.map { serviceName(of: $0).lowercased() })
            if services.count >= Self.roastDistinctServices { return slice }
        }
        return nil
    }

    // MARK: - AS-REP roasting (T1558.004)

    /// Security 4768 TGT request where pre-auth is disabled (PreAuthType=0) and
    /// the returned ticket is RC4. Pre-auth-off is non-default, so each such
    /// *user* account is its own finding.
    private func asRepRoasting(_ events: [EventLogRecord]) -> [Finding] {
        events.compactMap { event -> Finding? in
            guard event.eventID == 4768, isSecurity(event) else { return nil }
            // PreAuthType "0" is the AS-REP-roastable condition. Field is decimal
            // here (not hex). "-" / missing means it wasn't logged - skip.
            let preAuth = (event.data("PreAuthType") ?? "").trimmingCharacters(in: .whitespaces)
            guard preAuth == "0" else { return nil }
            // Gate RC4 to drop computer / smart-card pre-auth noise.
            guard Self.rc4EncTypes.contains(encType(of: event)) else { return nil }
            let acct = account(of: event)
            // A machine account ($) doing this is much more likely a config
            // artifact than a roast target; require a user account.
            guard acct != "<unknown>", acct.hasSuffix("$") == false else { return nil }

            return Finding(
                title: "AS-REP roastable account: \(acct)",
                detail: """
                Security 4768 (TGT request) for \(acct) carried PreAuthType=0 (Kerberos pre-authentication \
                disabled) with an RC4 ticket - the AS-REP can be requested and cracked offline without any \
                credential (AS-REP roasting).
                Time: \(event.writtenAt.formatted()) on \(event.computer).
                """,
                severity: .high,
                phase: .reconnaissance,
                technique: AttackTechnique(attackID: "T1558.004",
                                            name: "Steal or Forge Kerberos Tickets: AS-REP Roasting"),
                timestamp: event.writtenAt,
                evidencePaths: [event.sourceFile])
        }
    }

    // MARK: - Discovery command bursts (T1087 / T1018 / T1046)

    /// Each entry maps a lowercased command *signature* (image + argument
    /// fragments that must ALL be present) to the ATT&CK technique it evidences.
    /// Argument-gating is what keeps these specific: `net.exe` alone is benign,
    /// `net group /domain` is enumeration.
    private struct DiscoSig {
        let label: String
        let image: String              // substring of NewProcessName / Image
        let argTokens: [String]        // all must appear in the command line
        let technique: AttackTechnique
    }

    private static let t1087 = AttackTechnique(attackID: "T1087", name: "Account Discovery")
    private static let t1018 = AttackTechnique(attackID: "T1018", name: "Remote System Discovery")
    private static let t1046 = AttackTechnique(attackID: "T1046", name: "Network Service Discovery")
    private static let t1482 = AttackTechnique(attackID: "T1482", name: "Domain Trust Discovery")

    private static let discoSigs: [DiscoSig] = [
        // net.exe enumeration (account / group discovery)
        .init(label: "net group /domain",        image: "net",   argTokens: ["group", "/domain"], technique: t1087),
        .init(label: "net user /domain",         image: "net",   argTokens: ["user", "/domain"],  technique: t1087),
        .init(label: "net localgroup",           image: "net",   argTokens: ["localgroup"],       technique: t1087),
        .init(label: "net group \"domain admins\"", image: "net", argTokens: ["group", "domain admins"], technique: t1087),
        // nltest - DC / trust discovery
        .init(label: "nltest /dclist",           image: "nltest", argTokens: ["/dclist"],         technique: t1018),
        .init(label: "nltest /domain_trusts",    image: "nltest", argTokens: ["/domain_trusts"],  technique: t1482),
        // dsquery - directory enumeration. Gate on a real subcommand so a bare
        // path/string containing "dsquery" (a filename, a log line) can't match;
        // dsquery is always invoked as `dsquery <object-type> ...`.
        .init(label: "dsquery user",             image: "dsquery", argTokens: ["user"],          technique: t1087),
        .init(label: "dsquery computer",         image: "dsquery", argTokens: ["computer"],      technique: t1018),
        .init(label: "dsquery group",            image: "dsquery", argTokens: ["group"],         technique: t1087),
        .init(label: "dsquery *",                image: "dsquery", argTokens: ["* "],            technique: t1087),
        // whoami /all - token / group membership
        .init(label: "whoami /all",              image: "whoami", argTokens: ["/all"],            technique: t1087),
        // AD PowerShell module
        .init(label: "Get-ADUser",               image: "",      argTokens: ["get-aduser"],      technique: t1087),
        .init(label: "Get-ADComputer",           image: "",      argTokens: ["get-adcomputer"],  technique: t1018),
        .init(label: "Get-ADGroupMember",         image: "",      argTokens: ["get-adgroupmember"], technique: t1087),
        .init(label: "Get-ADDomain",              image: "",      argTokens: ["get-addomain"],    technique: t1087),
        // host / network recon
        .init(label: "quser",                    image: "quser", argTokens: [],                  technique: t1018),
        .init(label: "arp -a",                   image: "arp",   argTokens: ["-a"],              technique: t1018),
        .init(label: "route print",              image: "route", argTokens: ["print"],           technique: t1046),
        .init(label: "systeminfo",               image: "systeminfo", argTokens: [],             technique: t1087),
        // DC locator / share enumeration
        .init(label: "net view /domain",         image: "net",   argTokens: ["view", "/domain"], technique: t1018),
    ]

    /// Match each process-creation event to at most one discovery signature,
    /// then cluster the matches per host and flag windows with enough distinct
    /// commands.
    private func discoveryBursts(_ events: [EventLogRecord]) -> [Finding] {
        struct Hit { let label: String; let technique: AttackTechnique; let event: EventLogRecord }

        let hits: [Hit] = events.compactMap { event in
            guard let cmd = processHaystack(for: event) else { return nil }
            let lowered = cmd.lowercased()
            for sig in Self.discoSigs {
                // Image gate (when present) plus all argument tokens. Every sig
                // carries either a non-empty image (net/nltest/dsquery/quser/...)
                // or at least one arg token (the AD-PowerShell cmdlets), so a
                // field-less event never matches an all-empty rule.
                if sig.image.isEmpty || lowered.contains(sig.image) {
                    if sig.argTokens.allSatisfy({ lowered.contains($0) }) {
                        return Hit(label: sig.label, technique: sig.technique, event: event)
                    }
                }
            }
            return nil
        }
        guard hits.count >= Self.discoDistinctCommands else { return [] }

        let byHost = Dictionary(grouping: hits) { $0.event.computer }
        var findings: [Finding] = []
        for (host, hostHits) in byHost {
            let sorted = hostHits.sorted { $0.event.writtenAt < $1.event.writtenAt }
            guard let burst = firstDiscoBurst(in: sorted.map { $0.event }) else { continue }
            // Re-attach labels for the events that fell inside the burst window.
            let burstIDs = Set(burst.map { $0.id })
            let inBurst = sorted.filter { burstIDs.contains($0.event.id) }
            let labels = orderedDistinct(inBurst.map { $0.label })
            guard labels.count >= Self.discoDistinctCommands else { continue }
            let techniques = orderedDistinct(inBurst.map { $0.technique.attackID + " " + $0.technique.name })

            findings.append(Finding(
                title: "Domain reconnaissance burst on \(host): \(labels.count) discovery commands",
                detail: """
                \(labels.count) distinct domain/host discovery commands ran on \(host) within \
                \(Int(Self.discoWindow / 60))m - the enumeration pattern of a hands-on-keyboard operator or a \
                BloodHound/SharpHound collector. Any one alone is benign admin activity.
                Window: \(burst.first!.writtenAt.formatted()) -> \(burst.last!.writtenAt.formatted()).
                Commands: \(labels.joined(separator: ", "))
                Techniques: \(techniques.joined(separator: "; "))
                """,
                severity: .medium,
                phase: .reconnaissance,
                // Tag the headline technique as Account Discovery; the detail
                // enumerates the per-command techniques (T1018/T1046/T1482).
                technique: Self.t1087,
                timestamp: burst.first?.writtenAt,
                evidencePaths: Array(Set(inBurst.map { $0.event.sourceFile }))))
        }
        return findings
    }

    /// First window holding enough distinct discovery commands.
    private func firstDiscoBurst(in events: [EventLogRecord]) -> [EventLogRecord]? {
        guard events.count >= Self.discoDistinctCommands else { return nil }
        var start = 0
        for end in 0..<events.count {
            while events[end].writtenAt.timeIntervalSince(events[start].writtenAt) > Self.discoWindow {
                start += 1
            }
            if end - start + 1 >= Self.discoDistinctCommands {
                return Array(events[start...end])
            }
        }
        return nil
    }

    // MARK: - Field extraction

    private func isSecurity(_ e: EventLogRecord) -> Bool {
        e.channel.localizedCaseInsensitiveContains("Security")
    }

    /// `TicketEncryptionType` (4769) / `PreAuthType` sibling - normalized to a
    /// lowercased hex string ("0x17"). Missing -> "".
    private func encType(of e: EventLogRecord) -> String {
        (e.data("TicketEncryptionType") ?? "").trimmingCharacters(in: .whitespaces).lowercased()
    }

    /// The requesting account. 4769 uses `TargetUserName` (the requestor in the
    /// ticket-request event); 4768 uses `TargetUserName` (the account a TGT was
    /// requested for). Lowercased for stable grouping.
    private func account(of e: EventLogRecord) -> String {
        let name = (e.data("TargetUserName") ?? "").trimmingCharacters(in: .whitespaces)
        guard !name.isEmpty, name != "-" else { return "<unknown>" }
        return name.lowercased()
    }

    /// The SPN / service the ticket was requested for (4769 `ServiceName`).
    private func serviceName(of e: EventLogRecord) -> String {
        let s = (e.data("ServiceName") ?? "").trimmingCharacters(in: .whitespaces)
        // krbtgt service tickets are TGTs, not roastable service tickets - drop.
        guard !s.isEmpty, s != "-", s.lowercased() != "krbtgt" else { return "" }
        return s
    }

    /// Image + command line for a process-creation event (4688 Security or
    /// Sysmon 1), mirroring ImpacketRemoteExecAnalyzer's haystack.
    private func processHaystack(for e: EventLogRecord) -> String? {
        switch e.eventID {
        case 4688:
            let img = e.data("NewProcessName") ?? ""
            let cmd = e.data("CommandLine") ?? e.data("ProcessCommandLine") ?? ""
            return img.isEmpty && cmd.isEmpty ? nil : img + " " + cmd
        case 1 where e.channel.localizedCaseInsensitiveContains("Sysmon"):
            let img = e.data("Image") ?? ""
            let cmd = e.data("CommandLine") ?? ""
            return img.isEmpty && cmd.isEmpty ? nil : img + " " + cmd
        default:
            return nil
        }
    }

    /// Distinct values preserving first-seen order (for stable detail strings).
    private func orderedDistinct(_ values: [String]) -> [String] {
        var seen = Set<String>()
        var out: [String] = []
        for v in values where !v.isEmpty {
            let key = v.lowercased()
            if seen.insert(key).inserted { out.append(v) }
        }
        return out
    }
}
