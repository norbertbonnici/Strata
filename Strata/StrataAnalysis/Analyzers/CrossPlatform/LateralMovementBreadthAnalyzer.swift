import Foundation

/// Lateral-movement methods that the RDP (T1021.001), Impacket-service
/// (T1569.002) and SSH analyzers don't already cover. Four families, all read
/// from process-creation events (Security 4688 / Sysmon 1) plus the WinRM
/// operational channel:
///
///  - **WinRM / PowerShell Remoting (T1021.006)** — the canonical signal is
///    `wsmprovhost.exe` (the WinRM provider host) *spawning a shell or scripting
///    host*: that is a remote command landing on this box. The WinRM operational
///    channel's own 5985/5986 (HTTP/HTTPS listener) records are a weaker,
///    presence-only corroborator.
///  - **WMI remote exec (T1047)** — `WmiPrvSE.exe` (the WMI provider host)
///    spawning cmd/PowerShell/script hosts is `Win32_Process::Create` executing
///    on the target; `wmic /node:<host> process call create` on the *source* is
///    the matching outbound fingerprint.
///  - **DCOM lateral movement (T1021.003)** — the MMC20.Application /
///    ShellWindows / ShellBrowserWindow objects spawn a child through
///    `DcomLaunch`; `mmc.exe` or `svchost.exe -k DCOMLaunch` spawning a shell is
///    the on-host artifact, and the object monikers themselves appear in the
///    attacker's command line. (Excel.Application / Outlook.Application are
///    excluded as high-FP legitimate-automation ProgIDs.)
///  - **SMB / admin-share push (T1021.002 / T1570)** — `\\<host>\ADMIN$` or
///    `\\<host>\C$` referenced in a command line is a file dropped over an admin
///    share, the staging half of psexec-style movement.
///
/// FP discipline: the parent→child rules require the *remote-exec provider host*
/// (`wsmprovhost`/`WmiPrvSE`) or the DCOM-launch parent specifically — a normal
/// interactive `cmd.exe` -> `powershell.exe` never matches. The token rules
/// require the literal `/node:` / `ADMIN$` / object-moniker strings, not bare
/// keywords. This analyzer deliberately does **not** flag service creation —
/// that is `ImpacketRemoteExecAnalyzer`'s job — to avoid double-counting.
///
/// Kill-chain phase: Exploitation (remote code execution on the host).
public nonisolated struct LateralMovementBreadthAnalyzer: Analyzer {
    public let name = "Lateral Movement Breadth"
    public init() {}

    // MARK: ATT&CK techniques

    private static let winRM = AttackTechnique(
        attackID: "T1021.006", name: "Remote Services: Windows Remote Management")
    private static let wmiExec = AttackTechnique(
        attackID: "T1047", name: "Windows Management Instrumentation")
    private static let dcom = AttackTechnique(
        attackID: "T1021.003", name: "Remote Services: Distributed Component Object Model")
    private static let smbShare = AttackTechnique(
        attackID: "T1021.002", name: "Remote Services: SMB/Windows Admin Shares")

    // MARK: Tables

    /// Provider hosts that, when they *parent* a child process, indicate a
    /// remote command executed on this host. Keyed by lowercased basename.
    private static let winRMProviderHost = "wsmprovhost.exe"
    private static let wmiProviderHost   = "wmiprvse.exe"

    /// Shells / scripting hosts that are the interesting child of a remote-exec
    /// provider host (lowercased basenames).
    private static let shellChildren: Set<String> = [
        "cmd.exe", "powershell.exe", "pwsh.exe",
        "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe",
    ]

    /// DCOM object monikers an attacker passes to invoke a remote method. Each
    /// is distinctive enough to fire on its own (lowercased). Limited to the
    /// canonical DCOM-lateral-movement objects: `Excel.Application` /
    /// `Outlook.Application` are deliberately excluded because legitimate Office
    /// automation (admin VBScript `CreateObject("Excel.Application")`) uses them
    /// constantly, so they would be a steady false-positive source.
    private static let dcomMonikers: [String] = [
        "mmc20.application", "shellwindows", "shellbrowserwindow",
    ]

    // MARK: Analyze

    public func analyze(context: AnalysisContext) -> [Finding] {
        var findings: [Finding] = []
        for event in context.events {
            // WinRM operational-channel listener activity (no process fields).
            if let f = winRMChannelFinding(event) { findings.append(f) }

            // Everything else keys off the normalized process-creation row.
            guard let row = ProcRow(event: event) else { continue }
            if let f = remoteProviderSpawnFinding(row, event: event) { findings.append(f) }
            findings.append(contentsOf: commandTokenFindings(row, event: event))
        }
        return findings
    }

    // MARK: Rule 1 — remote-exec provider host spawning a shell

    /// `wsmprovhost.exe` or `WmiPrvSE.exe` parenting cmd/PowerShell/script host:
    /// the remote command actually executing. High confidence.
    private func remoteProviderSpawnFinding(_ row: ProcRow, event: EventLogRecord) -> Finding? {
        guard Self.shellChildren.contains(row.child) else { return nil }
        let technique: AttackTechnique
        let label: String
        switch row.parent {
        case Self.winRMProviderHost:
            technique = Self.winRM; label = "WinRM / PowerShell Remoting"
        case Self.wmiProviderHost:
            technique = Self.wmiExec; label = "WMI remote execution"
        default:
            return nil
        }
        let cmd = row.cmdline.isEmpty ? "" : "\nCommand line: \(row.cmdline)"
        return Finding(
            title: "\(label): \(row.parent) spawned \(row.child) on \(event.computer)",
            detail: "Process creation: \(row.parentImage) -> \(row.image).\(cmd)\n\n"
                + "Observed on \(event.computer) at \(event.writtenAt.formatted()). "
                + "\(row.parent) is the \(label.contains("WinRM") ? "WinRM" : "WMI") provider host; "
                + "a shell or scripting host as its child is a remote command executing on this box.",
            severity: .high,
            phase: .exploitation,
            technique: technique,
            timestamp: event.writtenAt,
            evidencePaths: [event.sourceFile])
    }

    // MARK: Rule 2 — command-line tokens (wmic /node:, DCOM monikers, admin shares)

    /// Token presence in the command line of *any* process-creation event.
    /// Each produces at most one finding per family (first match wins), medium
    /// severity — suggestive, not proof of execution on the remote end.
    private func commandTokenFindings(_ row: ProcRow, event: EventLogRecord) -> [Finding] {
        let cmd = row.cmdline.lowercased()
        guard !cmd.isEmpty else { return [] }
        var out: [Finding] = []

        // WMI remote process create from the source host: `wmic /node:<host>
        // process call create ...`. Require both /node: and the create verb so a
        // benign local `wmic /node:localhost product get` doesn't fire.
        if cmd.contains("/node:")
            && cmd.contains("process call create")
            && !cmd.contains("/node:localhost") && !cmd.contains("/node:127.0.0.1") {
            out.append(token(event: event, row: row,
                family: "WMI remote process creation (wmic /node:)",
                technique: Self.wmiExec,
                why: "wmic /node:<host> process call create spawns a process on a remote host."))
        }

        // DCOM object monikers in the command line.
        if let moniker = Self.dcomMonikers.first(where: { cmd.contains($0) }) {
            out.append(token(event: event, row: row,
                family: "DCOM lateral movement object (\(moniker))",
                technique: Self.dcom,
                why: "The \(moniker) DCOM object is abused to execute code on a remote host."))
        }

        // SMB / admin-share push: \\host\ADMIN$ or \\host\C$ in the command line.
        // Matched on the raw (non-lowercased) string is unnecessary — share names
        // are case-insensitive — so match the lowercased form.
        if let share = adminShareToken(in: cmd) {
            out.append(token(event: event, row: row,
                family: "SMB admin-share access (\(share))",
                technique: Self.smbShare,
                why: "A reference to the \(share.uppercased()) admin share is the staging half of an SMB push (e.g. copying a payload before a remote service create)."))
        }
        return out
    }

    /// Detect `\\<host>\admin$` or `\\<host>\c$` (UNC admin shares). Requires the
    /// leading `\\` so a bare drive letter `c$` substring can't match.
    private func adminShareToken(in lowered: String) -> String? {
        for share in ["admin$", "c$"] {
            // Find `\\...\<share>` — a UNC path ending in the share name.
            let needle = "\\" + share          // e.g. "\admin$"
            var search = lowered.startIndex
            while let r = lowered.range(of: needle, range: search..<lowered.endIndex) {
                // Ensure a UNC prefix (`\\`) appears before this share name.
                let before = lowered[lowered.startIndex..<r.lowerBound]
                if before.contains("\\\\") { return share }
                search = r.upperBound
            }
        }
        return nil
    }

    private func token(event: EventLogRecord, row: ProcRow,
                       family: String, technique: AttackTechnique, why: String) -> Finding {
        Finding(
            title: "\(family) on \(event.computer)",
            detail: "Process: \(row.image.isEmpty ? "(unknown)" : row.image)\n"
                + "Command line: \(row.cmdline)\n\n"
                + "Observed on \(event.computer) at \(event.writtenAt.formatted()). \(why)",
            severity: .medium,
            phase: .exploitation,
            technique: technique,
            timestamp: event.writtenAt,
            evidencePaths: [event.sourceFile])
    }

    // MARK: Rule 3 — WinRM operational-channel listener activity

    /// Microsoft-Windows-WinRM/Operational 5985/5986 (or any record on that
    /// channel referencing a WSMan listener) corroborates remote-management
    /// reachability. Presence-only ⇒ low severity, gated on the WinRM channel so
    /// it can't fire on unrelated logs that happen to carry "5985".
    private func winRMChannelFinding(_ event: EventLogRecord) -> Finding? {
        let onWinRMChannel = event.channel.localizedCaseInsensitiveContains("WinRM")
            || event.provider.localizedCaseInsensitiveContains("WinRM")
        guard onWinRMChannel else { return nil }
        guard event.eventID == 5985 || event.eventID == 5986
            || event.payloadXML.localizedCaseInsensitiveContains("WSMan") else { return nil }
        let scheme = event.eventID == 5986 ? "HTTPS (5986)" : "HTTP (5985)"
        return Finding(
            title: "WinRM remote-management activity on \(event.computer)",
            detail: "WinRM operational event \(event.eventID) (\(scheme)) on \(event.computer) "
                + "at \(event.writtenAt.formatted()). Indicates the WS-Management listener was "
                + "reached — corroborate against \(Self.winRMProviderHost) child processes for "
                + "actual remote command execution.",
            severity: .low,
            phase: .exploitation,
            technique: Self.winRM,
            timestamp: event.writtenAt,
            evidencePaths: [event.sourceFile])
    }

    // MARK: Normalized process-creation row

    /// Normalizes Security 4688 (NewProcessName / ParentProcessName) and
    /// Sysmon 1 (Image / ParentImage) into a single shape, mirroring
    /// `ProcessCreationAnalyzer`. Returns nil for non-process-creation events.
    private struct ProcRow {
        let image: String        // full child image path (verbatim)
        let parentImage: String  // full parent image path (verbatim)
        let child: String        // lowercased child basename
        let parent: String       // lowercased parent basename
        let cmdline: String      // child command line (may be empty on 4688)

        init?(event: EventLogRecord) {
            switch event.eventID {
            case 4688:
                let image = event.data("NewProcessName") ?? ""
                let parent = event.data("ParentProcessName") ?? ""
                let cmd = event.data("CommandLine") ?? event.data("ProcessCommandLine") ?? ""
                guard !image.isEmpty || !parent.isEmpty || !cmd.isEmpty else { return nil }
                self.init(image: image, parentImage: parent, cmdline: cmd)
            case 1 where event.channel.localizedCaseInsensitiveContains("Sysmon"):
                let image = event.data("Image") ?? ""
                let parent = event.data("ParentImage") ?? ""
                let cmd = event.data("CommandLine") ?? ""
                guard !image.isEmpty || !parent.isEmpty || !cmd.isEmpty else { return nil }
                self.init(image: image, parentImage: parent, cmdline: cmd)
            default:
                return nil
            }
        }

        private init(image: String, parentImage: String, cmdline: String) {
            self.image = image
            self.parentImage = parentImage
            self.cmdline = cmdline
            self.child = WindowsPath.basenameLower(image)
            self.parent = WindowsPath.basenameLower(parentImage)
        }
    }
}
