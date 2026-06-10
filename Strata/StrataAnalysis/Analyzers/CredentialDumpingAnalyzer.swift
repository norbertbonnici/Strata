import Foundation

/// OS credential dumping (T1003) and Kerberos credential-theft tooling (T1558).
///
/// Credential access is the hinge of most intrusions: once an attacker has
/// LSASS secrets, SAM/SECURITY hives, or the domain `NTDS.dit`, they pivot at
/// will. This analyzer fuses **process-execution evidence** (Security 4688
/// command lines + Sysmon 1) with the **LSASS-access primitive** (Sysmon 10),
/// the **file-system footprint** of a dump (files / `$MFT` / USN), and
/// **tool-presence** evidence across the execution artifacts (prefetch,
/// amcache, shimcache, LNK, browser downloads, Linux shell history).
///
/// Discipline: every rule gates on a *specific* token, path, or access mask -
/// never a bare keyword - so confirmed dumps land `.critical`, named offensive
/// tools `.high`, and merely-suggestive proximity (vssadmin near ntds) `.medium`.
///
/// Kill-chain phase: Exploitation (the act of stealing credentials on-host).
public nonisolated struct CredentialDumpingAnalyzer: Analyzer {
    public let name = "Credential Dumping"
    public init() {}

    // MARK: - ATT&CK references

    private static let lsassMemory      = AttackTechnique(attackID: "T1003.001", name: "OS Credential Dumping: LSASS Memory")
    private static let samDump          = AttackTechnique(attackID: "T1003.002", name: "OS Credential Dumping: Security Account Manager")
    private static let ntdsDump         = AttackTechnique(attackID: "T1003.003", name: "OS Credential Dumping: NTDS")
    private static let credDumpGeneric  = AttackTechnique(attackID: "T1003", name: "OS Credential Dumping")
    private static let kerberosSteal    = AttackTechnique(attackID: "T1558", name: "Steal or Forge Kerberos Tickets")

    // MARK: - Tool fingerprints (lowercased, substring-matched).

    /// Named offensive credential-access tools. Each maps to its technique; the
    /// strings are distinctive enough (mimikatz module names, project names) that
    /// a substring hit is high-confidence on its own.
    private static let toolFingerprints: [(token: String, technique: AttackTechnique)] = [
        ("mimikatz",   lsassMemory),
        ("sekurlsa",   lsassMemory),     // mimikatz LSASS module
        ("lsadump",    lsassMemory),     // mimikatz SAM/LSA/DCSync module
        ("gsecdump",   credDumpGeneric),
        ("pwdump",     samDump),
        ("dumpert",    lsassMemory),     // outflanknl/Dumpert
        ("nanodump",   lsassMemory),     // fortra/nanodump
        ("procdump64", lsassMemory),     // procdump specifically the 64-bit dumper variant name
        ("rubeus",     kerberosSteal),   // Kerberos ticket theft
        ("safetykatz", lsassMemory),
        ("comsvcs.dll,minidump", lsassMemory),  // the LOLBin LSASS-dump one-liner, no-space form
    ]

    // MARK: - Sysmon 10 (ProcessAccess) LSASS read masks.

    /// GrantedAccess values used to read LSASS memory for a dump. These are the
    /// canonical mimikatz / handle-duplication masks; a benign AV/EDR access of
    /// LSASS uses different (lower) rights, so the mask is load-bearing.
    private static let lsassDumpMasks: Set<String> = ["0x1010", "0x1410", "0x143a", "0x1438", "0x1fffff"]

    public func analyze(context: AnalysisContext) -> [Finding] {
        var findings: [Finding] = []
        findings.append(contentsOf: eventRules(context.events))
        findings.append(contentsOf: fileRules(context))
        findings.append(contentsOf: artifactRules(context))
        findings.append(contentsOf: vssNtdsProximity(context))
        return findings
    }

    // MARK: - Rule group 1: process-execution events (4688 / Sysmon 1 + 10)

    private func eventRules(_ events: [EventLogRecord]) -> [Finding] {
        var out: [Finding] = []
        for event in events {
            // --- Sysmon EventID 10: ProcessAccess against lsass.exe. ---
            if event.eventID == 10, event.channel.localizedCaseInsensitiveContains("Sysmon") {
                let target = (event.data("TargetImage") ?? "").lowercased()
                guard target.hasSuffix("\\lsass.exe") || target.hasSuffix("/lsass.exe") else { continue }
                let granted = (event.data("GrantedAccess") ?? "").lowercased()
                guard Self.lsassDumpMasks.contains(granted) else { continue }
                let sourceImg = event.data("SourceImage") ?? "(unknown)"
                out.append(Finding(
                    title: "LSASS memory access for credential dump on \(event.computer)",
                    detail: """
                    Sysmon ProcessAccess (EID 10) at \(event.writtenAt.formatted()): \(sourceImg) \
                    opened a handle to lsass.exe with GrantedAccess \(granted) - a mask used to \
                    read process memory for a credential dump (mimikatz sekurlsa / handle duplication).
                    """,
                    severity: .critical,
                    phase: .exploitation,
                    technique: Self.lsassMemory,
                    timestamp: event.writtenAt,
                    evidencePaths: [event.sourceFile]))
                continue
            }

            // --- 4688 / Sysmon 1: build a command-line haystack and apply the
            //     command-line rules below. ---
            guard let cmd = commandLine(for: event)?.lowercased(), !cmd.isEmpty else { continue }
            if let f = commandLineFinding(cmd, event: event) { out.append(f) }
        }
        return out
    }

    /// Concatenate image + command line for an execution event. Only 4688 and
    /// Sysmon 1 carry a command line; everything else returns nil so the rule is
    /// scoped to actual process launches.
    private func commandLine(for event: EventLogRecord) -> String? {
        switch event.eventID {
        case 4688:
            let img = event.data("NewProcessName") ?? ""
            let cmd = event.data("CommandLine") ?? event.data("ProcessCommandLine") ?? ""
            return img.isEmpty && cmd.isEmpty ? nil : img + " " + cmd
        case 1 where event.channel.localizedCaseInsensitiveContains("Sysmon"):
            let img = event.data("Image") ?? ""
            let cmd = event.data("CommandLine") ?? ""
            return img.isEmpty && cmd.isEmpty ? nil : img + " " + cmd
        default:
            return nil
        }
    }

    /// Command-line credential-dumping signatures, ordered most→least specific.
    /// Returns the first (single, highest-value) finding for the line.
    private func commandLineFinding(_ cmd: String, event: EventLogRecord) -> Finding? {
        // 1) Named tool fingerprint embedded in the command line.
        if let hit = Self.toolFingerprints.first(where: { cmd.contains($0.token) }) {
            return finding(event, title: "Credential-dumping tool invoked on \(event.computer): \(hit.token)",
                           detail: "Execution command line referenced the credential-access tool '\(hit.token)'.",
                           cmd: cmd, severity: .critical, technique: hit.technique)
        }

        // 2) comsvcs.dll MiniDump LOLBin (rundll32 ... comsvcs ... MiniDump). Both
        //    tokens must be present so a benign comsvcs reference doesn't fire.
        if cmd.contains("comsvcs") && cmd.contains("minidump") {
            return finding(event, title: "LSASS dump via comsvcs.dll MiniDump on \(event.computer)",
                           detail: "rundll32 comsvcs.dll MiniDump LOLBin - the fileless LSASS-dump one-liner.",
                           cmd: cmd, severity: .critical, technique: Self.lsassMemory)
        }

        // 3) procdump targeting lsass (the tool name + an lsass argument). Gate on
        //    both so a procdump of some other process isn't a credential finding.
        if cmd.contains("procdump") && cmd.contains("lsass") {
            return finding(event, title: "procdump of LSASS on \(event.computer)",
                           detail: "procdump invoked against lsass.exe to capture a memory dump for offline secret extraction.",
                           cmd: cmd, severity: .critical, technique: Self.lsassMemory)
        }

        // 4) reg save / reg.exe save of the SAM | SECURITY | SYSTEM hives. Require
        //    the save verb AND an HKLM credential-hive target.
        if (cmd.contains("reg save") || cmd.contains("reg.exe save")), savesCredentialHive(cmd) {
            return finding(event, title: "Credential hive export via reg save on \(event.computer)",
                           detail: "`reg save` of an HKLM SAM/SECURITY/SYSTEM hive - offline password-hash extraction.",
                           cmd: cmd, severity: .high, technique: Self.samDump)
        }

        // 5) ntdsutil IFM / "create full" - dumps the AD database (NTDS.dit).
        if cmd.contains("ntdsutil") && (cmd.contains("ifm") || cmd.contains("create full")) {
            return finding(event, title: "NTDS.dit extraction via ntdsutil IFM on \(event.computer)",
                           detail: "ntdsutil 'Install From Media' / 'create full' dumps the domain's NTDS.dit (all account hashes).",
                           cmd: cmd, severity: .critical, technique: Self.ntdsDump)
        }

        // 6) Shadow-copy access to \config\SAM (VSS GLOBALROOT path). Strong on its
        //    own: a SAM read through a shadow copy is an evasion of the file lock.
        if cmd.contains("harddiskvolumeshadowcopy") && cmd.contains("\\config\\sam") {
            return finding(event, title: "SAM hive copied from a Volume Shadow Copy on \(event.computer)",
                           detail: "Access to \\config\\SAM through a HarddiskVolumeShadowCopy path - reading the locked SAM via VSS.",
                           cmd: cmd, severity: .high, technique: Self.samDump)
        }

        return nil
    }

    /// True when a `reg save` command line targets an HKLM credential hive. Match
    /// `hklm\sam`, `hklm\security`, or `hklm\system` (with optional `\` variants),
    /// not a bare "sam"/"system" word that appears in many benign paths.
    private func savesCredentialHive(_ cmd: String) -> Bool {
        for hive in ["hklm\\sam", "hklm\\security", "hklm\\system",
                     "hkey_local_machine\\sam", "hkey_local_machine\\security", "hkey_local_machine\\system"] {
            if cmd.contains(hive) { return true }
        }
        return false
    }

    private func finding(_ event: EventLogRecord, title: String, detail: String,
                         cmd: String, severity: Severity, technique: AttackTechnique) -> Finding {
        Finding(
            title: title,
            detail: """
            \(detail)
            EID \(event.eventID) on \(event.computer) at \(event.writtenAt.formatted()).
            Command line: \(String(cmd.prefix(400)))
            """,
            severity: severity,
            phase: .exploitation,
            technique: technique,
            timestamp: event.writtenAt,
            evidencePaths: [event.sourceFile])
    }

    // MARK: - Rule group 2: file-system footprint of a dump

    /// A dropped LSASS dump (`lsass*.dmp`), the AD database (`ntds.dit`), or a
    /// SAM/SYSTEM/SECURITY hive copy left on disk - across the live file tree,
    /// the `$MFT`, and the USN journal. Names are gated tightly so an ordinary
    /// `.dmp` or the in-place `\Windows\System32\config\SAM` never fires.
    private func fileRules(_ context: AnalysisContext) -> [Finding] {
        var out: [Finding] = []

        // Live file tree.
        for file in context.files where !file.isDirectory {
            if let kind = dumpArtifact(name: file.name, path: file.fullPath) {
                out.append(Finding(
                    title: "\(kind.label) on disk: \(file.name)",
                    detail: "\(file.fullPath)\n\(kind.detail)",
                    severity: kind.severity, phase: .exploitation, technique: kind.technique,
                    timestamp: file.created ?? file.modified,
                    evidencePaths: [file.fullPath]))
            }
        }

        // $MFT records (recovers names of since-deleted dumps with timestomp-proof times).
        for entry in context.mft {
            let name = entry.fileName ?? ""
            if let kind = dumpArtifact(name: name, path: entry.displayPath) {
                out.append(Finding(
                    title: "\(kind.label) in $MFT: \(name)",
                    detail: "\(entry.displayPath)\n\(kind.detail)",
                    severity: kind.severity, phase: .exploitation, technique: kind.technique,
                    timestamp: entry.siCreated,
                    evidencePaths: [entry.displayPath, entry.sourceFile]))
            }
        }

        // USN journal: a *created* dump artifact (recovers cleaned-up names).
        for rec in context.usn where rec.isCreate {
            if let kind = dumpArtifact(name: rec.fileName, path: rec.fileName) {
                out.append(Finding(
                    title: "\(kind.label) created (USN journal): \(rec.fileName)",
                    detail: "USN \(rec.reasonSummary): \(rec.fileName)\n\(kind.detail)",
                    severity: kind.severity, phase: .exploitation, technique: kind.technique,
                    timestamp: rec.timestamp,
                    evidencePaths: [rec.sourceFile]))
            }
        }
        return out
    }

    private struct DumpArtifact { let label: String; let detail: String; let severity: Severity; let technique: AttackTechnique }

    /// Classify a filename (with full path for context) as a credential-dump
    /// artifact, or nil. Tight name matching, low false-positive.
    private func dumpArtifact(name: String, path: String) -> DumpArtifact? {
        let n = name.lowercased()
        let p = path.lowercased()

        // lsass*.dmp / lsass.exe.dmp / lsass-<n>.dmp - an LSASS memory dump.
        if n.hasSuffix(".dmp") && n.contains("lsass") {
            return DumpArtifact(
                label: "LSASS memory dump",
                detail: "A dump file named after lsass.exe - offline credential extraction target (T1003.001).",
                severity: .critical, technique: Self.lsassMemory)
        }
        // ntds.dit copied OUT of its normal NTDS directory (a copy/IFM export).
        if n == "ntds.dit" && !p.contains("\\windows\\ntds\\") && !p.contains("/windows/ntds/") {
            return DumpArtifact(
                label: "NTDS.dit copy",
                detail: "A copy of the AD database outside \\Windows\\NTDS - all domain account hashes (T1003.003).",
                severity: .high, technique: Self.ntdsDump)
        }
        // SAM/SYSTEM/SECURITY hive *copy* (no extension, outside config) - e.g.
        // a `reg save` target like \temp\sam or sam.save / sam.hive.
        if isCredentialHiveCopy(name: n, path: p) {
            return DumpArtifact(
                label: "Credential hive copy",
                detail: "A copy of a SAM/SYSTEM/SECURITY registry hive outside \\System32\\config - offline hash extraction (T1003.002).",
                severity: .high, technique: Self.samDump)
        }
        return nil
    }

    /// A SAM/SYSTEM/SECURITY hive *copy*: the bare hive name (optionally with a
    /// `.save`/`.hive`/`.bak`/`.bin` suffix), located OUTSIDE the live
    /// `\System32\config\` directory (where the originals legitimately live).
    ///
    /// FP discipline: a recognized copy-suffix (`sam.save`, `system.bak`, …) is a
    /// near-unambiguous reg-save/export artifact, so all three stems qualify. A
    /// *bare* extensionless name is murkier — `system` and `security` are ordinary
    /// English words / config-file names (e.g. a Linux `/etc/security/…`), so for
    /// those two we additionally require a staging-path context. The bare stem
    /// `sam` is kept unconditionally: it is rarely a benign extensionless filename
    /// and is the canonical `reg save HKLM\SAM \temp\sam` target.
    private func isCredentialHiveCopy(name: String, path: String) -> Bool {
        let bases: Set<String> = ["sam", "system", "security"]
        // Strip a single common copy-suffix; the remaining stem must be a hive name.
        var stem = name
        var hadCopySuffix = false
        for suffix in [".save", ".hive", ".bak", ".bin", ".old", ".copy"] where stem.hasSuffix(suffix) {
            stem = String(stem.dropLast(suffix.count)); hadCopySuffix = true; break
        }
        guard bases.contains(stem) else { return false }
        // Exclude the in-place originals and the RegBack copies Windows itself makes.
        if path.contains("\\system32\\config\\") || path.contains("/system32/config/") { return false }
        // A bare `system`/`security` with no copy-suffix is too generic on its own;
        // require it to sit in a staging location to fire. (`sam` and any
        // suffix-bearing copy are kept.)
        if !hadCopySuffix && stem != "sam" && !pathLooksLikeStaging(path) { return false }
        return true
    }

    /// True when a path is in a location attackers favour for dropped/staged
    /// artifacts — used to corroborate the otherwise-generic bare `system`/
    /// `security` hive-copy names. Matched on both path-separator conventions
    /// (TSK renders `/`, native Windows tooling `\`).
    private func pathLooksLikeStaging(_ path: String) -> Bool {
        let fragments = ["\\temp\\", "/temp/", "\\tmp\\", "/tmp/",
                         "\\users\\public\\", "/users/public/",
                         "\\$recycle.bin\\", "/$recycle.bin/",
                         "\\perflogs\\", "/perflogs/",
                         "\\downloads\\", "/downloads/",
                         "\\programdata\\", "/programdata/"]
        return fragments.contains { path.contains($0) }
    }

    // MARK: - Rule group 3: tool presence in execution / download / shell artifacts

    /// Named-tool fingerprints across prefetch, amcache, shimcache, LNK targets,
    /// browser downloads, and Linux shell history. Presence (not proven
    /// execution for some sources) of a named credential tool is .high.
    private func artifactRules(_ context: AnalysisContext) -> [Finding] {
        var out: [Finding] = []

        func emit(label: String, source: String, name: String, path: String?,
                  when: Date?, evidence: [String]) {
            let hay = (name + " " + (path ?? "")).lowercased()
            guard let hit = Self.toolFingerprints.first(where: { hay.contains($0.token) }) else { return }
            out.append(Finding(
                title: "Credential-dumping tool present (\(source)): \(name)",
                detail: "\(label)\nMatched fingerprint '\(hit.token)'.\(path.map { "\nPath: \($0)" } ?? "")",
                severity: .high, phase: .exploitation, technique: hit.technique,
                timestamp: when, evidencePaths: evidence))
        }

        for e in context.prefetch {
            emit(label: "Prefetch records this program ran.", source: "prefetch",
                 name: e.executableName, path: e.executablePath, when: e.lastRun,
                 evidence: [e.executablePath ?? e.executableName, e.sourceFile])
        }
        for e in context.amcache {
            emit(label: "Amcache registered this file (presence, not execution).", source: "amcache",
                 name: e.name, path: e.fullPath, when: e.registeredAt, evidence: [e.fullPath ?? e.name, e.sourceFile])
        }
        for e in context.shimcache {
            emit(label: "Shimcache recorded this path (presence, not execution).", source: "shimcache",
                 name: e.name, path: e.path, when: e.lastModified, evidence: [e.path, e.sourceFile])
        }
        for e in context.lnk {
            emit(label: "A shortcut referenced this target.", source: "lnk",
                 name: e.name, path: e.targetPath ?? e.arguments, when: e.targetModified,
                 evidence: [e.sourceFile])
        }
        for e in context.browserHistory where e.kind == .download {
            emit(label: "Browser download.", source: "download",
                 name: e.targetLeaf ?? e.displayTitle, path: e.targetPath ?? e.url, when: e.timestamp,
                 evidence: [e.sourceFile])
        }
        for e in context.shellHistory {
            emit(label: "Shell history command.", source: "shell history",
                 name: e.command, path: nil, when: e.timestamp,
                 evidence: [e.sourceFile])
        }
        return out
    }

    // MARK: - Rule group 4: VSS-create near NTDS access (suggestive proximity)

    /// `vssadmin create shadow` (or `wmic shadowcopy call create`) is a routine
    /// admin/backup action on its own, but when an `ntds.dit` access/copy appears
    /// in the same evidence it strongly suggests the shadow-copy NTDS-dump
    /// technique. Emitted at .medium (suggestive, not confirmed).
    private func vssNtdsProximity(_ context: AnalysisContext) -> [Finding] {
        // Did anything create a shadow copy?
        let vssCreate = context.events.compactMap { event -> EventLogRecord? in
            guard let cmd = commandLine(for: event)?.lowercased() else { return nil }
            let createsShadow = (cmd.contains("vssadmin") && cmd.contains("create") && cmd.contains("shadow"))
                || (cmd.contains("wmic") && cmd.contains("shadowcopy") && cmd.contains("call") && cmd.contains("create"))
            return createsShadow ? event : nil
        }
        guard let vss = vssCreate.first else { return [] }

        // Is there any ntds.dit footprint in the case (file / MFT / USN)?
        let ntdsTouched = context.files.contains { $0.name.lowercased() == "ntds.dit" }
            || context.mft.contains { ($0.fileName ?? "").lowercased() == "ntds.dit" }
            || context.usn.contains { $0.fileName.lowercased() == "ntds.dit" }
        guard ntdsTouched else { return [] }

        return [Finding(
            title: "Volume Shadow Copy created with NTDS.dit access nearby on \(vss.computer)",
            detail: """
            A Volume Shadow Copy was created and an ntds.dit artifact is present in this evidence - \
            together a strong indicator of the shadow-copy NTDS.dit dump technique (copy the locked \
            AD database out of a snapshot). Correlate the shadow-create time with the ntds.dit access.
            EID \(vss.eventID) on \(vss.computer) at \(vss.writtenAt.formatted()).
            """,
            severity: .medium,
            phase: .exploitation,
            technique: Self.ntdsDump,
            timestamp: vss.writtenAt,
            evidencePaths: [vss.sourceFile])]
    }
}
