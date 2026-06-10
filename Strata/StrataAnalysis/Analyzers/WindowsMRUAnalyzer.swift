import Foundation

/// Surfaces *intent* evidence buried in per-user Explorer Most-Recently-Used
/// (MRU) registry artifacts. These keys record what a human typed or opened on
/// the box - not that a process ran - so they are the registry counterpart to
/// shell history: a great way to catch the *human-in-the-loop* moment of an
/// intrusion (a typed `powershell -enc ...`, a double-clicked `invoice.iso`, an
/// Explorer-typed UNC path to a staging share) even when the resulting process
/// left no other trace.
///
/// We only emit findings for the **suspicious subset** - the whole point of MRU
/// triage is that the noise (every Notepad document the user ever opened) is
/// uninteresting. Each rule below gates on a concrete token, risky file
/// extension, suspicious path, or UNC marker rather than a broad keyword, so a
/// clean host yields zero findings.
///
/// Severity is capped at `.medium`: an MRU entry proves *intent / presence*, not
/// execution. (`PrefetchAnalyzer` / the EVTX analyzers carry the execution
/// proof.) We deliberately do not raise to `.high`.
///
/// Keys covered (all under the per-user `NTUSER` hive,
/// `Software\Microsoft\Windows\CurrentVersion\Explorer\...`):
///   - `RunMRU`            - commands typed into the Win+R "Run" box (T1059)
///   - `TypedPaths`        - paths typed into the Explorer address bar (T1083)
///   - `RecentDocs`        - recently opened documents by extension (T1204.002)
///   - `ComDlg32\OpenSavePidlMRU` / `LastVisitedPidlMRU`
///                         - files touched via Open/Save dialogs (T1204.002)
///   - `UserAssist`        - GUI-launched programs, ROT13-decoded (T1204.002)
///
/// Kill-chain phase: Exploitation for the execution-intent keys (RunMRU /
/// RecentDocs / dialog MRUs / UserAssist), Reconnaissance for TypedPaths
/// (operator navigating to a share / staging dir).
public nonisolated struct WindowsMRUAnalyzer: Analyzer {
    public let name = "Windows MRU Artifacts"
    public init() {}

    // MARK: Key path fragments (matched case-insensitively as substrings, so a
    // leading `Software\` prefix on NTUSER paths is tolerated).
    private static let runMRUKey            = "Explorer\\RunMRU"
    private static let typedPathsKey        = "Explorer\\TypedPaths"
    private static let recentDocsKey        = "Explorer\\RecentDocs"
    private static let openSaveMRUKey       = "ComDlg32\\OpenSavePidlMRU"
    private static let lastVisitedMRUKey    = "ComDlg32\\LastVisitedPidlMRU"
    private static let userAssistKey        = "Explorer\\UserAssist"

    /// Interpreters / proxy binaries whose mere appearance in a *typed* command
    /// (Win+R) is suspicious. Lowercased; matched as substrings so `powershell`
    /// catches `powershell.exe`, `c:\...\powershell`, etc.
    private static let interpreterTokens: [(token: String, technique: AttackTechnique)] = [
        ("powershell", AttackTechnique(attackID: "T1059.001", name: "Command and Scripting Interpreter: PowerShell")),
        ("pwsh",       AttackTechnique(attackID: "T1059.001", name: "Command and Scripting Interpreter: PowerShell")),
        ("cmd.exe",    AttackTechnique(attackID: "T1059.003", name: "Command and Scripting Interpreter: Windows Command Shell")),
        ("cmd /c",     AttackTechnique(attackID: "T1059.003", name: "Command and Scripting Interpreter: Windows Command Shell")),
        ("mshta",      AttackTechnique(attackID: "T1218.005", name: "System Binary Proxy Execution: Mshta")),
        ("rundll32",   AttackTechnique(attackID: "T1218.011", name: "System Binary Proxy Execution: Rundll32")),
        ("regsvr32",   AttackTechnique(attackID: "T1218.010", name: "System Binary Proxy Execution: Regsvr32")),
        ("wscript",    AttackTechnique(attackID: "T1059.005", name: "Command and Scripting Interpreter: Visual Basic")),
        ("cscript",    AttackTechnique(attackID: "T1059.005", name: "Command and Scripting Interpreter: Visual Basic")),
        ("bitsadmin",  AttackTechnique(attackID: "T1197", name: "BITS Jobs")),
        ("certutil",   AttackTechnique(attackID: "T1105", name: "Ingress Tool Transfer")),
    ]

    /// Encoded / download-cradle tokens that escalate a typed command beyond a
    /// bare interpreter mention - these don't appear in benign Run-box use.
    ///
    /// Deliberately *specific*: we dropped the bare `-e ` and bare `hidden`
    /// (PowerShell's `-e`/`-encodedcommand` and `-windowstyle hidden` shorthands)
    /// because `-e ` collides with countless ordinary tool flags (`7z -e ...`,
    /// `notepad -e ...`) and `hidden` is a common folder/word - both would fire
    /// on benign Run-box input. The retained forms (`-enc`, `-encodedcommand`,
    /// `-w hidden`, `-windowstyle hidden`) are unambiguous PowerShell tradecraft.
    private static let cradleTokens = [
        "-enc", "-encodedcommand", "frombase64string", "iex ",
        "invoke-expression", "downloadstring", "downloadfile", "webclient",
        "-nop", "-noprofile", "-w hidden", "-windowstyle hidden",
        "-exec bypass", "-executionpolicy bypass",
        "http://", "https://", "ftp://",
    ]

    /// Path fragments that shouldn't normally host a typed command target or a
    /// recently-opened file. Lowercased substrings.
    private static let suspiciousPathFragments = [
        "\\temp\\", "\\appdata\\", "\\public\\", "\\downloads\\",
        "\\programdata\\", "\\windows\\temp\\", "\\$recycle.bin\\",
        "\\perflogs\\", "%temp%", "%appdata%",
    ]

    /// Tighter path set used **only** for UserAssist. UserAssist enumerates
    /// *every* GUI program a user launched, so the broad `\appdata\` would flag
    /// the many legitimate apps that self-update out of `\AppData\Local\`
    /// (Slack, Teams, Discord, VS Code, GitHub Desktop - Squirrel/Electron
    /// installers all run from there). We keep only the high-signal staging
    /// locations that a normal *installed* program never executes from, which
    /// keeps this rule near-zero-FP on a real desktop.
    private static let userAssistPathFragments = [
        "\\temp\\", "\\public\\", "\\downloads\\",
        "\\windows\\temp\\", "\\$recycle.bin\\", "\\perflogs\\",
        "\\appdata\\local\\temp\\", "%temp%",
    ]

    /// File extensions that are script / installer / container payloads -
    /// rarely a *document* a user opens by accident. Includes the
    /// leading dot; matched as a suffix on the (lowercased) entry.
    private static let riskyExtensions = [
        ".ps1", ".hta", ".js", ".jse", ".vbs", ".vbe", ".wsf", ".wsh",
        ".scr", ".bat", ".cmd", ".lnk", ".iso", ".img", ".vhd", ".vhdx",
    ]

    public func analyze(context: AnalysisContext) -> [Finding] {
        var findings: [Finding] = []
        for value in context.registryValues {
            let path = value.path
            if path.localizedCaseInsensitiveContains(Self.runMRUKey) {
                if let f = runMRUFinding(value) { findings.append(f) }
            } else if path.localizedCaseInsensitiveContains(Self.typedPathsKey) {
                if let f = typedPathFinding(value) { findings.append(f) }
            } else if path.localizedCaseInsensitiveContains(Self.recentDocsKey) {
                if let f = recentDocFinding(value) { findings.append(f) }
            } else if path.localizedCaseInsensitiveContains(Self.openSaveMRUKey)
                   || path.localizedCaseInsensitiveContains(Self.lastVisitedMRUKey) {
                if let f = dialogMRUFinding(value) { findings.append(f) }
            } else if path.localizedCaseInsensitiveContains(Self.userAssistKey) {
                if let f = userAssistFinding(value) { findings.append(f) }
            }
        }
        return findings
    }

    // MARK: - RunMRU (Win+R typed commands)

    /// RunMRU stores one value per typed command (`a`, `b`, `c`, ...), each
    /// rendered by Explorer as `command\1` (the trailing `\1` selects the
    /// "open" verb). The `MRUList` ordering value is skipped (no command).
    private func runMRUFinding(_ value: RegistryValue) -> Finding? {
        guard !value.name.isEmpty,
              !value.name.equalsIgnoringCase("MRUList"),
              !value.name.equalsIgnoringCase("MRUListEx")
        else { return nil }

        // Strip the trailing `\1` verb suffix for readability / matching.
        var command = value.data
        if let r = command.range(of: "\\1", options: .backwards), r.upperBound == command.endIndex {
            command = String(command[..<r.lowerBound])
        }
        let lowered = command.lowercased()

        let interpreter = Self.interpreterTokens.first { lowered.contains($0.token) }
        let hasCradle = Self.cradleTokens.contains { lowered.contains($0) }
        let suspiciousPath = Self.suspiciousPathFragments.first { lowered.contains($0) }
        guard interpreter != nil || hasCradle || suspiciousPath != nil else { return nil }

        var reasons: [String] = []
        if let i = interpreter { reasons.append("interpreter/proxy binary (\(i.token))") }
        if hasCradle { reasons.append("encoded/download-cradle token") }
        if let p = suspiciousPath { reasons.append("suspicious path (\(p))") }

        let technique = interpreter?.technique
            ?? AttackTechnique(attackID: "T1059", name: "Command and Scripting Interpreter")
        return Finding(
            title: "Suspicious Run-box command typed: \(value.name)",
            detail: """
            A command was typed into the Win+R Run box and recorded in RunMRU.
            Command: \(command)
            Why flagged: \(reasons.joined(separator: "; "))
            Hive: \(value.hive)
            Key: \(value.path)
            This shows user intent to execute - confirm whether the user ran it.
            """,
            severity: .medium,
            phase: .exploitation,
            technique: technique,
            timestamp: value.lastWritten,
            evidencePaths: [value.fullPath, value.sourceFile])
    }

    // MARK: - TypedPaths (Explorer address bar)

    /// TypedPaths stores `url1`, `url2`, ... - paths typed into the Explorer
    /// address bar. UNC paths (`\\host\share`) point at remote shares (lateral
    /// staging / data access); suspicious local paths matter too.
    private func typedPathFinding(_ value: RegistryValue) -> Finding? {
        guard !value.name.isEmpty else { return nil }
        let raw = value.data
        let lowered = raw.lowercased()
        let isUNC = raw.hasPrefix("\\\\")
        let suspiciousPath = Self.suspiciousPathFragments.first { lowered.contains($0) }
        guard isUNC || suspiciousPath != nil else { return nil }

        let reason = isUNC
            ? "UNC path to a remote share"
            : "suspicious local path (\(suspiciousPath ?? ""))"
        let technique = isUNC
            ? AttackTechnique(attackID: "T1021.002", name: "Remote Services: SMB/Windows Admin Shares")
            : AttackTechnique(attackID: "T1083", name: "File and Directory Discovery")
        return Finding(
            title: "Suspicious path typed in Explorer: \(value.name)",
            detail: """
            A path was typed into the Explorer address bar (TypedPaths).
            Path: \(raw)
            Why flagged: \(reason)
            Hive: \(value.hive)
            Key: \(value.path)
            """,
            severity: .medium,
            phase: isUNC ? .exploitation : .reconnaissance,
            technique: technique,
            timestamp: value.lastWritten,
            evidencePaths: [value.fullPath, value.sourceFile])
    }

    // MARK: - RecentDocs (recently opened documents)

    /// RecentDocs records recently opened files (the value blob holds the
    /// filename as UTF-16). We only flag entries whose rendered data ends in a
    /// risky script/installer/container extension. The `MRUListEx` ordering
    /// value carries no name and is skipped.
    private func recentDocFinding(_ value: RegistryValue) -> Finding? {
        guard !value.name.isEmpty,
              !value.name.equalsIgnoringCase("MRUListEx")
        else { return nil }
        return riskyFileFinding(
            value,
            keyLabel: "RecentDocs",
            context: "recently opened (RecentDocs)")
    }

    // MARK: - ComDlg32 Open/Save & LastVisited dialog MRUs

    /// OpenSavePidlMRU / LastVisitedPidlMRU record files chosen in common
    /// Open/Save dialogs. Same risky-extension gate as RecentDocs.
    private func dialogMRUFinding(_ value: RegistryValue) -> Finding? {
        guard !value.name.isEmpty,
              !value.name.equalsIgnoringCase("MRUListEx")
        else { return nil }
        return riskyFileFinding(
            value,
            keyLabel: "ComDlg32 dialog MRU",
            context: "selected in an Open/Save dialog")
    }

    /// Shared risky-extension test for the file-oriented MRUs. Flags only when
    /// the data carries a risky extension *or* a suspicious path fragment.
    private func riskyFileFinding(_ value: RegistryValue, keyLabel: String, context: String) -> Finding? {
        let raw = value.data
        let lowered = raw.lowercased()
        let ext = Self.riskyExtensions.first { lowered.contains($0) }
        let suspiciousPath = Self.suspiciousPathFragments.first { lowered.contains($0) }
        guard ext != nil || suspiciousPath != nil else { return nil }

        var reasons: [String] = []
        if let e = ext { reasons.append("risky extension (\(e))") }
        if let p = suspiciousPath { reasons.append("suspicious path (\(p))") }

        return Finding(
            title: "Risky file in \(keyLabel): \(value.name)",
            detail: """
            A file was \(context) and recorded in the Explorer MRU.
            Entry: \(raw)
            Why flagged: \(reasons.joined(separator: "; "))
            Hive: \(value.hive)
            Key: \(value.path)
            User opened/handled this file - confirm provenance.
            """,
            severity: .medium,
            phase: .exploitation,
            technique: AttackTechnique(attackID: "T1204.002", name: "User Execution: Malicious File"),
            timestamp: value.lastWritten,
            evidencePaths: [value.fullPath, value.sourceFile])
    }

    // MARK: - UserAssist (GUI-launched programs)

    /// UserAssist records GUI-launched programs under
    /// `UserAssist\{GUID}\Count`, with the **value name ROT13-encoded** (the
    /// program path). We ROT13-decode the value name so we can path-match it;
    /// without decoding, `\downloads\` would never match the encrypted name.
    /// Note for the analyst: the run count / focus time live in the binary
    /// data blob, which we do not decode here.
    private func userAssistFinding(_ value: RegistryValue) -> Finding? {
        // Only the per-program counters carry an encoded name; skip the
        // `Version`/`Count` housekeeping values and any empty names.
        guard !value.name.isEmpty,
              !value.name.equalsIgnoringCase("Version")
        else { return nil }

        let decoded = Self.rot13(value.name)
        let lowered = decoded.lowercased()
        // Tighter path set than the other rules: UserAssist lists *every*
        // launched GUI program, so a broad `\appdata\` would flood on legit
        // self-updating apps. See `userAssistPathFragments`.
        guard let frag = Self.userAssistPathFragments.first(where: { lowered.contains($0) }) else { return nil }

        return Finding(
            title: "GUI launch from suspicious path (UserAssist): \(decoded)",
            detail: """
            UserAssist recorded a GUI launch of a program from a suspicious path.
            Program (ROT13-decoded): \(decoded)
            Encoded value name: \(value.name)
            Why flagged: suspicious path (\(frag))
            Hive: \(value.hive)
            Key: \(value.path)
            Run count / focus time are in the binary data blob (not decoded here).
            """,
            severity: .medium,
            phase: .exploitation,
            technique: AttackTechnique(attackID: "T1204.002", name: "User Execution: Malicious File"),
            timestamp: value.lastWritten,
            evidencePaths: [value.fullPath, value.sourceFile])
    }

    /// ROT13 over ASCII letters only; every other scalar (digits, `\`, `{`,
    /// `.`) passes through unchanged - exactly the UserAssist scheme.
    static func rot13(_ s: String) -> String {
        String(String.UnicodeScalarView(s.unicodeScalars.map { scalar in
            switch scalar.value {
            case 65...90:  return Unicode.Scalar((scalar.value - 65 + 13) % 26 + 65)!  // A-Z
            case 97...122: return Unicode.Scalar((scalar.value - 97 + 13) % 26 + 97)!  // a-z
            default:       return scalar
            }
        }))
    }
}

private extension String {
    func equalsIgnoringCase(_ other: String) -> Bool {
        caseInsensitiveCompare(other) == .orderedSame
    }
}
