import Foundation

/// HKLM\Software\Microsoft\Windows\CurrentVersion\Run (machine-wide) and
/// HKCU\Software\Microsoft\Windows\CurrentVersion\Run (per user) are the
/// classic "make this binary run every time someone logs in" persistence
/// points. RunOnce is the same minus the persistence after first run. We
/// surface every entry and score by the same lolbin / user-writable-path
/// heuristics we use for service installs.
///
/// ATT&CK T1547.001 Boot or Logon Autostart Execution: Registry Run Keys.
/// Kill-chain phase: Installation.
public nonisolated struct RunKeyAnalyzer: Analyzer {
    public let name = "Registry Run Keys"
    public init() {}

    private static let runKeyPaths: [String] = [
        "Microsoft\\Windows\\CurrentVersion\\Run",
        "Microsoft\\Windows\\CurrentVersion\\RunOnce",
        "Microsoft\\Windows\\CurrentVersion\\RunOnceEx",
        "Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run",
        "Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Run",
    ]

    private static let suspiciousTokens = [
        "powershell", "-enc", "-encodedcommand", "frombase64string",
        "downloadstring", "iex ", "invoke-expression",
        "cmd.exe /c", "cmd /c", "rundll32", "regsvr32", "mshta", "wmic",
        "\\users\\", "\\appdata\\", "\\temp\\", "\\public\\",
        "\\programdata\\", "\\windows\\temp\\",
    ]

    public func analyze(context: AnalysisContext) -> [Finding] {
        context.registryValues.compactMap { value -> Finding? in
            guard !value.name.isEmpty,
                  Self.runKeyPaths.contains(where: { value.path.localizedCaseInsensitiveContains($0) })
            else { return nil }

            let data = value.data.lowercased()
            let hits = Self.suspiciousTokens.filter { data.contains($0) }
            let severity: Severity
            switch hits.count {
            case 0:    severity = .medium    // every Run-key entry is at least worth a look
            case 1, 2: severity = .high
            default:   severity = .critical
            }

            var bullets: [String] = [
                "Entry: \(value.name)",
                "Command: \(value.data)",
                "Hive: \(value.hive)",
                "Key: \(value.path)",
            ]
            if !hits.isEmpty {
                bullets.append("Suspicious tokens: \(hits.joined(separator: ", "))")
            }
            if let written = value.lastWritten {
                bullets.append("Key last-written: \(written.formatted())")
            }
            return Finding(
                title: "Run-key persistence: \(value.name)",
                detail: bullets.joined(separator: "\n"),
                severity: severity,
                phase: .installation,
                technique: AttackTechnique(attackID: "T1547.001",
                                            name: "Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder"),
                timestamp: value.lastWritten,
                evidencePaths: [value.fullPath, value.sourceFile])
        }
    }
}
