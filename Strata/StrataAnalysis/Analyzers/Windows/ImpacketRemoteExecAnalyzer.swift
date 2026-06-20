import Foundation

/// Impacket's remote-execution scripts (psexec.py, smbexec.py, wmiexec.py,
/// dcomexec.py, atexec.py) leave distinctive fingerprints that don't appear
/// in legitimate admin tooling: hardcoded service names, stdout/stderr
/// redirected to \\127.0.0.1\ADMIN$ or \C$, and `cmd.exe /Q /c ... 2>&1`
/// wrappers. We match 10 such signatures across Security 4688, Security
/// 7045 / 4697 (service install), and Sysmon 1.
///
/// ATT&CK T1569.002 System Services: Service Execution.
/// Kill-chain phase: Exploitation.
public nonisolated struct ImpacketRemoteExecAnalyzer: Analyzer {
    public let name = "Impacket Remote Execution"
    public init() {}

    /// (label, lowercased substring). The first match per event wins.
    private static let signatures: [(label: String, token: String)] = [
        ("psexec.py service name (RemComSvc)",   "remcomsvc"),
        ("psexec service name (PSEXESVC)",        "psexesvc"),
        ("smbexec.py service name (BTOBTO)",      "btobto"),
        ("Impacket stdout redirect to ADMIN$",    "\\admin$\\__"),
        ("smbexec.py output file on C$",          "\\c$\\__output"),
        ("Impacket loopback redirect",            "1> \\\\127.0.0.1\\"),
        ("Impacket cmd /Q /c wrapper",            "cmd.exe /q /c "),
        ("Impacket cmd /Q /c wrapper (short)",    "cmd /q /c "),
        ("smbexec.py %COMSPEC% wrapper",          "%comspec% /q /c "),
        ("Impacket atexec output file pattern",   "\\temp\\__"),
    ]

    /// Tokens distinctive enough to fire on their own. The /Q /c and
    /// %COMSPEC% wrappers also need 2>&1 nearby to suppress false positives
    /// from benign scripts.
    private static let standaloneTokens: Set<String> = [
        "remcomsvc", "psexesvc", "btobto",
        "\\admin$\\__", "\\c$\\__output", "1> \\\\127.0.0.1\\", "\\temp\\__",
    ]

    public func analyze(context: AnalysisContext) -> [Finding] {
        context.events.compactMap { event -> Finding? in
            guard let haystack = haystack(for: event) else { return nil }
            let lowered = haystack.lowercased()
            let hasStderrRedirect = lowered.contains("2>&1")

            for sig in Self.signatures where lowered.contains(sig.token) {
                let confirmed = Self.standaloneTokens.contains(sig.token) || hasStderrRedirect
                guard confirmed else { continue }
                return Finding(
                    title: "Impacket remote-execution signature on \(event.computer): \(sig.label)",
                    detail: """
                    EID \(event.eventID) on \(event.computer) at \(event.writtenAt.formatted()) matched: \(sig.label).
                    Token: \(sig.token)
                    Payload excerpt: \(String(haystack.prefix(300)))
                    """,
                    severity: .critical,
                    phase: .exploitation,
                    technique: AttackTechnique(attackID: "T1569.002",
                                                name: "System Services: Service Execution"),
                    timestamp: event.writtenAt,
                    evidencePaths: [event.sourceFile])
            }
            return nil
        }
    }

    /// Concatenate every field Impacket might write into for this event type
    /// so we can match against a single string.
    private func haystack(for event: EventLogRecord) -> String? {
        switch event.eventID {
        case 4688:
            let img = event.data("NewProcessName") ?? ""
            let cmd = event.data("CommandLine") ?? event.data("ProcessCommandLine") ?? ""
            return img.isEmpty && cmd.isEmpty ? nil : img + " " + cmd
        case 1 where event.channel.localizedCaseInsensitiveContains("Sysmon"):
            let img = event.data("Image") ?? ""
            let cmd = event.data("CommandLine") ?? ""
            return img.isEmpty && cmd.isEmpty ? nil : img + " " + cmd
        case 7045:
            let name = event.data("ServiceName") ?? ""
            let path = event.data("ImagePath") ?? ""
            return name.isEmpty && path.isEmpty ? nil : name + " " + path
        case 4697:
            let name = event.data("ServiceName") ?? ""
            let path = event.data("ServiceFileName") ?? ""
            return name.isEmpty && path.isEmpty ? nil : name + " " + path
        default:
            return nil
        }
    }
}
