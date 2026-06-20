import Foundation

/// Microsoft-Windows-PowerShell/Operational event ID 4104 = ScriptBlock
/// logging. The payload holds the literal script text PowerShell saw, even
/// when the caller passed it base64-encoded - PowerShell decodes first, logs
/// second. Hits on FromBase64String / IEX / DownloadString are the classic
/// "live-off-the-land" download-and-execute pattern.
///
/// ATT&CK T1059.001 Command and Scripting Interpreter: PowerShell.
/// Kill-chain phase: Exploitation.
public nonisolated struct PowerShellAnalyzer: Analyzer {
    public let name = "Suspicious PowerShell"
    public init() {}

    private static let highRiskTokens = [
        "frombase64string", "downloadstring", "downloadfile", "downloaddata",
        "invoke-expression", " iex ", "iex(", "iex (",
        "-encodedcommand", "-enc ", "-e jab",  // -e <base64 starting with 'JAB' is a PS1 string literal
        "invoke-webrequest", "net.webclient", "system.net.webclient",
        "bitstransfer", "start-bitstransfer",
    ]
    private static let evasionTokens = [
        "-nop", "-noprofile", "-w hidden", "-windowstyle hidden",
        "-executionpolicy bypass", "-ep bypass", "bypass",
    ]

    public func analyze(context: AnalysisContext) -> [Finding] {
        context.events.compactMap { event -> Finding? in
            guard event.eventID == 4104,
                  event.channel.localizedCaseInsensitiveContains("PowerShell")
            else { return nil }

            // 4104 payload has <Data Name="ScriptBlockText">...</Data>.
            // For sufficiently large blocks PowerShell splits across multiple
            // events; we keep them independent here since each chunk is still
            // useful on its own.
            let script = (event.data("ScriptBlockText") ?? "").lowercased()
            guard !script.isEmpty else { return nil }

            let highHits = Self.highRiskTokens.filter { script.contains($0) }
            let evasionHits = Self.evasionTokens.filter { script.contains($0) }
            guard !highHits.isEmpty || evasionHits.count >= 2 else { return nil }

            let severity: Severity = highHits.isEmpty ? .medium
                : (highHits.count + evasionHits.count >= 3 ? .critical : .high)

            let snippet = String(script.prefix(220))
                .replacingOccurrences(of: "\n", with: " ")
            let reasons = (highHits + evasionHits).prefix(6).joined(separator: ", ")
            return Finding(
                title: "Suspicious PowerShell scriptblock (\(reasons))",
                detail: "ScriptBlock #\(event.recordNumber) on \(event.computer) contained: \(reasons).\n\nSnippet: \(snippet)...",
                severity: severity,
                phase: .exploitation,
                technique: AttackTechnique(attackID: "T1059.001",
                                            name: "Command and Scripting Interpreter: PowerShell"),
                timestamp: event.writtenAt,
                evidencePaths: [event.sourceFile])
        }
    }
}
