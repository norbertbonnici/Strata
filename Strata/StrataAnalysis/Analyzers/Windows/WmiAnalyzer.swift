import Foundation

/// Detection over carved WMI event-subscription persistence (T1546.003).
///
/// A WMI event subscription that isn't one of Windows' built-ins is worth a look
/// (the persistence is rare and identifiable), but some management software
/// (SCCM/ConfigMgr, monitoring agents) legitimately uses it — so a plain
/// non-built-in binding is **low** (surfaced for review), escalated to **high**
/// only when its consumer runs a script or its command / query carries an
/// attacker tell (encoded PowerShell, a LOLBin, a tool name). Script payloads
/// carved out of the repository (e.g. an `Invoke-Mimikatz` `ActiveScriptEventConsumer`)
/// are reported high on their own.
public nonisolated struct WmiAnalyzer: Analyzer {
    public let name = "WMI Persistence"
    public init() {}

    private static let suspiciousTokens = [
        "powershell", "-enc", "-encodedcommand", "frombase64string", "downloadstring",
        "downloadfile", "iex", "invoke-", "mimikatz", "reflectivepe", "bitsadmin",
        "certutil", "rundll32", "regsvr32", "mshta", "wscript", "cscript",
        "cmd.exe /c", "cmd /c", #"\temp\"#, #"\appdata\"#, #"\programdata\"#, "scrcons",
    ]

    public func analyze(context: AnalysisContext) -> [Finding] {
        guard !context.wmi.isEmpty else { return [] }
        var findings: [Finding] = []
        for e in context.wmi {
            switch e.kind {
            case .binding:
                guard !e.isCommonBenign else { continue }   // skip built-in BVT/SCM
                let hay = "\(e.command ?? "") \(e.query ?? "") \(e.consumerName ?? "")".lowercased()
                let isScript = e.consumerType == "ActiveScriptEventConsumer"
                let tell = Self.suspiciousTokens.first(where: { hay.contains($0) })
                let severity: Severity = (isScript || tell != nil) ? .high : .low

                var detail = "A WMI event subscription persists across reboots: filter "
                    + "\"\(e.filterName ?? "?")\" → consumer \"\(e.consumerName ?? "?")\" (\(e.consumerType ?? "?"))."
                if let q = e.query, !q.isEmpty { detail += "\nTrigger (WQL): \(q)" }
                if let c = e.command, !c.isEmpty { detail += "\nRuns: \(c)" }
                if isScript { detail += "\nConsumer executes a script — almost always malicious in a subscription." }
                else if let tell { detail += "\nCommand/trigger contains a suspicious indicator (\(tell))." }
                detail += "\nLegitimate software rarely uses WMI subscriptions for persistence (T1546.003)."

                findings.append(Finding(
                    title: "WMI persistence: \(e.consumerName ?? "?") ← \(e.filterName ?? "?")",
                    detail: detail,
                    severity: severity,
                    phase: .installation,
                    technique: AttackTechnique(attackID: "T1546.003",
                                               name: "Event Triggered Execution: WMI Event Subscription"),
                    evidencePaths: [e.command, e.sourceFile].compactMap { $0 }.filter { !$0.isEmpty }))

            case .scriptConsumer:
                let head = (e.scriptText ?? "").prefix(300)
                findings.append(Finding(
                    title: "WMI script consumer payload (\(e.scriptEngine ?? "script"))",
                    detail: "A script payload was carved from the WMI repository — an "
                        + "\(e.scriptEngine ?? "script") `ActiveScriptEventConsumer`, the body of a WMI "
                        + "event-subscription persistence (T1546.003):\n\(head)",
                    severity: .high,
                    phase: .installation,
                    technique: AttackTechnique(attackID: "T1546.003",
                                               name: "Event Triggered Execution: WMI Event Subscription"),
                    evidencePaths: [e.sourceFile]))
            }
        }
        return findings
    }
}
