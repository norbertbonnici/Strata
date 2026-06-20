import Foundation

/// Security 1102 (audit log cleared) and System 104 (other log cleared) are
/// almost never benign on a workstation - they're the classic "I was here,
/// let me erase the trail" move. Always surface, always high severity.
///
/// ATT&CK T1070.001 Indicator Removal: Clear Windows Event Logs.
/// Kill-chain phase: Actions on Objectives (treating evidence destruction as
/// a goal in itself; Defense Evasion would also be a defensible mapping.)
public nonisolated struct LogClearedAnalyzer: Analyzer {
    public let name = "Event Log Cleared"
    public init() {}

    public func analyze(context: AnalysisContext) -> [Finding] {
        context.events.compactMap { event -> Finding? in
            let isSecurityClear = event.eventID == 1102
                && event.channel.localizedCaseInsensitiveContains("Security")
            let isSystemClear   = event.eventID == 104
                && event.channel.localizedCaseInsensitiveContains("System")
            guard isSecurityClear || isSystemClear else { return nil }

            let actor = event.data("SubjectUserName")
                ?? event.data("UserData_LogFileCleared_SubjectUserName")
                ?? "unknown user"
            let logName = isSecurityClear ? "Security" : "System"
            return Finding(
                title: "\(logName) event log cleared by \(actor)",
                detail: "Channel '\(event.channel)' on \(event.computer) was cleared at \(event.writtenAt.formatted()). This is the hallmark of an attacker scrubbing evidence after action.",
                severity: .critical,
                phase: .actionsOnObjectives,
                technique: AttackTechnique(attackID: "T1070.001",
                                            name: "Indicator Removal: Clear Windows Event Logs"),
                timestamp: event.writtenAt,
                evidencePaths: [event.sourceFile])
        }
    }
}
