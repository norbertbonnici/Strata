import Foundation

/// Detection over macOS **network / device** context. Most of this set (Wi-Fi,
/// DHCP, Bluetooth, pairings) is investigative context, not detection — so this
/// runs one high-precision rule: a **Time Machine backup to a network
/// destination**. A networked backup replicates host data off-box, so it's a
/// data-egress / recovery vector worth confirming (and a raw-IP target is more
/// anomalous than a named NAS). Maps to T1074 (Data Staged).
public nonisolated struct MacNetworkAnalyzer: Analyzer {
    public let name = "Network & Devices"
    public init() {}

    public func analyze(context: AnalysisContext) -> [Finding] {
        analyze(context.network)
    }

    /// Pure detection entry point — unit-tested directly with fixtures.
    public func analyze(_ items: [MacNetworkItem]) -> [Finding] {
        guard !items.isEmpty else { return [] }
        return items.compactMap { item in
            // identifier carries the NetworkURL only for networked destinations.
            guard item.kind == .timeMachine, let url = item.identifier, !url.isEmpty else { return nil }
            let host = BrowserHistoryEntry.host(ofURL: url) ?? url
            let rawIP = MacMessagesAnalyzer.isRawIPv4(host)
            return Finding(
                title: "Time Machine backup to a network destination: \(host)",
                detail: "This host backs up over the network to \(url)."
                    + (rawIP ? " The target is a raw IP address." : "")
                    + "\n\nA networked Time Machine destination replicates host data off-box; confirm the "
                    + "target is authorised and treat it as a data-recovery / exfil vector.",
                severity: rawIP ? .high : .medium,
                phase: .actionsOnObjectives,
                technique: AttackTechnique(attackID: "T1074", name: "Data Staged"),
                timestamp: item.timestamp,
                evidencePaths: [item.sourceFile])
        }
    }
}
