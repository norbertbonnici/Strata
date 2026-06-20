import Foundation

/// Detection over the macOS **KnowledgeC** behavioural store. KnowledgeC is
/// primarily a *context* timeline (which app was used when), but one pattern is
/// high-signal on its own: a **remote-access / RMM / screen-sharing tool that
/// was actually in focus** — i.e. someone was hands-on-keyboard driving the
/// machine through it, with a precise timestamp. This complements the
/// file-based `RMMToolAnalyzer` (which flags *presence*) by showing *usage*.
public nonisolated struct KnowledgeCAnalyzer: Analyzer {
    public let name = "KnowledgeC"
    public init() {}

    /// Substrings of bundle ids for remote-control / screen-sharing software.
    static let remoteAccessHints = [
        "teamviewer", "anydesk", "screenconnect", "connectwise", "splashtop",
        "logmein", "gotomypc", "rustdesk", "ammyy", "realvnc", "tightvnc",
        "vnc", "screensharing", "remotedesktop", "ardagent", "supremo",
        "zoho.assist", "dwservice", "remoteutilities",
    ]

    public func analyze(context: AnalysisContext) -> [Finding] {
        guard !context.knowledgeC.isEmpty else { return [] }
        var findings: [Finding] = []

        struct Agg { var count = 0; var first: Date?; var last: Date? }
        var byApp: [String: Agg] = [:]

        for e in context.knowledgeC {
            guard e.category == .appFocus || e.category == .appUsage || e.category == .appActivity,
                  let bundle = e.value?.lowercased(),
                  Self.remoteAccessHints.contains(where: { bundle.contains($0) }) else { continue }
            var agg = byApp[bundle] ?? Agg()
            agg.count += 1
            if let t = e.startDate {
                if agg.first == nil || t < agg.first! { agg.first = t }
                if agg.last == nil || t > agg.last! { agg.last = t }
            }
            byApp[bundle] = agg
        }

        for (bundle, agg) in byApp {
            let span = (agg.first != nil && agg.last != nil)
                ? " between \(Self.fmt(agg.first!)) and \(Self.fmt(agg.last!))" : ""
            findings.append(Finding(
                title: "Remote-access app in active use: \(bundle)",
                detail: "KnowledgeC recorded \(bundle) in focus/use \(agg.count) time(s)\(span). "
                    + "Active use of remote-control software places an operator hands-on-keyboard; "
                    + "correlate with the login/network timeline.",
                severity: .high, phase: .commandAndControl,
                technique: AttackTechnique(attackID: "T1219", name: "Remote Access Software"),
                timestamp: agg.last, evidencePaths: ["knowledgeC.db"]))
        }
        return findings
    }

    private static func fmt(_ d: Date) -> String {
        d.formatted(date: .abbreviated, time: .standard)
    }
}
