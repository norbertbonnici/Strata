import Foundation

/// Detection over macOS user-activity / deleted-evidence (`MacActivityItem`).
/// QuickLook previews are investigative context (a file was viewed), so the one
/// detection here is a **trashed payload**: a script / installer / app moved to
/// the Trash is a common clean-up step after execution (Indicator Removal: File
/// Deletion, T1070.004). Aggregated; the QuickLook half just feeds the tab +
/// timeline.
public nonisolated struct MacActivityAnalyzer: Analyzer {
    public let name = "User Activity"
    public init() {}

    /// Risky extensions for a trashed file (a deleted script / installer / app).
    static let riskyExtensions = [
        ".sh", ".command", ".scpt", ".py", ".pl", ".rb", ".jar",
        ".app", ".dmg", ".pkg", ".mpkg", ".term", ".workflow",
    ]

    public func analyze(context: AnalysisContext) -> [Finding] {
        analyze(context.userActivity)
    }

    /// Pure detection entry point — unit-tested directly with fixtures.
    public func analyze(_ items: [MacActivityItem]) -> [Finding] {
        guard !items.isEmpty else { return [] }
        var findings: [Finding] = []
        var seen = Set<String>()
        for item in items where item.kind == .trash {
            let lower = item.path.lowercased()
            guard let ext = Self.riskyExtensions.first(where: { lower.hasSuffix($0) }) else { continue }
            guard seen.insert(lower).inserted else { continue }
            findings.append(Finding(
                title: "Trashed payload: \(item.name)",
                detail: "A \(ext) file was moved to the Trash: \(item.path)."
                    + "\n\nDeleting a script / installer / app after use is a common indicator-removal "
                    + "step; recover it from the Trash and check whether it ran (prefetch / unified log / "
                    + "quarantine).",
                severity: .medium,
                phase: .actionsOnObjectives,
                technique: AttackTechnique(attackID: "T1070.004", name: "Indicator Removal: File Deletion"),
                timestamp: item.timestamp,
                evidencePaths: [item.path, item.sourceFile]))
        }
        return findings
    }
}
