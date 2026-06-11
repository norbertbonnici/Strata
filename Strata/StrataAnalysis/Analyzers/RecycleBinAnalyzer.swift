import Foundation

/// Detection over recovered Windows `$Recycle.Bin` (`$I` index) entries.
///
/// The Recycle Bin is where an operator's "I deleted my tools" cleanup lands:
/// the `$I` record preserves the original path, size, and deletion time even
/// after the file is gone. Two high-signal rules, kept low-noise like
/// `UsnAnalyzer`:
///  1. **Deleted executable/script** — surfaces the deletion of a payload; HIGH
///     when it sat in a suspicious staging path, MEDIUM otherwise.
///  2. **Mass-deletion burst** — many files deleted in a short window (wiping /
///     cleanup), surfaced as one aggregate finding.
///
/// NOTE: `AnalysisContext` has no `recycleBin` field yet, so the protocol
/// entrypoint feeds `[]`. The integrator wires the real source (see the module
/// review's integration notes); the analysis lives in `analyze(_:)`, tested
/// directly.
public nonisolated struct RecycleBinAnalyzer: Analyzer {
    public let name = "Recycle Bin"
    public init() {}

    // Executable / script family — same bracket as UsnAnalyzer, widened with the
    // installer/archive-script extensions that show up in deletion cleanup.
    private static let exeExtensions: Set<String> = [
        "exe", "dll", "ps1", "bat", "cmd", "vbs", "vbe", "js", "jse", "scr", "hta",
        "wsf", "com", "msi", "ps1xml", "jar",
    ]

    // Lowercased substrings (backslashes normalized) marking a suspicious staging
    // location. The `$recycle` entry catches recursive deletion of a whole tree.
    private static let suspiciousPathTokens: [String] = [
        "\\temp\\", "\\tmp\\", "\\appdata\\local\\temp", "\\users\\public\\",
        "\\downloads\\", "\\windows\\temp\\", "\\programdata\\", "c:\\$recycle",
        "\\perflogs\\",
    ]

    private static let burstThreshold = 25       // entries within the window
    private static let burstWindow: TimeInterval = 300   // 5 minutes
    private static let burstHighThreshold = 100  // escalate to .high

    public func analyze(context: AnalysisContext) -> [Finding] {
        // AnalysisContext has no recycleBin field yet — integrator wires it.
        analyze([])
    }

    /// Real detection logic — test this directly.
    func analyze(_ entries: [RecycleBinEntry]) -> [Finding] {
        guard !entries.isEmpty else { return [] }
        var findings: [Finding] = []

        // Rule 1: deleted executable / script.
        for e in entries where Self.exeExtensions.contains(e.fileExtension) {
            let suspicious = Self.isSuspiciousPath(e.originalPath)
            findings.append(Finding(
                title: "Deleted executable in Recycle Bin: \(e.fileName)",
                detail: "An executable/script was deleted to the Recycle Bin"
                    + (suspicious ? " from a suspicious staging path" : "")
                    + " — possible indicator removal.\nOriginal path: \(e.originalPath)"
                    + (e.sid.map { "\nUser SID: \($0)" } ?? "")
                    + (e.deletedAt.map { "\nDeleted: \($0.ISO8601Format())" } ?? ""),
                severity: suspicious ? .high : .medium,
                phase: .actionsOnObjectives,
                technique: AttackTechnique(attackID: "T1070.004", name: "Indicator Removal: File Deletion"),
                timestamp: e.deletedAt,
                evidencePaths: [e.originalPath, e.sourceFile]))
        }

        // Rule 2: mass-deletion burst (one aggregate finding).
        if let burst = Self.findBurst(entries) {
            let span = "\(burst.first.ISO8601Format()) → \(burst.last.ISO8601Format())"
            findings.append(Finding(
                title: "Mass file deletion (Recycle Bin): \(burst.count) deletes",
                detail: "\(burst.count) files were deleted to the Recycle Bin within a "
                    + "\(Int(Self.burstWindow / 60))-minute window — possible wiping or cleanup.\nSpan: \(span)",
                severity: burst.count >= Self.burstHighThreshold ? .high : .medium,
                phase: .actionsOnObjectives,
                technique: AttackTechnique(attackID: "T1070.004", name: "Indicator Removal: File Deletion"),
                timestamp: burst.last,
                evidencePaths: [burst.sourceFile]))
        }

        return findings
    }

    // MARK: - Helpers (pure)

    private static func isSuspiciousPath(_ path: String) -> Bool {
        let p = path.replacingOccurrences(of: "/", with: "\\").lowercased()
        return suspiciousPathTokens.contains { p.contains($0) }
    }

    private struct Burst { let count: Int; let first: Date; let last: Date; let sourceFile: String }

    /// Find any 300-second sliding window holding >= `burstThreshold` deletions.
    /// Returns the *largest* such window (max entries inside any 300s span).
    private static func findBurst(_ entries: [RecycleBinEntry]) -> Burst? {
        let dated = entries.compactMap { e -> (Date, String)? in
            e.deletedAt.map { ($0, e.sourceFile) }
        }.sorted { $0.0 < $1.0 }
        guard dated.count >= burstThreshold else { return nil }

        var best: Burst?
        var start = 0
        for end in dated.indices {
            while dated[end].0.timeIntervalSince(dated[start].0) > burstWindow {
                start += 1
            }
            let count = end - start + 1
            if count >= burstThreshold, count > (best?.count ?? 0) {
                best = Burst(count: count,
                             first: dated[start].0,
                             last: dated[end].0,
                             sourceFile: dated[start].1.isEmpty ? "$Recycle.Bin" : dated[start].1)
            }
        }
        return best
    }
}
