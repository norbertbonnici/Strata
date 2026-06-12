import Foundation

/// Detection over the macOS **FSEvents** change history (`[FSEventRecord]`).
///
/// FSEvents coalesces per-path change reasons, so a single record can record a
/// file that was Created **and** Removed between flushes - the classic
/// anti-forensic "drop, run, delete" footprint (T1070.004). It also captures
/// writes into the launchd persistence directories even when the dropped plist
/// is long gone (T1543). FSEvents has no per-record timestamp, so findings are
/// presence-based, not time-anchored, and are aggregated so a busy store yields
/// one finding per indicator.
public nonisolated struct FSEventsAnalyzer: Analyzer {
    public let name = "macOS FSEvents"
    public init() {}

    /// Path fragments marking a non-standard staging / drop location.
    private static let stagingPaths = [
        "/tmp/", "/private/tmp/", "/var/tmp/", "/private/var/tmp/",
        "/users/shared/", "/library/caches/", "/.trash/",
    ]

    /// Executable / payload extensions that matter when created-then-removed.
    private static let payloadExtensions: Set<String> = [
        "sh", "bash", "zsh", "py", "pl", "rb", "command", "scpt", "app",
        "dylib", "so", "pkg", "dmg", "jar", "plist",
    ]

    /// launchd persistence directories - a write here is a persistence tell.
    /// (Matched against the leading-slash-normalised path; FSEvents paths are
    /// volume-root-relative and carry no leading slash of their own.)
    private static let launchdDirs = [
        "/library/launchagents/", "/library/launchdaemons/",
    ]

    public func analyze(context: AnalysisContext) -> [Finding] {
        analyze(context.fsEvents)
    }

    /// Core detection over parsed FSEvents records. Pure; unit-tested.
    public func analyze(_ records: [FSEventRecord]) -> [Finding] {
        guard !records.isEmpty else { return [] }
        var findings: [Finding] = []
        findings += createdThenRemovedFindings(records)
        findings += launchdWriteFindings(records)
        return findings
    }

    // MARK: - Rule 1: created-then-removed payload in a staging path

    private func createdThenRemovedFindings(_ records: [FSEventRecord]) -> [Finding] {
        var hits: [FSEventRecord] = []
        for r in records where r.wasCreated && r.wasRemoved {
            // Normalise to a leading slash: FSEvents paths are volume-root-
            // relative, so "Users/.." has no leading "/" the fragments expect.
            let lower = "/" + r.path.lowercased()
            guard Self.isStagingPath(lower) || Self.hasPayloadExtension(lower) else { continue }
            hits.append(r)
        }
        guard !hits.isEmpty else { return [] }
        let sample = hits.prefix(8).map { $0.path }.joined(separator: "\n")
        var detail = "FSEvents recorded \(hits.count) path(s) that were both created and removed - the drop-run-delete footprint of a payload that cleaned up after itself (T1070.004). FSEvents has no timestamp, so this proves the churn, not its time.\n\(sample)"
        if hits.count > 8 { detail += "\n…and \(hits.count - 8) more." }
        return [Finding(
            title: "FSEvents: files created then deleted (\(hits.count))",
            detail: detail,
            severity: .high,
            phase: .actionsOnObjectives,
            technique: AttackTechnique(attackID: "T1070.004", name: "Indicator Removal: File Deletion"),
            timestamp: nil,
            evidencePaths: Array(hits.prefix(8).map { $0.sourceFile }))]
    }

    // MARK: - Rule 2: writes into the launchd persistence directories

    private func launchdWriteFindings(_ records: [FSEventRecord]) -> [Finding] {
        var hits: [FSEventRecord] = []
        for r in records {
            let lower = "/" + r.path.lowercased()
            guard Self.launchdDirs.contains(where: { lower.contains($0) }) else { continue }
            // Only the .plist itself, and only when actually created/modified.
            guard lower.hasSuffix(".plist"), r.wasCreated || r.wasModified || r.wasRenamed else { continue }
            hits.append(r)
        }
        guard !hits.isEmpty else { return [] }
        let sample = hits.prefix(8).map { $0.path }.joined(separator: "\n")
        var detail = "FSEvents recorded \(hits.count) launchd job plist(s) created or modified under LaunchAgents / LaunchDaemons - a persistence install, recoverable from FSEvents even if the plist was later removed (T1543).\n\(sample)"
        if hits.count > 8 { detail += "\n…and \(hits.count - 8) more." }
        return [Finding(
            title: "FSEvents: launchd persistence write (\(hits.count))",
            detail: detail,
            severity: .medium,
            phase: .installation,
            technique: AttackTechnique(attackID: "T1543", name: "Create or Modify System Process"),
            timestamp: nil,
            evidencePaths: Array(hits.prefix(8).map { $0.sourceFile }))]
    }

    // MARK: - Helpers

    static func isStagingPath(_ lower: String) -> Bool {
        if lower.contains("/.") { return true }
        return stagingPaths.contains { lower.contains($0) }
    }

    static func hasPayloadExtension(_ lower: String) -> Bool {
        let leaf = lower.split(separator: "/").last.map(String.init) ?? lower
        guard let dot = leaf.lastIndex(of: "."), dot != leaf.startIndex else { return false }
        return payloadExtensions.contains(String(leaf[leaf.index(after: dot)...]))
    }
}
