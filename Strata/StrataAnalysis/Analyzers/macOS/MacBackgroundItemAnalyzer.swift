import Foundation

/// Detection over the macOS **Background Task Management** inventory (`.btm`).
/// BTM is the modern record of every registered login item / launch agent /
/// daemon, so it surfaces persistence the raw launchd-plist sweep can miss. The
/// signal is a **non-Apple** background item — **high** when its executable sits
/// in a staging / user-writable path (a dropped payload registering itself),
/// otherwise **medium**. A disabled item is still reported (it may be staged but
/// not yet active, or toggled off to evade) with that noted in the detail.
public nonisolated struct MacBackgroundItemAnalyzer: Analyzer {
    public let name = "Background Items (BTM)"
    public init() {}

    static let stagingTokens = [
        "/tmp/", "/private/tmp/", "/var/tmp/", "/private/var/tmp/",
        "/users/shared/", "/private/var/folders/", "/.", "/library/caches/",
    ]

    public func analyze(context: AnalysisContext) -> [Finding] {
        analyze(context.backgroundItems)
    }

    /// Pure detection entry point — unit-tested directly with fixtures.
    public func analyze(_ items: [MacBackgroundItem]) -> [Finding] {
        guard !items.isEmpty else { return [] }
        var findings: [Finding] = []
        var seen = Set<String>()
        for item in items where !item.isApple {
            let key = "\(item.bundleID ?? "")|\(item.executable ?? "")|\(item.name)"
            guard seen.insert(key).inserted else { continue }
            let exec = (item.executable ?? "").lowercased()
            let staging = !exec.isEmpty && Self.stagingTokens.contains { exec.contains($0) }

            var detail = "BTM registered a non-Apple background item: \(item.title)."
            if let b = item.bundleID { detail += "\nBundle ID: \(b)." }
            if let e = item.executable { detail += "\nExecutable: \(e)." }
            if let d = item.developerName, !d.isEmpty { detail += "\nDeveloper: \(d)." }
            if let t = item.teamID, !t.isEmpty { detail += "\nTeam ID: \(t)." }
            detail += "\nType: \(item.typeLabel)."
            if let enabled = item.enabled { detail += "\nState: \(enabled ? "enabled" : "disabled / not active")." }
            detail += staging
                ? "\nThe executable is in a staging / user-writable path — consistent with a dropped "
                    + "payload registering itself for persistence."
                : "\nConfirm this background item is expected; it persists across logins/reboots."

            findings.append(Finding(
                title: staging
                    ? "Background item from staging path: \(item.title)"
                    : "Non-Apple background item: \(item.title)",
                detail: detail,
                severity: staging ? .high : .medium,
                phase: .installation,
                technique: AttackTechnique(attackID: "T1547.015",
                                           name: "Boot or Logon Autostart Execution: Login Items"),
                timestamp: nil,
                evidencePaths: [item.executable, item.sourceFile].compactMap { $0 }))
        }
        return findings
    }
}
