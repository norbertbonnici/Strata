import Foundation

/// Detection over the macOS **kernel- / system-extension** inventory. Apple ships
/// many first-party extensions; the signal is a **non-Apple** one, because it
/// loads third-party code into a privileged context — the classic macOS rootkit /
/// persistence vector (ATT&CK T1547.006 Boot or Logon Autostart Execution: Kernel
/// Modules and Extensions).
///
/// A plain `.kext` runs in the **kernel**, so a third-party one is **high**; a
/// modern System Extension runs in user space (DriverKit / Network /
/// Endpoint-Security) and is more often a legitimate product, so it's **medium** —
/// but still worth confirming, and a disabled/terminated one can indicate an
/// install that was blocked or tampered with.
public nonisolated struct MacKextAnalyzer: Analyzer {
    public let name = "Kernel & System Extensions"
    public init() {}

    public func analyze(context: AnalysisContext) -> [Finding] {
        analyze(context.kexts)
    }

    /// Pure detection entry point — unit-tested directly with fixtures.
    public func analyze(_ entries: [MacKextEntry]) -> [Finding] {
        guard !entries.isEmpty else { return [] }
        var findings: [Finding] = []
        var seen = Set<String>()
        for e in entries where !e.isApple {
            let key = "\(e.bundleID)|\(e.path ?? "")"
            guard seen.insert(key).inserted else { continue }
            let isKernel = e.kind == .kext
            var detail = "\(e.kind.label) \(e.bundleID)"
            if let v = e.version { detail += " (v\(v))" }
            detail += " is not Apple-signed."
            if let t = e.teamID, !t.isEmpty { detail += "\nTeam ID: \(t)." }
            if let p = e.path { detail += "\nPath: \(p)." }
            if let enabled = e.enabled { detail += "\nState: \(enabled ? "enabled" : "disabled / not activated")." }
            detail += isKernel
                ? "\nA third-party kernel extension runs in the kernel — a high-impact persistence "
                    + "and rootkit vector. Verify the vendor and that it's expected on this host."
                : "\nA third-party system extension loads privileged code (DriverKit / Network / "
                    + "Endpoint Security). Confirm the product is authorised."
            findings.append(Finding(
                title: "Third-party \(e.kind.label.lowercased()): \(e.title)",
                detail: detail,
                severity: isKernel ? .high : .medium,
                phase: .installation,
                technique: AttackTechnique(attackID: "T1547.006",
                                           name: "Boot or Logon Autostart Execution: Kernel Modules and Extensions"),
                timestamp: nil,
                evidencePaths: [e.path, e.sourceFile].compactMap { $0 }))
        }
        return findings
    }
}
