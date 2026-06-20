import Foundation

/// Detection over the macOS **configuration-posture** inventory. Each flagged
/// `MacConfigSetting` (firewall off, Gatekeeper disabled, a remote service
/// enabled, auto-login/guest/hidden accounts, …) becomes one Finding. The
/// per-setting semantics — which value is risky, its ATT&CK technique, its
/// severity — live in `MacConfigParser`; this analyzer is the thin, testable
/// projection that turns those into kill-chain findings.
public nonisolated struct MacConfigAnalyzer: Analyzer {
    public let name = "macOS Configuration"
    public init() {}

    public func analyze(context: AnalysisContext) -> [Finding] {
        analyze(context.config)
    }

    /// Pure entry point (unit-tested with fixtures).
    public func analyze(_ settings: [MacConfigSetting]) -> [Finding] {
        guard !settings.isEmpty else { return [] }
        let flagged = settings.filter { $0.isFlagged }
        let findings = flagged.map { s in
            Finding(
                title: scopePrefix(s) + s.name + ": " + s.value,
                detail: s.interpretation,
                severity: severity(s.risk),
                phase: phase(s.category),
                technique: s.attackID.map { AttackTechnique(attackID: $0, name: s.attackName ?? "") },
                timestamp: nil,
                evidencePaths: [(s.sourceFile as NSString).lastPathComponent])
        }
        return findings.sorted { $0.severity > $1.severity }
    }

    private func scopePrefix(_ s: MacConfigSetting) -> String {
        s.scope == "system" || s.scope.isEmpty ? "" : "[\(s.scope)] "
    }

    private func severity(_ r: MacConfigSetting.Risk) -> Severity {
        switch r {
        case .high: return .high
        case .medium: return .medium
        case .low, .none: return .low
        }
    }

    private func phase(_ c: MacConfigSetting.Category) -> KillChainPhase {
        switch c {
        case .remoteAccess, .sharing:
            return .commandAndControl
        case .loginWindow, .account:
            return .installation
        case .firewall, .screenLock, .softwareUpdate, .gatekeeper, .fileVault:
            return .exploitation
        }
    }
}
