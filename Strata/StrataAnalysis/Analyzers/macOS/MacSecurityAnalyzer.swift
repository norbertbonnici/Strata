import Foundation

/// Detection over durable macOS **security telemetry** — Gatekeeper / syspolicyd
/// assessments, XProtect signature hits, XProtect Remediator scans, and MRT
/// removals (`[MacSecurityEvent]`). These logs are Apple's own record of
/// malicious code on the host and of attempts to subvert the trust controls that
/// gate it, so they are a high-value, low-volume source. The rules, aggregated
/// per subject so a chatty log yields one finding per indicator (mirroring
/// `MacQuarantineAnalyzer`):
///
///  1. **Malware detected / remediated** — XProtect / XProtect Remediator / MRT
///     reported (and possibly removed) a known-malicious file. The strongest
///     signal in this set: known-bad code was resident on the host
///     (T1204.002 User Execution: Malicious File). **High.**
///  2. **Trust override (allow-after-block)** — a binary Gatekeeper/XProtect once
///     blocked or flagged was *later allowed* to run. That is a deliberate
///     override of a security decision (right-click-Open, re-signing, or
///     stripping the quarantine attribute) — T1553.001 Gatekeeper Bypass. **High.**
///  3. **Security control disabled** — a message indicating Gatekeeper / XProtect
///     assessment was switched off (`spctl --master-disable`, "assessments
///     disabled") — T1562.001 Impair Defenses. **High.**
///  4. **Policy block of untrusted code** — Gatekeeper/syspolicyd denied an
///     unsigned / unnotarized / rejected binary (**medium**); the *same* binary
///     failing repeatedly escalates to a **high** "repeated policy failures"
///     finding — T1553.001 Gatekeeper Bypass attempt.
public nonisolated struct MacSecurityAnalyzer: Analyzer {
    public let name = "macOS Security"
    public init() {}

    /// A binary failing Gatekeeper/policy this many times (or more) is treated as
    /// a *repeated* policy failure and escalated from medium to high.
    static let repeatedFailureThreshold = 5

    /// Message substrings that indicate a trust control was switched off.
    static let disableHints: [String] = [
        "master-disable", "master disable", "assessments disabled",
        "assessment disabled", "gatekeeper disabled", "disabling gatekeeper",
        "xprotect disabled", "globaldisable", "security assessment disabled",
    ]

    public func analyze(context: AnalysisContext) -> [Finding] {
        analyze(context.macSecurityEvents)
    }

    /// Pure detection entry point over parsed security events — unit-tested
    /// directly with fixtures.
    public func analyze(_ events: [MacSecurityEvent]) -> [Finding] {
        guard !events.isEmpty else { return [] }
        var findings: [Finding] = []
        findings += malwareFindings(events)
        let overrides = trustOverrideFindings(events)
        findings += overrides.findings
        findings += disabledControlFindings(events)
        findings += policyBlockFindings(events, excluding: overrides.subjects)
        return findings
    }

    // MARK: - Rule 1: malware detected / remediated

    private struct MalwareAgg {
        var count = 0
        var last: Date?
        var kind: MacSecurityEvent.Kind = .other
        var detected = false
        var remediated = false
        var path: String?
        var signature: String?
        var sources: Set<String> = []
    }

    private func malwareFindings(_ events: [MacSecurityEvent]) -> [Finding] {
        var bySubject: [String: MalwareAgg] = [:]
        for e in events {
            guard e.severity == .detected || e.severity == .remediated else { continue }
            var agg = bySubject[subjectKey(e)] ?? MalwareAgg()
            agg.count += 1
            agg.kind = e.kind
            if e.severity == .detected { agg.detected = true }
            if e.severity == .remediated { agg.remediated = true }
            if agg.path == nil { agg.path = e.path }
            if agg.signature == nil { agg.signature = e.signature }
            agg.sources.insert(e.sourceFile)
            if let t = e.timestamp, t > (agg.last ?? .distantPast) { agg.last = t }
            bySubject[subjectKey(e)] = agg
        }
        return bySubject.map { (key, agg) in
            let subject = agg.signature ?? agg.path ?? key
            let verb = agg.remediated && agg.detected ? "detected and remediated"
                : agg.remediated ? "remediated" : "detected"
            let noun = agg.remediated ? "remediation" : "detection"
            var detail = "\(agg.kind.label) \(verb) malicious code: \(subject)."
            if let p = agg.path, p != subject { detail += "\nPath: \(p)" }
            if agg.count > 1 { detail += "\nSeen \(agg.count) times." }
            detail += "\nA malware \(noun) means known-bad code was present on this host; "
                + "scope the infection and confirm the remediation was complete."
            return Finding(
                title: "\(agg.kind.label) malware \(noun): \(subject)",
                detail: detail,
                severity: .high,
                phase: .installation,
                technique: AttackTechnique(attackID: "T1204.002", name: "User Execution: Malicious File"),
                timestamp: agg.last,
                evidencePaths: evidencePaths(path: agg.path, sources: agg.sources))
        }
    }

    // MARK: - Rule 2: trust override (allow-after-block)

    private struct OverrideAgg {
        var blocked = false
        var allowed = false
        var earliestBlock: Date?
        var latestAllow: Date?
        var blockKind: MacSecurityEvent.Kind = .other
        var path: String?
        var signature: String?
        var sources: Set<String> = []
    }

    private func trustOverrideFindings(_ events: [MacSecurityEvent]) -> (findings: [Finding], subjects: Set<String>) {
        var bySubject: [String: OverrideAgg] = [:]
        for e in events {
            // Only subjects with a stable identity (path or signature) can be
            // correlated across a block and a later allow.
            guard let key = stableSubjectKey(e) else { continue }
            var agg = bySubject[key] ?? OverrideAgg()
            switch e.severity {
            case .blocked, .detected:
                agg.blocked = true
                agg.blockKind = e.kind
                if let t = e.timestamp, t < (agg.earliestBlock ?? .distantFuture) { agg.earliestBlock = t }
            case .allowed:
                agg.allowed = true
                if let t = e.timestamp, t > (agg.latestAllow ?? .distantPast) { agg.latestAllow = t }
            default:
                break
            }
            if agg.path == nil { agg.path = e.path }
            if agg.signature == nil { agg.signature = e.signature }
            agg.sources.insert(e.sourceFile)
            bySubject[key] = agg
        }
        var findings: [Finding] = []
        var subjects: Set<String> = []
        for (key, agg) in bySubject {
            guard agg.blocked, agg.allowed else { continue }
            // When both timestamps are known, require the allow to be at or after
            // the block — an earlier approval is not an override.
            if let b = agg.earliestBlock, let a = agg.latestAllow, a < b { continue }
            subjects.insert(key)
            let subject = agg.signature ?? agg.path ?? key
            var detail = "\(agg.blockKind.label) previously blocked or flagged \(subject), "
                + "but it was later allowed to run."
            detail += "\nThis is a deliberate override of a security decision (e.g. right-click-Open, "
                + "re-signing, or removing the quarantine attribute)."
            if let a = agg.latestAllow { detail += "\nAllowed at: \(Self.fmt(a))." }
            detail += "\nTreat the binary as untrusted and verify who approved it."
            findings.append(Finding(
                title: "Trust control overridden after block: \(subject)",
                detail: detail,
                severity: .high,
                phase: .exploitation,
                technique: AttackTechnique(attackID: "T1553.001", name: "Subvert Trust Controls: Gatekeeper Bypass"),
                timestamp: agg.latestAllow ?? agg.earliestBlock,
                evidencePaths: evidencePaths(path: agg.path, sources: agg.sources)))
        }
        return (findings, subjects)
    }

    // MARK: - Rule 3: security control disabled

    private func disabledControlFindings(_ events: [MacSecurityEvent]) -> [Finding] {
        struct Agg { var last: Date?; var sample = ""; var source = "" }
        var byActor: [String: Agg] = [:]
        for e in events {
            let lower = e.message.lowercased()
            guard Self.disableHints.contains(where: { lower.contains($0) }) else { continue }
            let actor = e.process ?? e.sourceFile
            var agg = byActor[actor] ?? Agg()
            if agg.sample.isEmpty { agg.sample = e.message }
            agg.source = e.sourceFile
            if let t = e.timestamp, t > (agg.last ?? .distantPast) { agg.last = t }
            byActor[actor] = agg
        }
        return byActor.map { (_, agg) in
            var detail = "A macOS trust control appears to have been disabled: \(agg.sample)"
            detail += "\nDisabling Gatekeeper / XProtect assessment (e.g. `spctl --master-disable`) removes "
                + "the OS's barrier to running unsigned or unnotarized code; treat subsequent execution as untrusted."
            return Finding(
                title: "macOS security control disabled",
                detail: detail,
                severity: .high,
                phase: .exploitation,
                technique: AttackTechnique(attackID: "T1562.001", name: "Impair Defenses: Disable or Modify Tools"),
                timestamp: agg.last,
                evidencePaths: [agg.source])
        }
    }

    // MARK: - Rule 4: policy block of untrusted code (+ repeated-failure escalation)

    private struct BlockAgg {
        var count = 0
        var last: Date?
        var kind: MacSecurityEvent.Kind = .other
        var path: String?
        var signature: String?
        var sources: Set<String> = []
    }

    private func policyBlockFindings(_ events: [MacSecurityEvent], excluding overrides: Set<String>) -> [Finding] {
        var bySubject: [String: BlockAgg] = [:]
        for e in events {
            guard e.kind == .gatekeeper || e.kind == .syspolicyd else { continue }
            guard e.severity == .blocked || e.severity == .warning else { continue }
            // A block that was later overridden is reported by Rule 2 instead.
            if let stable = stableSubjectKey(e), overrides.contains(stable) { continue }
            var agg = bySubject[subjectKey(e)] ?? BlockAgg()
            agg.count += 1
            agg.kind = e.kind
            if agg.path == nil { agg.path = e.path }
            if agg.signature == nil { agg.signature = e.signature }
            agg.sources.insert(e.sourceFile)
            if let t = e.timestamp, t > (agg.last ?? .distantPast) { agg.last = t }
            bySubject[subjectKey(e)] = agg
        }
        return bySubject.map { (key, agg) in
            let subject = agg.path ?? agg.signature ?? key
            let repeated = agg.count >= Self.repeatedFailureThreshold
            var detail = "\(agg.kind.label) blocked an untrusted (unsigned / unnotarized / rejected) binary: \(subject)."
            if agg.count > 1 { detail += "\nFailed assessment \(agg.count) times." }
            detail += repeated
                ? "\nRepeated failures of the same binary suggest persistence relaunching it, or an "
                    + "operator repeatedly attempting to bypass Gatekeeper."
                : "\nConfirm whether the user subsequently attempted to override the block."
            return Finding(
                title: repeated
                    ? "Repeated macOS policy failures: \(subject)"
                    : "macOS policy blocked untrusted binary: \(subject)",
                detail: detail,
                severity: repeated ? .high : .medium,
                phase: .exploitation,
                technique: AttackTechnique(attackID: "T1553.001", name: "Subvert Trust Controls: Gatekeeper Bypass"),
                timestamp: agg.last,
                evidencePaths: evidencePaths(path: agg.path, sources: agg.sources))
        }
    }

    // MARK: - Helpers

    /// Grouping key: the most specific identity available (path → signature →
    /// free-text message).
    private func subjectKey(_ e: MacSecurityEvent) -> String {
        if let p = e.path, !p.isEmpty { return p.lowercased() }
        if let s = e.signature, !s.isEmpty { return "sig:" + s.lowercased() }
        return "msg:" + e.message.lowercased()
    }

    /// A *stable* identity (path or signature only) usable to correlate the same
    /// binary across separate events; nil when only the free-text message is known.
    private func stableSubjectKey(_ e: MacSecurityEvent) -> String? {
        if let p = e.path, !p.isEmpty { return p.lowercased() }
        if let s = e.signature, !s.isEmpty { return "sig:" + s.lowercased() }
        return nil
    }

    private func evidencePaths(path: String?, sources: Set<String>) -> [String] {
        var out: [String] = []
        if let p = path, !p.isEmpty { out.append(p) }
        out.append(contentsOf: sources.sorted())
        return out
    }

    private static func fmt(_ d: Date) -> String {
        d.formatted(date: .abbreviated, time: .standard)
    }
}
