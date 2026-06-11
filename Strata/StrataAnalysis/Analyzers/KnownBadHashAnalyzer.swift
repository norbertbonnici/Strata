import Foundation

/// Flags any indicator whose hash appears in a user-supplied **known-bad** set —
/// the detection-side counterpart to `KnownBadHashProvider` (which is the CTI
/// *enrichment* path). The set is supplied at construction; the integrator wires
/// the configured known-bad list, so by default (empty set) this analyzer is a
/// no-op and emits nothing.
///
/// It matches two evidence sources whose hashes are *file-content* digests (not
/// network indicators):
///   - **Case IOCs of kind `.hash`** that the analyst loaded — a known-bad hash
///     that's also a tracked IOC is a confirmed-bad file in the case. (IOCs are
///     not carried on `AnalysisContext` — they flow through the separate
///     `IOCMatcher` — so the integrator passes them to this analyzer's init.)
///   - **Amcache SHA-1s** — Amcache recovers a SHA-1 per registered binary, so a
///     match means a confirmed-bad binary was *present* on the host (presence,
///     not execution — wording stays careful, mirroring `AmcacheAnalyzer`).
///
/// (Shimcache carries no hash, so there's nothing to match there.)
///
/// Phase: Delivery — a known-bad payload landing on/within the host. Each match
/// is high severity; an Amcache match (a binary actually on disk) is critical.
public nonisolated struct KnownBadHashAnalyzer: Analyzer {
    public let name = "Known-Bad Hash Match"

    /// Normalised (lowercased, trimmed) malicious hashes. Empty ⇒ no-op.
    private let badHashes: Set<String>
    /// Case IOCs to cross-check against the set (kind `.hash` only is matched).
    /// Passed in because `AnalysisContext` doesn't carry IOCs.
    private let iocs: [IOC]

    /// Default-empty so an unconfigured pipeline runs this analyzer harmlessly;
    /// the integrator passes the configured set (and, optionally, the case IOCs).
    public init(badHashes: Set<String> = [], iocs: [IOC] = []) {
        self.badHashes = Set(badHashes.map { $0.trimmingCharacters(in: .whitespacesAndNewlines).lowercased() })
        self.iocs = iocs
    }

    private static let userExecution =
        AttackTechnique(attackID: "T1204", name: "User Execution")
    private static let maliciousFile =
        AttackTechnique(attackID: "T1588.001", name: "Obtain Capabilities: Malware")

    public func analyze(context: AnalysisContext) -> [Finding] {
        guard !badHashes.isEmpty else { return [] }   // unconfigured ⇒ nothing to do

        var findings: [Finding] = []

        // 1) Case IOCs that are hashes and land in the known-bad set.
        for ioc in iocs where ioc.kind == .hash {
            let h = normalise(ioc.value)
            guard badHashes.contains(h) else { continue }
            var detail = "Hash \(ioc.value) matches the known-bad hash set."
            if !ioc.note.isEmpty { detail += "\nIOC note: \(ioc.note)" }
            findings.append(Finding(
                title: "Known-bad hash (IOC): \(ioc.value)",
                detail: detail,
                severity: .high,
                phase: .delivery,
                technique: Self.maliciousFile,
                timestamp: nil,
                evidencePaths: [ioc.value]))
        }

        // 2) Amcache SHA-1s that land in the known-bad set — a confirmed-bad
        //    binary was present/registered on the host.
        for entry in context.amcache {
            guard let sha1 = entry.sha1 else { continue }
            let h = normalise(sha1)
            guard badHashes.contains(h) else { continue }
            var detail = "\(entry.fullPath ?? entry.name)\nSHA-1: \(sha1)"
            detail += "\nMatches the known-bad hash set."
            if let registered = entry.registeredAt {
                detail += "\nRegistered in Amcache: \(registered.ISO8601Format())"
            }
            detail += "\nAmcache records presence/registration, not execution - corroborate with Prefetch / event logs."
            findings.append(Finding(
                title: "Known-bad binary present (Amcache): \(entry.name)",
                detail: detail,
                severity: .critical,
                phase: .delivery,
                technique: Self.userExecution,
                timestamp: entry.registeredAt,
                evidencePaths: [entry.fullPath ?? entry.name, sha1]))
        }

        return findings
    }

    private func normalise(_ s: String) -> String {
        s.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
    }
}
