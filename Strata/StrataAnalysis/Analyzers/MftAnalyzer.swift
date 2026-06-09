import Foundation

/// Detection over parsed `$MFT` records — **timestomping** (T1070.006).
///
/// NTFS keeps two MACB sets per file: the visible `$STANDARD_INFORMATION` (which
/// the `SetFileTime` / timestomp API rewrites) and the `$FILE_NAME` set (which it
/// does **not**). When an attacker backdates a dropped payload's `$SI` times to
/// blend in, the `$SI` creation time falls *below* its own `$FN` creation time —
/// impossible on a clean system. Tools that write whole-second times also leave a
/// tell: real NTFS times carry 100-ns sub-second noise.
///
/// Kept low-noise: only non-directory executables/scripts are considered, the
/// backdate must exceed a day (excludes clock skew / same-day copies), AND the
/// `$SI` times must be whole-second — the timestomp-tool fingerprint that real
/// NTFS operations (which carry 100-ns sub-second noise) don't produce. That
/// whole-second requirement is what separates a timestomp from a benign
/// timestamp-preserving copy/restore, which keeps its sub-second precision.
/// (A legitimate executable unpacked from an archive can still trip it, so
/// findings are framed as *possible* and left to analyst triage.)
public nonisolated struct MftAnalyzer: Analyzer {
    public let name = "MFT Timestomp"
    public init() {}

    private static let exeExtensions: Set<String> = [
        "exe", "dll", "scr", "ps1", "bat", "cmd", "vbs", "vbe", "js", "jse",
        "wsf", "hta", "com", "sys", "msi",
    ]
    private static let suspiciousFragments = [
        #"\temp\"#, #"\$recycle.bin\"#, #"\users\public\"#, #"\perflogs\"#, #"\downloads\"#,
    ]
    /// A backdate must exceed this to count (excludes skew / same-day copies).
    private static let minBackdate: TimeInterval = 86_400   // 1 day

    public func analyze(context: AnalysisContext) -> [Finding] {
        guard !context.mft.isEmpty else { return [] }
        var findings: [Finding] = []
        for e in context.mft {
            guard !e.isDirectory, Self.exeExtensions.contains(e.fileExtension) else { continue }
            guard let si = e.siCreated, let fn = e.fnCreated else { continue }
            let backdate = fn.timeIntervalSince(si)
            guard backdate > Self.minBackdate else { continue }
            // Whole-second $SI is the mandatory tool fingerprint; without it a
            // backdate is almost always a benign timestamp-preserving copy.
            guard e.siHasZeroedSubseconds else { continue }

            let lower = (e.fullPath ?? e.fileName ?? "").lowercased()
            let suspiciousPath = Self.suspiciousFragments.contains { lower.contains($0) }
            let severity: Severity = suspiciousPath ? .high : .medium

            var detail = "\(e.displayPath)\n"
                + "$SI creation \(si.ISO8601Format()) predates $FN creation \(fn.ISO8601Format()) by \(Self.humanGap(backdate))."
                + "\nThe visible creation time was rolled back below the un-settable $FILE_NAME time, and the $SI times are whole-second (zero sub-second) — together a hallmark of timestomping. Verify against a known-good copy (a timestamp-preserving extract can look similar)."
            if suspiciousPath { detail += "\nLocated in a staging path commonly used for dropped payloads." }

            findings.append(Finding(
                title: "Possible timestomping (MFT): \(e.fileName ?? "MFT #\(e.recordNumber)")",
                detail: detail,
                severity: severity,
                phase: .actionsOnObjectives,
                technique: AttackTechnique(attackID: "T1070.006", name: "Indicator Removal: Timestomp"),
                timestamp: e.fnCreated,
                evidencePaths: [e.fullPath ?? e.fileName ?? "", e.sourceFile].filter { !$0.isEmpty }))
        }
        return findings
    }

    private static func humanGap(_ seconds: TimeInterval) -> String {
        let s = Int(seconds)
        if s >= 86_400 { return "\(s / 86_400)d" }
        if s >= 3_600 { return "\(s / 3_600)h" }
        return "\(s / 60)m"
    }
}
