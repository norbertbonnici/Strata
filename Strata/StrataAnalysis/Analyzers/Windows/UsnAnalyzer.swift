import Foundation

/// Detection over the NTFS USN change journal.
///
/// The journal's superpower is recording **deletes and renames by name** — so it
/// catches anti-forensic cleanup other artifacts miss. Kept deliberately
/// low-noise by surfacing only correlated, high-signal sequences rather than a
/// finding per record:
///  1. **Created-then-deleted executable/script** (same MFT entry gets a
///     FILE_CREATE then a FILE_DELETE) — classic staging + cleanup.
///  2. **Rename that *gains* an executable extension** from a non-exe name —
///     masquerading a payload into something that runs.
///  3. **Mass deletion burst** — a large number of FILE_DELETEs (wiping /
///     ransomware cleanup), surfaced as one aggregate finding.
public nonisolated struct UsnAnalyzer: Analyzer {
    public let name = "USN Journal"
    public init() {}

    private static let exeExtensions: Set<String> = [
        "exe", "dll", "ps1", "bat", "cmd", "vbs", "vbe", "js", "jse", "scr", "hta", "wsf", "com",
    ]
    private static let massDeleteThreshold = 200

    public func analyze(context: AnalysisContext) -> [Finding] {
        guard !context.usn.isEmpty else { return [] }
        var findings: [Finding] = []
        var createdName: [UInt64: String] = [:]      // mftEntry -> name at create
        var oldRenameName: [UInt64: String] = [:]    // mftEntry -> old name on rename
        var deleteCount = 0
        var firstDelete: Date?
        var lastDelete: Date?

        for r in context.usn {
            let ext = r.fileExtension
            if r.reasonRaw & UsnReason.fileCreate != 0 { createdName[r.mftEntry] = r.fileName }
            if r.reasonRaw & UsnReason.renameOldName != 0 { oldRenameName[r.mftEntry] = r.fileName }

            if r.reasonRaw & UsnReason.fileDelete != 0 {
                deleteCount += 1
                if let t = r.timestamp {
                    if firstDelete == nil { firstDelete = t }
                    lastDelete = t
                }
                // Rule 1: created-then-deleted executable.
                if Self.exeExtensions.contains(ext), createdName[r.mftEntry] != nil {
                    findings.append(Finding(
                        title: "Created-then-deleted executable (USN): \(r.fileName)",
                        detail: "MFT entry \(r.mftEntry) was created then deleted within the journal — staging followed by cleanup.\n\(reasonLine(r))",
                        severity: .high,
                        phase: .actionsOnObjectives,
                        technique: AttackTechnique(attackID: "T1070.004", name: "Indicator Removal: File Deletion"),
                        timestamp: r.timestamp,
                        evidencePaths: [r.fileName, r.sourceFile]))
                }
            }

            // Rule 2: rename that gains an executable extension.
            if r.reasonRaw & UsnReason.renameNewName != 0, Self.exeExtensions.contains(ext),
               let old = oldRenameName[r.mftEntry] {
                let oldExt = (old as NSString).pathExtension.lowercased()
                if !Self.exeExtensions.contains(oldExt) {
                    findings.append(Finding(
                        title: "Renamed to executable (USN): \(old) → \(r.fileName)",
                        detail: "A non-executable was renamed to gain an executable extension — masquerading a payload.\n\(reasonLine(r))",
                        severity: .medium,
                        phase: .installation,
                        technique: AttackTechnique(attackID: "T1036.003", name: "Masquerading: Rename System Utilities"),
                        timestamp: r.timestamp,
                        evidencePaths: [r.fileName, r.sourceFile]))
                }
            }
        }

        // Rule 3: mass-deletion burst (aggregate, one finding).
        if deleteCount >= Self.massDeleteThreshold {
            var detail = "\(deleteCount) file deletions recorded in the USN journal — possible wiping or ransomware cleanup."
            if let f = firstDelete, let l = lastDelete {
                detail += "\nSpan: \(f.ISO8601Format()) → \(l.ISO8601Format())"
            }
            findings.append(Finding(
                title: "Mass file deletion (USN): \(deleteCount) deletes",
                detail: detail,
                severity: .medium,
                phase: .actionsOnObjectives,
                technique: AttackTechnique(attackID: "T1070.004", name: "Indicator Removal: File Deletion"),
                timestamp: lastDelete,
                evidencePaths: [context.usn.first?.sourceFile ?? "$UsnJrnl:$J"]))
        }
        return findings
    }

    private func reasonLine(_ r: UsnRecord) -> String {
        "Reasons: \(r.reasonSummary)" + (r.timestamp.map { "\nWhen: \($0.ISO8601Format())" } ?? "")
    }
}
