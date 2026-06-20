import Foundation
import FoundationModels

/// FoundationModels tools that let the on-device summarizer query the case's
/// real artifact records by path **during** generation - the "reduce pass can
/// query the artifact DB through constrained tools rather than guessing"
/// mechanism. Both are read-only over a pure in-memory `CaseLookupIndex` (no I/O,
/// no network), so they stay within Strata's confidentiality rule.

/// Confirm a file in the evidence by path: existence, size, deleted state, and
/// MACB timestamps. Grounds any claim that names a file.
struct LookupFileTool: Tool {
    let index: CaseLookupIndex
    /// Whole-evidence-tree path set, so a miss in the (finding-scoped) metadata
    /// index can still distinguish "present, just not detail-indexed" from a
    /// genuine absence - never letting the model read a miss as proof a file is
    /// absent from the host.
    let knownPaths: Set<String>
    let name = "lookupFile"
    let description = """
        Look up a file referenced by the case findings, by its full path. Returns \
        its size, whether it is deleted, and its created/modified timestamps. This \
        index covers files cited by the findings, not the entire evidence tree, so a \
        miss does NOT prove a file is absent. Call this to confirm a file before \
        describing it.
        """

    @Generable
    struct Arguments {
        @Guide(description: "The full file path to look up, e.g. /Users/jane/Downloads/installer.dmg")
        let path: String
    }

    func call(arguments: Arguments) async throws -> String {
        guard let f = index.file(at: arguments.path) else {
            // Match the normalisation `index.file(at:)` uses (trim+lowercase) on
            // both sides, so a present-but-not-detail-indexed file the model
            // quoted in a different case/whitespace isn't misreported as absent.
            let q = CaseLookupIndex.key(arguments.path)
            if knownPaths.contains(where: { CaseLookupIndex.key($0) == q }) {
                return "'\(arguments.path)' is present in the evidence, but no extended record (size/timestamps) is indexed for it."
            }
            return "'\(arguments.path)' is not among the files referenced by the case findings; absence here does not mean it is absent from the host."
        }
        var parts = ["path: \(f.path)",
                     "size: \(f.size) bytes",
                     f.isDeleted ? "state: DELETED" : "state: present"]
        if let c = f.created { parts.append("created: \(Self.iso(c))") }
        if let m = f.modified { parts.append("modified: \(Self.iso(m))") }
        var out = parts.joined(separator: ", ")
        if index.isAmbiguousFile(at: arguments.path) {
            out += " (note: more than one file across the evidence shares this path; these facts may belong to a different volume or host)"
        }
        return out
    }

    private static func iso(_ d: Date) -> String { ISO8601DateFormatter().string(from: d) }
}

/// Resolve where a file was downloaded from (its `kMDItemWhereFroms` provenance)
/// by path. Grounds any claim about how a file arrived on the host.
struct LookupDownloadOriginTool: Tool {
    let index: CaseLookupIndex
    let name = "lookupDownloadOrigin"
    let description = """
        Look up where a file was downloaded from (its recorded download \
        provenance) by full path. Returns the download URL and referrer when \
        known. Call this before asserting how a file arrived on the host.
        """

    @Generable
    struct Arguments {
        @Guide(description: "The full file path to look up, e.g. /Users/jane/Downloads/installer.dmg")
        let path: String
    }

    func call(arguments: Arguments) async throws -> String {
        guard let o = index.downloadOrigin(at: arguments.path) else {
            return "No recorded download origin for '\(arguments.path)'."
        }
        var parts = ["path: \(o.path)"]
        if let u = o.downloadURL { parts.append("downloadedFrom: \(u)") }
        if let r = o.referrer { parts.append("referrer: \(r)") }
        var out = parts.count == 1
            ? "A download-origin record exists for '\(o.path)' but carries no URL."
            : parts.joined(separator: ", ")
        if index.isAmbiguousOrigin(at: arguments.path) {
            out += " (note: more than one file across the evidence shares this path; this origin may belong to a different volume or host)"
        }
        return out
    }
}
