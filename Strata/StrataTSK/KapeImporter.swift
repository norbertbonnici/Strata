import Foundation

/// Classifies an evidence source and routes it to the right ingestion path.
/// E01, .vhd/.vhdx and raw images go to TSK; loose KAPE folders are flagged
/// (TSK ingests images, not directories - that is a phase-2 artifact parser).
public struct KapeImporter {

    public static func classify(_ url: URL) -> EvidenceKind {
        var isDirectory: ObjCBool = false
        FileManager.default.fileExists(atPath: url.path, isDirectory: &isDirectory)
        if isDirectory.boolValue { return .kapeLooseFolder }
        switch url.pathExtension.lowercased() {
        case "e01", "ex01", "s01": return .e01
        case "vhd", "vhdx":        return .kapeVHD
        default:                   return .raw
        }
    }

    public static func isTSKIngestible(_ kind: EvidenceKind) -> Bool {
        kind != .kapeLooseFolder
    }

    public static func makeEvidence(from url: URL) throws -> Evidence {
        let kind = classify(url)
        guard isTSKIngestible(kind) else { throw TSKError.looseFolderNotSupported(url) }
        return Evidence(displayName: url.lastPathComponent, sourceURL: url, kind: kind)
    }
}
