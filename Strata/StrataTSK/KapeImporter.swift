import Foundation

/// Classifies an evidence source and routes it to the right ingestion path.
/// E01, .vhd/.vhdx and raw images go to TSK; loose KAPE folders are walked
/// directly by `KapeFolderIngestor` (TSK ingests images, not directories).
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

    /// Whether this kind goes through TSK (`tsk_loaddb` + `icat`) or is read
    /// directly off disk. Loose folders take the direct path.
    public static func isTSKIngestible(_ kind: EvidenceKind) -> Bool {
        kind != .kapeLooseFolder
    }

    public static func makeEvidence(from url: URL) -> Evidence {
        Evidence(displayName: url.lastPathComponent, sourceURL: url, kind: classify(url))
    }
}
