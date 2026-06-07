import Foundation

/// Persists a set of generated files as one timestamped export. Each export
/// lands in its own `<Case> Export <stamp>/` subfolder of the chosen
/// destination, so nothing is ever clobbered and an export is a discrete,
/// groupable artifact set (the layout the future chain-of-custody feature will
/// hang a manifest off). Pure Foundation - no SwiftUI.
public nonisolated enum CaseExportWriter {
    public struct Output: Sendable {
        public let folderURL: URL
        public let filenames: [String]
    }

    public static func write(_ files: [ExportedFile], caseName: String,
                             timestamp: Date, to destination: URL) throws -> Output {
        let folderName = "\(sanitize(caseName)) Export \(ReportFormat.fileStamp(timestamp))"
        let folder = destination.appendingPathComponent(folderName, isDirectory: true)
        try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true)

        var written: [String] = []
        for file in files {
            let url = folder.appendingPathComponent(file.filename)
            try file.data.write(to: url, options: .atomic)
            written.append(file.filename)
        }
        return Output(folderURL: folder, filenames: written)
    }

    /// Make a case name safe to use in a file/folder name: replace path-hostile
    /// characters, collapse to a non-empty fallback.
    static func sanitize(_ name: String) -> String {
        let illegal = CharacterSet(charactersIn: "/\\:?%*|\"<>")
        let cleaned = String(String.UnicodeScalarView(name.unicodeScalars.map {
            illegal.contains($0) ? Unicode.Scalar("_") : $0
        }))
        let trimmed = cleaned.trimmingCharacters(in: .whitespacesAndNewlines)
        return trimmed.isEmpty ? "Case" : trimmed
    }
}
