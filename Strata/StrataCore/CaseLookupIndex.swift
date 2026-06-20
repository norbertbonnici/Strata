import Foundation

/// A pure, in-memory, path-keyed view of the case's artifact records that the
/// on-device summarizer's **tools** query during generation - so the model can
/// confirm a file or its download origin against the real evidence instead of
/// guessing. FoundationModels-free (the `Tool` conformances live in StrataAI),
/// `Sendable`, and unit-testable without a model.
///
/// Scoped to the files referenced by findings (the paths the model actually
/// sees) plus all download-provenance records, so it stays small even on a
/// multi-million-file image.
public nonisolated struct CaseLookupIndex: Sendable {

    /// What `lookupFile` returns: the evidence's record of a file.
    public struct FileFact: Sendable, Hashable, Codable {
        public let path: String
        public let size: Int64
        public let isDeleted: Bool
        public let created: Date?
        public let modified: Date?
        public init(path: String, size: Int64, isDeleted: Bool, created: Date?, modified: Date?) {
            self.path = path; self.size = size; self.isDeleted = isDeleted
            self.created = created; self.modified = modified
        }
    }

    /// What `lookupDownloadOrigin` returns: a file's download provenance
    /// (`kMDItemWhereFroms`).
    public struct DownloadOrigin: Sendable, Hashable, Codable {
        public let path: String
        public let downloadURL: String?
        public let referrer: String?
        public init(path: String, downloadURL: String?, referrer: String?) {
            self.path = path; self.downloadURL = downloadURL; self.referrer = referrer
        }
    }

    private let filesByPath: [String: FileFact]
    private let originsByPath: [String: DownloadOrigin]
    // Paths that more than one *distinct* record maps to - a disk image holds
    // several volumes (and a case several hosts), each able to carry the same
    // path (`/Users/x/Downloads/a.dmg`). `FileEntry.fullPath` drops the
    // `fsID`/host, so we can't key them apart - instead we flag the collision so
    // the tool discloses the ambiguity rather than attributing one authoritatively.
    private let ambiguousFiles: Set<String>
    private let ambiguousOrigins: Set<String>

    public init(filesByPath: [String: FileFact], originsByPath: [String: DownloadOrigin],
                ambiguousFiles: Set<String> = [], ambiguousOrigins: Set<String> = []) {
        self.filesByPath = filesByPath
        self.originsByPath = originsByPath
        self.ambiguousFiles = ambiguousFiles
        self.ambiguousOrigins = ambiguousOrigins
    }

    public static let empty = CaseLookupIndex(filesByPath: [:], originsByPath: [:])

    public var isEmpty: Bool { filesByPath.isEmpty && originsByPath.isEmpty }

    public func file(at path: String) -> FileFact? { filesByPath[Self.key(path)] }
    public func downloadOrigin(at path: String) -> DownloadOrigin? { originsByPath[Self.key(path)] }
    public func isAmbiguousFile(at path: String) -> Bool { ambiguousFiles.contains(Self.key(path)) }
    public func isAmbiguousOrigin(at path: String) -> Bool { ambiguousOrigins.contains(Self.key(path)) }

    /// Normalised lookup key: trimmed + lowercased so the model's path string
    /// resolves regardless of case / surrounding whitespace.
    static func key(_ path: String) -> String {
        path.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
    }

    /// Build from case artifacts. File facts are limited to paths referenced by
    /// `findings` (what the model will quote); download origins include every
    /// `whereFroms` record (already a bounded set).
    public static func build(findings: [Finding],
                             files: [FileEntry],
                             whereFroms: [MacWhereFrom]) -> CaseLookupIndex {
        let wanted = Set(findings.flatMap { $0.evidencePaths }.map { key($0) })
        var filesByPath: [String: FileFact] = [:]
        var ambiguousFiles: Set<String> = []
        if !wanted.isEmpty {
            for f in files where !f.isDirectory {
                let k = key(f.fullPath)
                guard wanted.contains(k) else { continue }
                let fact = FileFact(path: f.fullPath, size: f.size, isDeleted: f.isDeleted,
                                    created: f.created, modified: f.modified)
                if let existing = filesByPath[k] {
                    if existing != fact { ambiguousFiles.insert(k) }   // a distinct file shares this path
                } else {
                    filesByPath[k] = fact
                }
            }
        }
        var originsByPath: [String: DownloadOrigin] = [:]
        var ambiguousOrigins: Set<String> = []
        for w in whereFroms {
            let k = key(w.path)
            let origin = DownloadOrigin(path: w.path, downloadURL: w.downloadURL, referrer: w.referrerURL)
            if let existing = originsByPath[k] {
                if existing != origin { ambiguousOrigins.insert(k) }
            } else {
                originsByPath[k] = origin
            }
        }
        return CaseLookupIndex(filesByPath: filesByPath, originsByPath: originsByPath,
                               ambiguousFiles: ambiguousFiles, ambiguousOrigins: ambiguousOrigins)
    }
}
