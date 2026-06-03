import Foundation

/// Persisted to `case.json` inside a .strata bundle. `evidence` is excluded
/// from the on-disk representation; the host list lives in `hosts.json` so
/// host membership can be edited without rewriting case metadata.
public struct ForensicCase: Identifiable, Hashable, Sendable, Codable {
    public let id: UUID
    public var name: String
    public var examiner: String
    public var createdAt: Date
    public var evidence: [Evidence] = []

    enum CodingKeys: String, CodingKey { case id, name, examiner, createdAt }

    public init(id: UUID = UUID(), name: String, examiner: String = "",
                createdAt: Date = Date(), evidence: [Evidence] = []) {
        self.id = id; self.name = name; self.examiner = examiner
        self.createdAt = createdAt; self.evidence = evidence
    }
}

public enum EvidenceKind: String, Sendable, Codable {
    case e01
    case kapeVHD
    case raw
    case kapeLooseFolder   // not TSK-ingestible; flagged for phase 2
}

/// Persisted to `hosts.json` inside a .strata bundle. `tskDatabaseURL` is
/// excluded from the on-disk form because it's a bundle-relative location
/// reconstructed on load - that keeps the bundle portable across paths.
public struct Evidence: Identifiable, Hashable, Sendable, Codable {
    public let id: UUID
    public var displayName: String
    public var sourceURL: URL        // path to the .E01 / .vhd / folder
    public var kind: EvidenceKind
    public var tskDatabaseURL: URL? = nil

    enum CodingKeys: String, CodingKey { case id, displayName, sourceURL, kind }

    public init(id: UUID = UUID(), displayName: String, sourceURL: URL,
                kind: EvidenceKind, tskDatabaseURL: URL? = nil) {
        self.id = id; self.displayName = displayName; self.sourceURL = sourceURL
        self.kind = kind; self.tskDatabaseURL = tskDatabaseURL
    }
}
