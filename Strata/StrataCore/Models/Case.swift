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
    case kapeLooseFolder   // read directly off disk, not via TSK

    /// Human-readable description for the UI.
    public var label: String {
        switch self {
        case .e01:             return "E01 image"
        case .kapeVHD:         return "KAPE VHD"
        case .raw:             return "Raw image"
        case .kapeLooseFolder: return "KAPE folder"
        }
    }
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

    // Chain-of-custody / integrity (see Custody.swift). Both are optional /
    // defaulted and listed in CodingKeys, so a legacy `hosts.json` written
    // before this feature decodes cleanly to nil / [].
    public var acquisition: AcquisitionInfo? = nil
    public var sourceHashes: [SourceHash] = []

    enum CodingKeys: String, CodingKey {
        case id, displayName, sourceURL, kind, acquisition, sourceHashes
    }

    public init(id: UUID = UUID(), displayName: String, sourceURL: URL,
                kind: EvidenceKind, tskDatabaseURL: URL? = nil,
                acquisition: AcquisitionInfo? = nil, sourceHashes: [SourceHash] = []) {
        self.id = id; self.displayName = displayName; self.sourceURL = sourceURL
        self.kind = kind; self.tskDatabaseURL = tskDatabaseURL
        self.acquisition = acquisition; self.sourceHashes = sourceHashes
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        id = try c.decode(UUID.self, forKey: .id)
        displayName = try c.decode(String.self, forKey: .displayName)
        sourceURL = try c.decode(URL.self, forKey: .sourceURL)
        kind = try c.decode(EvidenceKind.self, forKey: .kind)
        // Tolerate older bundles that predate these keys.
        acquisition = try c.decodeIfPresent(AcquisitionInfo.self, forKey: .acquisition)
        sourceHashes = try c.decodeIfPresent([SourceHash].self, forKey: .sourceHashes) ?? []
    }
}
