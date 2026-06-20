import Foundation

/// Lockheed Martin Cyber Kill Chain phases, used for the headline visualization.
/// Phase-2 detections tag findings with a phase (and optionally an ATT&CK technique).
public nonisolated enum KillChainPhase: String, CaseIterable, Identifiable, Sendable, Codable {
    case reconnaissance, weaponization, delivery, exploitation
    case installation, commandAndControl, actionsOnObjectives

    public var id: String { rawValue }

    public var title: String {
        switch self {
        case .reconnaissance:      return "Reconnaissance"
        case .weaponization:       return "Weaponization"
        case .delivery:            return "Delivery"
        case .exploitation:        return "Exploitation"
        case .installation:        return "Installation"
        case .commandAndControl:   return "Command & Control"
        case .actionsOnObjectives: return "Actions on Objectives"
        }
    }

    /// SF Symbol for the phase header.
    public var symbol: String {
        switch self {
        case .reconnaissance:      return "binoculars"
        case .weaponization:       return "hammer"
        case .delivery:            return "shippingbox"
        case .exploitation:        return "burst"
        case .installation:        return "internaldrive"
        case .commandAndControl:   return "antenna.radiowaves.left.and.right"
        case .actionsOnObjectives: return "target"
        }
    }

    public var order: Int { Self.allCases.firstIndex(of: self) ?? 0 }
}

public nonisolated enum Severity: Int, CaseIterable, Comparable, Sendable, Codable {
    case info = 0, low, medium, high, critical
    public static func < (l: Severity, r: Severity) -> Bool { l.rawValue < r.rawValue }
    public var label: String {
        switch self {
        case .info: return "Info"; case .low: return "Low"; case .medium: return "Medium"
        case .high: return "High"; case .critical: return "Critical"
        }
    }
}

/// A MITRE ATT&CK technique reference (populated in phase 2).
public nonisolated struct AttackTechnique: Hashable, Identifiable, Sendable, Codable {
    public var id: String { attackID }
    public let attackID: String   // e.g. "T1547.001"
    public let name: String       // e.g. "Registry Run Keys / Startup Folder"
    public init(attackID: String, name: String) { self.attackID = attackID; self.name = name }
}

/// A detection produced by an analyzer. v1 uses sample/manual entries;
/// phase-2 analyzers emit them from real artifacts.
public nonisolated struct Finding: Identifiable, Hashable, Sendable, Codable {
    public let id: UUID
    public let title: String
    public let detail: String
    public let severity: Severity
    public let phase: KillChainPhase
    public let technique: AttackTechnique?
    public let timestamp: Date?
    public let evidencePaths: [String]

    public init(id: UUID = UUID(), title: String, detail: String, severity: Severity,
                phase: KillChainPhase, technique: AttackTechnique? = nil,
                timestamp: Date? = nil, evidencePaths: [String] = []) {
        self.id = id; self.title = title; self.detail = detail
        self.severity = severity; self.phase = phase; self.technique = technique
        self.timestamp = timestamp; self.evidencePaths = evidencePaths
    }

    /// The technique-bucket key used to group findings into one ATT&CK bucket:
    /// the ATT&CK ID when tagged, else the title. Single source of truth so the
    /// summary validator (which records it per kept claim) and the self-eval
    /// scorer can't drift on how a claim's techniques are identified.
    public var techniqueBucketKey: String { technique?.attackID ?? title }
}
