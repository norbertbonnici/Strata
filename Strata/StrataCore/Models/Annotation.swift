import Foundation

// Analyst work product: bookmarks/tags on findings and timeline events, plus
// the free-form case narrative. This is the *analysis* layer (what the analyst
// thinks), deliberately separate from the custody ledger (what was done to the
// evidence) - deleting a bookmark is normal triage, deleting a custody event
// is tampering.
//
// All types are value types, `nonisolated` + `Sendable`, persisted case-wide
// (`annotations.json` / `notes.json`) so they survive re-parses: artifacts are
// rebuilt from source on every load, so annotations key off *stable* target
// identities (`Finding.id`, `TimelineEvent.stableKey`), never off the
// ephemeral parse-time UUIDs.

/// Analyst verdict tag - a small, closed set so triage reads consistently
/// (and reports/exports can rely on the vocabulary).
public nonisolated enum AnalystTag: String, CaseIterable, Codable, Sendable, Hashable {
    case malicious
    case suspicious
    case benign
    case followUp

    public var label: String {
        switch self {
        case .malicious:  return "Malicious"
        case .suspicious: return "Suspicious"
        case .benign:     return "Benign"
        case .followUp:   return "Follow up"
        }
    }

    /// SF Symbol for list rows and chips.
    public var symbol: String {
        switch self {
        case .malicious:  return "xmark.octagon.fill"
        case .suspicious: return "exclamationmark.triangle.fill"
        case .benign:     return "checkmark.circle.fill"
        case .followUp:   return "flag.fill"
        }
    }
}

/// One analyst bookmark: a tag and/or note pinned to a finding or a timeline
/// event. Carries a denormalized snapshot (title / timestamp / source) so the
/// Annotations list and the report render it even when the target artifact
/// isn't currently loaded (e.g. the iOS viewer skipping the FS timeline).
public nonisolated struct Annotation: Identifiable, Codable, Sendable, Hashable {
    public enum TargetKind: String, Codable, Sendable, Hashable {
        case finding
        case timelineEvent

        public var label: String {
            switch self {
            case .finding:       return "Finding"
            case .timelineEvent: return "Timeline event"
            }
        }
    }

    public let id: UUID
    public let createdAt: Date
    public var modifiedAt: Date
    public var author: String
    public let targetKind: TargetKind
    /// `Finding.id.uuidString` or `TimelineEvent.stableKey` - the join key
    /// back to the live object when it's loaded.
    public let targetKey: String
    /// Owning host; nil when the target was annotated in the combined "All"
    /// scope (or is case-level).
    public let evidenceID: UUID?
    public var tag: AnalystTag?
    public var note: String

    // Denormalized display snapshot.
    public let title: String            // finding title / timeline event path
    public let timestamp: Date?         // the target's own time (not createdAt)
    public let sourceLabel: String      // "Event Log", "Filesystem", "Finding", ...

    public init(id: UUID = UUID(), createdAt: Date = Date(), modifiedAt: Date = Date(),
                author: String, targetKind: TargetKind, targetKey: String,
                evidenceID: UUID? = nil, tag: AnalystTag? = nil, note: String = "",
                title: String, timestamp: Date? = nil, sourceLabel: String) {
        self.id = id
        self.createdAt = createdAt
        self.modifiedAt = modifiedAt
        self.author = author
        self.targetKind = targetKind
        self.targetKey = targetKey
        self.evidenceID = evidenceID
        self.tag = tag
        self.note = note
        self.title = title
        self.timestamp = timestamp
        self.sourceLabel = sourceLabel
    }
}

/// The free-form case narrative - one Markdown-ish text per case, the running
/// "story of the incident" the analyst builds while triaging. Persisted as
/// `notes.json`; surfaced in the report as the analyst narrative.
public nonisolated struct CaseNotes: Codable, Sendable, Equatable {
    public var text: String
    public var modifiedAt: Date?
    public var author: String

    public init(text: String = "", modifiedAt: Date? = nil, author: String = "") {
        self.text = text
        self.modifiedAt = modifiedAt
        self.author = author
    }

    public var isEmpty: Bool {
        text.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
    }
}
