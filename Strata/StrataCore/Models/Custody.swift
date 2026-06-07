import Foundation

// Chain-of-custody & evidence-integrity model.
//
// Two concerns live here:
//   1. Per-evidence integrity - acquisition metadata + source hashes. These
//      ride inside `Evidence` (see Case.swift) and persist via `hosts.json`.
//   2. The case-wide custody log - an append-only ledger of who did what, when.
//      Persisted in its own `custody.json` so a routine host-list rewrite can
//      never truncate the legal record.
//
// All types are value types, `nonisolated` + `Sendable` so the ingest /
// hashing / report code can build and carry them off the main actor.

// MARK: - Source hashes

/// Digest algorithm for a source hash. MD5 + SHA-1 appear in E01 acquisition
/// metadata; SHA-256 is what we compute for raw/VHD images.
public nonisolated enum HashAlgorithm: String, CaseIterable, Codable, Sendable, Hashable {
    case md5
    case sha1
    case sha256

    public var label: String {
        switch self {
        case .md5:    return "MD5"
        case .sha1:   return "SHA-1"
        case .sha256: return "SHA-256"
        }
    }
}

/// Where a hash value came from. `embedded` is read from the image's own
/// acquisition metadata (E01/EWF) and is trusted without rehashing; `computed`
/// is streamed over the file by Strata.
public nonisolated enum HashOrigin: String, Codable, Sendable, Hashable {
    case embedded
    case computed

    public var label: String {
        switch self {
        case .embedded: return "Embedded"
        case .computed: return "Computed"
        }
    }
}

/// Integrity state of a recorded hash.
public nonisolated enum HashVerificationStatus: String, Codable, Sendable, Hashable {
    case notVerified   // recorded but never re-checked
    case verified      // a re-check (ewfverify / recompute) matched the stored value
    case mismatch      // a re-check DISAGREED - integrity alarm
    case unavailable   // N/A (e.g. loose KAPE folder, or the tool was missing)

    public var label: String {
        switch self {
        case .notVerified: return "Not verified"
        case .verified:    return "Verified"
        case .mismatch:    return "Mismatch"
        case .unavailable: return "Unavailable"
        }
    }
}

/// One digest recorded for an evidence source.
public nonisolated struct SourceHash: Identifiable, Codable, Sendable, Hashable {
    public let id: UUID
    public var algorithm: HashAlgorithm
    public var value: String                 // lowercase hex
    public var origin: HashOrigin
    public var status: HashVerificationStatus
    public var computedAt: Date?             // when `value` was first obtained
    public var verifiedAt: Date?             // last verify pass
    public var note: String                  // e.g. "from ewfinfo", "ewfverify OK"

    public init(id: UUID = UUID(), algorithm: HashAlgorithm, value: String,
                origin: HashOrigin, status: HashVerificationStatus = .notVerified,
                computedAt: Date? = nil, verifiedAt: Date? = nil, note: String = "") {
        self.id = id
        self.algorithm = algorithm
        self.value = value.lowercased()
        self.origin = origin
        self.status = status
        self.computedAt = computedAt
        self.verifiedAt = verifiedAt
        self.note = note
    }
}

// MARK: - Acquisition metadata

/// Acquisition provenance for an evidence item - how, when, and by whom the
/// image/collection was made. Distinct from when it was *ingested* into Strata.
public nonisolated struct AcquisitionInfo: Codable, Sendable, Hashable {
    /// Where these values came from, so the UI/report can disclose whether they
    /// were auto-extracted, typed by the examiner, or a mix.
    public enum Source: String, Codable, Sendable, Hashable {
        case manual        // examiner typed them
        case ewfMetadata   // auto-extracted from E01/EWF header
        case mixed         // auto-seeded then edited
    }

    public var examiner: String          // may differ from the case examiner
    public var acquisitionTool: String   // e.g. "FTK Imager 4.7", "Guymager"
    public var acquisitionMethod: String // free text: "physical", "logical", "KAPE+VHDX"
    public var acquiredAt: Date?         // when the image was made (not ingest time)
    public var caseNumber: String
    public var mediaSerial: String       // disk serial if known
    public var notes: String
    public var source: Source

    public init(examiner: String = "", acquisitionTool: String = "",
                acquisitionMethod: String = "", acquiredAt: Date? = nil,
                caseNumber: String = "", mediaSerial: String = "",
                notes: String = "", source: Source = .manual) {
        self.examiner = examiner
        self.acquisitionTool = acquisitionTool
        self.acquisitionMethod = acquisitionMethod
        self.acquiredAt = acquiredAt
        self.caseNumber = caseNumber
        self.mediaSerial = mediaSerial
        self.notes = notes
        self.source = source
    }

    /// True when nothing meaningful has been captured - lets the UI show a
    /// "no acquisition details" placeholder instead of an empty grid.
    public var isEmpty: Bool {
        examiner.isEmpty && acquisitionTool.isEmpty && acquisitionMethod.isEmpty
            && acquiredAt == nil && caseNumber.isEmpty && mediaSerial.isEmpty
            && notes.isEmpty
    }
}

// MARK: - Custody log

/// A recorded action in the chain of custody. The set is deliberately small and
/// closed so the ledger reads consistently in a report.
public nonisolated enum CustodyAction: String, CaseIterable, Codable, Sendable, Hashable {
    case acquired             // the image/collection was created (often back-dated)
    case addedToCase          // ingested into this Strata case
    case analysed             // parse / analyzers run
    case hashRecorded         // a source hash was captured
    case hashVerified         // a verify pass run (verdict in `detail`)
    case enrichmentPerformed  // IOC match / future CTI lookup
    case exported             // a report or data export was produced
    case noteAdded            // free-form examiner annotation

    public var label: String {
        switch self {
        case .acquired:            return "Acquired"
        case .addedToCase:         return "Added to case"
        case .analysed:            return "Analysed"
        case .hashRecorded:        return "Hash recorded"
        case .hashVerified:        return "Hash verified"
        case .enrichmentPerformed: return "Enrichment"
        case .exported:            return "Exported"
        case .noteAdded:           return "Note"
        }
    }

    /// SF Symbol for the timeline row.
    public var symbol: String {
        switch self {
        case .acquired:            return "externaldrive.badge.plus"
        case .addedToCase:         return "tray.and.arrow.down"
        case .analysed:            return "magnifyingglass"
        case .hashRecorded:        return "number"
        case .hashVerified:        return "checkmark.seal"
        case .enrichmentPerformed: return "scope"
        case .exported:            return "square.and.arrow.up"
        case .noteAdded:           return "text.bubble"
        }
    }
}

/// One immutable entry in the append-only custody ledger. `timestamp` is the
/// moment the event was *recorded* (so the log stays monotonic); a back-dated
/// real-world time (e.g. the acquisition date) lives in `detail`.
public nonisolated struct CustodyEvent: Identifiable, Codable, Sendable, Hashable {
    public let id: UUID
    public let timestamp: Date
    public var action: CustodyAction
    public var actor: String           // examiner name at the time of the action
    public var detail: String          // human-readable specifics
    public var evidenceID: UUID?       // nil = case-level event

    public init(id: UUID = UUID(), timestamp: Date = Date(),
                action: CustodyAction, actor: String, detail: String,
                evidenceID: UUID? = nil) {
        self.id = id
        self.timestamp = timestamp
        self.action = action
        self.actor = actor
        self.detail = detail
        self.evidenceID = evidenceID
    }
}
