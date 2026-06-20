//
//  Domain.swift
//  Strata
//
//  Platform-agnostic domain model. These are plain Codable value types on
//  purpose: the custody chain hashes over them and needs determinism, and the
//  evidence taxonomy is easier to reason about as values. Persist with a thin
//  layer (Codable-to-disk or a SwiftData shadow) — keep the logic here pure.
//
//  Accent colors live in DesignSystem.swift; this file maps domain → tokens.
//

import SwiftUI

// MARK: - OS families (drives the entire evidence taxonomy)

enum OSFamily: String, Codable, CaseIterable, Identifiable {
    case macOS, windows, linux, iOS, android
    var id: String { rawValue }

    var displayName: String {
        switch self {
        case .macOS:   return "macOS"
        case .windows: return "Windows"
        case .linux:   return "Linux"
        case .iOS:     return "iOS"
        case .android: return "Android"
        }
    }

    /// Name of the custom vector asset to ship in Assets.xcassets. The HTML
    /// references draw these as SVG (Apple logo, Windows squares, Tux,
    /// iOS phone, Android robot). Provide matching single-color/flat assets.
    var glyphAsset: String { "os.\(rawValue)" }

    /// Fallback SF Symbol if the custom asset is unavailable. No first-party
    /// SF Symbols exist for Windows/Linux/Android — these are placeholders.
    var fallbackSymbol: String {
        switch self {
        case .macOS:   return "apple.logo"
        case .windows: return "square.grid.2x2.fill"
        case .linux:   return "terminal.fill"
        case .iOS:     return "iphone"
        case .android: return "candybarphone"
        }
    }
}

// MARK: - Encryption (per-OS lock types surfaced across intake/viewer)

enum EncryptionKind: String, Codable {
    case bitLocker = "BitLocker", fileVault = "FileVault", luks = "LUKS", iosBackup = "Backup encryption"
}

enum Encryption: Codable, Hashable {
    case none
    case locked(EncryptionKind)
    case unlocked(EncryptionKind)

    var isLocked: Bool { if case .locked = self { return true }; return false }
    var kind: EncryptionKind? {
        switch self { case .locked(let k), .unlocked(let k): return k; case .none: return nil }
    }
}

// MARK: - Classification / priority

enum Classification: String, Codable, CaseIterable, Identifiable {
    case official = "Official", restricted = "Restricted", confidential = "Confidential", secret = "Secret"
    var id: String { rawValue }
    var color: Color {
        switch self {
        case .official:     return StrataColor.steel
        case .restricted:   return StrataColor.teal
        case .confidential: return StrataColor.amber
        case .secret:       return StrataColor.coral
        }
    }
}

enum CasePriority: String, Codable, CaseIterable, Identifiable {
    case low = "Low", normal = "Normal", high = "High", urgent = "Urgent"
    var id: String { rawValue }
}

// MARK: - Exhibit

struct Exhibit: Codable, Identifiable, Hashable {
    var id = UUID()
    var fileName: String
    var os: OSFamily
    var osVersion: String          // e.g. "macOS 14.5"
    var osBuild: String            // e.g. "23F79 · Mac14,2"
    var filesystem: String         // e.g. "APFS", "NTFS", "ext4"
    var format: String             // e.g. "EnCase · 4 seg", "QEMU"
    var sizeGB: Double
    var acquisitionHash: String    // SHA-256 baseline (display-truncated in UI)
    var encryption: Encryption = .none
}

// MARK: - Case lifecycle

/// Linear case state machine: open → active → review → closed → archived.
enum CaseState: String, Codable, CaseIterable, Identifiable {
    case open = "Open", active = "Active", review = "Review", closed = "Closed", archived = "Archived"
    var id: String { rawValue }
    var color: Color {
        switch self {
        case .open:     return StrataColor.steel
        case .active:   return StrataColor.teal
        case .review:   return StrataColor.amber
        case .closed:   return StrataColor.indigo
        case .archived: return StrataColor.steel
        }
    }
    /// Next state in the lifecycle, or nil at the end.
    var next: CaseState? {
        switch self {
        case .open: return .active;   case .active: return .review
        case .review: return .closed; case .closed: return .archived
        case .archived: return nil
        }
    }
    /// Closed/archived cases are frozen read-only.
    var isFrozen: Bool { self == .closed || self == .archived }
}

enum RetentionPolicy: String, Codable, CaseIterable, Identifiable {
    case tenYears           = "10 years (financial crime)"
    case sevenYears         = "7 years"
    case indefinite         = "Indefinite (active prosecution)"
    case untilCourtDisposal = "Until court disposal"
    var id: String { rawValue }
    /// Fixed length in years, or nil for open-ended policies.
    var years: Int? {
        switch self { case .tenYears: return 10; case .sevenYears: return 7; default: return nil }
    }
}

enum Disposition: String, Codable, CaseIterable, Identifiable {
    case retainSealed         = "Retain sealed in evidence store"
    case returnToOwner        = "Return to owner"
    case transferToProsecution = "Transfer to prosecution"
    case secureDestruction    = "Secure destruction (after retention)"
    var id: String { rawValue }
}

// MARK: - Case

struct DigitalCase: Codable, Identifiable, Hashable {
    var id = UUID()
    var reference: String          // "FIAU-2026-0114"
    var title: String
    var type: String               // from Settings.caseTypes
    var priority: CasePriority = .normal
    var classification: Classification = .confidential
    var requestingAuthority: String
    var legalBasis: String
    var authorizationRef: String
    var leadExaminer: String
    var dateOpened: Date = .now
    var synopsis: String = ""

    // Lifecycle
    var state: CaseState = .open
    var retention: RetentionPolicy = .tenYears
    var disposition: Disposition = .retainSealed
    var closedDate: Date? = nil
}

extension DigitalCase {
    /// Date evidence becomes eligible for disposition (close date + retention),
    /// or nil while open or under an open-ended policy.
    var disposeAfter: Date? {
        guard let closedDate, let years = retention.years else { return nil }
        return Calendar.current.date(byAdding: .year, value: years, to: closedDate)
    }

    /// Advance one step along the lifecycle. Closing stamps the close date.
    /// Returns false if already archived. State changes should be journaled
    /// by the caller via ActivityLog.
    @discardableResult
    mutating func advanceState(now: Date = .now) -> Bool {
        guard let n = state.next else { return false }
        state = n
        if n == .closed, closedDate == nil { closedDate = now }
        return true
    }
}

// MARK: - Evidence viewer: artifact taxonomy

enum ArtifactClass: String, Codable {
    case comms, web, system, security, persistence, location, user, media, device, accounts

    var accent: Color {
        switch self {
        case .comms, .accounts:  return StrataColor.teal
        case .web, .media:       return StrataColor.indigo
        case .system, .device:   return StrataColor.steel
        case .security:          return StrataColor.coral
        case .persistence, .user: return StrataColor.amber
        case .location:          return StrataColor.green
        }
    }
    var displayName: String {
        switch self {
        case .comms: return "Comms"; case .web: return "Web & usage"; case .system: return "System"
        case .security: return "Security"; case .persistence: return "Persistence"; case .location: return "Location"
        case .user: return "User"; case .media: return "Media"; case .device: return "Device"; case .accounts: return "Accounts"
        }
    }
}

/// A single parsed field in a record's detail (ordered, so use an array not a dict).
struct ArtifactField: Codable, Hashable {
    let key: String
    let value: String
    var isMono: Bool {
        key.range(of: #"url|path|sha|hash|fingerprint|serial|bssid"#, options: [.regularExpression, .caseInsensitive]) != nil
    }
}

struct ArtifactRecord: Codable, Identifiable, Hashable {
    var id = UUID()
    /// Sortable canonical timestamp "YYYY-MM-DD HH:MM:SS".
    var timestamp: String
    var title: String
    var source: String             // artifact path, e.g. "sms.db · iMessage"
    var fields: [ArtifactField]
    var raw: String? = nil         // optional raw artifact (EVTX XML, plist, syslog line)
}

struct ArtifactCategory: Codable, Identifiable, Hashable {
    var id = UUID()
    var key: String                // "ulog", "evtx", "msg", …
    var name: String
    var artifactClass: ArtifactClass
    /// SF Symbol or asset name for the category glyph (the HTML uses a small
    /// inline icon set; map to SF Symbols or ship matching assets).
    var symbol: String
    /// Realistic total in the image; `samples` is the parsed subset shown.
    var totalCount: Int
    var samples: [ArtifactRecord]
}

/// One exhibit's parsed evidence + filesystem, as shown in the viewer.
struct EvidenceSet: Codable, Identifiable, Hashable {
    var id = UUID()
    var exhibitID: UUID
    var os: OSFamily
    var categories: [ArtifactCategory]
    var fileTree: [FileNode]

    /// Flattened, time-sorted events for the unified timeline.
    func timeline(filter: ArtifactClass? = nil) -> [(category: ArtifactCategory, record: ArtifactRecord)] {
        categories
            .filter { filter == nil || $0.artifactClass == filter }
            .flatMap { cat in cat.samples.map { (category: cat, record: $0) } }
            .sorted { $0.record.timestamp < $1.record.timestamp }
    }

    /// Full-text search across titles, sources, and field key/values.
    func search(_ query: String) -> [(category: ArtifactCategory, record: ArtifactRecord)] {
        let q = query.lowercased()
        guard !q.isEmpty else { return [] }
        return categories.flatMap { cat in
            cat.samples.compactMap { rec -> (category: ArtifactCategory, record: ArtifactRecord)? in
                let hay = (rec.title + " " + rec.source + " " +
                           rec.fields.map { "\($0.key) \($0.value)" }.joined(separator: " ")).lowercased()
                return hay.contains(q) ? (category: cat, record: rec) : nil
            }
        }
    }
}

// MARK: - Filesystem tree (Files view)

struct FileNode: Codable, Identifiable, Hashable {
    var id = UUID()
    var name: String
    var isDirectory: Bool
    var size: String? = nil        // "482 MB", nil for directories
    var modified: String? = nil
    var children: [FileNode]? = nil
}

// MARK: - Settings (single source of truth for every dropdown)

struct Examiner: Codable, Identifiable, Hashable { var id = UUID(); var name: String; var role: String; var org: String }
struct Entity: Codable, Identifiable, Hashable { var id = UUID(); var name: String; var kind: String }
struct Tool: Codable, Identifiable, Hashable { var id = UUID(); var name: String; var type: String? = nil; var isAvailable: Bool = true }
struct HashAlgorithm: Codable, Identifiable, Hashable { var id = UUID(); var name: String; var isAvailable: Bool = true; var isDefault: Bool = false }

struct StrataSettings: Codable {
    var unitName: String = "FIAU Malta"
    var casePrefix: String = "FIAU"
    var timezone: String = "Europe/Malta (CEST)"
    var defaultClassification: Classification = .confidential

    var examiners: [Examiner] = []
    var entities: [Entity] = []
    var tools: [Tool] = []
    var writeBlockers: [Tool] = []
    var hashAlgorithms: [HashAlgorithm] = []

    var caseTypes: [String] = []
    var legalBases: [String] = []
    var acquisitionMethods: [String] = []
    var deviceTypes: [String] = []
    var transferPurposes: [String] = []
    var transferMethods: [String] = []
    var storageLocations: [String] = []

    // Convenience accessors the forms bind their dropdowns to.
    var examinerOptions: [String] { examiners.map { "\($0.name) — \($0.org)" } }
    var entityOptions: [String] { entities.map(\.name) }
    var availableTools: [String] { tools.filter(\.isAvailable).map(\.name) }
    var availableWriteBlockers: [String] { writeBlockers.filter(\.isAvailable).map(\.name) }
    var availableHashAlgorithms: [String] { hashAlgorithms.filter(\.isAvailable).map(\.name) }
    var defaultHashAlgorithm: String {
        hashAlgorithms.first { $0.isAvailable && $0.isDefault }?.name
            ?? hashAlgorithms.first(where: \.isAvailable)?.name ?? "SHA-256"
    }
}

// MARK: - Activity tint (ActivityCategory + Action live in ActivityLog.swift)

extension ActivityCategory {
    var color: Color {
        switch self {
        case .evidence:  return StrataColor.teal
        case .custody:   return StrataColor.indigo
        case .analysis:  return StrataColor.amber
        case .exports:   return StrataColor.green
        case .lifecycle: return StrataColor.steel
        case .settings:  return StrataColor.steel
        }
    }
}

extension ActivityEvent.Action {
    /// Mismatch is the one activity that should read as an alert.
    var isAlert: Bool { self == .integrityMismatch }
}
