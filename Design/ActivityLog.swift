//
//  ActivityLog.swift
//  Strata
//
//  A tamper-evident record of what the examiner did — opened an image, ran a
//  parser, recorded custody, exported a report. This is NOT access control and
//  NOT an admin policing users: on a single-Mac build there's one authenticated
//  operator. It exists for *defensibility and reproducibility of your own work*,
//  which matters even solo, and it costs almost nothing because it reuses the
//  custody hash-chain pattern.
//
//  Append-only by contract: you never edit or delete an entry, only add. Each
//  entry hashes over its content + the previous entry's hash (via the shared
//  `Hashing.sha256Hex` in CustodyChain.swift), so any later tampering with a
//  past entry is detectable by `verify()`.
//
//  Foundation-only on purpose (no SwiftUI/CryptoKit beyond the shared helper) so
//  it unit-tests cleanly. Display tint lives in Domain.swift.
//
//  IDENTITY, NOT ENFORCEMENT: `actor` records *who* did something. It's modeled,
//  not enforced — there's no server to check a role against, and local files are
//  readable by whoever holds them. Treat actor as provenance, not a gate.
//

import Foundation
// Hashing { sha256Hex } is defined in CustodyChain.swift.

// MARK: - Activity event

struct ActivityEvent: Codable, Identifiable, Hashable {
    enum Action: String, Codable {
        case caseOpened          = "Opened case"
        case imageIngested       = "Ingested image"
        case imageProcessed      = "Processed image"
        case parserRun           = "Ran parser"
        case findingTagged       = "Tagged finding"
        case custodyRecorded     = "Recorded custody"
        case custodyTransferred  = "Transferred custody"
        case evidenceVerified    = "Verified evidence hash"
        case integrityMismatch   = "Integrity mismatch"
        case reportGenerated     = "Generated report"
        case reportExported      = "Exported report"
        case caseStateChanged    = "Changed case state"
        case settingsChanged     = "Changed settings"

        var category: ActivityCategory {
            switch self {
            case .imageIngested, .imageProcessed, .parserRun, .evidenceVerified, .integrityMismatch:
                return .evidence
            case .custodyRecorded, .custodyTransferred:        return .custody
            case .findingTagged:                                return .analysis
            case .reportGenerated, .reportExported:            return .exports
            case .caseOpened, .caseStateChanged:               return .lifecycle
            case .settingsChanged:                              return .settings
            }
        }
    }

    var id = UUID()
    /// Canonical, sortable timestamp, e.g. "2026-06-14 11:08Z".
    var timestamp: String
    /// Examiner name — provenance, not an enforced identity (see file header).
    var actor: String
    var action: Action
    /// What it acted on: exhibit / case / finding reference.
    var target: String
    /// Human-readable summary line.
    var detail: String

    // Chain linkage — set by ActivityLog.record(); never by hand.
    var prevHash: String = "GENESIS"
    var entryHash: String = ""

    func canonical() -> String {
        [timestamp, actor, action.rawValue, target, detail]
            .joined(separator: ActivityLog.separator)
    }
}

enum ActivityCategory: String, Codable, CaseIterable, Identifiable {
    case evidence, custody, analysis, exports, lifecycle, settings
    var id: String { rawValue }
    var label: String { rawValue.capitalized }
}

// MARK: - Activity log (append-only, hash-linked)

struct ActivityLog: Codable {
    /// U+00A6 BROKEN BAR — same on-disk separator convention as the custody chain.
    static let separator = "\u{00A6}"
    static let genesis = "GENESIS"

    private(set) var events: [ActivityEvent] = []

    /// Append one entry, linking it to the tail of the chain. The only mutation
    /// this type allows — there is deliberately no edit or delete.
    mutating func record(_ event: ActivityEvent) {
        var e = event
        e.prevHash = events.last?.entryHash ?? Self.genesis
        e.entryHash = Hashing.sha256Hex(e.canonical() + Self.separator + e.prevHash)
        events.append(e)
    }

    /// Convenience for the common call site.
    mutating func log(_ action: ActivityEvent.Action, by actor: String,
                      target: String, detail: String, at timestamp: String) {
        record(ActivityEvent(timestamp: timestamp, actor: actor, action: action,
                             target: target, detail: detail))
    }

    /// Re-walk the chain; returns the first broken index, or nil if intact.
    func verify() -> Int? {
        var prev = Self.genesis
        for (i, e) in events.enumerated() {
            let expected = Hashing.sha256Hex(e.canonical() + Self.separator + e.prevHash)
            if e.prevHash != prev || expected != e.entryHash { return i }
            prev = e.entryHash
        }
        return nil
    }

    func events(in category: ActivityCategory) -> [ActivityEvent] {
        events.filter { $0.action.category == category }
    }
}

// MARK: - Self-check

#if DEBUG
extension ActivityLog {
    /// Append builds a valid chain; a covert edit to a past entry breaks it.
    static func runSelfCheck() -> Bool {
        var log = ActivityLog()
        log.log(.caseOpened, by: "N. Borg", target: "FIAU-2026-0114", detail: "opened", at: "t0")
        log.log(.imageIngested, by: "N. Borg", target: "EXH-001", detail: "win11", at: "t1")
        log.log(.reportExported, by: "A. Vella", target: "EXH-001", detail: "pdf", at: "t2")
        guard log.verify() == nil else { return false }              // valid chain

        log.events[1].detail += " [edited]"                          // tamper, no relink
        guard log.verify() == 1 else { return false }                // breaks at the edit
        return true
    }
}
#endif
