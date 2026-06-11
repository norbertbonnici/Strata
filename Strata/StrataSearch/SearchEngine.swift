import Foundation

/// One result of a global, cross-artifact search.
///
/// A `SearchHit` is a flattened, presentation-ready projection of a match in
/// one of the case's underlying collections (files, event-log records, registry
/// values, timeline events, findings). It carries:
///
/// - a `kind` so the UI can route a click to the right tab/inspector,
/// - human-readable `title` / `subtitle` / `snippet` for the result row,
/// - a `score` so callers can rank (the engine pre-sorts, but the field is kept
///   so a view can re-rank or merge across queries),
/// - a `reference` discriminated union that locates the source object
///   (file `obj_id`, event/registry/finding `UUID`, or a timeline `stableKey`),
///   so selecting a hit can pivot to the real record without a re-search.
///
/// Pure value type: `Identifiable` for SwiftUI lists, `Sendable` so the whole
/// search can run in a `Task.detached` off the main actor.
public nonisolated struct SearchHit: Identifiable, Hashable, Sendable {

    /// Which collection produced the hit — drives the result icon and the pivot.
    public enum Kind: String, Sendable, Hashable, CaseIterable {
        case file
        case event
        case registry
        case timeline
        case finding

        public var label: String {
            switch self {
            case .file:     return "File"
            case .event:    return "Event Log"
            case .registry: return "Registry"
            case .timeline: return "Timeline"
            case .finding:  return "Finding"
            }
        }
    }

    /// A back-reference to the matched source object, so a UI can locate and
    /// reveal it after a click. Each case carries the stable identity that the
    /// corresponding model already exposes (no fresh UUIDs minted here).
    public enum Reference: Hashable, Sendable {
        /// `FileEntry.id` — the TSK `obj_id`.
        case file(id: Int64, path: String)
        /// `EventLogRecord.id`.
        case event(id: UUID)
        /// `RegistryValue.id`.
        case registry(id: UUID)
        /// `TimelineEvent.stableKey` (the per-load UUID is not stable; the
        /// content-derived key is what persisted state keys off).
        case timeline(stableKey: String)
        /// `Finding.id`.
        case finding(id: UUID)
    }

    public let id: UUID
    public let kind: Kind
    public let title: String
    public let subtitle: String
    /// A short excerpt of the matched text (the field that actually matched,
    /// trimmed/collapsed), for the result row's secondary line.
    public let snippet: String
    /// Relevance score; higher is better. The engine returns hits already sorted
    /// descending by this (ties broken by kind then title for stable ordering).
    public let score: Int
    public let reference: Reference

    public init(id: UUID = UUID(), kind: Kind, title: String, subtitle: String,
                snippet: String, score: Int, reference: Reference) {
        self.id = id
        self.kind = kind
        self.title = title
        self.subtitle = subtitle
        self.snippet = snippet
        self.score = score
        self.reference = reference
    }
}

/// Pure, stateless, cross-artifact search over an already-loaded case.
///
/// The engine takes snapshots of the five searchable collections and returns a
/// ranked, capped list of `SearchHit`s for a case-insensitive substring query.
/// It does no I/O and holds no state, so a single `static` entry point keeps
/// callers from having to thread an instance around; everything is `Sendable`
/// and the whole call is safe to run off the main actor.
///
/// Ranking model (see `Score`): an *exact* match of the query against a salient
/// identifier (file name, registry value name, event channel/EID, finding
/// title) outranks a name/title *prefix*, which outranks a substring hit in a
/// name/title, which outranks a hit anywhere in the "body" (path, payload XML,
/// registry data, finding detail, timeline detail). Each collection scans in
/// O(n) over its members; the final sort is O(k log k) over the matched hits,
/// and the result is truncated to `limit`.
public nonisolated struct SearchEngine: Sendable {

    /// Queries shorter than this never match — a 1-character substring search
    /// across a whole case is all noise. Callers should also debounce.
    public static let minimumQueryLength = 2

    // MARK: Score bands (kept ordered so the intent is legible at the call site)

    private enum Score {
        static let exactName  = 100   // query == a salient identifier
        static let namePrefix = 70    // identifier starts with query
        static let nameMatch  = 50    // identifier contains query
        static let bodyMatch  = 20    // query found in a secondary/body field
        // Small kind bias so that, all else equal, high-signal artifacts
        // (findings, registry) float above raw filesystem noise.
        static func kindBias(_ kind: SearchHit.Kind) -> Int {
            switch kind {
            case .finding:  return 5
            case .registry: return 4
            case .event:    return 3
            case .timeline: return 2
            case .file:     return 1
            }
        }
    }

    public init() {}

    /// Run the search.
    ///
    /// - Parameters:
    ///   - query: the user's raw search string. Trimmed; case-folded internally.
    ///     Empty or shorter than ``minimumQueryLength`` after trimming → `[]`.
    ///   - files / events / registry / timeline / findings: the case snapshots.
    ///     Any may be empty.
    ///   - limit: maximum hits to return (default 500). The engine ranks the
    ///     full match set, then truncates — so the cap keeps the *best* hits.
    /// - Returns: hits sorted by descending score (stable tie-break), capped.
    public static func search(query rawQuery: String,
                              files: [FileEntry] = [],
                              events: [EventLogRecord] = [],
                              registry: [RegistryValue] = [],
                              timeline: [TimelineEvent] = [],
                              findings: [Finding] = [],
                              limit: Int = 500) -> [SearchHit] {
        let trimmed = rawQuery.trimmingCharacters(in: .whitespacesAndNewlines)
        guard trimmed.count >= minimumQueryLength, limit > 0 else { return [] }
        let needle = trimmed.lowercased()

        var hits: [SearchHit] = []
        // Rough reserve: most queries match a small fraction; avoid churn on big cases.
        hits.reserveCapacity(min(limit * 2, 1024))

        appendFileHits(into: &hits, needle: needle, files: files)
        appendEventHits(into: &hits, needle: needle, events: events)
        appendRegistryHits(into: &hits, needle: needle, registry: registry)
        appendTimelineHits(into: &hits, needle: needle, timeline: timeline)
        appendFindingHits(into: &hits, needle: needle, findings: findings)

        // Rank: score desc, then a deterministic tie-break so paging is stable.
        hits.sort { a, b in
            if a.score != b.score { return a.score > b.score }
            if a.kind != b.kind { return a.kind.rawValue < b.kind.rawValue }
            if a.title != b.title { return a.title < b.title }
            return a.snippet < b.snippet
        }
        if hits.count > limit { hits.removeLast(hits.count - limit) }
        return hits
    }

    // MARK: - Per-collection scanners

    private static func appendFileHits(into hits: inout [SearchHit],
                                       needle: String, files: [FileEntry]) {
        for f in files {
            let nameScore = identifierScore(f.name, needle: needle)
            let path = f.fullPath
            if let s = nameScore {
                hits.append(SearchHit(
                    kind: .file, title: f.name, subtitle: f.parentPath,
                    snippet: path, score: s + Score.kindBias(.file),
                    reference: .file(id: f.id, path: path)))
            } else if path.lowercased().contains(needle) {
                // Matched only on the directory portion of the path.
                hits.append(SearchHit(
                    kind: .file, title: f.name, subtitle: f.parentPath,
                    snippet: excerpt(path, around: needle),
                    score: Score.bodyMatch + Score.kindBias(.file),
                    reference: .file(id: f.id, path: path)))
            }
        }
    }

    private static func appendEventHits(into hits: inout [SearchHit],
                                        needle: String, events: [EventLogRecord]) {
        for e in events {
            let eidString = String(e.eventID)
            // Salient identifiers for an event: the channel, the provider, and
            // the (string-rendered) event ID. Take the strongest of these.
            let identifierScores = [
                identifierScore(e.channel, needle: needle),
                identifierScore(e.provider, needle: needle),
                identifierScore(eidString, needle: needle),
            ].compactMap { $0 }
            let title = "\(e.channel) — Event \(eidString)"
            let subtitle = e.provider.isEmpty ? e.computer : e.provider

            if let best = identifierScores.max() {
                hits.append(SearchHit(
                    kind: .event, title: title, subtitle: subtitle,
                    snippet: payloadSnippet(e, needle: needle),
                    score: best + Score.kindBias(.event),
                    reference: .event(id: e.id)))
            } else if e.payloadXML.lowercased().contains(needle)
                        || e.computer.lowercased().contains(needle) {
                hits.append(SearchHit(
                    kind: .event, title: title, subtitle: subtitle,
                    snippet: payloadSnippet(e, needle: needle),
                    score: Score.bodyMatch + Score.kindBias(.event),
                    reference: .event(id: e.id)))
            }
        }
    }

    private static func appendRegistryHits(into hits: inout [SearchHit],
                                           needle: String, registry: [RegistryValue]) {
        for v in registry {
            // The value name is the prime identifier; hive + path are body.
            let nameScore = identifierScore(v.name, needle: needle)
            let full = v.fullPath
            let displayName = v.name.isEmpty ? "(Default)" : v.name
            if let s = nameScore {
                hits.append(SearchHit(
                    kind: .registry, title: displayName, subtitle: full,
                    snippet: v.data.isEmpty ? full : excerpt(v.data, around: needle),
                    score: s + Score.kindBias(.registry),
                    reference: .registry(id: v.id)))
            } else if full.lowercased().contains(needle)
                        || v.hive.lowercased().contains(needle)
                        || v.data.lowercased().contains(needle) {
                let dataHit = v.data.lowercased().contains(needle)
                hits.append(SearchHit(
                    kind: .registry, title: displayName, subtitle: full,
                    snippet: dataHit ? excerpt(v.data, around: needle) : full,
                    score: Score.bodyMatch + Score.kindBias(.registry),
                    reference: .registry(id: v.id)))
            }
        }
    }

    private static func appendTimelineHits(into hits: inout [SearchHit],
                                           needle: String, timeline: [TimelineEvent]) {
        for ev in timeline {
            // The path is a timeline event's only free-text "detail". A path-tail
            // match (the file/leaf) is stronger than a deep-in-the-path match.
            guard ev.path.lowercased().contains(needle) else { continue }
            let leaf = (ev.path as NSString).lastPathComponent
            let leafScore = identifierScore(leaf, needle: needle)
            let score = (leafScore ?? Score.bodyMatch) + Score.kindBias(.timeline)
            hits.append(SearchHit(
                kind: .timeline,
                title: leaf.isEmpty ? ev.path : leaf,
                subtitle: "\(ev.source.label) · \(ev.kind.label)",
                snippet: excerpt(ev.path, around: needle),
                score: score,
                reference: .timeline(stableKey: ev.stableKey)))
        }
    }

    private static func appendFindingHits(into hits: inout [SearchHit],
                                          needle: String, findings: [Finding]) {
        for f in findings {
            let titleScore = identifierScore(f.title, needle: needle)
            let subtitle = f.technique.map { "\($0.attackID) · \(f.phase.title)" } ?? f.phase.title
            if let s = titleScore {
                hits.append(SearchHit(
                    kind: .finding, title: f.title, subtitle: subtitle,
                    snippet: excerpt(f.detail, around: needle),
                    score: s + Score.kindBias(.finding),
                    reference: .finding(id: f.id)))
            } else if f.detail.lowercased().contains(needle)
                        || (f.technique?.attackID.lowercased().contains(needle) ?? false)
                        || (f.technique?.name.lowercased().contains(needle) ?? false)
                        || f.evidencePaths.contains(where: { $0.lowercased().contains(needle) }) {
                hits.append(SearchHit(
                    kind: .finding, title: f.title, subtitle: subtitle,
                    snippet: excerpt(f.detail, around: needle),
                    score: Score.bodyMatch + Score.kindBias(.finding),
                    reference: .finding(id: f.id)))
            }
        }
    }

    // MARK: - Scoring & snippet helpers

    /// Score `value` as a *salient identifier* against the (already-lowercased)
    /// `needle`. nil ⇒ no match in this identifier. Exact > prefix > contains.
    private static func identifierScore(_ value: String, needle: String) -> Int? {
        guard !value.isEmpty else { return nil }
        let lowered = value.lowercased()
        if lowered == needle { return Score.exactName }
        if lowered.hasPrefix(needle) { return Score.namePrefix }
        if lowered.contains(needle) { return Score.nameMatch }
        return nil
    }

    /// Build the event snippet: prefer a window around the needle in the
    /// payload; fall back to the (collapsed) payload head.
    private static func payloadSnippet(_ e: EventLogRecord, needle: String) -> String {
        let xml = collapseWhitespace(e.payloadXML)
        if xml.lowercased().contains(needle) {
            return excerpt(xml, around: needle)
        }
        return String(xml.prefix(120))
    }

    /// A short, whitespace-collapsed excerpt of `text` centered on the first
    /// occurrence of `needle` (case-insensitive). If `needle` isn't present,
    /// returns the head of the text. Used for the secondary result line.
    private static func excerpt(_ text: String, around needle: String,
                                window: Int = 80) -> String {
        let collapsed = collapseWhitespace(text)
        guard !collapsed.isEmpty else { return "" }
        let lower = collapsed.lowercased()
        guard let r = lower.range(of: needle) else {
            return String(collapsed.prefix(window))
        }
        let matchStart = collapsed.distance(from: collapsed.startIndex, to: r.lowerBound)
        let half = max(0, (window - needle.count) / 2)
        let startOffset = max(0, matchStart - half)
        let start = collapsed.index(collapsed.startIndex, offsetBy: startOffset)
        let end = collapsed.index(start, offsetBy: window, limitedBy: collapsed.endIndex)
            ?? collapsed.endIndex
        var out = String(collapsed[start..<end])
        if startOffset > 0 { out = "…" + out }
        if end < collapsed.endIndex { out += "…" }
        return out
    }

    /// Collapse runs of whitespace/newlines to single spaces and trim — keeps
    /// XML/multi-line registry data readable on one result line.
    private static func collapseWhitespace(_ s: String) -> String {
        s.split(whereSeparator: { $0 == " " || $0 == "\n" || $0 == "\r" || $0 == "\t" })
            .joined(separator: " ")
    }
}
