import Foundation

/// Expands FileEntry timestamps into discrete timeline events - the same model
/// TSK's `mactime` uses: one event per non-empty MACB timestamp.
///
/// `nonisolated` so the (pure, value-in/value-out) build can run off the main
/// actor during case load - see `AppModel.loadEvidenceState`.
public nonisolated enum TimelineBuilder {

    /// TSK emits a `<name>-slack` pseudo-entry for every allocated cluster's
    /// trailing slack space. These carry 1980-epoch timestamps and inflate
    /// the timeline by orders of magnitude without forensic value most of
    /// the time, so callers can opt to drop them at build time. The macOS
    /// UI exposes this as a toggle; the iOS load path forces it on because
    /// the timeline simply won't fit in phone memory otherwise.
    public static func isSlackEntry(_ file: FileEntry) -> Bool {
        file.name.hasSuffix("-slack")
    }

    public static func build(from files: [FileEntry],
                             excludeSlack: Bool = false) -> [TimelineEvent] {
        var events: [TimelineEvent] = []
        events.reserveCapacity(files.count * 2)

        for file in files {
            if excludeSlack, isSlackEntry(file) { continue }
            func add(_ date: Date?, _ kind: MACBKind) {
                guard let date else { return }
                events.append(TimelineEvent(date: date, kind: kind, source: .filesystem,
                                            fileID: file.id,
                                            path: file.fullPath, size: file.size,
                                            isDeleted: file.isDeleted))
            }
            add(file.modified, .modified)
            add(file.accessed, .accessed)
            add(file.changed, .changed)
            add(file.created, .born)
        }
        return events.sorted { $0.date < $1.date }
    }

    /// Events within a closed date range.
    public static func build(from files: [FileEntry],
                             in range: ClosedRange<Date>,
                             excludeSlack: Bool = false) -> [TimelineEvent] {
        build(from: files, excludeSlack: excludeSlack).filter { range.contains($0.date) }
    }

    /// Project Windows event log records onto the timeline so analysts can
    /// sessionize over real host activity instead of MACB noise. We surface
    /// one event per record; `kind` is forced to `.changed` (the closest fs
    /// analogue - "something happened") and the path encodes channel + EID
    /// so the table row stays readable.
    public static func build(from records: [EventLogRecord]) -> [TimelineEvent] {
        var events: [TimelineEvent] = []
        events.reserveCapacity(records.count)
        for record in records {
            // Path is now just the channel - the EID renders in its own
            // column. We keep it in `path` too so the existing free-text
            // search ("Security", "Sysmon") still matches.
            events.append(TimelineEvent(date: record.writtenAt,
                                        kind: .changed,
                                        source: .evtx,
                                        fileID: 0,
                                        path: record.channel,
                                        size: 0,
                                        isDeleted: false,
                                        eventID: record.eventID))
        }
        return events.sorted { $0.date < $1.date }
    }

    /// Project USN journal records onto the timeline. `kind` reflects the change
    /// (.born for create, .changed otherwise); the path encodes the filename +
    /// reasons so the row reads well and free-text search matches; `isDeleted`
    /// surfaces deletes. Records without a timestamp are dropped.
    public static func build(from records: [UsnRecord]) -> [TimelineEvent] {
        var events: [TimelineEvent] = []
        events.reserveCapacity(records.count)
        for record in records {
            guard let date = record.timestamp else { continue }
            events.append(TimelineEvent(date: date,
                                        kind: record.isCreate ? .born : .changed,
                                        source: .usn,
                                        fileID: 0,
                                        path: "\(record.fileName)  [\(record.reasonSummary)]",
                                        size: 0,
                                        isDeleted: record.isDelete))
        }
        return events.sorted { $0.date < $1.date }
    }

    /// Project SRUM rows onto the timeline. `kind` is `.changed` (the closest fs
    /// analogue for "activity recorded"); the path encodes the app + a kind/detail
    /// summary so the row reads well and free-text search matches. Rows without a
    /// timestamp are dropped.
    public static func build(from records: [SrumEntry]) -> [TimelineEvent] {
        var events: [TimelineEvent] = []
        events.reserveCapacity(records.count)
        for record in records {
            guard let date = record.timestamp else { continue }
            events.append(TimelineEvent(date: date,
                                        kind: .changed,
                                        source: .srum,
                                        fileID: 0,
                                        path: "\(record.appShortName)  [\(record.kind.label): \(record.detailSummary)]",
                                        size: 0,
                                        isDeleted: false))
        }
        return events.sorted { $0.date < $1.date }
    }
}
