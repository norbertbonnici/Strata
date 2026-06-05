import Foundation

/// Expands FileEntry timestamps into discrete timeline events - the same model
/// TSK's `mactime` uses: one event per non-empty MACB timestamp.
public enum TimelineBuilder {

    public static func build(from files: [FileEntry]) -> [TimelineEvent] {
        var events: [TimelineEvent] = []
        events.reserveCapacity(files.count * 2)

        for file in files {
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
                             in range: ClosedRange<Date>) -> [TimelineEvent] {
        build(from: files).filter { range.contains($0.date) }
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
}
