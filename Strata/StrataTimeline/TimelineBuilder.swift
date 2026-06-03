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
                events.append(TimelineEvent(date: date, kind: kind, fileID: file.id,
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
}
