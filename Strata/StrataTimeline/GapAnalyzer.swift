import Foundation

/// A run of timeline events with no inter-event gap exceeding the analyst's
/// threshold. Useful for spotting interactive operator windows or focused
/// bursts of host activity.
public struct ActivitySession: Identifiable, Hashable, Sendable {
    public let id: UUID
    public let start: Date
    public let end: Date
    public let count: Int

    public var duration: TimeInterval { end.timeIntervalSince(start) }
}

/// A stretch of time bounded by two events whose inter-arrival gap exceeds
/// the threshold. In evtx-scoped analysis these are the prime tampering /
/// missing-telemetry signal (cleared logs, machine powered off, etc.).
public struct QuietGap: Identifiable, Hashable, Sendable {
    public let id: UUID
    public let start: Date    // last event before the gap
    public let end: Date      // first event after the gap

    public var duration: TimeInterval { end.timeIntervalSince(start) }
}

public enum GapAnalyzer {

    /// One-pass sessionization over a date-sorted event sequence. Caller must
    /// pre-sort - we don't pay the n log n every time the filter changes.
    /// `threshold` is the inter-arrival delta that separates one session from
    /// the next; values <= 0 fall back to a 1-hour default so a misconfigured
    /// stepper can't reduce everything to single-event sessions.
    ///
    /// `nonisolated` so callers can invoke us from a `Task.detached` without
    /// inheriting the app target's default MainActor isolation - Swift 6
    /// strict concurrency otherwise flags the call site as a violation.
    public nonisolated static func analyze(_ events: [TimelineEvent],
                                           threshold: TimeInterval) -> (sessions: [ActivitySession],
                                                                        gaps: [QuietGap]) {
        guard !events.isEmpty else { return ([], []) }
        let cutoff = threshold > 0 ? threshold : 3600

        var sessions: [ActivitySession] = []
        var gaps: [QuietGap] = []
        var sessionStart = events[0].date
        var sessionEnd   = events[0].date
        var sessionCount = 1

        for i in 1..<events.count {
            let prev = events[i - 1].date
            let curr = events[i].date
            if curr.timeIntervalSince(prev) > cutoff {
                sessions.append(ActivitySession(id: UUID(),
                                                start: sessionStart,
                                                end: sessionEnd,
                                                count: sessionCount))
                gaps.append(QuietGap(id: UUID(), start: prev, end: curr))
                sessionStart = curr
                sessionCount = 1
            } else {
                sessionCount += 1
            }
            sessionEnd = curr
        }
        sessions.append(ActivitySession(id: UUID(),
                                        start: sessionStart,
                                        end: sessionEnd,
                                        count: sessionCount))
        return (sessions, gaps)
    }
}
