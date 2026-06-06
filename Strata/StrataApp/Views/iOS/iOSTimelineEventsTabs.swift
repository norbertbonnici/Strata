#if !os(macOS)
import SwiftUI

// MARK: - Timeline tab

/// MACB-chip + day-grouped timeline list. Long lists chew memory on iPhone so
/// we render only the first `displayLimit` entries by default and offer a
/// "Show more" tail; this keeps the initial view snappy even on 1M-event
/// timelines.
struct TimelineTab: View {
    @EnvironmentObject private var model: AppModel
    @State private var filter: MACBFilter = .all
    @State private var query: String = ""
    @State private var displayLimit: Int = 200

    private let pageSize = 200

    /// Cross-tab filter for the MACB chip row. Mirrors the mockup's
    /// All/M/A/C/B options 1:1.
    enum MACBFilter: Hashable {
        case all, modified, accessed, changed, born

        var matchesAny: Bool { self == .all }
        var kind: MACBKind? {
            switch self {
            case .modified: return .modified
            case .accessed: return .accessed
            case .changed:  return .changed
            case .born:     return .born
            case .all:      return nil
            }
        }
    }

    private var filtered: [TimelineEvent] {
        let q = query.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        return model.timeline.filter { ev in
            if let kind = filter.kind, ev.kind != kind { return false }
            if !q.isEmpty, !ev.path.lowercased().contains(q) { return false }
            return true
        }
    }

    /// Newest-first grouping over the newest `displayLimit` slice. The source is
    /// sorted ascending, so we take the suffix (most recent) and sort days +
    /// within-day events descending — matching triage expectation and the
    /// Events tab. Forensic timestamps are absolute (UTC); bucketing in the
    /// device timezone would shift events across day boundaries, so we use a
    /// fixed UTC calendar.
    private func grouped(_ visible: [TimelineEvent]) -> [(String, [TimelineEvent])] {
        let window = visible.suffix(displayLimit)
        let groups = Dictionary(grouping: window) { ev in
            Self.utcCalendar.startOfDay(for: ev.date)
        }
        return groups
            .sorted { $0.key > $1.key }
            .map { (Self.dayLabel(for: $0.key), $0.value.sorted { $0.date > $1.date }) }
    }

    private static let utcCalendar: Calendar = {
        var c = Calendar(identifier: .gregorian)
        c.timeZone = TimeZone(identifier: "UTC")!
        return c
    }()

    var body: some View {
        let visible = filtered
        return ScrollView {
            VStack(alignment: .leading, spacing: 0) {
                LargeTitle(
                    title: "Timeline",
                    subtitle: subtitle)

                ChipRow(options: chipOptions, selection: $filter)
                    .padding(.bottom, 2)

                searchBar.padding(.horizontal, 16).padding(.bottom, 6)

                if model.timelineCount == 0 {
                    emptyState
                } else {
                    ForEach(grouped(visible), id: \.0) { (day, events) in
                        Text(day.uppercased())
                            .font(.system(size: 12.5, weight: .heavy))
                            .tracking(0.7)
                            .foregroundStyle(Theme.text3)
                            .padding(.horizontal, 22)
                            .padding(.top, 16)
                            .padding(.bottom, 6)

                        Card { tlRows(events) }
                    }
                    if visible.count > displayLimit {
                        Button {
                            displayLimit += pageSize
                        } label: {
                            Text("Show \(min(pageSize, visible.count - displayLimit)) more")
                                .font(.system(size: 13, weight: .semibold))
                                .frame(maxWidth: .infinity)
                                .padding(.vertical, 12)
                                .foregroundStyle(Theme.teal2)
                        }
                        .padding(.horizontal, 16)
                        .padding(.top, 8)
                    }
                }

                Spacer(minLength: 26)
            }
        }
        .background(Theme.bg.ignoresSafeArea())
        .toolbar(.hidden, for: .navigationBar)
        // Restart paging when the result set changes, else a deep displayLimit
        // dumps thousands of rows after a chip/search change.
        .onChange(of: filter) { displayLimit = pageSize }
        .onChange(of: query) { displayLimit = pageSize }
    }

    private var subtitle: String {
        let n = model.timelineCount
        let f = NumberFormatter(); f.numberStyle = .decimal
        let total = f.string(from: NSNumber(value: n)) ?? "\(n)"
        return "MACB · \(total) events"
    }

    private var chipOptions: [(MACBFilter, String)] {
        [(.all, "All"), (.modified, "Modified"), (.accessed, "Accessed"),
         (.changed, "Changed"), (.born, "Born")]
    }

    private var searchBar: some View {
        HStack(spacing: 8) {
            Image(systemName: "magnifyingglass")
                .font(.system(size: 13, weight: .semibold))
                .foregroundStyle(Theme.text3)
            TextField("Filter path", text: $query)
                .textInputAutocapitalization(.never)
                .autocorrectionDisabled()
                .font(.system(size: 13.5))
                .foregroundStyle(Theme.text)
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 9)
        .background(Theme.card)
        .overlay(RoundedRectangle(cornerRadius: 11).stroke(Theme.hair, lineWidth: 1))
        .clipShape(RoundedRectangle(cornerRadius: 11))
    }

    private var emptyState: some View {
        ContentUnavailableView(
            "No timeline yet",
            systemImage: "clock",
            description: Text("Open a case ingested on macOS to view its timeline here."))
            .padding(.top, 60)
            .frame(maxWidth: .infinity)
    }

    @ViewBuilder private func tlRows(_ events: [TimelineEvent]) -> some View {
        ForEach(events) { ev in
            HStack(spacing: 11) {
                Text(Self.timeLabel.string(from: ev.date))
                    .font(.system(size: 12, design: .monospaced))
                    .foregroundStyle(Theme.text2)
                    .frame(width: 58, alignment: .leading)

                Text(Theme.macbLetter(ev.kind))
                    .font(.system(size: 11, weight: .heavy, design: .monospaced))
                    .frame(width: 21, height: 21)
                    .background(Theme.macbColor(ev.kind).opacity(0.18))
                    .foregroundStyle(Theme.macbColor(ev.kind))
                    .clipShape(RoundedRectangle(cornerRadius: 6))

                Text(ev.path)
                    .font(.system(size: 12, design: .monospaced))
                    .foregroundStyle(Theme.text)
                    .lineLimit(1)
                    .truncationMode(.middle)
                    .frame(maxWidth: .infinity, alignment: .leading)

                if ev.isDeleted { DeletedBadge() }
            }
            .padding(.horizontal, 14)
            .padding(.vertical, 11)
            .overlay(alignment: .bottom) {
                Divider().background(Theme.hair2)
            }
        }
    }

    private static let timeLabel: DateFormatter = {
        let f = DateFormatter()
        f.dateFormat = "HH:mm:ss"
        f.locale = Locale(identifier: "en_US_POSIX")
        f.timeZone = TimeZone(identifier: "UTC")   // forensic timestamps are UTC
        return f
    }()

    // Hoisted formatter (was re-allocated per call in the grouping hot path).
    private static let dayFmt: DateFormatter = {
        let f = DateFormatter()
        f.dateFormat = "MMM d, yyyy"
        f.locale = Locale(identifier: "en_US_POSIX")
        f.timeZone = TimeZone(identifier: "UTC")
        return f
    }()

    private static func dayLabel(for date: Date) -> String { dayFmt.string(from: date) }
}

// MARK: - Events tab

/// Source-chipped event list. Sysmon/Security/System mirror the mockup; an
/// "All" chip puts the cap back. Severity dot derives from EVTX level, EID
/// pill is monospaced.
struct EventsTab: View {
    @EnvironmentObject private var model: AppModel
    @State private var filter: SourceFilter = .all
    @State private var displayLimit: Int = 200

    private let pageSize = 200

    enum SourceFilter: Hashable {
        case all, security, sysmon, system

        var channelMatches: (String) -> Bool {
            switch self {
            case .all:      return { _ in true }
            case .security: return { $0.localizedCaseInsensitiveContains("security") }
            // Match Sysmon precisely - the old "operational" clause also matched
            // every <Provider>/Operational channel (PowerShell, WinRM, ...).
            case .sysmon:   return { $0.localizedCaseInsensitiveContains("sysmon") }
            case .system:   return { $0.localizedCaseInsensitiveContains("system") }
            }
        }
    }

    private var filtered: [EventLogRecord] {
        model.events.filter { filter.channelMatches($0.channel) }
    }

    var body: some View {
        let visible = filtered
        return ScrollView {
            VStack(alignment: .leading, spacing: 0) {
                LargeTitle(
                    title: "Events",
                    subtitle: subtitle)

                ChipRow(options: chipOptions, selection: $filter)
                    .padding(.bottom, 4)

                if model.eventCount == 0 {
                    emptyState
                } else {
                    Card { eventRows(visible) }.padding(.top, 8)

                    if visible.count > displayLimit {
                        Button {
                            displayLimit += pageSize
                        } label: {
                            Text("Show \(min(pageSize, visible.count - displayLimit)) more")
                                .font(.system(size: 13, weight: .semibold))
                                .frame(maxWidth: .infinity)
                                .padding(.vertical, 12)
                                .foregroundStyle(Theme.teal2)
                        }
                        .padding(.horizontal, 16)
                        .padding(.top, 8)
                    }
                }

                Spacer(minLength: 26)
            }
        }
        .background(Theme.bg.ignoresSafeArea())
        .toolbar(.hidden, for: .navigationBar)
        .onChange(of: filter) { displayLimit = pageSize }   // restart paging on chip change
    }

    private var subtitle: String {
        let n = model.eventCount
        let f = NumberFormatter(); f.numberStyle = .decimal
        return "Parsed · \(f.string(from: NSNumber(value: n)) ?? "0") records"
    }

    private var chipOptions: [(SourceFilter, String)] {
        [(.all, "All"), (.security, "Security"), (.sysmon, "Sysmon"), (.system, "System")]
    }

    private var emptyState: some View {
        ContentUnavailableView(
            "No events yet",
            systemImage: "doc.text.magnifyingglass",
            description: Text("Event logs are parsed on macOS; reopen the case once they're populated."))
            .padding(.top, 60)
            .frame(maxWidth: .infinity)
    }

    @ViewBuilder private func eventRows(_ visible: [EventLogRecord]) -> some View {
        // Newest-first: source is ascending, so take the newest slice and
        // reverse for display (consistent with the Timeline tab).
        let window = Array(visible.suffix(displayLimit).reversed())
        ForEach(window) { ev in
            HStack(spacing: 11) {
                SeverityDot(color: levelColor(ev.level))
                Pill(text: "\(ev.eventID)")
                VStack(alignment: .leading, spacing: 1) {
                    Text(ev.channel.isEmpty ? ev.provider : ev.channel)
                        .font(.system(size: 11, weight: .semibold))
                        .foregroundStyle(Theme.teal2)
                        .lineLimit(1)
                    Text(describe(ev))
                        .font(.system(size: 13))
                        .foregroundStyle(Theme.text)
                        .lineLimit(2)
                }
                .frame(maxWidth: .infinity, alignment: .leading)
                Text(Self.timeFmt.string(from: ev.writtenAt))
                    .font(.system(size: 11, design: .monospaced))
                    .foregroundStyle(Theme.text3)
            }
            .padding(.horizontal, 14)
            .padding(.vertical, 12)
            .overlay(alignment: .bottom) {
                Divider().background(Theme.hair2)
            }
        }
    }

    /// Map the EVTX level field (1=Crit, 2=Err, 3=Warn, 4=Info, 0=Verbose)
    /// onto our finding-severity palette so the same eye-line works across
    /// every tab.
    private func levelColor(_ level: UInt8) -> Color {
        switch level {
        case 1: return Theme.crit
        case 2: return Theme.high
        case 3: return Theme.med
        case 4: return Theme.low
        default: return Theme.info
        }
    }

    /// Cheap one-line description — provider + payload fragment. Avoids
    /// XML parsing on the hot path; the full payload is available in the
    /// detail screen which we haven't ported to iOS yet.
    private func describe(_ ev: EventLogRecord) -> String {
        if !ev.provider.isEmpty { return "\(ev.provider) · EID \(ev.eventID)" }
        return "EID \(ev.eventID) on \(ev.computer)"
    }

    private static let timeFmt: DateFormatter = {
        let f = DateFormatter()
        f.dateFormat = "HH:mm:ss"
        f.locale = Locale(identifier: "en_US_POSIX")
        f.timeZone = TimeZone(identifier: "UTC")   // forensic timestamps are UTC
        return f
    }()
}
#endif
