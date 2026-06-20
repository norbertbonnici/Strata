import SwiftUI

struct TimelineView: View {
    @EnvironmentObject private var model: AppModel
    @State private var enabledKinds: Set<MACBKind> = Set(MACBKind.allCases)
    /// First-render source selection. Seeded once from
    /// `model.defaultTimelineSources` (the populated *bounded* sources -
    /// Event Log on Windows, the auth/journal/syslog/login set on Linux) so the
    /// timeline isn't blank on a non-Windows image. The unbounded sources
    /// (filesystem MACB, USN, MFT) stay off until the analyst enables them, since
    /// they expand to millions of rows. `.evtx` is a placeholder until the
    /// one-time seed runs (see `initSourcesIfNeeded`).
    @State private var enabledSources: Set<TimelineSource> = [.evtx]
    /// Guards the one-time seed of `enabledSources` so it doesn't clobber the
    /// analyst's manual source toggles on a later re-render.
    @State private var didSeedSources = false
    @State private var query = ""
    @State private var dateSelection: ClosedRange<Date>?
    /// Restrict to bookmarked events only (the analyst's pinned story).
    @State private var bookmarksOnly = false
    /// Table selection - enables the row context menu (bookmarking).
    @State private var selection = Set<TimelineEvent.ID>()
    /// TSK emits a `<name>-slack` pseudo-entry for every allocated cluster's
    /// trailing slack. They carry epoch (1980) timestamps that swamp the
    /// histogram and clutter the table, so we hide them by default.
    @State private var hideSlack = true

    /// Gap-analysis controls. Default 60 min mirrors the typical DFIR
    /// triage threshold for "operator session boundary"; analysts can dial
    /// it up to surface multi-hour log silence or down to find tight bursts.
    @State private var showGapAnalysis = false
    @State private var gapThresholdMinutes: Int = 60

    /// Filtered event set + its full date extent. Derived on a background
    /// task whenever filter inputs change so per-render body invocations
    /// (e.g. drag updates) don't re-scan ~1M events.
    @State private var afterToggles: [TimelineEvent] = []
    @State private var fullExtent: ClosedRange<Date>?
    @State private var isDeriving = false

    /// Date-narrowed slice + total count, also cached to avoid an O(n)
    /// filter per body invocation. `tableRows` is capped to `maxTableRows`
    /// because handing SwiftUI's Table millions of identifiable rows
    /// exhausts the AttributeGraph data space.
    @State private var tableRows: [TimelineEvent] = []
    @State private var tableTotal: Int = 0

    /// Cached gap-analysis output for the current filter set. Recomputed
    /// on the same background pass as `afterToggles` to keep the panel in
    /// sync with the source/kind toggles.
    @State private var sessions: [ActivitySession] = []
    @State private var gaps: [QuietGap] = []

    private static let maxTableRows = 20_000

    private struct DeriveKey: Equatable {
        let timelineCount: Int
        let kinds: Set<MACBKind>
        let sources: Set<TimelineSource>
        let hideSlack: Bool
        let query: String
        let gapThresholdMinutes: Int
        let bookmarksOnly: Bool
        let annotationCount: Int   // re-derive the bookmark filter on add/remove
    }

    private var deriveKey: DeriveKey {
        DeriveKey(timelineCount: model.timelineCount,
                  kinds: enabledKinds,
                  sources: enabledSources,
                  hideSlack: hideSlack,
                  query: query,
                  gapThresholdMinutes: gapThresholdMinutes,
                  bookmarksOnly: bookmarksOnly,
                  annotationCount: model.annotations.count)
    }

    private struct TableKey: Equatable {
        let toggleCount: Int
        let lower: Date?
        let upper: Date?
    }

    private var tableKey: TableKey {
        TableKey(toggleCount: afterToggles.count,
                 lower: dateSelection?.lowerBound,
                 upper: dateSelection?.upperBound)
    }

    var body: some View {
        VStack(spacing: 0) {
            HStack {
                ForEach(MACBKind.allCases, id: \.self) { kind in
                    Toggle(kind.label, isOn: Binding(
                        get: { enabledKinds.contains(kind) },
                        set: { on in
                            if on { enabledKinds.insert(kind) } else { enabledKinds.remove(kind) }
                        }))
                        .toggleStyle(.button)
                        .controlSize(.small)
                }
                Divider().frame(height: 16)
                // Twelve sources no longer fit as inline chips - a menu of
                // checkable toggles keeps the bar usable at any window width.
                Menu {
                    ForEach(TimelineSource.allCases, id: \.self) { source in
                        Toggle(source.label, isOn: Binding(
                            get: { enabledSources.contains(source) },
                            set: { on in
                                if on { enabledSources.insert(source) } else { enabledSources.remove(source) }
                            }))
                    }
                    Divider()
                    Button("All sources") { enabledSources = Set(TimelineSource.allCases) }
                    Button("Event Log only") { enabledSources = [.evtx] }
                } label: {
                    Text("Sources (\(enabledSources.count)/\(TimelineSource.allCases.count))")
                }
                #if os(macOS)
                .menuStyle(.borderedButton)
                #endif
                .controlSize(.small)
                .fixedSize()
                .help("Restrict the timeline (and Gap Analysis) to the checked artifact sources.")
                Toggle(isOn: $bookmarksOnly) {
                    Label("Bookmarked", systemImage: "bookmark")
                }
                .toggleStyle(.button)
                .controlSize(.small)
                .help("Show only events the analyst has bookmarked.")
                Divider().frame(height: 16)
                Toggle("Hide slack", isOn: $hideSlack)
                    .toggleStyle(.button)
                    .controlSize(.small)
                    .help("Hide TSK *-slack pseudo-entries (slack-space rows with 1980 epoch timestamps).")
                Toggle("Gaps", isOn: $showGapAnalysis)
                    .toggleStyle(.button)
                    .controlSize(.small)
                    .help("Show activity sessions and quiet periods detected from the filtered timeline.")
                Spacer()
                if isDeriving {
                    ProgressView().controlSize(.small)
                }
                TextField("Filter path...", text: $query)
                    .textFieldStyle(.roundedBorder)
                    .frame(width: 220)
            }
            .padding(8)
            Divider()

            if !afterToggles.isEmpty {
                histogramSection
                Divider()
            }

            if showGapAnalysis {
                gapAnalysisSection
                Divider()
            }

            if tableTotal > tableRows.count {
                HStack(spacing: 6) {
                    Image(systemName: "info.circle")
                    Text("Showing first \(tableRows.count.formatted()) of \(tableTotal.formatted()) - zoom or filter to narrow.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                    Spacer()
                }
                .padding(.horizontal, 8)
                .padding(.vertical, 4)
                .background(Color.secondary.opacity(0.08))
            }

            // Snapshot once per body - row closures run for up to 20k rows
            // and must not hit the model per row beyond a dict lookup.
            let annotationIndex = model.annotationsByTargetKey
            Table(tableRows, selection: $selection) {
                TableColumn("") { e in
                    if let a = annotationIndex[e.stableKey] {
                        Image(systemName: "bookmark.fill")
                            .foregroundStyle(AnnotationStyle.color(for: a.tag))
                            .help(a.note.isEmpty ? (a.tag?.label ?? "Bookmarked") : a.note)
                    }
                }
                .width(min: 18, ideal: 18, max: 22)
                TableColumn("Time") { e in
                    Text(e.date.formatted(date: .numeric, time: .standard)).monospacedDigit()
                }
                TableColumn("MACB / Event ID") { e in
                    if let eid = e.eventID {
                        Text(String(eid)).monospacedDigit()
                    } else {
                        MACBBadge(kind: e.kind)
                    }
                }
                TableColumn("Path") { e in
                    HStack {
                        Text(e.path).lineLimit(1).truncationMode(.middle)
                        if e.isDeleted { Image(systemName: "trash").foregroundStyle(.red) }
                    }
                }
            }
            .contextMenu(forSelectionType: TimelineEvent.ID.self) { ids in
                if let id = ids.first,
                   let event = tableRows.first(where: { $0.id == id }) {
                    let bookmarked = annotationIndex[event.stableKey] != nil
                    Button(bookmarked ? "Edit Bookmark…" : "Add Bookmark…") {
                        model.activeSheet = .annotationEditor(
                            AnnotationDraft(event: event, evidenceID: model.activeEvidenceID))
                    }
                    if bookmarked {
                        Button("Remove Bookmark", role: .destructive) {
                            if let a = annotationIndex[event.stableKey] {
                                model.removeAnnotation(a.id)
                            }
                        }
                    }
                }
            }
        }
        .navigationTitle("Timeline - \(tableTotal.formatted()) events")
        .task(id: deriveKey) {
            await deriveAfterToggles()
        }
        .task(id: tableKey) {
            await deriveTableRows()
        }
        // Consume a pivot request (Annotations list / finding "Reveal in
        // Timeline"): widen the source scope so the target is actually
        // visible, zoom to the range, and clear the request.
        .onAppear { initSourcesIfNeeded(); applyPivotIfPending() }
        .onChange(of: model.timelineCount) { _, _ in initSourcesIfNeeded() }
        .onChange(of: model.timelinePivot) { _, _ in applyPivotIfPending() }
        .overlay {
            if model.timelineCount == 0 {
                ContentUnavailableView("No timeline yet", systemImage: "clock",
                    description: Text("Ingest evidence to build a MACB timeline."))
            } else if afterToggles.isEmpty && !isDeriving {
                // The default scope is the populated bounded sources; if the
                // analyst has narrowed Sources (or only unbounded data exists)
                // this can look empty. Nudge them toward the Sources menu.
                ContentUnavailableView("No events match",
                    systemImage: "line.3.horizontal.decrease.circle",
                    description: Text("Widen the Sources menu (e.g. enable Filesystem) to populate this view."))
            }
        }
    }

    /// Range currently visible in the histogram - the active zoom or the
    /// full extent. Cheap, derived from cached state only.
    private var visibleRange: ClosedRange<Date>? {
        dateSelection ?? fullExtent
    }

    /// Seed `enabledSources` from the case's populated bounded sources, once,
    /// the first time the timeline has data. Before this runs the selection is
    /// the `.evtx` placeholder, which is empty (and thus blank) on a Linux image.
    private func initSourcesIfNeeded() {
        guard !didSeedSources, model.timelineCount > 0 else { return }
        enabledSources = model.defaultTimelineSources
        didSeedSources = true
    }

    private func applyPivotIfPending() {
        guard let pivot = model.timelinePivot else { return }
        enabledSources = Set(TimelineSource.allCases)
        bookmarksOnly = false
        query = ""
        dateSelection = pivot.range
        model.timelinePivot = nil
    }

    @ViewBuilder
    private var histogramSection: some View {
        VStack(spacing: 4) {
            histogramControls
            TimelineHistogram(events: afterToggles,
                              fullExtent: fullExtent,
                              selection: $dateSelection)
                .frame(maxWidth: .infinity, minHeight: 140, maxHeight: 140)
        }
        .padding(8)
    }

    @ViewBuilder
    private var histogramControls: some View {
        HStack(spacing: 8) {
            if let extent = fullExtent {
                // Clamp the displayed value into `extent`: a "Reveal in Timeline"
                // pivot can set `dateSelection` ±30 min beyond the current source
                // scope's extent, and DatePicker(selection:in:) requires the value
                // to lie within the range. (Inlined min/max — a local func isn't
                // allowed inside the ViewBuilder body.)
                let lower = Binding<Date>(
                    get: { min(max(visibleRange?.lowerBound ?? extent.lowerBound, extent.lowerBound), extent.upperBound) },
                    set: { newStart in
                        let current = visibleRange ?? extent
                        let end = max(newStart, current.upperBound)
                        dateSelection = newStart...end
                    }
                )
                let upper = Binding<Date>(
                    get: { min(max(visibleRange?.upperBound ?? extent.upperBound, extent.lowerBound), extent.upperBound) },
                    set: { newEnd in
                        let current = visibleRange ?? extent
                        let start = min(current.lowerBound, newEnd)
                        dateSelection = start...newEnd
                    }
                )
                DatePicker("", selection: lower, in: extent, displayedComponents: [.date])
                    .labelsHidden()
                    .controlSize(.small)
                Text("→").foregroundStyle(.secondary)
                DatePicker("", selection: upper, in: extent, displayedComponents: [.date])
                    .labelsHidden()
                    .controlSize(.small)
                Button { zoom(factor: 0.5) } label: {
                    Image(systemName: "plus.magnifyingglass")
                }
                .buttonStyle(.borderless)
                .controlSize(.small)
                .help("Zoom in")
                Button { zoom(factor: 2.0) } label: {
                    Image(systemName: "minus.magnifyingglass")
                }
                .buttonStyle(.borderless)
                .controlSize(.small)
                .help("Zoom out")
                if dateSelection != nil {
                    Button("Reset") { dateSelection = nil }
                        .buttonStyle(.borderless)
                        .controlSize(.small)
                }
            } else {
                Text("Click and drag the chart to filter by date range")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            Spacer()
        }
    }

    /// Scale the visible range around its midpoint by `factor`. <1 zooms in,
    /// >1 zooms out. Result is clamped to the full event extent.
    private func zoom(factor: Double) {
        guard let extent = fullExtent else { return }
        let current = visibleRange ?? extent
        let mid = current.lowerBound.timeIntervalSinceReferenceDate
                + (current.upperBound.timeIntervalSinceReferenceDate
                   - current.lowerBound.timeIntervalSinceReferenceDate) / 2
        let halfSpan = (current.upperBound.timeIntervalSinceReferenceDate
                        - current.lowerBound.timeIntervalSinceReferenceDate) / 2 * factor
        let minHalfSpan: TimeInterval = 60  // don't shrink below a 2-minute window
        let clampedHalf = max(halfSpan, minHalfSpan)
        var newStart = Date(timeIntervalSinceReferenceDate: mid - clampedHalf)
        var newEnd   = Date(timeIntervalSinceReferenceDate: mid + clampedHalf)
        newStart = max(newStart, extent.lowerBound)
        newEnd   = min(newEnd, extent.upperBound)
        if newStart >= newEnd { return }
        // Zoom-out that reaches both ends == no active selection.
        if factor > 1 && newStart == extent.lowerBound && newEnd == extent.upperBound {
            dateSelection = nil
        } else {
            dateSelection = newStart...newEnd
        }
    }

    /// Recompute `afterToggles` + `fullExtent` off the main thread. Driven by
    /// `.task(id:)` so it re-runs only when filter inputs change. Gap
    /// analysis runs on the same pass: the analyzer is single-pass O(n) so
    /// folding it in costs basically nothing compared to a re-trigger.
    private func deriveAfterToggles() async {
        // Debounce: .task(id:) cancels + restarts this on every filter/query
        // change, so a short sleep coalesces rapid keystrokes into one pass. A
        // cancelled sleep (a newer change arrived) bails before the heavy work.
        isDeriving = true
        try? await Task.sleep(nanoseconds: 250_000_000)
        if Task.isCancelled { return }
        let source = model.timeline
        let kinds = enabledKinds
        let sources = enabledSources
        let hideSlackLocal = hideSlack
        let queryLocal = query
        let threshold = TimeInterval(max(1, gapThresholdMinutes) * 60)
        // Snapshot the bookmarked keys (Sendable) for the detached filter.
        let bookmarkedKeys: Set<String>? = bookmarksOnly
            ? Set(model.annotations.filter { $0.targetKind == .timelineEvent }.map(\.targetKey))
            : nil
        let result: ([TimelineEvent], ClosedRange<Date>?, [ActivitySession], [QuietGap]) = await Task.detached(priority: .userInitiated) {
            let filtered = source.filter { event in
                guard kinds.contains(event.kind),
                      sources.contains(event.source),
                      hideSlackLocal == false || !event.path.hasSuffix("-slack")
                else { return false }
                if let bookmarkedKeys, !bookmarkedKeys.contains(event.stableKey) { return false }
                if queryLocal.isEmpty { return true }
                if event.path.localizedCaseInsensitiveContains(queryLocal) { return true }
                // Event-ID search: "4624" should match Security:4624 rows
                // now that the EID lives in its own field rather than the
                // path string.
                if let eid = event.eventID,
                   String(eid).contains(queryLocal) { return true }
                return false
            }
            var lo: Date? = nil
            var hi: Date? = nil
            for event in filtered {
                if lo == nil || event.date < lo! { lo = event.date }
                if hi == nil || event.date > hi! { hi = event.date }
            }
            let extent: ClosedRange<Date>?
            if let lo, let hi, lo <= hi { extent = lo...hi } else { extent = nil }
            let (sessions, gaps) = GapAnalyzer.analyze(filtered, threshold: threshold)
            return (filtered, extent, sessions, gaps)
        }.value
        if Task.isCancelled { return }
        afterToggles = result.0
        fullExtent = result.1
        sessions = result.2
        gaps = result.3
        // Clamp any active zoom selection to the new extent so it stays valid.
        if let range = dateSelection, let extent = result.1 {
            let lo = max(range.lowerBound, extent.lowerBound)
            let hi = min(range.upperBound, extent.upperBound)
            dateSelection = lo < hi ? lo...hi : nil
        }
        isDeriving = false
    }

    /// Compute the table slice off-main. We count the total matches but only
    /// materialize the first `maxTableRows` to keep SwiftUI's Table happy.
    private func deriveTableRows() async {
        let source = afterToggles
        let range = dateSelection
        let cap = Self.maxTableRows
        let result: ([TimelineEvent], Int) = await Task.detached(priority: .userInitiated) {
            var rows: [TimelineEvent] = []
            rows.reserveCapacity(min(cap, source.count))
            var total = 0
            for event in source {
                if let range, !range.contains(event.date) { continue }
                total += 1
                if rows.count < cap { rows.append(event) }
            }
            return (rows, total)
        }.value
        if Task.isCancelled { return }
        tableRows = result.0
        tableTotal = result.1
    }
}

extension TimelineView {

    @ViewBuilder
    fileprivate var gapAnalysisSection: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack(spacing: 12) {
                Text("Gap Analysis").font(.headline)
                Stepper(value: $gapThresholdMinutes, in: 1...1440, step: 5) {
                    Text("Threshold: \(thresholdLabel)").font(.callout)
                }
                .controlSize(.small)
                .help("Inter-event delta above this value starts a new session and records a quiet gap.")
                Spacer()
                Text("\(sessions.count) session\(sessions.count == 1 ? "" : "s") · \(gaps.count) gap\(gaps.count == 1 ? "" : "s")")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            HStack(alignment: .top, spacing: 12) {
                gapsTable
                sessionsTable
            }
        }
        .padding(8)
    }

    private var thresholdLabel: String {
        if gapThresholdMinutes < 60 {
            return "\(gapThresholdMinutes) min"
        } else if gapThresholdMinutes % 60 == 0 {
            return "\(gapThresholdMinutes / 60) h"
        } else {
            let h = gapThresholdMinutes / 60
            let m = gapThresholdMinutes % 60
            return "\(h)h \(m)m"
        }
    }

    @ViewBuilder
    private var gapsTable: some View {
        VStack(alignment: .leading, spacing: 2) {
            Text("Quiet Gaps").font(.subheadline.bold())
            if gaps.isEmpty {
                Text("None at this threshold.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .frame(maxWidth: .infinity, minHeight: 120, alignment: .topLeading)
            } else {
                Table(gaps.sorted { $0.duration > $1.duration }) {
                    TableColumn("Duration") { gap in
                        Text(Self.formatDuration(gap.duration)).monospacedDigit()
                    }
                    .width(min: 70, ideal: 90)
                    TableColumn("From") { gap in
                        Text(gap.start.formatted(date: .numeric, time: .standard))
                            .monospacedDigit()
                    }
                    TableColumn("To") { gap in
                        Text(gap.end.formatted(date: .numeric, time: .standard))
                            .monospacedDigit()
                    }
                    TableColumn("") { gap in
                        Button("Zoom") { dateSelection = gap.start...gap.end }
                            .buttonStyle(.borderless)
                            .controlSize(.small)
                    }
                    .width(min: 50, ideal: 50)
                }
                .frame(minHeight: 120, maxHeight: 220)
            }
        }
    }

    @ViewBuilder
    private var sessionsTable: some View {
        VStack(alignment: .leading, spacing: 2) {
            Text("Activity Sessions").font(.subheadline.bold())
            if sessions.isEmpty {
                Text("No events in scope.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .frame(maxWidth: .infinity, minHeight: 120, alignment: .topLeading)
            } else {
                Table(sessions.sorted { $0.duration > $1.duration }) {
                    TableColumn("Duration") { session in
                        Text(Self.formatDuration(session.duration)).monospacedDigit()
                    }
                    .width(min: 70, ideal: 90)
                    TableColumn("Events") { session in
                        Text(session.count.formatted()).monospacedDigit()
                    }
                    .width(min: 60, ideal: 80)
                    TableColumn("Start") { session in
                        Text(session.start.formatted(date: .numeric, time: .standard))
                            .monospacedDigit()
                    }
                    TableColumn("") { session in
                        Button("Zoom") { dateSelection = session.start...session.end }
                            .buttonStyle(.borderless)
                            .controlSize(.small)
                    }
                    .width(min: 50, ideal: 50)
                }
                .frame(minHeight: 120, maxHeight: 220)
            }
        }
    }

    /// Compact h/m/s formatter - DFIR analysts read gaps faster as
    /// "2h 14m" than as 8040 s.
    fileprivate static func formatDuration(_ seconds: TimeInterval) -> String {
        let total = Int(seconds.rounded())
        if total <= 0 { return "0s" }
        let days = total / 86_400
        let hours = (total % 86_400) / 3600
        let minutes = (total % 3600) / 60
        let secs = total % 60
        if days > 0 { return "\(days)d \(hours)h" }
        if hours > 0 { return "\(hours)h \(minutes)m" }
        if minutes > 0 { return "\(minutes)m \(secs)s" }
        return "\(secs)s"
    }
}

private struct MACBBadge: View {
    let kind: MACBKind
    var body: some View {
        Text(kind.rawValue)
            .font(.caption.monospaced())
            .frame(width: 18, height: 18)
            .background(color.opacity(0.25), in: RoundedRectangle(cornerRadius: 4))
            .foregroundStyle(color)
    }
    private var color: Color {
        switch kind {
        case .modified: return .blue
        case .accessed: return .green
        case .changed:  return .orange
        case .born:     return .purple
        }
    }
}
