import SwiftUI

struct TimelineView: View {
    @EnvironmentObject private var model: AppModel
    @State private var enabledKinds: Set<MACBKind> = Set(MACBKind.allCases)
    @State private var query = ""
    @State private var dateSelection: ClosedRange<Date>?
    /// TSK emits a `<name>-slack` pseudo-entry for every allocated cluster's
    /// trailing slack. They carry epoch (1980) timestamps that swamp the
    /// histogram and clutter the table, so we hide them by default.
    @State private var hideSlack = true

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

    private static let maxTableRows = 20_000

    private struct DeriveKey: Equatable {
        let timelineCount: Int
        let kinds: Set<MACBKind>
        let hideSlack: Bool
        let query: String
    }

    private var deriveKey: DeriveKey {
        DeriveKey(timelineCount: model.timeline.count,
                  kinds: enabledKinds,
                  hideSlack: hideSlack,
                  query: query)
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
                Toggle("Hide slack", isOn: $hideSlack)
                    .toggleStyle(.button)
                    .controlSize(.small)
                    .help("Hide TSK *-slack pseudo-entries (slack-space rows with 1980 epoch timestamps).")
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

            Table(tableRows) {
                TableColumn("Time") { e in
                    Text(e.date.formatted(date: .numeric, time: .standard)).monospacedDigit()
                }
                TableColumn("MACB") { e in MACBBadge(kind: e.kind) }
                TableColumn("Path") { e in
                    HStack {
                        Text(e.path).lineLimit(1).truncationMode(.middle)
                        if e.isDeleted { Image(systemName: "trash").foregroundStyle(.red) }
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
        .overlay {
            if model.timeline.isEmpty {
                ContentUnavailableView("No timeline yet", systemImage: "clock",
                    description: Text("Ingest evidence to build a MACB timeline."))
            }
        }
    }

    /// Range currently visible in the histogram - the active zoom or the
    /// full extent. Cheap, derived from cached state only.
    private var visibleRange: ClosedRange<Date>? {
        dateSelection ?? fullExtent
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
                let lower = Binding<Date>(
                    get: { visibleRange?.lowerBound ?? extent.lowerBound },
                    set: { newStart in
                        let current = visibleRange ?? extent
                        let end = max(newStart, current.upperBound)
                        dateSelection = newStart...end
                    }
                )
                let upper = Binding<Date>(
                    get: { visibleRange?.upperBound ?? extent.upperBound },
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
    /// `.task(id:)` so it re-runs only when filter inputs change.
    private func deriveAfterToggles() async {
        let source = model.timeline
        let kinds = enabledKinds
        let hideSlackLocal = hideSlack
        let queryLocal = query
        isDeriving = true
        let result: ([TimelineEvent], ClosedRange<Date>?) = await Task.detached(priority: .userInitiated) {
            let filtered = source.filter { event in
                kinds.contains(event.kind) &&
                (!hideSlackLocal || !event.path.hasSuffix("-slack")) &&
                (queryLocal.isEmpty || event.path.localizedCaseInsensitiveContains(queryLocal))
            }
            var lo: Date? = nil
            var hi: Date? = nil
            for event in filtered {
                if lo == nil || event.date < lo! { lo = event.date }
                if hi == nil || event.date > hi! { hi = event.date }
            }
            let extent: ClosedRange<Date>?
            if let lo, let hi, lo <= hi { extent = lo...hi } else { extent = nil }
            return (filtered, extent)
        }.value
        if Task.isCancelled { return }
        afterToggles = result.0
        fullExtent = result.1
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
