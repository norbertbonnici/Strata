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

    /// Events after kind toggles, path query, and slack filter - before the
    /// histogram date selection. This is what the histogram visualises.
    private var afterToggles: [TimelineEvent] {
        model.timeline.filter { event in
            enabledKinds.contains(event.kind) &&
            (!hideSlack || !event.path.hasSuffix("-slack")) &&
            (query.isEmpty || event.path.localizedCaseInsensitiveContains(query))
        }
    }

    /// Final set rendered in the table - afterToggles further narrowed to
    /// the histogram's selected window if one exists.
    private var filtered: [TimelineEvent] {
        guard let range = dateSelection else { return afterToggles }
        return afterToggles.filter { range.contains($0.date) }
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

            Table(filtered) {
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
        .navigationTitle("Timeline - \(filtered.count) events")
        .overlay {
            if model.timeline.isEmpty {
                ContentUnavailableView("No timeline yet", systemImage: "clock",
                    description: Text("Ingest evidence to build a MACB timeline."))
            }
        }
    }

    @ViewBuilder
    private var histogramSection: some View {
        VStack(spacing: 4) {
            HStack(spacing: 8) {
                if let range = dateSelection {
                    Text("Range: \(range.lowerBound.formatted(date: .abbreviated, time: .shortened)) — \(range.upperBound.formatted(date: .abbreviated, time: .shortened))")
                        .font(.caption.monospacedDigit())
                    Button("Clear") { dateSelection = nil }
                        .buttonStyle(.borderless)
                        .controlSize(.small)
                } else {
                    Text("Click and drag the chart to filter by date range")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
                Spacer()
            }
            TimelineHistogram(events: afterToggles, selection: $dateSelection)
                .frame(maxWidth: .infinity, minHeight: 140, maxHeight: 140)
        }
        .padding(8)
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
