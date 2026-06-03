import SwiftUI
import Charts

/// Per-day bar chart over a flat list of TimelineEvents, stacked by MACB kind.
/// Click-drag on the chart sets `selection` to a date range; the parent view
/// is expected to filter its table down to that range.
struct TimelineHistogram: View {
    let events: [TimelineEvent]
    @Binding var selection: ClosedRange<Date>?

    private struct DayBin: Identifiable {
        let day: Date
        let kind: MACBKind
        let count: Int
        var id: String { "\(day.timeIntervalSinceReferenceDate)-\(kind.rawValue)" }
    }

    private var bins: [DayBin] {
        var grouped: [Date: [MACBKind: Int]] = [:]
        let calendar = Calendar.current
        for event in events {
            let day = calendar.startOfDay(for: event.date)
            grouped[day, default: [:]][event.kind, default: 0] += 1
        }
        return grouped.flatMap { day, kinds in
            kinds.map { DayBin(day: day, kind: $0.key, count: $0.value) }
        }.sorted { $0.day < $1.day }
    }

    var body: some View {
        Chart {
            ForEach(bins) { bin in
                BarMark(
                    x: .value("Day", bin.day, unit: .day),
                    y: .value("Count", bin.count)
                )
                .foregroundStyle(by: .value("Kind", bin.kind.rawValue))
            }
            // Translucent band rendered as part of the chart so it scales with
            // the x-axis automatically.
            if let range = selection {
                RectangleMark(
                    xStart: .value("Start", range.lowerBound),
                    xEnd: .value("End", range.upperBound)
                )
                .foregroundStyle(Color.accentColor.opacity(0.18))
            }
        }
        // Match the badge colors used by the table so kinds read the same in
        // both places.
        .chartForegroundStyleScale([
            "M": Color.blue,
            "A": Color.green,
            "C": Color.orange,
            "B": Color.purple,
        ])
        .chartXAxis {
            AxisMarks(values: .stride(by: .day, count: max(1, autoStrideDays))) { _ in
                AxisGridLine()
                AxisValueLabel(format: .dateTime.month(.abbreviated).day())
            }
        }
        .chartLegend(.hidden)
        // chartXSelection(range:) crashes on stacked bars in current Charts
        // releases, so we roll our own drag-to-select with an overlay. The
        // overlay covers exactly the plot area, so gesture coordinates map
        // directly through proxy.value(atX:).
        .chartOverlay { proxy in
            GeometryReader { geo in
                Rectangle()
                    .fill(Color.clear)
                    .contentShape(Rectangle())
                    .gesture(
                        DragGesture(minimumDistance: 4)
                            .onChanged { drag in
                                let width = geo.size.width
                                let xStart = clamp(min(drag.startLocation.x, drag.location.x),
                                                   to: 0...width)
                                let xEnd   = clamp(max(drag.startLocation.x, drag.location.x),
                                                   to: 0...width)
                                guard let dStart: Date = proxy.value(atX: xStart),
                                      let dEnd: Date   = proxy.value(atX: xEnd) else { return }
                                selection = dStart...dEnd
                            }
                    )
                    .onTapGesture { selection = nil }
            }
        }
        .frame(maxWidth: .infinity)
    }

    private func clamp(_ value: CGFloat, to range: ClosedRange<CGFloat>) -> CGFloat {
        min(max(value, range.lowerBound), range.upperBound)
    }

    /// Pick a sane label stride so the x-axis stays readable on a multi-year
    /// window. ~12 labels max.
    private var autoStrideDays: Int {
        guard let first = bins.first?.day, let last = bins.last?.day else { return 1 }
        let totalDays = max(1, Calendar.current.dateComponents([.day],
                                                                from: first,
                                                                to: last).day ?? 1)
        return max(1, totalDays / 12)
    }
}
