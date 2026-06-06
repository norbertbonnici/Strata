import SwiftUI
import Charts

/// Adaptive bar chart over a flat list of TimelineEvents - one bar per bucket
/// representing total file activity. Bucket size scales with the visible span
/// (day / week / month / year) so multi-year datasets still draw visible bars.
/// `selection` doubles as a zoom window: when set, the chart's x-axis clamps
/// to it and bins are recomputed against the narrower range.
/// Heavy binning runs on a background task via `.task(id:)` so drag updates
/// don't restart the work each frame.
struct TimelineHistogram: View {
    let events: [TimelineEvent]
    let fullExtent: ClosedRange<Date>?
    @Binding var selection: ClosedRange<Date>?

    struct Bin: Identifiable, Sendable {
        let bucket: Date
        let count: Int
        var id: TimeInterval { bucket.timeIntervalSinceReferenceDate }
    }

    @State private var bins: [Bin] = []
    @State private var binUnit: Calendar.Component = .day

    /// Recompute key - the binning depends on which events are visible and
    /// the span (which drives bucket size). Using count as a cheap fingerprint
    /// is safe because the parent rebuilds the array whenever filters change.
    private struct BinKey: Equatable {
        let eventCount: Int
        let lower: Date?
        let upper: Date?
    }

    private var visibleSpan: ClosedRange<Date>? {
        selection ?? fullExtent
    }

    var body: some View {
        Chart {
            ForEach(bins) { bin in
                BarMark(
                    x: .value("Bucket", bin.bucket, unit: binUnit),
                    y: .value("Count", bin.count)
                )
                .foregroundStyle(Color.accentColor)
            }
        }
        .chartXScale(domain: scaleDomain)
        .chartXAxis {
            AxisMarks(values: .automatic(desiredCount: 8)) { _ in
                AxisGridLine()
                AxisValueLabel(format: axisFormat(for: binUnit))
            }
        }
        .chartLegend(.hidden)
        // chartXSelection(range:) crashes on stacked bars in current Charts
        // releases, so we roll our own drag-to-select with an overlay. The
        // overlay GeometryReader spans the whole chart (including the y-axis
        // gutter), so we convert gesture coordinates into the plot area's space
        // before handing them to proxy.value(atX:) - otherwise the selection is
        // skewed right by the gutter width.
        .chartOverlay { proxy in
            GeometryReader { geo in
                Rectangle()
                    .fill(Color.clear)
                    .contentShape(Rectangle())
                    .gesture(
                        DragGesture(minimumDistance: 4)
                            .onEnded { drag in
                                guard let plotAnchor = proxy.plotFrame else { return }
                                let plot = geo[plotAnchor]
                                guard plot.width > 0 else { return }
                                let xStart = clamp(min(drag.startLocation.x, drag.location.x) - plot.minX,
                                                   to: 0...plot.width)
                                let xEnd   = clamp(max(drag.startLocation.x, drag.location.x) - plot.minX,
                                                   to: 0...plot.width)
                                // Reject a near-vertical drag: a zero-width
                                // selection feeds a degenerate domain to
                                // chartXScale and collapses the plot.
                                guard xEnd > xStart else { return }
                                guard let dStart: Date = proxy.value(atX: xStart),
                                      let dEnd: Date   = proxy.value(atX: xEnd),
                                      dEnd > dStart else { return }
                                selection = dStart...dEnd
                            }
                    )
            }
        }
        .frame(maxWidth: .infinity)
        .task(id: BinKey(eventCount: events.count,
                         lower: visibleSpan?.lowerBound,
                         upper: visibleSpan?.upperBound)) {
            await recomputeBins()
        }
    }

    private var scaleDomain: ClosedRange<Date> {
        if let span = visibleSpan { return span }
        let now = Date()
        return now...now.addingTimeInterval(1)
    }

    private func clamp(_ value: CGFloat, to range: ClosedRange<CGFloat>) -> CGFloat {
        min(max(value, range.lowerBound), range.upperBound)
    }

    private func axisFormat(for unit: Calendar.Component) -> Date.FormatStyle {
        switch unit {
        case .day, .weekOfYear: return .dateTime.month(.abbreviated).day()
        case .month:            return .dateTime.month(.abbreviated).year(.twoDigits)
        case .year:             return .dateTime.year()
        default:                return .dateTime.month(.abbreviated).day()
        }
    }

    private func recomputeBins() async {
        let eventsCopy = events
        let span = visibleSpan
        let result: ([Bin], Calendar.Component) = await Task.detached(priority: .userInitiated) {
            let calendar = Calendar.current
            // Bucket size from the span itself (O(1)) rather than from event
            // min/max (O(n)).
            let unit: Calendar.Component
            if let span {
                let totalDays = max(1, calendar.dateComponents([.day],
                                                                from: span.lowerBound,
                                                                to: span.upperBound).day ?? 1)
                switch totalDays {
                case ..<120:  unit = .day
                case ..<800:  unit = .weekOfYear
                case ..<8000: unit = .month
                default:      unit = .year
                }
            } else {
                unit = .day
            }
            var grouped: [Date: Int] = [:]
            for event in eventsCopy {
                if let span, !span.contains(event.date) { continue }
                if let bucket = calendar.dateInterval(of: unit, for: event.date)?.start {
                    grouped[bucket, default: 0] += 1
                }
            }
            let bins = grouped.map { Bin(bucket: $0.key, count: $0.value) }
                .sorted { $0.bucket < $1.bucket }
            return (bins, unit)
        }.value
        if Task.isCancelled { return }
        bins = result.0
        binUnit = result.1
    }
}
