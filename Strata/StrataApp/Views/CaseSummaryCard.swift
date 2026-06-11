import SwiftUI

/// Shared card that displays the on-device (Apple Intelligence) executive
/// summary of the case findings. macOS shows a generate/regenerate control;
/// iOS compiles that out and displays the persisted summary read-only - the
/// same viewer/ingest split the rest of the app follows.
///
/// Used on the Kill Chain and Overview tabs. The whole thing runs on-device,
/// so no evidence leaves the host.
struct CaseSummaryCard: View {
    @EnvironmentObject private var model: AppModel

    /// When set, the summary text scrolls within this max height instead of
    /// growing to fit. Required when the card sits in a non-scrolling parent
    /// (the Kill Chain VStack), where unbounded growth would starve the
    /// kill-chain columns of vertical space. Overview (itself in a ScrollView)
    /// leaves it nil so the full summary lays out inline.
    var textMaxHeight: CGFloat? = nil

    /// Measured natural height of the summary text, so the card sizes to its
    /// content and only scrolls once it exceeds `textMaxHeight` (a ScrollView
    /// alone is greedy and would always reserve the full cap, leaving dead space).
    @State private var measuredTextHeight: CGFloat = 0

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack(alignment: .firstTextBaseline) {
                Label("AI Summary", systemImage: "sparkles")
                    .font(.subheadline.bold())
                Spacer()
                #if os(macOS)
                generateButton
                #endif
            }

            if let summary = model.caseSummary {
                summaryText(summary.text)
                caption(for: summary)
            } else {
                Text(placeholder)
                    .font(.callout)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
        .padding(14)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(.quaternary.opacity(0.4), in: RoundedRectangle(cornerRadius: 10))
    }

    /// The summary body. With `textMaxHeight` set it sizes to the measured text
    /// height, capped at the max and scrolling only past it - so a short summary
    /// leaves no dead space while a long one stays bounded.
    @ViewBuilder
    private func summaryText(_ text: String) -> some View {
        let label = Text(text)
            .font(.callout)
            .textSelection(.enabled)
            .fixedSize(horizontal: false, vertical: true)
            .frame(maxWidth: .infinity, alignment: .leading)
        if let maxHeight = textMaxHeight {
            // Before measurement, fall back to the cap (no worse than today).
            let height = measuredTextHeight > 0 ? min(measuredTextHeight, maxHeight) : maxHeight
            ScrollView(.vertical) {
                label.background(
                    GeometryReader { geo in
                        Color.clear.preference(key: SummaryTextHeightKey.self,
                                               value: geo.size.height)
                    })
            }
            .frame(height: height)
            .scrollBounceBehavior(.basedOnSize)   // no rubber-banding when it fits
            .onPreferenceChange(SummaryTextHeightKey.self) { measuredTextHeight = $0 }
        } else {
            label
        }
    }

    private func caption(for summary: CaseSummary) -> some View {
        HStack(spacing: 6) {
            Image(systemName: "lock.shield")
            Text("\(summary.modelLabel) · \(summary.generatedAt.formatted(date: .abbreviated, time: .shortened))")
        }
        .font(.caption2)
        .foregroundStyle(.secondary)
    }

    private var placeholder: String {
        #if os(macOS)
        if case .unavailable(let reason) = model.summaryAvailability {
            return reason
        }
        return "No summary yet. Generate an on-device executive summary of the case findings with Apple Intelligence."
        #else
        return "No AI summary has been generated for this case."
        #endif
    }

    #if os(macOS)
    private var generateButton: some View {
        let availability = model.summaryAvailability
        let hasFindings = model.findingCount > 0
        let enabled = !model.isWorking && hasFindings && availability.isAvailable
        return Button {
            Task { await model.generateSummary() }
        } label: {
            Label(model.caseSummary == nil ? "Generate" : "Regenerate",
                  systemImage: "sparkles")
        }
        .controlSize(.small)
        .disabled(!enabled)
        .help(helpText(availability: availability, hasFindings: hasFindings))
    }

    private func helpText(availability: SummarizerAvailability, hasFindings: Bool) -> String {
        if case .unavailable(let reason) = availability { return reason }
        if !hasFindings { return "Run the analyzers first, then generate a summary." }
        return "Summarize the case findings on-device with Apple Intelligence. No data leaves this Mac."
    }
    #endif
}

/// Carries the summary text's natural height up so the card can size to it.
private struct SummaryTextHeightKey: PreferenceKey {
    static let defaultValue: CGFloat = 0
    static func reduce(value: inout CGFloat, nextValue: () -> CGFloat) {
        value = max(value, nextValue())
    }
}
