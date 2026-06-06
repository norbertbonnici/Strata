import SwiftUI

/// Shown right after a successful ingest, or from the Tools menu. Lets the
/// analyst opt-in to enrichments that aren't part of the standard parse.
/// Currently only IOC matching - more (eg. VT lookup, GeoIP, AV hash check)
/// can land here as new toggles without touching the ingest path.
struct EnrichmentSheet: View {
    @EnvironmentObject private var model: AppModel
    @Environment(\.dismiss) private var dismiss

    @State private var runIOCMatching = true

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            VStack(alignment: .leading, spacing: 4) {
                Text("Run Enrichment").font(.title2).bold()
                Text("These passes are optional and not part of standard ingest. Pick which to run now; they can be re-run later from the Tools menu.")
                    .font(.caption).foregroundStyle(.secondary)
            }

            VStack(alignment: .leading, spacing: 12) {
                Toggle(isOn: $runIOCMatching) {
                    VStack(alignment: .leading, spacing: 2) {
                        Text("IOC matching")
                        Text("Match \(model.iocs.count) IOC\(model.iocs.count == 1 ? "" : "s") against this case's events, registry, and files.")
                            .font(.caption).foregroundStyle(.secondary)
                    }
                }
                .disabled(model.iocs.isEmpty)
            }
            .padding(12)
            .background(.quaternary, in: RoundedRectangle(cornerRadius: 6))

            HStack {
                if model.isWorking { ProgressView().controlSize(.small) }
                Spacer()
                Button("Skip") { dismiss() }
                Button("Run") {
                    Task {
                        if runIOCMatching && !model.iocs.isEmpty {
                            await model.runIOCMatch()
                        }
                        dismiss()
                    }
                }
                .keyboardShortcut(.defaultAction)
                // Also gate on isWorking so repeated taps / Return can't launch
                // overlapping IOC-match passes while one is in flight.
                .disabled(!runIOCMatching || model.iocs.isEmpty || model.isWorking)
            }
        }
        .padding(20)
        .frame(width: 460)
    }
}
