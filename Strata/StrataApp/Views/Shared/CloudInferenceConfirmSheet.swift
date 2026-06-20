#if os(macOS)
import SwiftUI

/// First-run confirmation shown before evidence-derived data leaves this Mac for
/// a cloud model. Strata's hard rule is that evidence never leaves the host
/// except opt-in and clearly labeled — this is the explicit gate. Shown once per
/// acknowledged destination (base URL + model); changing the endpoint re-prompts.
/// Reuses the single `.sheet(item:)` host on `ContentView`
/// (`AppModel.ActiveSheet.cloudInferenceConfirm`).
struct CloudInferenceConfirmSheet: View {
    @EnvironmentObject private var model: AppModel
    @Environment(\.dismiss) private var dismiss

    let action: AppModel.PendingCloudAction

    var body: some View {
        let cfg = InferenceConfiguration.load()
        let isPCC = cfg.mode == .privateCloud
        // The self-eval runs a small built-in synthetic corpus — NOT this case's
        // evidence — so its disclosure must not claim the case's findings egress.
        let isEval = action == .runEval
        let destination = isPCC ? "to Apple Private Cloud Compute." : "to the configured cloud model."
        return VStack(alignment: .leading, spacing: 16) {
            HStack(spacing: 10) {
                Image(systemName: isPCC ? "lock.icloud" : "cloud")
                    .font(.title)
                    .foregroundStyle(isPCC ? Color.accentColor : .orange)
                Text(isPCC ? "Use Apple Private Cloud Compute?" : "Send data off this Mac?")
                    .font(.title2).bold()
            }

            VStack(alignment: .leading, spacing: 10) {
                if isEval {
                    Text("\(actionNoun) will send a small **built-in test corpus** — synthetic findings, not data from this case — \(destination)")
                        .fixedSize(horizontal: false, vertical: true)
                    row(systemImage: "checkmark.circle", tint: .secondary,
                        "No data from this case — no evidence, findings, or paths — is sent.")
                } else {
                    Text("\(actionNoun) will send **finding summaries** — titles, details, and evidence paths — \(destination)")
                        .fixedSize(horizontal: false, vertical: true)
                    row(systemImage: "checkmark.circle", tint: .secondary,
                        "Raw evidence, disk images, and file contents are never sent.")
                }
                if isPCC {
                    row(systemImage: "lock.shield", tint: .secondary,
                        "Apple-operated and attested: data is used only for this request, retained by no one, and the servers are independently verifiable. No API key, no third party.")
                    row(systemImage: "checkmark.seal", tint: .secondary,
                        "This run is recorded in the chain of custody, and the result is marked as generated via Apple Private Cloud Compute.")
                } else {
                    row(systemImage: "cpu", tint: .secondary,
                        "Destination: \(model.summaryBackendLabel)")
                    row(systemImage: "link", tint: .secondary,
                        cfg.cloudBaseURL)
                    row(systemImage: "checkmark.seal", tint: .secondary,
                        "This run is recorded in the chain of custody, and the result is marked cloud-generated.")
                }
                row(systemImage: "desktopcomputer", tint: .secondary,
                    "Switch to on-device mode in AI Inference settings to keep everything on this Mac.")
            }
            .font(.callout)
            .foregroundStyle(.secondary)

            Text(isPCC
                 ? "This confirmation is remembered for Apple Private Cloud Compute."
                 : "This confirmation is remembered for this destination.")
                .font(.caption).foregroundStyle(.secondary)

            HStack {
                Spacer()
                Button("Cancel") { dismiss() }
                    .keyboardShortcut(.cancelAction)
                Button(isPCC ? "Continue" : "Send & Continue") {
                    model.proceedAfterCloudConfirm(action)
                    dismiss()
                }
                .keyboardShortcut(.defaultAction)
                .buttonStyle(.borderedProminent)
            }
        }
        .padding(20)
        .frame(width: 480)
    }

    private var actionNoun: String {
        switch action {
        case .generateSummary: return "Generating the summary"
        case .runEval:         return "Running the summary self-eval"
        }
    }

    private func row(systemImage: String, tint: Color, _ text: String) -> some View {
        HStack(alignment: .firstTextBaseline, spacing: 8) {
            Image(systemName: systemImage).foregroundStyle(tint).frame(width: 16)
            Text(text).fixedSize(horizontal: false, vertical: true)
        }
    }
}
#endif
