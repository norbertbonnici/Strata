#if os(macOS)
import SwiftUI

/// Where the AI executive-summary inference runs. **Sovereignty is a
/// configuration, not a rewrite** (see `InferenceBackend`): on-device keeps the
/// whole pipeline on this Mac; cloud routes the *same* validated pipeline to a
/// configured model, sending only finding summaries (never raw evidence).
///
/// App-wide config: the mode/base-URL/model persist to `UserDefaults`
/// (`InferenceConfiguration`), the API token to the macOS Keychain — never the
/// case bundle. Reuses the single `.sheet(item:)` host on `ContentView`
/// (`AppModel.ActiveSheet.inferenceSettings`).
struct InferenceSettingsSheet: View {
    @EnvironmentObject private var model: AppModel
    @Environment(\.dismiss) private var dismiss

    @State private var mode: InferenceConfiguration.Mode = .onDevice
    @State private var cloudBaseURL = ""
    @State private var cloudModel = ""
    @State private var apiKey = ""
    @State private var onDeviceWindow = InferenceConfiguration.defaultOnDeviceWindow
    @State private var privateCloudWindow = InferenceConfiguration.defaultPrivateCloudWindow
    @State private var cloudWindow = InferenceConfiguration.defaultCloudWindow

    private let keychain = KeychainCredentialStore()

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            VStack(alignment: .leading, spacing: 4) {
                Text("AI Inference").font(.title2).bold()
                Text("Choose where the case-summary model runs. The evidence-reference validation gate applies either way — only the model's location changes.")
                    .font(.caption).foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }

            Picker("Run inference", selection: $mode) {
                Text("On-device").tag(InferenceConfiguration.Mode.onDevice)
                Text("Private Cloud").tag(InferenceConfiguration.Mode.privateCloud)
                Text("Third-party").tag(InferenceConfiguration.Mode.cloud)
            }
            .pickerStyle(.segmented)
            .labelsHidden()

            switch mode {
            case .onDevice:     onDeviceCard
            case .privateCloud: privateCloudCard
            case .cloud:        cloudCard
            }

            HStack {
                Spacer()
                Button("Cancel") { dismiss() }
                Button("Save") { save() }
                    .keyboardShortcut(.defaultAction)
                    .disabled(!canSave)
            }
        }
        .padding(20)
        .frame(width: 540)
        .onAppear(perform: load)
    }

    private var canSave: Bool {
        guard mode == .cloud else { return true }
        // A blank/garbage base URL would silently fail safe to on-device; block
        // the obviously-broken case so Save means what it says.
        let base = cloudBaseURL.trimmingCharacters(in: .whitespacesAndNewlines)
        return URL(string: base)?.scheme != nil && !cloudModel.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
    }

    // MARK: - On-device

    private var onDeviceCard: some View {
        VStack(alignment: .leading, spacing: 8) {
            Label("Runs entirely on this Mac via Apple Intelligence. No evidence — and no evidence-derived data — leaves the host.",
                  systemImage: "lock.shield")
                .font(.callout)
                .fixedSize(horizontal: false, vertical: true)
            if case .unavailable(let reason) = FindingsSummarizer.availability {
                Label(reason, systemImage: "exclamationmark.triangle.fill")
                    .font(.caption).foregroundStyle(.orange)
                    .fixedSize(horizontal: false, vertical: true)
            }
            Divider()
            windowField($onDeviceWindow)
        }
        .padding(12)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(.quaternary, in: RoundedRectangle(cornerRadius: 6))
    }

    // MARK: - Apple Private Cloud Compute

    private var privateCloudCard: some View {
        VStack(alignment: .leading, spacing: 8) {
            Label("Runs Apple's larger server model on Private Cloud Compute. Finding summaries (titles, details, evidence paths) leave the device — but only to Apple-operated, attested nodes that retain nothing. No API key, no third party. Raw evidence is never sent.",
                  systemImage: "lock.icloud")
                .font(.callout)
                .fixedSize(horizontal: false, vertical: true)
            Text("A middle tier between on-device and a third-party cloud: more capable than on-device, more private than an external endpoint. Each run is still confirmed and recorded in the chain of custody.")
                .font(.caption).foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            if case .unavailable(let reason) = InferenceConfiguration.privateCloudAvailability() {
                Label(reason, systemImage: "exclamationmark.triangle.fill")
                    .font(.caption).foregroundStyle(.orange)
                    .fixedSize(horizontal: false, vertical: true)
            }
            Divider()
            windowField($privateCloudWindow)
        }
        .padding(12)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(.quaternary, in: RoundedRectangle(cornerRadius: 6))
    }

    // MARK: - Third-party cloud

    private var cloudCard: some View {
        VStack(alignment: .leading, spacing: 10) {
            Label("Cloud mode sends finding summaries (titles, details, evidence paths) to the endpoint below. Raw evidence, disk images, and file contents are never sent. Every cloud run is recorded in the chain of custody.",
                  systemImage: "cloud")
                .font(.callout)
                .fixedSize(horizontal: false, vertical: true)

            VStack(alignment: .leading, spacing: 8) {
                labeledField("Base URL", systemImage: "link") {
                    TextField("https://api.anthropic.com", text: $cloudBaseURL)
                        .textFieldStyle(.roundedBorder).font(.caption.monospaced())
                }
                Text("Point at a self-hosted or sovereign-cloud gateway to keep data in your control.")
                    .font(.caption2).foregroundStyle(.secondary)

                labeledField("Model", systemImage: "cpu") {
                    TextField("claude-opus-4-8", text: $cloudModel)
                        .textFieldStyle(.roundedBorder).font(.caption.monospaced())
                }

                labeledField("API key", systemImage: "key") {
                    SecureField("Stored in the macOS Keychain", text: $apiKey)
                        .textFieldStyle(.roundedBorder)
                }
                if apiKey.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                    Label("No API key set — runs fall back to on-device until a key is provided.",
                          systemImage: "exclamationmark.triangle")
                        .font(.caption2).foregroundStyle(.orange)
                }
                Divider()
                windowField($cloudWindow)
            }

            Label("The API key is stored in the macOS Keychain, never in the case bundle.",
                  systemImage: "lock.shield")
                .font(.caption2).foregroundStyle(.secondary)
        }
        .padding(12)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(.quaternary, in: RoundedRectangle(cornerRadius: 6))
    }

    @ViewBuilder
    private func labeledField(_ title: String, systemImage: String,
                              @ViewBuilder _ field: () -> some View) -> some View {
        HStack(spacing: 8) {
            Label(title, systemImage: systemImage)
                .labelStyle(.titleAndIcon)
                .frame(width: 90, alignment: .leading)
                .font(.callout)
            field()
        }
    }

    /// Editable model **input** context window for the selected backend. Lets the
    /// analyst tune the window at runtime (e.g. shrink Apple PCC's 32k if a run
    /// still overflows, or raise the conservative on-device guess) — the
    /// summarizer sizes its batches + group cap to this. Persisted per mode.
    @ViewBuilder
    private func windowField(_ value: Binding<Int>) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            labeledField("Context", systemImage: "ruler") {
                HStack(spacing: 6) {
                    TextField("", value: value, format: .number.grouping(.never))
                        .textFieldStyle(.roundedBorder)
                        .frame(width: 110)
                        .multilineTextAlignment(.trailing)
                    Text("input tokens").font(.caption).foregroundStyle(.secondary)
                    Spacer()
                }
            }
            Text("Lower it if a run overflows the model; raise it to fit more findings per request. Sizes the summary's prompt batches and technique-group cap.")
                .font(.caption2).foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
        }
    }

    // MARK: - Persistence

    private func load() {
        let cfg = InferenceConfiguration.load()
        mode = cfg.mode
        cloudBaseURL = cfg.cloudBaseURL
        cloudModel = cfg.cloudModel
        onDeviceWindow = cfg.onDeviceContextWindow
        privateCloudWindow = cfg.privateCloudContextWindow
        cloudWindow = cfg.cloudContextWindow
        apiKey = keychain.load(for: InferenceConfiguration.keychainService)?.token ?? ""
    }

    private func save() {
        let base = cloudBaseURL.trimmingCharacters(in: .whitespacesAndNewlines)
        let modelID = cloudModel.trimmingCharacters(in: .whitespacesAndNewlines)
        let floor = InferenceConfiguration.minContextWindow
        let cfg = InferenceConfiguration(
            mode: mode,
            cloudBaseURL: base.isEmpty ? "https://api.anthropic.com" : base,
            cloudModel: modelID.isEmpty ? "claude-opus-4-8" : modelID,
            onDeviceContextWindow: max(floor, onDeviceWindow),
            privateCloudContextWindow: max(floor, privateCloudWindow),
            cloudContextWindow: max(floor, cloudWindow))
        cfg.save()
        // The token is written even in on-device mode so toggling to cloud later
        // doesn't lose it; it's only ever *read* when cloud is the active mode.
        _ = keychain.save(CTICredentials(token: apiKey.trimmingCharacters(in: .whitespacesAndNewlines)),
                          for: InferenceConfiguration.keychainService)
        model.refreshInferenceConfig()
        dismiss()
    }
}
#endif
