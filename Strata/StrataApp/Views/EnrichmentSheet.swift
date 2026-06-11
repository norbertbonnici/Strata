import SwiftUI

/// Shown right after a successful ingest, or from the Tools menu. Lets the
/// analyst opt-in to enrichments that aren't part of the standard parse:
///  - **IOC matching** — scan the case for loaded indicators.
///  - **Threat-intel lookup** — the tiered CTI waterfall (NSRL → MISP/OpenCTI →
///    VirusTotal). Strictly opt-in and per-instance configured; nothing leaves
///    the host unless a network tier is enabled here with credentials.
struct EnrichmentSheet: View {
    @EnvironmentObject private var model: AppModel
    @Environment(\.dismiss) private var dismiss

    @State private var runIOCMatching = true
    @State private var runCTI = false
    @State private var showConfig = false

    // Credential fields — loaded from the Keychain on appear, written back on Run.
    @State private var vtToken = ""
    @State private var mispBase = ""
    @State private var mispToken = ""
    @State private var openCTIBase = ""
    @State private var openCTIToken = ""

    private let keychain = KeychainCredentialStore()

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            VStack(alignment: .leading, spacing: 4) {
                Text("Run Enrichment").font(.title2).bold()
                Text("These passes are optional and not part of standard ingest. Pick which to run now; they can be re-run later from the Tools menu.")
                    .font(.caption).foregroundStyle(.secondary)
            }

            iocMatchingCard
            ctiCard

            HStack {
                if model.isWorking { ProgressView().controlSize(.small) }
                Spacer()
                Button("Skip") { dismiss() }
                Button("Run") { Task { await run() } }
                    .keyboardShortcut(.defaultAction)
                    .disabled(!canRun || model.isWorking)
            }
        }
        .padding(20)
        .frame(width: 520)
        .onAppear(perform: loadCredentials)
    }

    private var canRun: Bool {
        (runIOCMatching && !model.iocs.isEmpty)
            || (runCTI && model.ctiConfig.anyEnabled && !model.iocs.isEmpty)
    }

    // MARK: - IOC matching

    private var iocMatchingCard: some View {
        Toggle(isOn: $runIOCMatching) {
            VStack(alignment: .leading, spacing: 2) {
                Text("IOC matching")
                Text("Match \(model.iocs.count) IOC\(model.iocs.count == 1 ? "" : "s") against this case's events, registry, and files.")
                    .font(.caption).foregroundStyle(.secondary)
            }
        }
        .disabled(model.iocs.isEmpty)
        .padding(12)
        .background(.quaternary, in: RoundedRectangle(cornerRadius: 6))
    }

    // MARK: - CTI

    private var ctiCard: some View {
        VStack(alignment: .leading, spacing: 10) {
            Toggle(isOn: $runCTI) {
                VStack(alignment: .leading, spacing: 2) {
                    Text("Threat-intel lookup (CTI)")
                    Text("Enrich loaded indicators via NSRL → MISP/OpenCTI → VirusTotal. Opt-in; only enabled sources are contacted, short-circuiting on the first definitive verdict.")
                        .font(.caption).foregroundStyle(.secondary)
                }
            }
            .disabled(model.iocs.isEmpty)

            DisclosureGroup("Configure sources (\(model.ctiConfig.enabledSummary))", isExpanded: $showConfig) {
                VStack(alignment: .leading, spacing: 10) {
                    // NSRL — local, no token.
                    Toggle("NSRL known-good (local hash list)", isOn: $model.ctiConfig.nsrlEnabled)
                    if model.ctiConfig.nsrlEnabled {
                        TextField("Path to newline-delimited hash list", text: Binding(
                            get: { model.ctiConfig.nsrlFilePath ?? "" },
                            set: { model.ctiConfig.nsrlFilePath = $0.isEmpty ? nil : $0 }))
                            .textFieldStyle(.roundedBorder).font(.caption.monospaced())
                    }
                    Divider()
                    // Known-bad hashes — local, no token; emits a malicious verdict.
                    Toggle("Known-bad hashes (local hash list)", isOn: $model.ctiConfig.knownBadEnabled)
                    if model.ctiConfig.knownBadEnabled {
                        TextField("Path to newline-delimited bad-hash list", text: Binding(
                            get: { model.ctiConfig.knownBadFilePath ?? "" },
                            set: { model.ctiConfig.knownBadFilePath = $0.isEmpty ? nil : $0 }))
                            .textFieldStyle(.roundedBorder).font(.caption.monospaced())
                    }
                    Divider()
                    // VirusTotal — token only.
                    Toggle("VirusTotal", isOn: $model.ctiConfig.virusTotalEnabled)
                    if model.ctiConfig.virusTotalEnabled {
                        SecureField("API key", text: $vtToken).textFieldStyle(.roundedBorder)
                    }
                    Divider()
                    // MISP — base URL + token.
                    Toggle("MISP (self-hosted)", isOn: $model.ctiConfig.mispEnabled)
                    if model.ctiConfig.mispEnabled {
                        TextField("Base URL (https://misp.example)", text: $mispBase).textFieldStyle(.roundedBorder)
                        SecureField("Auth token", text: $mispToken).textFieldStyle(.roundedBorder)
                    }
                    Divider()
                    // OpenCTI — base URL + token.
                    Toggle("OpenCTI (self-hosted)", isOn: $model.ctiConfig.openCTIEnabled)
                    if model.ctiConfig.openCTIEnabled {
                        TextField("Base URL (https://opencti.example)", text: $openCTIBase).textFieldStyle(.roundedBorder)
                        SecureField("API token", text: $openCTIToken).textFieldStyle(.roundedBorder)
                    }
                    Label("Tokens are stored in the macOS Keychain, never in the case bundle.",
                          systemImage: "lock.shield")
                        .font(.caption2).foregroundStyle(.secondary)
                }
                .padding(.top, 6)
            }
            .font(.callout)
        }
        .padding(12)
        .background(.quaternary, in: RoundedRectangle(cornerRadius: 6))
    }

    // MARK: - Credentials ↔ Keychain

    private func loadCredentials() {
        if let c = keychain.load(for: CTIConfiguration.vtService) { vtToken = c.token ?? "" }
        if let c = keychain.load(for: CTIConfiguration.mispService) {
            mispBase = c.baseURL?.absoluteString ?? ""; mispToken = c.token ?? ""
        }
        if let c = keychain.load(for: CTIConfiguration.openCTIService) {
            openCTIBase = c.baseURL?.absoluteString ?? ""; openCTIToken = c.token ?? ""
        }
    }

    private func saveCredentials() {
        _ = keychain.save(CTICredentials(token: vtToken), for: CTIConfiguration.vtService)
        _ = keychain.save(CTICredentials(baseURL: URL(string: mispBase), token: mispToken),
                          for: CTIConfiguration.mispService)
        _ = keychain.save(CTICredentials(baseURL: URL(string: openCTIBase), token: openCTIToken),
                          for: CTIConfiguration.openCTIService)
    }

    private func run() async {
        if runCTI { saveCredentials() }
        if runIOCMatching && !model.iocs.isEmpty {
            await model.runIOCMatch()
        }
        if runCTI && model.ctiConfig.anyEnabled && !model.iocs.isEmpty {
            await model.enrichIndicators()
        }
        dismiss()
    }
}
