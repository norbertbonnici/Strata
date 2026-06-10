import Foundation

/// The examiner's instance-level CTI configuration: which tiers are enabled and
/// where the local NSRL hash list lives. **Tokens and base URLs are NOT stored
/// here** — they live in the Keychain (`KeychainCredentialStore`); this struct
/// only records the on/off flags + the NSRL file path, and persists to
/// `UserDefaults` (it is examiner config, not case evidence).
///
/// `makeProviders` turns the config + Keychain credentials into the concrete,
/// ordered provider list for an `EnrichmentEngine`. Disabled or unconfigured
/// tiers are omitted, so the engine only ever contacts services the analyst has
/// explicitly enabled and credentialed — the opt-in guarantee, enforced in one
/// place.
public nonisolated struct CTIConfiguration: Codable, Hashable, Sendable {
    public var nsrlEnabled: Bool
    public var nsrlFilePath: String?
    public var virusTotalEnabled: Bool
    public var mispEnabled: Bool
    public var openCTIEnabled: Bool

    public init(nsrlEnabled: Bool = false, nsrlFilePath: String? = nil,
                virusTotalEnabled: Bool = false, mispEnabled: Bool = false,
                openCTIEnabled: Bool = false) {
        self.nsrlEnabled = nsrlEnabled
        self.nsrlFilePath = nsrlFilePath
        self.virusTotalEnabled = virusTotalEnabled
        self.mispEnabled = mispEnabled
        self.openCTIEnabled = openCTIEnabled
    }

    /// Keychain service keys for the network tiers.
    public static let vtService = "virustotal"
    public static let mispService = "misp"
    public static let openCTIService = "opencti"

    public var anyEnabled: Bool {
        nsrlEnabled || virusTotalEnabled || mispEnabled || openCTIEnabled
    }

    /// Comma-joined list of enabled tier names (for the custody-ledger note).
    public var enabledSummary: String {
        var on: [String] = []
        if nsrlEnabled { on.append("NSRL") }
        if mispEnabled { on.append("MISP") }
        if openCTIEnabled { on.append("OpenCTI") }
        if virusTotalEnabled { on.append("VirusTotal") }
        return on.isEmpty ? "no sources" : on.joined(separator: " + ")
    }

    /// Build the configured, credentialed providers. A tier is included only
    /// when it is both enabled AND has the credentials it needs (NSRL: a hash
    /// file path; VT: an API token; MISP/OpenCTI: a base URL + token). Anything
    /// short of that is silently omitted — never a half-configured network call.
    public func makeProviders(credentials store: CredentialStoring) -> [any CTIProvider] {
        var providers: [any CTIProvider] = []

        if nsrlEnabled, let path = nsrlFilePath, !path.isEmpty {
            providers.append(NSRLProvider(loading: URL(fileURLWithPath: path)))
        }
        if virusTotalEnabled, let token = store.load(for: Self.vtService)?.token,
           !token.isEmpty {
            providers.append(VirusTotalProvider(apiKey: token))
        }
        if mispEnabled, let creds = store.load(for: Self.mispService),
           let base = creds.baseURL, let token = creds.token, !token.isEmpty {
            providers.append(MISPProvider(baseURL: base, token: token))
        }
        if openCTIEnabled, let creds = store.load(for: Self.openCTIService),
           let base = creds.baseURL, let token = creds.token, !token.isEmpty {
            providers.append(OpenCTIProvider(baseURL: base, token: token))
        }
        return providers
    }
}
