import Foundation

/// The examiner's choice of where summary inference runs. **Sovereignty is a
/// configuration, not a rewrite** - flipping `mode` routes the *same* validated
/// pipeline to a cloud model. Persisted to `UserDefaults` (examiner config, not
/// case evidence); the cloud token lives in the Keychain (`CredentialStoring`,
/// shared with the CTI tiers), never here.
///
/// Default + fail-safe is on-device: `makeBackend` returns the sovereign backend
/// unless cloud is explicitly selected AND fully credentialed, so a
/// half-configured cloud mode can never leak evidence or silently break.
public nonisolated struct InferenceConfiguration: Codable, Hashable, Sendable {
    public enum Mode: String, Codable, Sendable, CaseIterable {
        /// On-device Apple Intelligence (sovereign default).
        case onDevice
        /// Apple Private Cloud Compute — off-device but attested + non-retaining.
        case privateCloud
        /// A third-party Anthropic-compatible endpoint the analyst credentials.
        case cloud
    }

    public var mode: Mode
    public var cloudBaseURL: String
    public var cloudModel: String

    /// Per-mode model **input** context window (tokens), editable from the
    /// inference settings sheet so the window can be tuned without recompiling —
    /// e.g. dial Apple PCC down from 32k if a run still overflows, or raise the
    /// conservative on-device guess if Apple's real window is larger. The
    /// summarizer sizes its digest batches + technique-group cap to the active
    /// backend's value (`FindingsSummarizer.promptBudgetChars` / `digestGroupCap`).
    /// Stored per mode so a value tuned for one backend never silently applies to
    /// another with a very different real window.
    public var onDeviceContextWindow: Int
    public var privateCloudContextWindow: Int
    public var cloudContextWindow: Int

    /// Built-in window defaults — the single source of truth, shared by the
    /// backends' init defaults so the UI default matches the compiled-in one.
    public static let defaultOnDeviceWindow = 4_096
    public static let defaultPrivateCloudWindow = 32_000
    public static let defaultCloudWindow = 200_000

    /// Smallest window the UI will accept — below this the summarizer can't fit
    /// even one digest row plus its reserve, so it's clamped on save.
    public static let minContextWindow = 1_024

    public init(mode: Mode = .onDevice,
                cloudBaseURL: String = "https://api.anthropic.com",
                cloudModel: String = "claude-opus-4-8",
                onDeviceContextWindow: Int = defaultOnDeviceWindow,
                privateCloudContextWindow: Int = defaultPrivateCloudWindow,
                cloudContextWindow: Int = defaultCloudWindow) {
        self.mode = mode
        self.cloudBaseURL = cloudBaseURL
        self.cloudModel = cloudModel
        self.onDeviceContextWindow = onDeviceContextWindow
        self.privateCloudContextWindow = privateCloudContextWindow
        self.cloudContextWindow = cloudContextWindow
    }

    private enum CodingKeys: String, CodingKey {
        case mode, cloudBaseURL, cloudModel
        case onDeviceContextWindow, privateCloudContextWindow, cloudContextWindow
    }

    /// Back-compat decode: a config persisted before the context-window fields
    /// existed falls back to the defaults. (Synthesized decoding would *throw* on
    /// the missing keys, and `load()` would then silently reset the whole config —
    /// losing the examiner's mode/endpoint.)
    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        mode = try c.decodeIfPresent(Mode.self, forKey: .mode) ?? .onDevice
        cloudBaseURL = try c.decodeIfPresent(String.self, forKey: .cloudBaseURL) ?? "https://api.anthropic.com"
        cloudModel = try c.decodeIfPresent(String.self, forKey: .cloudModel) ?? "claude-opus-4-8"
        onDeviceContextWindow = try c.decodeIfPresent(Int.self, forKey: .onDeviceContextWindow) ?? Self.defaultOnDeviceWindow
        privateCloudContextWindow = try c.decodeIfPresent(Int.self, forKey: .privateCloudContextWindow) ?? Self.defaultPrivateCloudWindow
        cloudContextWindow = try c.decodeIfPresent(Int.self, forKey: .cloudContextWindow) ?? Self.defaultCloudWindow
    }

    /// The configured context window for a given mode.
    public func contextWindow(for mode: Mode) -> Int {
        switch mode {
        case .onDevice:     return onDeviceContextWindow
        case .privateCloud: return privateCloudContextWindow
        case .cloud:        return cloudContextWindow
        }
    }

    /// Keychain service key for the cloud token (reuses `CTICredentials` storage).
    public static let keychainService = "inference-cloud"

    /// Build the configured backend, failing safe to the sovereign on-device one.
    ///
    /// - `.privateCloud` returns the PCC backend when the OS provides it (its own
    ///   `availability()` then reports device/system readiness — no silent
    ///   downgrade to a different model); on an OS without the API it falls back
    ///   to on-device, since PCC simply can't run there.
    /// - `.cloud` fails safe to on-device unless fully credentialed (token + a
    ///   parseable base URL), so a half-configured cloud mode can't leak or break.
    public func makeBackend(credentials store: CredentialStoring) -> any InferenceBackend {
        switch mode {
        case .onDevice:
            return OnDeviceBackend(contextWindowTokens: onDeviceContextWindow)
        case .privateCloud:
            if #available(macOS 27.0, iOS 27.0, visionOS 27.0, *) {
                return PrivateCloudComputeBackend(contextWindowTokens: privateCloudContextWindow)
            }
            return OnDeviceBackend(contextWindowTokens: onDeviceContextWindow)
        case .cloud:
            guard let token = store.load(for: Self.keychainService)?.token,
                  !token.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty,
                  let base = URL(string: cloudBaseURL.trimmingCharacters(in: .whitespacesAndNewlines)),
                  base.scheme != nil
            else { return OnDeviceBackend(contextWindowTokens: onDeviceContextWindow) }
            return CloudInferenceBackend(baseURL: base, model: cloudModel, apiKey: token,
                                         contextWindowTokens: cloudContextWindow)
        }
    }

    /// PCC availability, surfaced in the settings sheet even when PCC isn't the
    /// active mode (so the analyst can see it before switching). Guarded so it is
    /// safe to call below the PCC deployment floor.
    public static func privateCloudAvailability() -> SummarizerAvailability {
        if #available(macOS 27.0, iOS 27.0, visionOS 27.0, *) {
            return PrivateCloudComputeBackend().availability()
        }
        return .unavailable(reason: "Apple Private Cloud Compute requires a newer version of macOS / iOS.")
    }

    /// True when cloud is selected and credentialed (so the UI can warn that a
    /// run will send evidence-derived data off-host).
    public func cloudConfigured(credentials store: CredentialStoring) -> Bool {
        guard mode == .cloud, let t = store.load(for: Self.keychainService)?.token else { return false }
        return !t.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
    }

    /// Stable identifier of the *egress destination* a run would send finding
    /// summaries to. The first-run confirmation is keyed on this, so acknowledging
    /// one destination doesn't silently authorise a different one the config is
    /// later pointed at. Mode-aware: Apple Private Cloud Compute is one fixed
    /// destination (no endpoint/key to vary), while a third-party endpoint varies
    /// by base URL + model. The on-device value is never consulted (sovereign →
    /// no gate); the run-time gate checks the *effective* backend is non-sovereign
    /// before comparing this.
    public var destinationFingerprint: String {
        switch mode {
        case .onDevice:     return "on-device"
        case .privateCloud: return "apple-pcc"
        case .cloud:
            return "\(cloudBaseURL.trimmingCharacters(in: .whitespacesAndNewlines))|\(cloudModel.trimmingCharacters(in: .whitespacesAndNewlines))"
        }
    }

    // MARK: - Persistence

    private static let defaultsKey = "com.bonnicilabs.strata.inferenceConfig"

    public static func load(_ defaults: UserDefaults = .standard) -> InferenceConfiguration {
        guard let data = defaults.data(forKey: defaultsKey),
              let cfg = try? JSONDecoder().decode(InferenceConfiguration.self, from: data)
        else { return InferenceConfiguration() }
        return cfg
    }

    public func save(_ defaults: UserDefaults = .standard) {
        if let data = try? JSONEncoder().encode(self) { defaults.set(data, forKey: Self.defaultsKey) }
    }
}
