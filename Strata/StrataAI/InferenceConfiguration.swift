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

    public init(mode: Mode = .onDevice,
                cloudBaseURL: String = "https://api.anthropic.com",
                cloudModel: String = "claude-opus-4-8") {
        self.mode = mode
        self.cloudBaseURL = cloudBaseURL
        self.cloudModel = cloudModel
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
            return OnDeviceBackend()
        case .privateCloud:
            if #available(macOS 27.0, iOS 27.0, visionOS 27.0, *) {
                return PrivateCloudComputeBackend()
            }
            return OnDeviceBackend()
        case .cloud:
            guard let token = store.load(for: Self.keychainService)?.token,
                  !token.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty,
                  let base = URL(string: cloudBaseURL.trimmingCharacters(in: .whitespacesAndNewlines)),
                  base.scheme != nil
            else { return OnDeviceBackend() }
            return CloudInferenceBackend(baseURL: base, model: cloudModel, apiKey: token)
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
