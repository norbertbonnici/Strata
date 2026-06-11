import Foundation
import Security

/// Per-instance credentials for a network CTI provider (MISP / OpenCTI /
/// VirusTotal). Both fields are optional so a half-configured provider is
/// representable; a provider treats "no token" (and, for the self-hosted tiers,
/// "no baseURL") as **unconfigured** and returns nil from `lookup` — that's how
/// the opt-in / fail-open contract is honoured without any network call.
///
/// Persisted as JSON in the Keychain's `kSecValueData`, one item per provider
/// service key.
public nonisolated struct CTICredentials: Codable, Hashable, Sendable {
    public var baseURL: URL?
    public var token: String?

    public init(baseURL: URL? = nil, token: String? = nil) {
        self.baseURL = baseURL
        self.token = token
    }

    /// True once there's enough here to attempt a lookup. VirusTotal (a fixed
    /// public endpoint) needs only a token; the self-hosted tiers need a baseURL
    /// too. Providers decide which rule applies — this is the loosest check
    /// (a token is the universal minimum).
    public var hasToken: Bool {
        guard let t = token else { return false }
        return !t.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
    }
}

/// Abstraction over credential persistence so callers (and the providers built
/// on top) can be unit-tested against an in-memory fake instead of the real
/// Keychain (which is unavailable / flaky in a headless CI run). The real impl
/// is `KeychainCredentialStore`; tests/previews use `InMemoryCredentialStore`.
public protocol CredentialStoring: Sendable {
    /// Persist (insert-or-update) the credentials under a provider service key.
    @discardableResult
    nonisolated func save(_ credentials: CTICredentials, for service: String) -> Bool
    /// Load the credentials for a provider service key, or nil if none stored.
    nonisolated func load(for service: String) -> CTICredentials?
    /// Remove any stored credentials for a provider service key.
    @discardableResult
    nonisolated func delete(for service: String) -> Bool
}

/// Real Keychain-backed credential store (`kSecClassGenericPassword`). One item
/// per provider, keyed by a namespaced service string + the service name as the
/// account. The `CTICredentials` value is JSON-encoded into `kSecValueData`.
///
/// No `kSecAttrAccessGroup` is set, so the item lives in the app's own keychain
/// — macOS and iOS compatible with no shared-keychain entitlement. `save`
/// upserts (delete-then-add) so re-saving a provider's config just overwrites.
public nonisolated struct KeychainCredentialStore: CredentialStoring {
    /// Service-string prefix; the per-provider key is `<prefix>.<service>`.
    public static let servicePrefix = "com.bonnicilabs.strata.cti"

    public init() {}

    /// Namespaced `kSecAttrService` for a provider, e.g.
    /// `com.bonnicilabs.strata.cti.virustotal`.
    public static func serviceKey(for service: String) -> String {
        "\(servicePrefix).\(service)"
    }

    /// Base query identifying exactly one item for a provider service.
    private func baseQuery(for service: String) -> [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: Self.serviceKey(for: service),
            kSecAttrAccount as String: service,
        ]
    }

    @discardableResult
    public func save(_ credentials: CTICredentials, for service: String) -> Bool {
        guard let data = try? JSONEncoder().encode(credentials) else { return false }
        // Upsert: drop any existing item, then add fresh. (SecItemUpdate is
        // finicky across platforms; delete-then-add is the portable idiom.)
        SecItemDelete(baseQuery(for: service) as CFDictionary)
        var add = baseQuery(for: service)
        add[kSecValueData as String] = data
        let status = SecItemAdd(add as CFDictionary, nil)
        return status == errSecSuccess
    }

    public func load(for service: String) -> CTICredentials? {
        var query = baseQuery(for: service)
        query[kSecReturnData as String] = kCFBooleanTrue
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        guard status == errSecSuccess, let data = item as? Data else { return nil }
        return try? JSONDecoder().decode(CTICredentials.self, from: data)
    }

    @discardableResult
    public func delete(for service: String) -> Bool {
        let status = SecItemDelete(baseQuery(for: service) as CFDictionary)
        return status == errSecSuccess || status == errSecItemNotFound
    }
}

/// Dictionary-backed credential store for tests and SwiftUI previews — never
/// touches the Keychain, so it's headless-safe and deterministic. A `final
/// class` (reference semantics) so callers holding it as a `CredentialStoring`
/// observe each other's saves; thread-safe via a small lock to keep `Sendable`
/// honest under concurrency.
public final class InMemoryCredentialStore: CredentialStoring, @unchecked Sendable {
    private let lock = NSLock()
    private var storage: [String: CTICredentials] = [:]

    public init(seed: [String: CTICredentials] = [:]) {
        self.storage = seed
    }

    @discardableResult
    public func save(_ credentials: CTICredentials, for service: String) -> Bool {
        lock.lock(); defer { lock.unlock() }
        storage[service] = credentials
        return true
    }

    public func load(for service: String) -> CTICredentials? {
        lock.lock(); defer { lock.unlock() }
        return storage[service]
    }

    @discardableResult
    public func delete(for service: String) -> Bool {
        lock.lock(); defer { lock.unlock() }
        storage.removeValue(forKey: service)
        return true
    }
}
