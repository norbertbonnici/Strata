import Testing
import Foundation
@testable import Strata

/// Locks the credential-store contract used by the network CTI providers:
///  - `CTICredentials` JSON round-trips (it's what lands in `kSecValueData`),
///  - the `CredentialStoring` save→load→delete lifecycle via the in-memory fake
///    (so providers can be tested headless, never hitting the real Keychain),
///  - the `hasToken` opt-in gate (empty/missing token ⇒ not configured),
///  - and a best-effort real-Keychain round-trip that is *skipped*, never
///    failed, when SecItem is unavailable (CI / sandboxed runner).
struct KeychainCredentialStoreTests {

    // MARK: CTICredentials Codable

    @Test func credentialsJSONRoundTrips() throws {
        let creds = CTICredentials(baseURL: URL(string: "https://misp.example.org"),
                                   token: "abc123-secret")
        let data = try JSONEncoder().encode(creds)
        let back = try JSONDecoder().decode(CTICredentials.self, from: data)
        #expect(back == creds)
        #expect(back.baseURL?.absoluteString == "https://misp.example.org")
        #expect(back.token == "abc123-secret")
    }

    @Test func credentialsDecodeFromRealisticJSON() throws {
        // The exact shape persisted into kSecValueData.
        let json = #"{"baseURL":"https://opencti.example.org\/graphql","token":"tok_999"}"#
        let creds = try JSONDecoder().decode(CTICredentials.self, from: Data(json.utf8))
        #expect(creds.token == "tok_999")
        #expect(creds.baseURL?.absoluteString == "https://opencti.example.org/graphql")
    }

    @Test func credentialsTolerateMissingFields() throws {
        // A token-only provider (e.g. VirusTotal) has no baseURL.
        let json = #"{"token":"vt_key"}"#
        let creds = try JSONDecoder().decode(CTICredentials.self, from: Data(json.utf8))
        #expect(creds.baseURL == nil)
        #expect(creds.token == "vt_key")
        #expect(creds.hasToken)
        // An entirely empty object is the "unconfigured" sentinel.
        let empty = try JSONDecoder().decode(CTICredentials.self, from: Data("{}".utf8))
        #expect(empty.baseURL == nil && empty.token == nil)
        #expect(!empty.hasToken)
    }

    // MARK: hasToken opt-in gate

    @Test func hasTokenRejectsBlankAndMissing() {
        #expect(!CTICredentials(token: nil).hasToken)
        #expect(!CTICredentials(token: "").hasToken)
        #expect(!CTICredentials(token: "   ").hasToken)
        #expect(CTICredentials(token: "x").hasToken)
    }

    // MARK: CredentialStoring lifecycle (in-memory fake)

    @Test func inMemoryStoreSaveLoadDeleteRoundTrip() {
        let store: any CredentialStoring = InMemoryCredentialStore()
        let service = "misp"
        #expect(store.load(for: service) == nil)            // empty to start

        let creds = CTICredentials(baseURL: URL(string: "https://misp.local"), token: "t1")
        #expect(store.save(creds, for: service))
        #expect(store.load(for: service) == creds)          // round-trips

        // Re-save overwrites (upsert semantics callers rely on).
        let updated = CTICredentials(baseURL: URL(string: "https://misp.local"), token: "t2")
        #expect(store.save(updated, for: service))
        #expect(store.load(for: service)?.token == "t2")

        #expect(store.delete(for: service))
        #expect(store.load(for: service) == nil)            // gone after delete
    }

    @Test func inMemoryStoreIsolatesServices() {
        let store = InMemoryCredentialStore()
        store.save(CTICredentials(token: "misp-tok"), for: "misp")
        store.save(CTICredentials(token: "vt-tok"), for: "virustotal")
        #expect(store.load(for: "misp")?.token == "misp-tok")
        #expect(store.load(for: "virustotal")?.token == "vt-tok")
        store.delete(for: "misp")
        #expect(store.load(for: "misp") == nil)
        #expect(store.load(for: "virustotal")?.token == "vt-tok")   // untouched
    }

    @Test func inMemoryStoreSeedsFromInitializer() {
        let store = InMemoryCredentialStore(seed: ["opencti": CTICredentials(token: "seeded")])
        #expect(store.load(for: "opencti")?.token == "seeded")
    }

    // MARK: Keychain service-key namespacing

    @Test func keychainServiceKeyIsNamespaced() {
        #expect(KeychainCredentialStore.serviceKey(for: "virustotal")
                == "com.bonnicilabs.strata.cti.virustotal")
    }

    // MARK: Real Keychain (best-effort; skipped, never failed, when unavailable)

    @Test func realKeychainRoundTripWhenAvailable() {
        let store = KeychainCredentialStore()
        // Unique per-run service so concurrent runs / leftovers don't collide.
        let service = "test-\(UUID().uuidString)"
        let creds = CTICredentials(baseURL: URL(string: "https://kc.test"), token: "kc-token")

        // If the Keychain isn't writable here (headless CI, sandbox), save
        // returns false — treat the whole check as a no-op skip, not a failure.
        guard store.save(creds, for: service) else { return }
        defer { store.delete(for: service) }

        #expect(store.load(for: service) == creds)
        #expect(store.delete(for: service))
        #expect(store.load(for: service) == nil)
    }
}
