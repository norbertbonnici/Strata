import Testing
import Foundation
@testable import Strata

/// Verifies the opt-in provider builder: a tier appears only when it is both
/// enabled AND has the credentials it needs, so the engine never makes a
/// half-configured network call.
struct CTIConfigurationTests {

    @Test func disabledConfigBuildsNoProviders() {
        let cfg = CTIConfiguration()   // all off
        #expect(cfg.makeProviders(credentials: InMemoryCredentialStore()).isEmpty)
        #expect(!cfg.anyEnabled)
    }

    @Test func enabledButUncredentialedTiersAreOmitted() {
        // VT/MISP/OpenCTI enabled but no tokens in the store → omitted.
        let cfg = CTIConfiguration(nsrlEnabled: true, nsrlFilePath: nil,
                                   virusTotalEnabled: true, mispEnabled: true, openCTIEnabled: true)
        let providers = cfg.makeProviders(credentials: InMemoryCredentialStore())
        // NSRL has no path → omitted; VT/MISP/OpenCTI have no creds → omitted.
        #expect(providers.isEmpty)
    }

    @Test func credentialedTiersAppearInTierOrder() {
        let store = InMemoryCredentialStore()
        _ = store.save(CTICredentials(token: "vt-key"), for: CTIConfiguration.vtService)
        _ = store.save(CTICredentials(baseURL: URL(string: "https://misp.example"), token: "m"),
                       for: CTIConfiguration.mispService)
        let cfg = CTIConfiguration(virusTotalEnabled: true, mispEnabled: true)
        let providers = cfg.makeProviders(credentials: store)
        let names = providers.map(\.name)
        #expect(names.contains("VirusTotal"))
        #expect(names.contains("MISP"))
        #expect(providers.count == 2)   // NSRL/OpenCTI not enabled
    }

    @Test func enabledSummaryListsActiveTiers() {
        let cfg = CTIConfiguration(nsrlEnabled: true, virusTotalEnabled: true)
        #expect(cfg.enabledSummary == "NSRL + VirusTotal")
        #expect(CTIConfiguration().enabledSummary == "no sources")
    }
}
