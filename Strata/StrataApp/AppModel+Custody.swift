import Foundation
import SwiftUI

extension AppModel {
    // MARK: - Chain of custody

    /// Append one entry to the case's custody ledger and persist immediately.
    /// The actor is the case examiner at the time of the action. Single funnel
    /// so every recorded event is written through one place.
    func appendCustody(_ action: CustodyAction, detail: String, evidenceID: UUID? = nil) {
        guard currentCase != nil else { return }
        let event = CustodyEvent(action: action, actor: currentCase?.examiner ?? "",
                                 detail: detail, evidenceID: evidenceID)
        custodyLog.append(event)
        saveCustody()
    }

    /// Record a free-form examiner annotation in the custody log.
    func addCustodyNote(_ text: String, evidenceID: UUID? = nil) {
        let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return }
        appendCustody(.noteAdded, detail: trimmed, evidenceID: evidenceID)
    }

    private func saveCustody() {
        guard let bundleURL = currentCaseBundleURL else { return }
        do {
            try CaseStore.writeCustody(custodyLog, in: bundleURL)
        } catch {
            errorMessage = "Failed to save custody log: \(error.localizedDescription)"
        }
    }

    /// Record `acquired` + `hashRecorded` events for any acquisition metadata /
    /// embedded hashes captured at ingest (E01). No-op when none were found.
    func recordIngestIntegrityEvents(for evidence: Evidence) {
        if let acq = evidence.acquisition, !acq.isEmpty {
            var parts = ["Acquired \(evidence.displayName)"]
            if let date = acq.acquiredAt { parts.append("on \(date.ISO8601Format())") }
            if !acq.examiner.isEmpty { parts.append("by \(acq.examiner)") }
            if !acq.acquisitionTool.isEmpty { parts.append("using \(acq.acquisitionTool)") }
            appendCustody(.acquired, detail: parts.joined(separator: " "),
                          evidenceID: evidence.id)
        }
        for h in evidence.sourceHashes where h.origin == .embedded {
            appendCustody(.hashRecorded,
                          detail: "Embedded \(h.algorithm.label) of \(evidence.displayName): \(h.value)",
                          evidenceID: evidence.id)
        }
    }

    /// Scan every loaded host for IOC matches. Heavy lifting runs on a
    /// detached task so the UI keeps responsive on multi-million-event
    /// corpora.
    func runIOCMatch() async {
        guard !isWorking else { return }   // no overlapping passes
        guard !iocs.isEmpty else {
            statusMessage = "No IOCs loaded."
            return
        }
        guard let bundleURL = currentCaseBundleURL else { return }
        errorMessage = nil
        isWorking = true
        defer { isWorking = false }

        statusMessage = "Matching \(iocs.count) IOC(s) across \(evidenceList.count) host(s)..."
        // Capture as Sendable values up front so the detached Task doesn't
        // close over main-actor-isolated state (Swift 6 strict isolation).
        let iocSnapshot = iocs
        var total = 0
        for evidence in evidenceList {
            guard let state = states[evidence.id] else { continue }
            let events = state.events
            let registry = state.registryValues
            let files = state.files
            let matches = await Task.detached(priority: .userInitiated) {
                let matcher = IOCMatcher(iocs: iocSnapshot)
                return matcher.match(events: events, registry: registry, files: files)
            }.value
            var updated = state
            updated.iocMatches = matches
            states[evidence.id] = updated
            try? CaseStore.writeIOCMatches(matches, forHostID: evidence.id, in: bundleURL)
            total += matches.count
        }
        statusMessage = total == 0
            ? "No IOC matches."
            : "Found \(total) IOC match\(total == 1 ? "" : "es")."
        appendCustody(.enrichmentPerformed,
                      detail: "IOC match: \(iocSnapshot.count) indicator\(iocSnapshot.count == 1 ? "" : "s") across \(evidenceList.count) host\(evidenceList.count == 1 ? "" : "s") → \(total) match\(total == 1 ? "" : "es").")
    }

    /// Tiered CTI enrichment (NSRL → MISP/OpenCTI → VirusTotal) of the loaded
    /// IOCs. Opt-in: only the tiers enabled + credentialed in `ctiConfig` are
    /// contacted; with nothing configured this is a no-op. Verdicts are merged
    /// case-wide (`enrichment.json`), and the lookup is recorded in the custody
    /// ledger (the CTI audit trail the chain-of-custody feature consumes).
    func enrichIndicators() async {
        guard !isWorking else { return }
        guard let bundleURL = currentCaseBundleURL else { return }
        guard !iocs.isEmpty else { statusMessage = "No IOCs loaded to enrich."; return }
        guard ctiConfig.anyEnabled else {
            statusMessage = "No CTI sources enabled — configure them in Enrichment settings."
            return
        }
        errorMessage = nil
        isWorking = true
        defer { isWorking = false }
        statusMessage = "Enriching \(iocs.count) indicator(s) via configured CTI sources..."

        // Snapshot Sendable inputs so the detached lookup doesn't touch
        // main-actor state. Providers are built off-main (Keychain read + the
        // potentially large NSRL file load); the network happens via URLSession.
        let config = ctiConfig
        let indicators = iocs.map { (value: $0.value, kind: $0.kind) }
        let fresh = await Task.detached(priority: .userInitiated) { () -> [EnrichmentVerdict]? in
            let providers = config.makeProviders(credentials: KeychainCredentialStore())
            guard !providers.isEmpty else { return nil }
            let engine = EnrichmentEngine(providers: providers)
            return await engine.enrichAll(indicators)
        }.value

        guard let fresh else {
            statusMessage = "No CTI sources are configured (missing token / NSRL file)."
            return
        }
        // Merge by identity: new verdicts overwrite prior ones for the same
        // indicator, others are retained.
        var merged = Dictionary(enrichmentVerdicts.map { ($0.id, $0) }, uniquingKeysWith: { _, new in new })
        for v in fresh { merged[v.id] = v }
        enrichmentVerdicts = Array(merged.values)
        try? CaseStore.writeEnrichment(enrichmentVerdicts, in: bundleURL)

        let bad = fresh.filter { $0.verdict == .malicious || $0.verdict == .suspicious }.count
        let good = fresh.filter { $0.verdict == .knownGood }.count
        statusMessage = "Enriched \(fresh.count) indicator(s): \(bad) flagged, \(good) known-good."
        appendCustody(.enrichmentPerformed,
                      detail: "CTI lookup: \(fresh.count) indicator\(fresh.count == 1 ? "" : "s") via \(config.enabledSummary) → \(bad) malicious/suspicious, \(good) known-good.")
    }
}
