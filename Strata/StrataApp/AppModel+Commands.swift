import Foundation
import SwiftUI

extension AppModel {
    // MARK: - Menu command entry points

    /// Triggered by File > New Case (Cmd-N). Closes any open case so the
    /// New Case sheet binds to a clean state, then shows the sheet.
    func requestNewCase() {
        if currentCase != nil { closeCase() }
        activeSheet = .newCase
    }

    /// Triggered by Tools > Run Enrichment (Cmd-E). Reuses the same sheet
    /// shown after ingest. Only meaningful when a case is open.
    func requestEnrichment() {
        guard currentCase != nil else { return }
        activeSheet = .enrichment
    }

    /// Triggered by Tools > Export (Shift-Cmd-E). Presents the export sheet.
    func requestExport() {
        guard currentCase != nil else { return }
        activeSheet = .export
    }

    /// True when any loaded host has a FileVault-locked APFS volume awaiting a
    /// secret (drives the Tools ▸ Unlock command's enabled state).
    var hasLockedApfsVolumes: Bool {
        lockedApfsVolumes.values.contains { !$0.isEmpty }
    }

    /// True when any loaded host is an APFS image (the carve target — drives the
    /// Tools ▸ Carve command's enabled state).
    var hasApfsHost: Bool {
        evidenceList.contains { $0.kind == .apfs }
    }

    /// Triggered by Tools ▸ Unlock FileVault Volume (and auto-shown after an
    /// ingest that found locked volumes). Prompts for the active host's secret,
    /// falling back to the first host that has a locked volume.
    func requestFileVaultUnlock() {
        let id = (activeEvidenceID.flatMap { id in
            (lockedApfsVolumes[id]?.isEmpty == false) ? id : nil
        }) ?? lockedApfsVolumes.first(where: { !$0.value.isEmpty })?.key
        guard let id else { return }
        activeSheet = .fileVaultUnlock(id)
    }

    /// Generate the selected report/export artifacts and write them as one
    /// timestamped set into `folder`. Returns the created export folder on
    /// success (so the sheet can reveal it in Finder), or nil.
    ///
    /// `hostIDs` selects which endpoints to include - both the report and the
    /// data exports cover exactly those hosts, in the case's host order.
    ///
    /// Mirrors `runIOCMatch`: snapshot the (Sendable) per-host data on the main
    /// actor, then build + write off the main actor so a large timeline doesn't
    /// stall the UI.
    @discardableResult
    func exportSet(_ selection: ExportSelection, hostIDs: Set<UUID>,
                   to folder: URL) async -> URL? {
        guard !isWorking else { return nil }
        guard let theCase = currentCase, !selection.isEmpty else { return nil }
        let selectedHosts = evidenceList.filter { hostIDs.contains($0.id) }
        guard !selectedHosts.isEmpty else { return nil }
        errorMessage = nil
        isWorking = true
        defer { isWorking = false }
        statusMessage = "Generating export…"

        let hosts: [ReportInputs.Host] = selectedHosts.map { evidence in
            let state = states[evidence.id]
            return ReportInputs.Host(
                displayName: evidence.displayName,
                kindLabel: evidence.kind.label,
                sourcePath: evidence.sourceURL.path,
                registryValues: state?.registryValues ?? [],
                findings: state?.findings ?? [],
                iocMatches: state?.iocMatches ?? [],
                timeline: state?.timeline ?? [],
                fileCount: state?.files.count ?? 0,
                eventCount: state?.events.count ?? 0,
                evidenceID: evidence.id,
                acquisition: evidence.acquisition,
                sourceHashes: evidence.sourceHashes,
                linuxInfo: state?.linuxInfo)
        }
        let now = Date()
        // Custody log and annotations are case-wide; include the entries for
        // the selected hosts plus unscoped (nil-evidence) ones.
        let selectedIDs = Set(selectedHosts.map(\.id))
        let custodyForExport = custodyLog.filter { $0.evidenceID == nil || selectedIDs.contains($0.evidenceID!) }
        let annotationsForExport = annotations.filter { $0.evidenceID == nil || selectedIDs.contains($0.evidenceID!) }
        let inputs = ReportInputs(caseName: theCase.name, examiner: theCase.examiner,
                                  createdAt: theCase.createdAt, generatedAt: now,
                                  hosts: hosts, custodyLog: custodyForExport,
                                  caseNotes: caseNotes.text,
                                  annotations: annotationsForExport,
                                  executiveSummary: caseSummary?.text ?? "",
                                  summaryClaims: caseSummary?.claims ?? [],
                                  summaryValidation: caseSummary?.validation,
                                  summaryModelLabel: caseSummary?.modelLabel ?? "",
                                  summarySovereignty: caseSummary?.sovereignty ?? .onDevice)

        let outcome = await Task.detached(priority: .userInitiated) { () -> ExportOutcome in
            let files = ExportGenerator.generate(inputs: inputs, selection: selection)
            do {
                let output = try CaseExportWriter.write(files, caseName: inputs.caseName,
                                                        timestamp: now, to: folder)
                return .success(folderURL: output.folderURL, filenames: output.filenames)
            } catch {
                return .failure(message: error.localizedDescription)
            }
        }.value

        switch outcome {
        case let .success(folderURL, filenames):
            let n = filenames.count
            statusMessage = "Exported \(n) file\(n == 1 ? "" : "s") to \(folderURL.lastPathComponent)."
            appendCustody(.exported,
                          detail: "Exported \(n) file\(n == 1 ? "" : "s") to \(folderURL.lastPathComponent): \(filenames.joined(separator: ", "))")
            return folderURL
        case let .failure(message):
            errorMessage = "Export failed: \(message)"
            return nil
        }
    }

    /// Triggered by File > Open Case... (Cmd-O). Closes any open case before
    /// presenting the picker so the user doesn't end up with mismatched
    /// state if the open fails partway through. The actual file dialog is
    /// presented by WelcomeView via SwiftUI's `.fileImporter`.
    func requestOpenCase() {
        fileImportMode = .openCase
        if currentCase != nil {
            closeCase()
            // Let WelcomeView (which hosts the .fileImporter) mount before we
            // present - otherwise the binding is already true at insertion and
            // SwiftUI can silently drop the presentation.
            Task { @MainActor in fileImportPresented = true }
        } else {
            fileImportPresented = true
        }
    }
}
