import Foundation
import SwiftUI

extension AppModel {
    // MARK: - Ingest

    #if os(macOS)

    /// Add a new host to the current case. For an image, `tsk_loaddb` output
    /// lands inside the case bundle so the case stays self-contained; for a
    /// loose KAPE folder we walk the directory directly. After ingest the new
    /// host becomes the active scope so the user immediately sees its
    /// contents.
    func ingest(sourceURL: URL) async {
        guard let bundleURL = currentCaseBundleURL else {
            errorMessage = "Open or create a case first."
            return
        }
        errorMessage = nil
        isWorking = true
        defer { isWorking = false }

        do {
            var evidence = KapeImporter.makeEvidence(from: sourceURL)
            let hostDir = CaseStore.hostDirectory(forHostID: evidence.id, in: bundleURL)
            try FileManager.default.createDirectory(at: hostDir, withIntermediateDirectories: true)

            var state: EvidenceState
            if evidence.kind == .kapeLooseFolder {
                statusMessage = "Scanning \(evidence.displayName)..."
                // The folder can hold many thousands of files; walk it off the
                // main actor so the UI stays responsive.
                let root = evidence.sourceURL
                let loaded = await Task.detached(priority: .userInitiated) {
                    KapeFolderIngestor().ingest(folderAt: root)
                }.value
                var s = EvidenceState(dbURL: nil)
                s.files = loaded
                s.timeline = TimelineBuilder.build(from: loaded)
                state = s
            } else {
                let dbURL = CaseStore.tskDatabaseURL(forHostID: evidence.id, in: bundleURL)
                evidence.tskDatabaseURL = dbURL

                let environment = try TSKEnvironment.discover()
                let ingestor = TSKImageIngestor(environment: environment)

                statusMessage = "Ingesting \(evidence.displayName) with TSK..."
                do {
                    try await ingestor.ingest(imageAt: evidence.sourceURL, into: dbURL) { line in
                        Task { @MainActor in self.statusMessage = line }
                    }
                    statusMessage = "Reading file system..."
                    let database = try TSKDatabase(path: dbURL)
                    let loaded = try database.fetchFiles()
                    var s = EvidenceState(dbURL: dbURL)
                    s.files = loaded
                    s.volumes = (try? database.fetchVolumes()) ?? []
                    s.timeline = TimelineBuilder.build(from: loaded)
                    state = s
                } catch let tskError as TSKError {
                    // The Sleuth Kit's APFS parser crashes (SIGABRT) on real
                    // macOS volumes - fall back to libfsapfs (fsapfsinfo) for an
                    // APFS image instead of failing the ingest.
                    guard case .ingestionCrashed = tskError else { throw tskError }
                    try? FileManager.default.removeItem(at: dbURL)   // drop the partial DB
                    statusMessage = "The Sleuth Kit can't read this volume (likely APFS) — switching to fsapfsinfo…"
                    state = try await performApfsIngest(
                        for: &evidence, environment: environment, hostDir: hostDir,
                        bundleURL: bundleURL, credential: fileVaultCredentials[evidence.id])
                }

                // E01 carries acquisition metadata + acquisition hashes in its
                // header - read them (cheap) instead of rehashing the image.
                // (Check the source extension, not `kind`, which may now be .apfs.)
                if TSKImageIngestor.imageType(for: evidence.sourceURL) == "ewf" {
                    statusMessage = "Reading E01 acquisition metadata…"
                    if let meta = try? await EWFInfo(environment: environment).read(imageAt: evidence.sourceURL) {
                        Self.applyEWFMetadata(meta, to: &evidence)
                    }
                }
            }

            state.osFamilies = OSFamily.detect(volumes: state.volumes, files: state.files)
            self.evidenceList.append(evidence)
            self.states[evidence.id] = state
            self.activeEvidenceID = evidence.id
            saveHosts()
            appendCustody(.addedToCase,
                          detail: "Ingested \(evidence.displayName) (\(evidence.kind.label)) from \(evidence.sourceURL.path)",
                          evidenceID: evidence.id)
            recordIngestIntegrityEvents(for: evidence)
            self.statusMessage = "Loaded \(state.files.count) files from \(evidence.displayName)."
            // An encrypted APFS volume blocks comprehension of the host, so the
            // FileVault prompt takes priority over the enrichment offer. Skip the
            // enrichment popup when there's nothing to opt into - prompting about
            // an empty list is just friction.
            if let locked = lockedApfsVolumes[evidence.id], !locked.isEmpty {
                activeSheet = .fileVaultUnlock(evidence.id)
            } else if !iocs.isEmpty {
                activeSheet = .enrichment
            }
        } catch {
            self.errorMessage = error.localizedDescription
            self.statusMessage = ""
        }
    }

    /// Run (or re-run) the libfsapfs ingest for an APFS image: build the
    /// `EvidenceState`, reclassify the evidence as `.apfs`, persist the tree +
    /// volumes (there's no `tsk.db`), and record any FileVault-locked volumes on
    /// `lockedApfsVolumes`. `credential` unlocks an encrypted volume's metadata.
    /// Shared by the first-ingest fallback and `unlockFileVault`.
    private func performApfsIngest(for evidence: inout Evidence,
                                   environment: TSKEnvironment,
                                   hostDir: URL, bundleURL: URL,
                                   credential: FileVaultCredential?) async throws -> EvidenceState {
        let scratch = hostDir.appendingPathComponent("apfs")
        // A re-ingest of an already-converted E01 reuses the raw scratch so we
        // don't run ewfexport again; a first ingest reads the source directly.
        let imageURL: URL
        let imageType: String?
        if evidence.kind == .apfs, let raw = evidence.apfsRawURL,
           FileManager.default.fileExists(atPath: raw.path) {
            imageURL = raw
            imageType = nil                       // already raw
        } else {
            imageURL = evidence.sourceURL
            imageType = TSKImageIngestor.imageType(for: evidence.sourceURL)
        }
        let apfs = FsApfsIngestor(environment: environment)
        let result = try await apfs.ingest(
            imageAt: imageURL, imageType: imageType, scratchDirectory: scratch,
            credential: credential) { line in
                Task { @MainActor in self.statusMessage = line }
            }
        // Reclassify as an APFS image + record the raw the content extractor reads
        // from (the source if raw, else the ewfexport scratch).
        evidence.kind = .apfs
        evidence.apfsRawURL = result.rawScratchURL ?? evidence.apfsRawURL ?? evidence.sourceURL
        var s = EvidenceState(dbURL: nil)         // no tsk.db on the APFS path
        s.files = result.files
        s.volumes = result.volumes
        s.timeline = TimelineBuilder.build(from: result.files)
        try? CaseStore.writeApfsFiles(result.files, forHostID: evidence.id, in: bundleURL)
        try? CaseStore.writeApfsVolumes(result.volumes, forHostID: evidence.id, in: bundleURL)
        lockedApfsVolumes[evidence.id] = result.lockedVolumes.isEmpty ? nil : result.lockedVolumes
        return s
    }

    /// Supply a FileVault secret for an encrypted APFS host and re-ingest so its
    /// Data-volume artifacts become readable, then re-run the macOS / browser /
    /// unified-log parsers. The secret is held in memory only (never persisted).
    func unlockFileVault(evidenceID: UUID, password: String?, recovery: String?) async {
        guard let bundleURL = currentCaseBundleURL,
              var evidence = evidenceList.first(where: { $0.id == evidenceID }) else { return }
        let credential = FileVaultCredential(password: password, recovery: recovery)
        guard credential.hasSecret else { return }
        fileVaultCredentials[evidenceID] = credential
        errorMessage = nil
        isWorking = true
        defer { isWorking = false }
        do {
            let environment = try TSKEnvironment.discover()
            let hostDir = CaseStore.hostDirectory(forHostID: evidenceID, in: bundleURL)
            statusMessage = "Unlocking FileVault volume for \(evidence.displayName)…"
            var state = try await performApfsIngest(
                for: &evidence, environment: environment, hostDir: hostDir,
                bundleURL: bundleURL, credential: credential)
            state.osFamilies = OSFamily.detect(volumes: state.volumes, files: state.files)
            // The kind / apfsRawURL may have changed; replace the host record too.
            if let idx = evidenceList.firstIndex(where: { $0.id == evidenceID }) {
                evidenceList[idx] = evidence
            }
            states[evidenceID] = state
            saveHosts()
            appendCustody(.analysed,
                          detail: "Unlocked FileVault volume and re-ingested \(evidence.displayName)",
                          evidenceID: evidenceID)
            if let locked = lockedApfsVolumes[evidenceID], !locked.isEmpty {
                statusMessage = "Some volumes are still locked — verify the password / recovery key."
            } else {
                statusMessage = "Unlocked \(state.files.count) files from \(evidence.displayName). Re-running analysis…"
                await parseMac()
                await parseBrowserHistory()
                await parseMessages()
                await parseMail()
                await parseUnifiedLog()
                statusMessage = "Unlocked and analysed \(evidence.displayName)."
            }
        } catch {
            errorMessage = error.localizedDescription
            statusMessage = ""
        }
    }

    /// Carve recoverable files directly out of each APFS host's raw image by
    /// signature, bypassing the filesystem + libfsapfs — this reaches deleted
    /// files in unallocated space and content libfsapfs won't surface (sealed
    /// System snapshot, locked FileVault). Opt-in (Tools ▸ Carve Deleted Files);
    /// results persist as `carved.json`. No timeline splice (carved files carry
    /// no timestamps, like FSEvents / the WMI carve).
    func carveArtifacts() async {
        guard let bundleURL = currentCaseBundleURL else { return }
        errorMessage = nil
        isWorking = true
        defer { isWorking = false; progress = nil }
        var hostsTouched = 0
        for evidence in evidenceList where evidence.kind == .apfs {
            guard var state = states[evidence.id],
                  let raw = evidence.apfsRawURL,
                  FileManager.default.fileExists(atPath: raw.path) else { continue }
            let name = evidence.displayName
            statusMessage = "Carving \(name) (raw signature scan)…"
            // A full-image scan can take minutes; stream a determinate progress
            // bar (MB scanned) so the UI clearly shows it's working, not hung.
            progress = ProgressInfo(current: 0, total: 0, label: "Carving \(name)")
            let source = raw.lastPathComponent
            let carved: [CarvedFile] = await Task.detached(priority: .userInitiated) {
                (try? FileCarver.carveFile(at: raw, source: source) { scanned, total in
                    Task { @MainActor in
                        self.progress = ProgressInfo(current: scanned >> 20, total: total >> 20,
                                                     label: "Carving \(name)")
                    }
                }) ?? []
            }.value
            state.carvedFiles = carved
            states[evidence.id] = state
            try? CaseStore.writeCarved(carved, forHostID: evidence.id, in: bundleURL)
            appendCustody(.analysed,
                          detail: "Carved \(carved.count) recoverable file(s) from \(evidence.displayName)",
                          evidenceID: evidence.id)
            hostsTouched += 1
        }
        statusMessage = hostsTouched == 0
            ? "No APFS image to carve — carving runs on the macOS APFS ingest path."
            : "Carving complete."
    }

    /// Re-read a carved file's bytes from its source image (offset + length), for
    /// the macOS view's Save action. Matches the host by the carve's source name.
    func carvedFileData(_ carved: CarvedFile) -> Data? {
        for evidence in evidenceList where evidence.kind == .apfs {
            guard let raw = evidence.apfsRawURL, raw.lastPathComponent == carved.source,
                  let handle = try? FileHandle(forReadingFrom: raw) else { continue }
            defer { try? handle.close() }
            do {
                try handle.seek(toOffset: UInt64(carved.offset))
                return try handle.read(upToCount: Int(carved.size))
            } catch { return nil }
        }
        return nil
    }

    #endif

    /// Drop a host from the current case. We delete the entire host directory
    /// inside the bundle (TSK DB, extracted .evtx / hive scratch) since the
    /// data is reproducible from the original source image.
    func removeEvidence(_ id: UUID) {
        if let bundleURL = currentCaseBundleURL {
            CaseStore.removeHostDirectory(forHostID: id, in: bundleURL)
        }
        evidenceList.removeAll { $0.id == id }
        states[id] = nil
        if activeEvidenceID == id { activeEvidenceID = nil }
        saveHosts()
    }
}
