import Foundation
import SwiftUI

extension AppModel {
    // MARK: - Source-hash integrity (compute / verify)

    #if os(macOS)


    /// Cancel an in-progress compute/verify pass.
    func cancelHashing() { hashTask?.cancel() }

    /// Stream MD5 + SHA-256 over a raw/VHD source and record them as `.computed`
    /// source hashes on the evidence. No-op for E01 (use the embedded hashes)
    /// and loose folders (no single image). Runs off the main actor with a
    /// determinate progress bar; persists to `hosts.json` when done.
    func computeSourceHashes(for evidenceID: UUID) async {
        guard !isWorking else { return }
        guard let evidence = evidenceList.first(where: { $0.id == evidenceID }) else { return }
        guard evidence.kind != .kapeLooseFolder else {
            statusMessage = "\(evidence.displayName): a loose folder has no single image to hash."
            return
        }
        let src = evidence.sourceURL
        guard FileManager.default.fileExists(atPath: src.path) else {
            errorMessage = "Source missing for \(evidence.displayName) at \(src.path)."
            return
        }
        errorMessage = nil
        isWorking = true
        defer { isWorking = false; progress = nil; hashTask = nil }
        let name = evidence.displayName
        statusMessage = "Hashing \(name)…"
        progress = ProgressInfo(current: 0, total: 0, label: "Hashing \(name)")

        let task = Task.detached(priority: .userInitiated) { () throws -> FileHasher.Result in
            try FileHasher.hash(fileAt: src) { read, total in
                Task { @MainActor in
                    self.progress = ProgressInfo(current: Int(read >> 20),
                                                 total: Int(total >> 20),
                                                 label: "Hashing \(name)")
                }
            }
        }
        hashTask = task

        do {
            let result = try await task.value
            let now = Date()
            let computed = [
                SourceHash(algorithm: .md5, value: result.md5, origin: .computed,
                           status: .notVerified, computedAt: now, note: "Computed by Strata"),
                SourceHash(algorithm: .sha256, value: result.sha256, origin: .computed,
                           status: .notVerified, computedAt: now, note: "Computed by Strata"),
            ]
            updateEvidence(evidenceID) { ev in
                // Replace any prior computed digests; keep embedded ones intact.
                ev.sourceHashes.removeAll { $0.origin == .computed }
                ev.sourceHashes.append(contentsOf: computed)
            }
            for h in computed {
                appendCustody(.hashRecorded,
                              detail: "Computed \(h.algorithm.label) of \(name): \(h.value)",
                              evidenceID: evidenceID)
            }
            statusMessage = "Hashed \(name): SHA-256 \(result.sha256.prefix(16))…"
        } catch is CancellationError {
            statusMessage = "Hashing cancelled."
        } catch {
            errorMessage = "Hashing failed: \(error.localizedDescription)"
        }
    }

    /// Re-hash a raw/VHD source and compare against the stored `.computed`
    /// digests, flipping each to `.verified` or `.mismatch`. If nothing has been
    /// computed yet, falls back to a first computation.
    func verifyComputedHashes(for evidenceID: UUID) async {
        guard !isWorking else { return }
        guard let evidence = evidenceList.first(where: { $0.id == evidenceID }) else { return }
        let priorComputed = evidence.sourceHashes.filter { $0.origin == .computed }
        guard !priorComputed.isEmpty else {
            await computeSourceHashes(for: evidenceID)
            return
        }
        let src = evidence.sourceURL
        guard FileManager.default.fileExists(atPath: src.path) else {
            errorMessage = "Source missing for \(evidence.displayName) at \(src.path)."
            return
        }
        errorMessage = nil
        isWorking = true
        defer { isWorking = false; progress = nil; hashTask = nil }
        let name = evidence.displayName
        statusMessage = "Verifying \(name)…"
        progress = ProgressInfo(current: 0, total: 0, label: "Verifying \(name)")

        let task = Task.detached(priority: .userInitiated) { () throws -> FileHasher.Result in
            try FileHasher.hash(fileAt: src) { read, total in
                Task { @MainActor in
                    self.progress = ProgressInfo(current: Int(read >> 20),
                                                 total: Int(total >> 20),
                                                 label: "Verifying \(name)")
                }
            }
        }
        hashTask = task

        do {
            let result = try await task.value
            let now = Date()
            var allMatch = true
            updateEvidence(evidenceID) { ev in
                for i in ev.sourceHashes.indices where ev.sourceHashes[i].origin == .computed {
                    let expected: String
                    switch ev.sourceHashes[i].algorithm {
                    case .md5:    expected = result.md5
                    case .sha256: expected = result.sha256
                    case .sha1:   continue   // not computed by FileHasher
                    }
                    let ok = ev.sourceHashes[i].value == expected
                    allMatch = allMatch && ok
                    ev.sourceHashes[i].status = ok ? .verified : .mismatch
                    ev.sourceHashes[i].verifiedAt = now
                }
            }
            appendCustody(.hashVerified,
                          detail: allMatch
                              ? "Re-hashed \(name): computed digests match (integrity verified)."
                              : "Re-hashed \(name): DIGEST MISMATCH — integrity check failed.",
                          evidenceID: evidenceID)
            statusMessage = allMatch ? "\(name): integrity verified." : "\(name): integrity MISMATCH."
        } catch is CancellationError {
            statusMessage = "Verification cancelled."
        } catch {
            errorMessage = "Verification failed: \(error.localizedDescription)"
        }
    }

    /// Mutate one evidence record in place and persist the host list.
    private func updateEvidence(_ id: UUID, _ mutate: (inout Evidence) -> Void) {
        guard let idx = evidenceList.firstIndex(where: { $0.id == id }) else { return }
        var ev = evidenceList[idx]
        mutate(&ev)
        evidenceList[idx] = ev
        saveHosts()
    }

    /// Re-run `ewfverify` over an E01 and flip its embedded hashes to verified /
    /// mismatch. Expensive (reads the whole image) so it is explicit, never
    /// automatic.
    func verifyEWF(for evidenceID: UUID) async {
        guard !isWorking else { return }
        guard let evidence = evidenceList.first(where: { $0.id == evidenceID }),
              evidence.kind == .e01 else { return }
        let src = evidence.sourceURL
        guard FileManager.default.fileExists(atPath: src.path) else {
            errorMessage = "Source missing for \(evidence.displayName) at \(src.path)."
            return
        }
        errorMessage = nil
        isWorking = true
        defer { isWorking = false; progress = nil }
        let name = evidence.displayName
        statusMessage = "Verifying \(name) (ewfverify)…"
        progress = ProgressInfo(current: 0, total: 0, label: "Verifying \(name)")

        do {
            let env = try TSKEnvironment.discover()
            let result = try await EWFInfo(environment: env).verify(imageAt: src) { line in
                Task { @MainActor in self.statusMessage = line }
            }
            // No SUCCESS/FAILURE line means the run was inconclusive (not a
            // genuine failure). Surface it without flipping the embedded hashes to
            // .mismatch — recording a false integrity failure in the custody
            // ledger would be worse than reporting "couldn't verify".
            guard result.verdictPresent else {
                errorMessage = "\(name): ewfverify produced no verdict — integrity check inconclusive (left unrecorded, neither verified nor failed)."
                statusMessage = ""
                return
            }
            let now = Date()
            updateEvidence(evidenceID) { ev in
                for i in ev.sourceHashes.indices where ev.sourceHashes[i].origin == .embedded {
                    ev.sourceHashes[i].status = result.passed ? .verified : .mismatch
                    ev.sourceHashes[i].verifiedAt = now
                }
            }
            appendCustody(.hashVerified,
                          detail: result.passed
                              ? "ewfverify: integrity verified for \(name)."
                              : "ewfverify: integrity FAILURE for \(name).",
                          evidenceID: evidenceID)
            statusMessage = result.passed
                ? "\(name): integrity verified (ewfverify)."
                : "\(name): integrity MISMATCH (ewfverify)."
        } catch {
            errorMessage = "ewfverify failed: \(error.localizedDescription)"
        }
    }

    /// Persist examiner-edited acquisition metadata. Marks the record `.mixed`
    /// when it began as auto-extracted EWF data, else `.manual`.
    func recordAcquisition(_ info: AcquisitionInfo, for evidenceID: UUID) {
        let name = evidenceList.first(where: { $0.id == evidenceID })?.displayName ?? "evidence"
        updateEvidence(evidenceID) { ev in
            var updated = info
            let wasAuto = ev.acquisition?.source == .ewfMetadata || ev.acquisition?.source == .mixed
            updated.source = wasAuto ? .mixed : .manual
            ev.acquisition = updated.isEmpty ? nil : updated
        }
        appendCustody(.noteAdded, detail: "Edited acquisition metadata for \(name).",
                      evidenceID: evidenceID)
    }

    /// Map parsed EWF metadata onto an evidence record: acquisition provenance +
    /// embedded source hashes (trusted, recorded as `.embedded`).
    static func applyEWFMetadata(_ meta: EWFInfo.Metadata, to evidence: inout Evidence) {
        var acq = AcquisitionInfo(source: .ewfMetadata)
        acq.examiner = meta.examinerName ?? ""
        acq.caseNumber = meta.caseNumber ?? ""
        acq.acquisitionTool = meta.acquisitionVersion ?? ""
        acq.acquiredAt = meta.acquisitionDate
        acq.mediaSerial = meta.mediaSerial ?? ""
        var noteParts: [String] = []
        if let n = meta.notes { noteParts.append(n) }
        if let e = meta.evidenceNumber { noteParts.append("Evidence #\(e)") }
        if let d = meta.descriptionText { noteParts.append(d) }
        if let os = meta.operatingSystem { noteParts.append("Acquisition OS: \(os)") }
        acq.notes = noteParts.joined(separator: " · ")
        if !acq.isEmpty { evidence.acquisition = acq }

        var hashes: [SourceHash] = []
        if let md5 = meta.storedMD5 {
            hashes.append(SourceHash(algorithm: .md5, value: md5, origin: .embedded,
                                     note: "Embedded in E01 (ewfinfo)"))
        }
        if let sha1 = meta.storedSHA1 {
            hashes.append(SourceHash(algorithm: .sha1, value: sha1, origin: .embedded,
                                     note: "Embedded in E01 (ewfinfo)"))
        }
        evidence.sourceHashes = hashes
    }

    #endif
}
