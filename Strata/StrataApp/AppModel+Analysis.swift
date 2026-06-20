import Foundation
import SwiftUI

extension AppModel {
    // MARK: - Analysis

    /// Run analyzers against each evidence's own context, then store the
    /// findings on that evidence. "All" mode unions the per-evidence buckets
    /// via the computed `findings` property.
    // MARK: - Ransomware entropy verification

#if os(macOS)
    private static let entropyMaxSamplesPerExt = 8
    private static let entropyHeadBytes = 65_536
    private static let entropyMinFileBytes: Int64 = 512
    private static let entropyMaxFileBytes: Int64 = 16 * 1024 * 1024

    /// Sample the real bytes of files caught in a ransomware mass-encryption
    /// burst and compute their Shannon entropy, so `ImpactDestructionAnalyzer`
    /// can confirm the files were actually encrypted (high entropy) rather than
    /// merely renamed. Returns `[extension: stat]`; empty (and no I/O) when there
    /// is no burst - the common case - so this costs nothing unless one is found.
    private func sampleEncryptionEntropy(for evidence: Evidence,
                                         state: EvidenceState) async -> [String: EncryptionEntropyStat] {
        let bursts = ImpactDestructionAnalyzer.encryptionBursts(
            files: state.files, usn: state.usn, mft: state.mft)
        guard !bursts.isEmpty else { return [:] }

        let isLoose = evidence.kind == .kapeLooseFolder
        let isAPFS = evidence.kind == .apfs
        var database: TSKDatabase?
        var extractor: TSKFileExtractor?
        var apfsExtractor: FsApfsExtractor?
        var scratch: URL?
        if !isLoose {
            guard let env = try? TSKEnvironment.discover() else { return [:] }
            let dir = FileManager.default.temporaryDirectory
                .appendingPathComponent("strata-entropy-\(evidence.id.uuidString)")
            try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
            scratch = dir
            if isAPFS {
                apfsExtractor = FsApfsExtractor(environment: env,
                                                rawURL: evidence.apfsRawURL ?? evidence.sourceURL,
                                                credential: fileVaultCredentials[evidence.id])
            } else {
                guard let dbURL = state.dbURL, let db = try? TSKDatabase(path: dbURL) else { return [:] }
                database = db
                extractor = TSKFileExtractor(environment: env, imageURL: evidence.sourceURL,
                                             imageType: TSKImageIngestor.imageType(for: evidence.sourceURL))
            }
        }
        defer { if let scratch { try? FileManager.default.removeItem(at: scratch) } }

        var result: [String: EncryptionEntropyStat] = [:]
        for burst in bursts {
            // Sample only LIVE files that are part of THIS burst (matched by the
            // lowercased leaf name `encryptionBursts` counted), so the entropy
            // reflects the burst population - not incidental same-extension files
            // - and never a deleted entry whose runlist may point at reallocated
            // (stale) clusters under icat.
            let candidates = state.files
                .filter { !$0.isDirectory && !$0.isDeleted
                          && $0.fileExtension == burst.ext
                          && burst.names.contains($0.name.lowercased())
                          && $0.size >= Self.entropyMinFileBytes
                          && $0.size <= Self.entropyMaxFileBytes }
                .prefix(Self.entropyMaxSamplesPerExt)
            var perFile: [Double] = []
            for entry in candidates {
                if let e = await fileMaxEntropy(of: entry, isLoose: isLoose, isAPFS: isAPFS,
                                                state: state, database: database, extractor: extractor,
                                                apfsExtractor: apfsExtractor, scratch: scratch) {
                    perFile.append(e)
                }
            }
            if let stat = EncryptionEntropyStat.from(fileMaxEntropies: perFile) { result[burst.ext] = stat }
        }
        return result
    }

    /// The maximum windowed entropy of one file's content, read via the right
    /// path for the evidence kind (loose disk / APFS fsapfscat / TSK icat).
    /// Best-effort: nil when the bytes can't be read (analyzer → "unverified").
    private func fileMaxEntropy(of entry: FileEntry, isLoose: Bool, isAPFS: Bool,
                               state: EvidenceState, database: TSKDatabase?,
                               extractor: TSKFileExtractor?, apfsExtractor: FsApfsExtractor?,
                               scratch: URL?) async -> Double? {
        let url: URL
        var cleanup: URL?
        if isLoose {
            guard let disk = entry.diskURL else { return nil }
            url = disk
        } else {
            guard let scratch else { return nil }
            let outURL = scratch.appendingPathComponent("\(entry.id)")
            cleanup = outURL
            if isAPFS {
                guard let apfsExtractor else { return nil }
                let off = state.volumes.first { $0.id == entry.fsID }?.offsetBytes ?? 0
                try? await apfsExtractor.extract(volumePath: entry.fullPath, volumeIndex: entry.fsID ?? 0,
                                                 offsetBytes: off, to: outURL)
            } else {
                guard let database, let extractor,
                      let info = try? database.fetchExtractInfo(forFileID: entry.id) else { return nil }
                try? await extractor.extract(metaAddr: info.metaAddr,
                                             imageOffsetSectors: info.imageOffsetSectors, to: outURL)
            }
            url = outURL
        }
        defer { if let cleanup { try? FileManager.default.removeItem(at: cleanup) } }
        return Self.windowedMaxEntropy(at: url, fileSize: entry.size)
    }

    /// Max Shannon entropy over up to three windows (head / middle / tail) of the
    /// file. Sampling more than the head is what lets partial / intermittent /
    /// append-based encryptors - which leave the head plaintext - still register
    /// as encrypted.
    private static func windowedMaxEntropy(at url: URL, fileSize: Int64) -> Double? {
        guard let handle = try? FileHandle(forReadingFrom: url) else { return nil }
        defer { try? handle.close() }
        let window = entropyHeadBytes
        var offsets: [UInt64] = [0]
        if fileSize > Int64(window) * 2 {
            offsets.append(UInt64(Swift.max(0, fileSize / 2 - Int64(window / 2))))
            offsets.append(UInt64(Swift.max(0, fileSize - Int64(window))))
        }
        var best: Double?
        for off in offsets {
            try? handle.seek(toOffset: off)
            guard let data = try? handle.read(upToCount: window),
                  data.count >= Int(entropyMinFileBytes) else { continue }
            best = Swift.max(best ?? 0, FileEntropy.shannonEntropy(data))
        }
        return best
    }
#else
    private func sampleEncryptionEntropy(for evidence: Evidence,
                                         state: EvidenceState) async -> [String: EncryptionEntropyStat] { [:] }
#endif

    func runAnalyzers(recordCustody: Bool = true) async {
        statusMessage = "Running analyzers..."
        var total = 0
        for evidence in evidenceList {
            guard var state = states[evidence.id] else { continue }
            // Verify any ransomware mass-encryption burst by sampling real file
            // bytes (no-op / no I/O unless a burst is actually present).
            let encryptionEntropy = await sampleEncryptionEntropy(for: evidence, state: state)
            let context = AnalysisContext(files: state.files,
                                          events: state.events,
                                          timeline: state.timeline,
                                          registryValues: state.registryValues,
                                          prefetch: state.prefetch,
                                          amcache: state.amcache,
                                          shimcache: state.shimcache,
                                          lnk: state.lnk,
                                          jumpList: state.jumpList,
                                          usn: state.usn,
                                          recycleBin: state.recycleBin,
                                          srum: state.srum,
                                          browserHistory: state.browserHistory,
                                          mft: state.mft,
                                          wmi: state.wmi,
                                          authLog: state.authLog,
                                          logins: state.logins,
                                          shellHistory: state.shellHistory,
                                          linuxPersistence: state.linuxPersistence,
                                          linuxInfo: state.linuxInfo,
                                          linuxAccess: state.linuxAccess,
                                          webAccess: state.webAccess,
                                          packages: state.packages,
                                          journald: state.journald,
                                          audit: state.audit,
                                          syslog: state.syslog,
                                          lastlog: state.lastlog,
                                          launchItems: state.launchItems,
                                          quarantine: state.quarantine,
                                          macPersistence: state.macPersistence,
                                          fsEvents: state.fsEvents,
                                          unifiedLog: state.unifiedLog,
                                          tcc: state.tcc,
                                          knowledgeC: state.knowledgeC,
                                          macRecentItems: state.macRecentItems,
                                          macSecurityEvents: state.macSecurityEvents,
                                          kexts: state.kexts,
                                          backgroundItems: state.backgroundItems,
                                          messages: state.messages,
                                          mail: state.mail,
                                          network: state.network,
                                          userActivity: state.userActivity,
                                          powerlog: state.powerlog,
                                          config: state.macConfig,
                                          installHistory: state.installHistory,
                                          whereFroms: state.whereFroms,
                                          encryptionEntropy: encryptionEntropy)
            let results = await analysisEngine.run(on: context)
            state.findings = results
            states[evidence.id] = state
            if let bundleURL = currentCaseBundleURL {
                try? CaseStore.writeFindings(results, forHostID: evidence.id, in: bundleURL)
            }
            total += results.count
        }
        // Case-wide multi-host correlation (roadmap #8): line every host's IOC
        // hits, accounts, and inbound-logon source IPs up and flag what spans ≥2
        // hosts (shared indicator, pivoting source, reused credential).
        let summaries: [HostSummary] = evidenceList.compactMap { evidence in
            guard let s = states[evidence.id] else { return nil }
            let users = Set((s.linuxInfo?.users.map(\.name) ?? [])
                + s.logins.map(\.user)
                + s.authLog.compactMap(\.user)).filter { !$0.isEmpty }
            let ips = Set(s.authLog.filter { $0.kind == .sshAccepted }.compactMap(\.sourceIP)
                + s.events.filter { $0.eventID == 4624 || $0.eventID == 4625 }.compactMap { $0.data("IpAddress") })
                .filter { !$0.isEmpty && $0 != "-" && $0 != "::1" && $0 != "127.0.0.1" }
            let hostname = HostProfile.derive(from: s.registryValues).hostname
                ?? s.linuxInfo?.hostname ?? evidence.displayName
            return HostSummary(hostID: evidence.id, hostname: hostname,
                               iocMatches: s.iocMatches, users: Array(users),
                               remoteLogonSourceIPs: Array(ips))
        }
        correlationFindings = CorrelationEngine.correlate(summaries)
        total += correlationFindings.count
        // `total` is case-wide, but the findings / kill-chain views render
        // `model.findings`, which is scoped to `activeEvidenceID`. If the active
        // host produced nothing while another did, the views would sit empty
        // even though we just announced findings - so drop to the combined "All"
        // scope to surface them instead of silently hiding the result.
        var switchedScope = false
        if let id = activeEvidenceID, states[id]?.findings.isEmpty ?? true, total > 0 {
            activeEvidenceID = nil
            switchedScope = true
        }
        if total == 0 {
            statusMessage = "No detections."
        } else if switchedScope {
            statusMessage = "Surfaced \(total) findings (showing all evidence)."
        } else {
            statusMessage = "Surfaced \(total) findings."
        }
        if recordCustody {
            appendCustody(.analysed,
                          detail: "Ran detection analyzers across \(evidenceList.count) host\(evidenceList.count == 1 ? "" : "s") → \(total) finding\(total == 1 ? "" : "s").")
        }
    }
}
