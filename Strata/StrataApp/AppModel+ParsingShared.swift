import Foundation
import SwiftUI

#if os(macOS)

extension AppModel {
    /// One-stop button: parse event logs, registry hives, prefetch, and LNK
    /// shortcuts, then run the detection engine over the combined evidence.
    func parseArtifacts() async {
        await runAllParsers()
        await runAnalyzers()
    }

    /// Run every artifact parser once. Each self-gates (a no-op when its buckets
    /// already hold data / there are no candidate files), so this is cheap on an
    /// already-parsed case and backfills only what's missing. Shared by
    /// `parseArtifacts` and the open-time backfill.
    private func runAllParsers() async {
        await parseEventLogs()
        await parseRegistry()
        await parsePrefetch()
        await parseLnk()
        await parseJumpList()
        await parseUsn()
        await parseRecycleBin()
        await parseSrum()
        await parseBrowserHistory()
        await parseMessages()
        await parseMail()
        await parseMft()
        await parseWmi()
        await parseLinux()
        await parseMac()
        await parseUnifiedLog()
    }

    /// Called after a case opens: backfill any artifact buckets an older build
    /// never produced (newly-added artifact types) so an old case shows the newest
    /// tabs without the analyst knowing to re-run Parse. Each parser self-gates,
    /// so an up-to-date case only does cheap candidate scans and degrades silently
    /// when the source media is gone (archived image). Analyzers re-run — *without*
    /// a custody entry, since this is an automatic refresh, not an examiner action
    /// — only when a parser actually added data.
    func backfillOnOpen() async {
        guard currentCase != nil, !evidenceList.isEmpty, !isWorking else { return }
        let before = dataVersion
        await runAllParsers()
        if dataVersion != before {
            await runAnalyzers(recordCustody: false)
            // Backfill re-parsed available sources and overwrote any corrupt caches
            // (E1): drop the now-stale load faults for buckets that are populated
            // again, so the Overview banner stops flagging freshly-rebuilt evidence
            // as corrupt. Faults for buckets still empty (source gone → unhealable)
            // remain surfaced.
            pruneHealedLoadFaults()
        }
        statusMessage = ""
    }

    /// Drop per-host load faults whose artifact bucket is now populated (a
    /// re-parse healed the corrupt cache). Unknown labels are kept — conservative,
    /// so a fault we can't confirm healed is never hidden. Case-wide faults
    /// (custody etc.) are not touched: backfill can't rebuild them.
    private func pruneHealedLoadFaults() {
        for (hostID, hostFaults) in loadFaults {
            guard let state = states[hostID] else { continue }
            let remaining = hostFaults.filter { !Self.artifactBucketPopulated($0.artifact, in: state) }
            loadFaults[hostID] = remaining.isEmpty ? nil : remaining
        }
    }

    /// Whether the state bucket behind a load-fault label now holds data. Labels
    /// mirror `loadEvidenceState`'s `loadArr`/`loadOne` call sites.
    private static func artifactBucketPopulated(_ artifact: String, in s: EvidenceState) -> Bool {
        switch artifact {
        case "Event logs":              return !s.events.isEmpty
        case "Registry":                return !s.registryValues.isEmpty
        case "Prefetch":                return !s.prefetch.isEmpty
        case "Amcache":                 return !s.amcache.isEmpty
        case "Shimcache":               return !s.shimcache.isEmpty
        case "LNK shortcuts":           return !s.lnk.isEmpty
        case "JumpLists":               return !s.jumpList.isEmpty
        case "USN journal":             return !s.usn.isEmpty
        case "Recycle Bin":             return !s.recycleBin.isEmpty
        case "SRUM":                    return !s.srum.isEmpty
        case "Browser history":         return !s.browserHistory.isEmpty
        case "$MFT":                    return !s.mft.isEmpty
        case "WMI persistence":         return !s.wmi.isEmpty
        case "Launch items":            return !s.launchItems.isEmpty
        case "Quarantine":              return !s.quarantine.isEmpty
        case "macOS persistence":       return !s.macPersistence.isEmpty
        case "FSEvents":                return !s.fsEvents.isEmpty
        case "Unified log":             return !s.unifiedLog.isEmpty
        case "TCC":                     return !s.tcc.isEmpty
        case "KnowledgeC":              return !s.knowledgeC.isEmpty
        case "Recent items":            return !s.macRecentItems.isEmpty
        case "macOS security":          return !s.macSecurityEvents.isEmpty
        case "Carved files":            return !s.carvedFiles.isEmpty
        case "Extensions":              return !s.kexts.isEmpty
        case "Background items":        return !s.backgroundItems.isEmpty
        case "Messages":                return !s.messages.isEmpty
        case "Mail":                    return !s.mail.isEmpty
        case "Network & devices":       return !s.network.isEmpty
        case "QuickLook & Trash":       return !s.userActivity.isEmpty
        case "Document versions":       return !s.documentVersions.isEmpty
        case "Notifications":           return !s.notifications.isEmpty
        case "Powerlog":                return !s.powerlog.isEmpty
        case "Configuration":           return !s.macConfig.isEmpty
        case "Installs":                return !s.installHistory.isEmpty
        case "Download origins":        return !s.whereFroms.isEmpty
        case "macOS host info":         return s.macInfo != nil
        case "Auth & logins":           return !s.authLog.isEmpty
        case "Login records":           return !s.logins.isEmpty
        case "Shell history":           return !s.shellHistory.isEmpty
        case "Linux persistence":       return !s.linuxPersistence.isEmpty
        case "Linux host info":         return s.linuxInfo != nil
        case "Accounts & SSH":          return s.linuxAccess != nil
        case "Web access logs":         return !s.webAccess.isEmpty
        case "Packages":                return !s.packages.isEmpty
        case "Journal":                 return !s.journald.isEmpty
        case "Audit":                   return !s.audit.isEmpty
        case "Syslog":                  return !s.syslog.isEmpty
        case "Lastlog":                 return !s.lastlog.isEmpty
        case "Findings":                return !s.findings.isEmpty
        case "IOC matches":             return !s.iocMatches.isEmpty
        case "Volumes", "APFS volumes": return !s.volumes.isEmpty
        case "APFS file tree":          return !s.files.isEmpty
        default:                        return false   // unknown → keep the fault
        }
    }

    // MARK: - Browser history parsing

    /// Parse web-browser history stores (Chromium `History`, Firefox
    /// `places.sqlite`, Safari `History.db` and `Downloads.plist`) for every
    /// loaded evidence that doesn't already have results. These are ordinary
    /// files (not sparse ADSes), so they're extracted with the plain icat path
    /// that registry/prefetch/SRUM use. The SQLite/plist read itself
    /// (`BrowserHistoryParser`, GRDB for SQLite) is run off the main actor in a
    /// detached task. Mirrors `parseSrum`; does NOT run analyzers.
    func parseBrowserHistory() async {
        guard !isWorking else { return }   // single-flight: don't overlap parse passes
        guard !evidenceList.isEmpty else {
            errorMessage = "No evidence loaded."
            return
        }
        errorMessage = nil
        isWorking = true
        defer {
            isWorking = false
            progress = nil
        }

        func candidates(_ state: EvidenceState) -> [FileEntry] {
            state.files.filter {
                guard !$0.isDirectory, $0.size > 0 else { return false }
                let n = $0.name.lowercased()
                // Safari's DB/download plist live under ~/Library/Safari/; gate
                // those names on the Safari directory so unrelated History.db or
                // Downloads.plist files elsewhere aren't copied + probed.
                let lower = $0.fullPath.lowercased()
                return n == "history" || n == "places.sqlite"
                    || (n == "history.db" && lower.contains("/safari/"))
                    || (n == "downloads.plist" && lower.contains("/safari/"))
            }
        }

        let totalCandidates = evidenceList.reduce(0) { acc, evidence in
            guard let state = states[evidence.id], state.browserHistory.isEmpty else { return acc }
            return acc + candidates(state).count
        }
        guard totalCandidates > 0 else {
            statusMessage = "No new browser history to parse."
            return
        }
        progress = ProgressInfo(current: 0, total: totalCandidates, label: "Parsing browser history")
        var completed = 0

        do {
            let tskEnv = try TSKEnvironment.discover()
            var hostsTouched = 0
            var hostsCollected = 0
            // A Linux host carries unrelated files named `History` (IPython, etc.);
            // count how many candidates were *actually* parseable browser stores so
            // an image with only name-collisions reports "none found", not "corrupt".
            var realStoresSeen = 0

            for evidence in evidenceList {
                guard var state = states[evidence.id] else { continue }
                if !state.browserHistory.isEmpty { continue }

                let found = candidates(state)
                guard !found.isEmpty else { continue }
                hostsTouched += 1

                let isLoose = evidence.kind == .kapeLooseFolder
                let isAPFS = evidence.kind == .apfs
                var database: TSKDatabase?
                var extractor: TSKFileExtractor?
                var apfsExtractor: FsApfsExtractor?
                var scratch: URL?
                if !isLoose {
                    guard let bundleURL = currentCaseBundleURL else { continue }
                    let dir = CaseStore.browserHistoryScratchDirectory(forHostID: evidence.id, in: bundleURL)
                    try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
                    scratch = dir
                    if isAPFS {
                        apfsExtractor = FsApfsExtractor(environment: tskEnv,
                                                        rawURL: evidence.apfsRawURL ?? evidence.sourceURL,
                                                        credential: fileVaultCredentials[evidence.id])
                    } else {
                        guard let dbURL = state.dbURL else { continue }
                        database = try TSKDatabase(path: dbURL)
                        extractor = TSKFileExtractor(
                            environment: tskEnv,
                            imageURL: evidence.sourceURL,
                            imageType: TSKImageIngestor.imageType(for: evidence.sourceURL))
                    }
                }

                var collected: [BrowserHistoryEntry] = []
                for entry in found {
                    progress = ProgressInfo(current: completed, total: totalCandidates,
                                            label: "\(evidence.displayName): \(entry.name)")
                    let fileURL: URL
                    if isLoose {
                        guard let disk = entry.diskURL,
                              FileManager.default.fileExists(atPath: disk.path) else {
                            completed += 1; continue
                        }
                        fileURL = disk
                    } else if isAPFS {
                        // APFS: extract the DB + its -wal/-shm sidecars via libfsapfs.
                        let outURL = scratch!.appendingPathComponent("\(entry.id)-\(entry.name.scratchSafeComponent)")
                        let off = state.volumes.first { $0.id == entry.fsID }?.offsetBytes ?? 0
                        try? await apfsExtractor!.extract(volumePath: entry.fullPath,
                                                          volumeIndex: entry.fsID ?? 0,
                                                          offsetBytes: off, to: outURL)
                        for suffix in ["-wal", "-shm"] {
                            guard let side = state.files.first(where: {
                                !$0.isDirectory && $0.parentPath == entry.parentPath
                                    && $0.name.caseInsensitiveCompare(entry.name + suffix) == .orderedSame
                            }) else { continue }
                            let soff = state.volumes.first { $0.id == side.fsID }?.offsetBytes ?? 0
                            try? await apfsExtractor!.extract(volumePath: side.fullPath,
                                                              volumeIndex: side.fsID ?? 0, offsetBytes: soff,
                                                              to: URL(fileURLWithPath: outURL.path + suffix))
                        }
                        fileURL = outURL
                    } else {
                        guard let info = try database!.fetchExtractInfo(forFileID: entry.id) else {
                            completed += 1; continue
                        }
                        let outURL = scratch!.appendingPathComponent("\(entry.id)-\(entry.name.scratchSafeComponent)")
                        do {
                            try await extractor!.extract(metaAddr: info.metaAddr,
                                                         imageOffsetSectors: info.imageOffsetSectors,
                                                         to: outURL)
                        } catch {
                            // One file's extraction failure must not abort the whole
                            // pass (discarding partials + skipping later hosts): record
                            // it and move on. Bytes are adversary-controlled.
                            statusMessage = "\(evidence.displayName): \(entry.name) — extraction failed (\(error.localizedDescription))"
                            completed += 1
                            continue
                        }
                        // Extract the `-wal`/`-shm` sidecars next to the main DB
                        // (matching names) so the parser can recover history still
                        // sitting in the `-wal`. Best-effort: absence is normal.
                        for suffix in ["-wal", "-shm"] {
                            guard let side = state.files.first(where: {
                                !$0.isDirectory && $0.parentPath == entry.parentPath
                                    && $0.name.caseInsensitiveCompare(entry.name + suffix) == .orderedSame
                            }), let sInfo = try? database!.fetchExtractInfo(forFileID: side.id) else { continue }
                            try? await extractor!.extract(metaAddr: sInfo.metaAddr,
                                                          imageOffsetSectors: sInfo.imageOffsetSectors,
                                                          to: URL(fileURLWithPath: outURL.path + suffix))
                        }
                        fileURL = outURL
                    }
                    // The SQLite read copies the DB (+ sidecars) to a private
                    // scratch and opens it off the main actor. A single unreadable
                    // DB shouldn't abort the whole run - but surface the failure
                    // (mirrors parseRegistry) so it isn't indistinguishable from
                    // "nothing was ever parsed".
                    let source = entry.fullPath
                    let isSafariDownloads = entry.name.caseInsensitiveCompare("Downloads.plist") == .orderedSame
                        && entry.fullPath.lowercased().contains("/safari/")
                    if isSafariDownloads || BrowserHistoryParser.isSQLiteDatabase(at: fileURL) { realStoresSeen += 1 }
                    do {
                        let parsed = try await Task.detached(priority: .userInitiated) {
                            if isSafariDownloads {
                                return try BrowserHistoryParser.parseSafariDownloads(fileAt: fileURL, sourceFile: source)
                            }
                            return try BrowserHistoryParser.parse(fileAt: fileURL, sourceFile: source)
                        }.value
                        collected.append(contentsOf: parsed)
                    } catch {
                        statusMessage = "\(evidence.displayName): \(entry.name) failed (\(error.localizedDescription))"
                    }
                    completed += 1
                }

                collected.sort { ($0.timestamp ?? .distantPast) > ($1.timestamp ?? .distantPast) }
                if !collected.isEmpty { hostsCollected += 1 }
                state.browserHistory = collected
                // Drop any prior browser slice (paranoia for re-parses) and splice
                // the freshly built browser-history timeline back in, sorted.
                state.timeline.removeAll { $0.source == .browser }
                state.timeline.append(contentsOf: TimelineBuilder.build(from: collected))
                state.timeline.sort { $0.date < $1.date }
                states[evidence.id] = state
                if let bundleURL = currentCaseBundleURL {
                    try? CaseStore.writeBrowserHistory(collected, forHostID: evidence.id, in: bundleURL)
                }
            }
            progress = ProgressInfo(current: completed, total: totalCandidates,
                                    label: "Browser history parse complete")
            if realStoresSeen > 0, hostsCollected == 0 {
                // Real browser stores were present but yielded nothing - a genuine
                // problem (unreadable/corrupt/schema drift).
                errorMessage = "Browser history parse extracted no entries - check that the History / places.sqlite / Safari Downloads.plist stores are accessible and not corrupt."
            } else if hostsTouched > 0, realStoresSeen == 0 {
                // Only files *named* like browser stores that aren't parseable stores
                // (common on Linux servers with no browser installed) - expected.
                statusMessage = "No browser history stores found."
            }
        } catch {
            self.errorMessage = error.localizedDescription
            self.statusMessage = ""
        }
    }
}

#endif
