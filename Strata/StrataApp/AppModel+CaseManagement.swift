import Foundation
import SwiftUI

extension AppModel {
    // MARK: - Case Library

    /// Remember a new library folder and list its cases.
    func setCaseLibrary(_ url: URL) {
        let didStart = url.startAccessingSecurityScopedResource()
        defer { if didStart { url.stopAccessingSecurityScopedResource() } }
        CaseLibrary.setURL(url)
        libraryURL = url
        refreshLibrary()
    }

    /// Re-scan the library folder for `.strata` cases.
    func refreshLibrary() {
        guard let url = libraryURL else { libraryCases = []; return }
        let didStart = url.startAccessingSecurityScopedResource()
        defer { if didStart { url.stopAccessingSecurityScopedResource() } }
        libraryCases = CaseLibrary.cases(in: url)
    }

    /// Open a case from the library, downloading it from iCloud first if it's a
    /// placeholder. The library's security scope is held across the read.
    func openLibraryCase(_ item: LibraryCase) {
        Task {
            guard let lib = libraryURL else { return }
            let didStart = lib.startAccessingSecurityScopedResource()
            defer { if didStart { lib.stopAccessingSecurityScopedResource() } }

            if !item.isDownloaded {
                isWorking = true
                statusMessage = "Downloading \(item.name) from iCloud..."
                try? FileManager.default.startDownloadingUbiquitousItem(at: item.url)
                let marker = CaseStore.caseFile(in: item.url)   // bundle/case.json
                for _ in 0..<120 {                              // wait up to ~30s
                    if FileManager.default.fileExists(atPath: marker.path) { break }
                    try? await Task.sleep(nanoseconds: 250_000_000)
                }
                isWorking = false
                guard FileManager.default.fileExists(atPath: marker.path) else {
                    errorMessage = "\(item.name) hasn't finished downloading from iCloud yet - try again in a moment."
                    return
                }
            }
            await openCase(at: item.url)
            refreshLibrary()
        }
    }

    // MARK: - Case management

    /// Create a new .strata bundle on disk and open it. Existing in-memory
    /// state is reset; the user is starting fresh.
    func createCase(name: String, examiner: String, at bundleURL: URL) async {
        errorMessage = nil
        // Starting fresh: drop any security scope held for a previously open bundle.
        caseSecurityScopeURL?.stopAccessingSecurityScopedResource()
        caseSecurityScopeURL = nil
        do {
            let theCase = ForensicCase(name: name, examiner: examiner, createdAt: Date())
            try CaseStore.createBundle(at: bundleURL, case: theCase)
            RecentCases.record(bundleURL)
            recentCases = RecentCases.load()
            currentCase = theCase
            currentCaseBundleURL = bundleURL
            evidenceList = []
            states = [:]
            iocs = []
            custodyLog = []
            activeEvidenceID = nil
            statusMessage = "Created case '\(name)'."
        } catch {
            errorMessage = "Failed to create case: \(error.localizedDescription)"
        }
    }

    /// Open an existing bundle and rehydrate per-host state. Event-log and
    /// registry parsing are NOT replayed - the user clicks Parse on the
    /// Events / Overview screen to do that.
    ///
    /// `case.json` / `hosts.json` are tiny, so the case window, host picker, and
    /// tabs render immediately. The expensive part - re-reading the TSK file
    /// listing, building the MACB timeline (200k+ files × 4 stamps = millions of
    /// events), and decoding the per-host events/registry/findings JSON - runs
    /// off the main actor in `loadEvidenceState`, and each host is published as
    /// it finishes. So a case opens to a responsive (if briefly empty) UI that
    /// fills in progressively, instead of freezing until everything is parsed.
    func openCase(at bundleURL: URL) async {
        errorMessage = nil
        isWorking = true
        defer { isWorking = false }
        // Hold the bundle's security scope for the whole case lifetime (not just
        // the caller's synchronous prelude), so both the off-main host reads and
        // the detached open-time backfill can read a security-scoped bundle
        // (recents / library / iCloud). Released in closeCase / on re-open (E7).
        caseSecurityScopeURL?.stopAccessingSecurityScopedResource()
        caseSecurityScopeURL = bundleURL.startAccessingSecurityScopedResource() ? bundleURL : nil
        do {
            let theCase = try CaseStore.readCase(in: bundleURL)
            let hosts = try CaseStore.readHosts(in: bundleURL)
            currentCase = theCase
            currentCaseBundleURL = bundleURL
            evidenceList = hosts
            states = [:]
            // Show the first host's (briefly empty) scope right away; its
            // working set streams in below.
            activeEvidenceID = hosts.first?.id

            // Load hosts one at a time off the main actor. Sequential rather
            // than a task group: a multi-host case loading every TSK DB +
            // events.json in parallel can spike memory hard (and OOM-kill iOS),
            // and the UI stays responsive either way since nothing blocks main.
            for (index, evidence) in hosts.enumerated() {
                statusMessage = hosts.count > 1
                    ? "Loading \(evidence.displayName) (\(index + 1) of \(hosts.count))…"
                    : "Loading \(evidence.displayName)…"
                let outcome = await Task.detached(priority: .userInitiated) {
                    Self.loadEvidenceState(for: evidence, in: bundleURL)
                }.value
                switch outcome {
                case .loaded(let state):
                    states[evidence.id] = state
                case .loadedWithWarning(let state, let message):
                    states[evidence.id] = state
                    statusMessage = message
                case .skippedSilently:
                    break
                case .skipped(let message):
                    statusMessage = message
                }
            }

            // The first host was optimistically selected for fast first paint; if
            // it failed to load (missing DB, corrupt, undownloaded), advance the
            // scope to the first host that DID load so the case doesn't present as
            // entirely empty when a later host is fine (E4).
            if let active = activeEvidenceID, states[active] == nil {
                activeEvidenceID = hosts.first { states[$0.id] != nil }?.id
            }

            // Case-wide indicators + custody ledger + analyst annotations,
            // also decoded off-main.
            let caseWide = await Task.detached(priority: .userInitiated) {
                (iocs: (try? CaseStore.readIOCs(in: bundleURL)) ?? [],
                 custody: (try? CaseStore.readCustody(in: bundleURL)) ?? [],
                 annotations: (try? CaseStore.readAnnotations(in: bundleURL)) ?? [],
                 notes: (try? CaseStore.readNotes(in: bundleURL)) ?? CaseNotes(),
                 enrichment: (try? CaseStore.readEnrichment(in: bundleURL)) ?? [],
                 summary: (try? CaseStore.readSummary(in: bundleURL)) ?? nil)
            }.value
            iocs = caseWide.iocs
            custodyLog = caseWide.custody
            annotations = caseWide.annotations
            caseNotes = caseWide.notes
            enrichmentVerdicts = caseWide.enrichment
            caseSummary = caseWide.summary

            RecentCases.record(bundleURL)
            recentCases = RecentCases.load()
            statusMessage = "Loaded case '\(theCase.name)' (\(hosts.count) host\(hosts.count == 1 ? "" : "s"))."
            #if os(macOS)
            // Resolve the configured inference backend's status now, so the Tools
            // menu's summary actions reflect the real backend even if the analyst
            // never opens the Overview card (which also refreshes this).
            refreshInferenceConfig()
            // Backfill artifact types an older build never produced (e.g. kexts /
            // BTM / Messages added after this case was last parsed), so the newest
            // tabs populate without a manual re-parse. Off the open path; no-op +
            // cheap when nothing is missing.
            Task { await self.backfillOnOpen() }
            #endif
        } catch {
            errorMessage = "Failed to open case: \(error.localizedDescription)"
        }
    }

    /// Outcome of assembling one host's working set off the main actor.
    /// `skippedSilently` covers a host whose TSK DB is simply absent (nothing to
    /// report); `skipped(_)` carries a user-facing reason (missing source folder
    /// or a load error) for the status bar.
    private nonisolated enum HostLoadOutcome: Sendable {
        case loaded(EvidenceState)
        /// Loaded, but with a caveat worth surfacing (e.g. a loose host whose
        /// source folder is gone: cached artifacts loaded, file tree could not).
        case loadedWithWarning(EvidenceState, String)
        case skippedSilently
        case skipped(String)
    }

    /// Build one host's working set entirely off the main actor: re-read the TSK
    /// file listing (or re-walk the loose folder - both cheap and reproducible,
    /// so neither is persisted in the bundle), build the MACB timeline, and
    /// decode the cached events/registry/findings/IOC-match JSON. All inputs are
    /// value types and the result is `Sendable`, so the caller just publishes it.
    ///
    /// iOS can't replay the macOS path verbatim: it drops the trailing-slack
    /// pseudo-entries and skips the full file-MACB timeline - on a real case
    /// that's the difference between opening and an OOM kill. macOS keeps full
    /// fidelity. The cached event JSON is read "lite" on iOS (no per-event XML
    /// payload, the bulk of each record's footprint) for the same reason.
    private nonisolated static func loadEvidenceState(for evidence: Evidence,
                                                      in bundleURL: URL) -> HostLoadOutcome {
        do {
            var state: EvidenceState
            var timeline: [TimelineEvent]
            var loadWarning: String?
            if evidence.kind == .kapeLooseFolder {
                let root = evidence.sourceURL
                if FileManager.default.fileExists(atPath: root.path) {
                    var files = KapeFolderIngestor().ingest(folderAt: root)
                    #if !os(macOS)
                    files.removeAll(where: TimelineBuilder.isSlackEntry)
                    #endif
                    state = EvidenceState(dbURL: nil)
                    state.files = files
                    #if os(macOS)
                    // includeBorn: false — a loose collection's `created` is the
                    // collector's copy time, not a real birth time (see C2).
                    timeline = TimelineBuilder.build(from: files, includeBorn: false)
                    #else
                    timeline = []
                    #endif
                } else {
                    // The collection folder is gone (moved / unmounted / archived),
                    // so the file tree + FS-MACB can't be re-walked. But the parsed
                    // artifacts — events.json, findings.json, iocmatches.json and
                    // every timeline source — live self-contained in the bundle and
                    // need no source folder. Load with an empty tree (and a warning)
                    // instead of dropping the host, so the examiner's findings don't
                    // vanish with the collection folder.
                    state = EvidenceState(dbURL: nil)
                    state.files = []
                    timeline = []
                    loadWarning = "\(evidence.displayName): source folder missing at \(root.path) — showing cached artifacts only (file tree unavailable)."
                }
            } else if evidence.kind == .apfs {
                // APFS images have no tsk.db; the tree + volumes were persisted
                // as JSON at ingest. Content is re-extracted on demand via
                // libfsapfs (see parseMac / parseBrowserHistory).
                var files = (try? CaseStore.readApfsFiles(forHostID: evidence.id, in: bundleURL)) ?? []
                #if !os(macOS)
                files.removeAll(where: TimelineBuilder.isSlackEntry)
                #endif
                state = EvidenceState(dbURL: nil)
                state.files = files
                state.volumes = (try? CaseStore.readApfsVolumes(forHostID: evidence.id, in: bundleURL)) ?? []
                #if os(macOS)
                timeline = TimelineBuilder.build(from: files)
                #else
                timeline = []
                #endif
            } else {
                let dbURL = CaseStore.tskDatabaseURL(forHostID: evidence.id, in: bundleURL)
                guard FileManager.default.fileExists(atPath: dbURL.path) else { return .skippedSilently }
                let database = try TSKDatabase(path: dbURL)
                var files = try database.fetchFiles()
                #if !os(macOS)
                files.removeAll(where: TimelineBuilder.isSlackEntry)
                #endif
                state = EvidenceState(dbURL: dbURL)
                state.files = files
                state.volumes = (try? database.fetchVolumes()) ?? []
                #if os(macOS)
                timeline = TimelineBuilder.build(from: files)
                #else
                timeline = []
                #endif
            }
            // Rehydrate cached parse output. Missing files mean the user hasn't
            // run Parse on this host yet (or it pre-dates the caching format) -
            // either way, fall back to empty.
            #if os(macOS)
            state.events = (try? CaseStore.readEvents(forHostID: evidence.id, in: bundleURL)) ?? []
            #else
            state.events = (try? CaseStore.readEventsLite(forHostID: evidence.id, in: bundleURL)) ?? []
            #endif
            // Fold evtx records back into the timeline so the sessions panel and
            // Source filter work without re-parsing on every case open.
            if !state.events.isEmpty {
                timeline.append(contentsOf: TimelineBuilder.build(from: state.events))
            }
            state.timeline = timeline   // one final sort happens after all splices
            // Every remaining cached collection is an independent file read +
            // JSON decode (CaseStore.jsonDecoder is a fresh instance per call, so
            // this is thread-safe), so fan them out across cores — each job writes
            // its own local, joined by the concurrentPerform barrier, no locking.
            // The file listing + events above stay on this thread.
            let id = evidence.id
            var registry: [RegistryValue] = []
            var prefetch: [PrefetchEntry] = []
            var amcache: [AmcacheEntry] = []
            var shimcache: [ShimcacheEntry] = []
            var lnk: [LnkEntry] = []
            var jumpList: [JumpListEntry] = []
            var usn: [UsnRecord] = []
            var recycleBin: [RecycleBinEntry] = []
            var srum: [SrumEntry] = []
            var browserHistory: [BrowserHistoryEntry] = []
            var mft: [MftEntry] = []
            var wmi: [WmiPersistenceEntry] = []
            var launchItems: [LaunchItemEntry] = []
            var quarantine: [QuarantineEvent] = []
            var macPersistence: [MacPersistenceItem] = []
            var fsEvents: [FSEventRecord] = []
            var unifiedLog: [UnifiedLogEntry] = []
            var tcc: [TCCAccess] = []
            var knowledgeC: [KnowledgeEntry] = []
            var macRecentItems: [MacRecentItem] = []
            var macSecurityEvents: [MacSecurityEvent] = []
            var carvedFiles: [CarvedFile] = []
            var kexts: [MacKextEntry] = []
            var backgroundItems: [MacBackgroundItem] = []
            var messages: [MessageEntry] = []
            var mail: [MailMessageEntry] = []
            var network: [MacNetworkItem] = []
            var userActivity: [MacActivityItem] = []
            var documentVersions: [MacDocumentVersion] = []
            var notifications: [MacNotification] = []
            var powerlog: [PowerlogEntry] = []
            var macConfig: [MacConfigSetting] = []
            var installHistory: [MacInstallEntry] = []
            var whereFroms: [MacWhereFrom] = []
            var macInfo: MacHostInfo?
            var authLog: [AuthLogEntry] = []
            var logins: [UtmpRecord] = []
            var shellHistory: [ShellHistoryEntry] = []
            var linuxPersistence: [LinuxPersistenceEntry] = []
            var linuxInfo: LinuxHostInfo?
            var linuxAccess: LinuxAccessInfo?
            var webAccess: [WebAccessLogEntry] = []
            var packages: [PackageEvent] = []
            var journald: [JournaldEntry] = []
            var audit: [AuditEvent] = []
            var syslog: [SyslogEntry] = []
            var lastlog: [LastlogEntry] = []
            var findings: [Finding] = []
            var iocMatches: [IOCMatch] = []
            let jobs: [() -> Void] = [
                { registry = (try? CaseStore.readRegistry(forHostID: id, in: bundleURL)) ?? [] },
                { prefetch = (try? CaseStore.readPrefetch(forHostID: id, in: bundleURL)) ?? [] },
                { amcache = (try? CaseStore.readAmcache(forHostID: id, in: bundleURL)) ?? [] },
                { shimcache = (try? CaseStore.readShimcache(forHostID: id, in: bundleURL)) ?? [] },
                { lnk = (try? CaseStore.readLnk(forHostID: id, in: bundleURL)) ?? [] },
                { jumpList = (try? CaseStore.readJumpList(forHostID: id, in: bundleURL)) ?? [] },
                { usn = (try? CaseStore.readUsn(forHostID: id, in: bundleURL)) ?? [] },
                { recycleBin = (try? CaseStore.readRecycleBin(forHostID: id, in: bundleURL)) ?? [] },
                { srum = (try? CaseStore.readSrum(forHostID: id, in: bundleURL)) ?? [] },
                { browserHistory = (try? CaseStore.readBrowserHistory(forHostID: id, in: bundleURL)) ?? [] },
                { mft = (try? CaseStore.readMft(forHostID: id, in: bundleURL)) ?? [] },
                { wmi = (try? CaseStore.readWmi(forHostID: id, in: bundleURL)) ?? [] },
                { launchItems = (try? CaseStore.readLaunchItems(forHostID: id, in: bundleURL)) ?? [] },
                { quarantine = (try? CaseStore.readQuarantine(forHostID: id, in: bundleURL)) ?? [] },
                { macPersistence = (try? CaseStore.readMacPersistence(forHostID: id, in: bundleURL)) ?? [] },
                { fsEvents = (try? CaseStore.readFSEvents(forHostID: id, in: bundleURL)) ?? [] },
                { unifiedLog = (try? CaseStore.readUnifiedLog(forHostID: id, in: bundleURL)) ?? [] },
                { tcc = (try? CaseStore.readTCC(forHostID: id, in: bundleURL)) ?? [] },
                { knowledgeC = (try? CaseStore.readKnowledgeC(forHostID: id, in: bundleURL)) ?? [] },
                { macRecentItems = (try? CaseStore.readMacRecentItems(forHostID: id, in: bundleURL)) ?? [] },
                { macSecurityEvents = (try? CaseStore.readMacSecurityEvents(forHostID: id, in: bundleURL)) ?? [] },
                { carvedFiles = (try? CaseStore.readCarved(forHostID: id, in: bundleURL)) ?? [] },
                { kexts = (try? CaseStore.readKexts(forHostID: id, in: bundleURL)) ?? [] },
                { backgroundItems = (try? CaseStore.readBackgroundItems(forHostID: id, in: bundleURL)) ?? [] },
                { messages = (try? CaseStore.readMessages(forHostID: id, in: bundleURL)) ?? [] },
                { mail = (try? CaseStore.readMail(forHostID: id, in: bundleURL)) ?? [] },
                { network = (try? CaseStore.readNetwork(forHostID: id, in: bundleURL)) ?? [] },
                { userActivity = (try? CaseStore.readUserActivity(forHostID: id, in: bundleURL)) ?? [] },
                { documentVersions = (try? CaseStore.readDocumentVersions(forHostID: id, in: bundleURL)) ?? [] },
                { notifications = (try? CaseStore.readNotifications(forHostID: id, in: bundleURL)) ?? [] },
                { powerlog = (try? CaseStore.readPowerlog(forHostID: id, in: bundleURL)) ?? [] },
                { macConfig = (try? CaseStore.readMacConfig(forHostID: id, in: bundleURL)) ?? [] },
                { installHistory = (try? CaseStore.readInstallHistory(forHostID: id, in: bundleURL)) ?? [] },
                { whereFroms = (try? CaseStore.readWhereFroms(forHostID: id, in: bundleURL)) ?? [] },
                { macInfo = try? CaseStore.readMacInfo(forHostID: id, in: bundleURL) },
                { authLog = (try? CaseStore.readAuthLog(forHostID: id, in: bundleURL)) ?? [] },
                { logins = (try? CaseStore.readLogins(forHostID: id, in: bundleURL)) ?? [] },
                { shellHistory = (try? CaseStore.readShellHistory(forHostID: id, in: bundleURL)) ?? [] },
                { linuxPersistence = (try? CaseStore.readLinuxPersistence(forHostID: id, in: bundleURL)) ?? [] },
                { linuxInfo = try? CaseStore.readLinuxInfo(forHostID: id, in: bundleURL) },
                { linuxAccess = try? CaseStore.readLinuxAccess(forHostID: id, in: bundleURL) },
                { webAccess = (try? CaseStore.readWebAccess(forHostID: id, in: bundleURL)) ?? [] },
                { packages = (try? CaseStore.readPackages(forHostID: id, in: bundleURL)) ?? [] },
                { journald = (try? CaseStore.readJournald(forHostID: id, in: bundleURL)) ?? [] },
                { audit = (try? CaseStore.readAudit(forHostID: id, in: bundleURL)) ?? [] },
                { syslog = (try? CaseStore.readSyslog(forHostID: id, in: bundleURL)) ?? [] },
                { lastlog = (try? CaseStore.readLastlog(forHostID: id, in: bundleURL)) ?? [] },
                { findings = (try? CaseStore.readFindings(forHostID: id, in: bundleURL)) ?? [] },
                { iocMatches = (try? CaseStore.readIOCMatches(forHostID: id, in: bundleURL)) ?? [] },
            ]
            DispatchQueue.concurrentPerform(iterations: jobs.count) { jobs[$0]() }

            state.registryValues = registry
            state.prefetch = prefetch
            // Backfill the registry-derived artifacts: a case whose registry was
            // parsed before Amcache/Shimcache existed (or before they were
            // persisted) has registry values but no amcache/shimcache JSON. Both
            // reconstruct purely from the loaded registry values. (Amcache still
            // needs a forced re-parse on pre-feature cases whose registry.json
            // never captured Amcache.hve - there are no AMCACHE values to map.)
            state.amcache = amcache.isEmpty ? AmcacheEntry.reconstruct(from: registry) : amcache
            state.shimcache = shimcache.isEmpty ? ShimcacheParser.fromRegistry(registry) : shimcache
            state.lnk = lnk
            state.jumpList = jumpList
            state.usn = usn
            state.recycleBin = recycleBin
            state.srum = srum
            state.browserHistory = browserHistory
            state.mft = mft
            state.wmi = wmi
            state.launchItems = launchItems
            state.quarantine = quarantine
            state.macPersistence = macPersistence
            state.fsEvents = fsEvents
            state.unifiedLog = unifiedLog
            state.tcc = tcc
            state.knowledgeC = knowledgeC
            state.macRecentItems = macRecentItems
            state.macSecurityEvents = macSecurityEvents
            state.carvedFiles = carvedFiles
            state.kexts = kexts
            state.backgroundItems = backgroundItems
            state.messages = messages
            state.mail = mail
            state.network = network
            state.userActivity = userActivity
            state.documentVersions = documentVersions
            state.notifications = notifications
            state.powerlog = powerlog
            state.macConfig = macConfig
            state.installHistory = installHistory
            state.whereFroms = whereFroms
            state.macInfo = macInfo
            state.authLog = authLog
            state.logins = logins
            state.shellHistory = shellHistory
            state.linuxPersistence = linuxPersistence
            state.linuxInfo = linuxInfo
            state.linuxAccess = linuxAccess
            state.webAccess = webAccess
            state.packages = packages
            state.journald = journald
            state.audit = audit
            state.syslog = syslog
            state.lastlog = lastlog
            state.findings = findings
            state.iocMatches = iocMatches

            // Splice every timestamped source onto the timeline (which already
            // holds the FS-MACB + evtx rows), then sort once instead of after each
            // group. Gating mirrors the parsers: the registry slice is macOS-only
            // (a big hive is phone-hostile), and the $MFT $SI MACB is loose-folder
            // only (an image's TSK FS source already carries it). recycleBin / wmi
            // / carved / launch items / quarantine / persistence / fsEvents have no
            // timestamps, so they aren't spliced.
            #if os(macOS)
            state.timeline.append(contentsOf: TimelineBuilder.build(from: state.registryValues))
            #endif
            state.timeline.append(contentsOf: TimelineBuilder.build(from: state.prefetch))
            state.timeline.append(contentsOf: TimelineBuilder.build(from: state.amcache))
            state.timeline.append(contentsOf: TimelineBuilder.build(from: state.shimcache))
            state.timeline.append(contentsOf: TimelineBuilder.build(from: state.lnk))
            state.timeline.append(contentsOf: TimelineBuilder.build(from: state.jumpList))
            state.timeline.append(contentsOf: TimelineBuilder.build(from: state.usn))
            state.timeline.append(contentsOf: TimelineBuilder.build(from: state.srum))
            state.timeline.append(contentsOf: TimelineBuilder.build(from: state.browserHistory))
            state.timeline.append(contentsOf: TimelineBuilder.build(from: state.messages))
            state.timeline.append(contentsOf: TimelineBuilder.build(from: state.mail))
            state.timeline.append(contentsOf: TimelineBuilder.build(from: state.network))
            state.timeline.append(contentsOf: TimelineBuilder.build(from: state.userActivity))
            state.timeline.append(contentsOf: TimelineBuilder.build(from: state.documentVersions))
            state.timeline.append(contentsOf: TimelineBuilder.build(from: state.notifications))
            state.timeline.append(contentsOf: TimelineBuilder.build(from: state.powerlog))
            state.timeline.append(contentsOf: TimelineBuilder.build(from: state.installHistory))
            state.timeline.append(contentsOf: TimelineBuilder.build(from: state.unifiedLog))
            state.timeline.append(contentsOf: TimelineBuilder.build(from: state.tcc))
            state.timeline.append(contentsOf: TimelineBuilder.build(from: state.knowledgeC))
            state.timeline.append(contentsOf: TimelineBuilder.build(from: state.macRecentItems))
            state.timeline.append(contentsOf: TimelineBuilder.build(from: state.macSecurityEvents))
            if evidence.kind == .kapeLooseFolder {
                state.timeline.append(contentsOf: TimelineBuilder.build(from: state.mft))
            }
            state.timeline.append(contentsOf: TimelineBuilder.build(from: state.authLog))
            state.timeline.append(contentsOf: TimelineBuilder.build(from: state.logins))
            state.timeline.append(contentsOf: TimelineBuilder.build(from: state.shellHistory))
            state.timeline.append(contentsOf: TimelineBuilder.build(from: state.webAccess))
            state.timeline.append(contentsOf: TimelineBuilder.build(from: state.packages))
            state.timeline.append(contentsOf: TimelineBuilder.build(from: state.journald))
            state.timeline.append(contentsOf: TimelineBuilder.build(from: state.audit))
            state.timeline.append(contentsOf: TimelineBuilder.build(from: state.syslog))
            state.timeline.append(contentsOf: TimelineBuilder.build(from: state.lastlog))
            state.timeline.sort { $0.date < $1.date }

            state.osFamilies = OSFamily.detect(volumes: state.volumes, files: state.files)
            if let loadWarning { return .loadedWithWarning(state, loadWarning) }
            return .loaded(state)
        } catch {
            // Skip this host but keep going so a single corrupted DB doesn't
            // block the whole case from opening.
            return .skipped("Failed to load \(evidence.displayName): \(error.localizedDescription)")
        }
    }

    /// Drop the open case; return to the welcome screen. In-memory state is
    /// cleared but nothing on disk is touched.
    func closeCase() {
        caseSecurityScopeURL?.stopAccessingSecurityScopedResource()
        caseSecurityScopeURL = nil
        currentCase = nil
        currentCaseBundleURL = nil
        evidenceList = []
        states = [:]
        iocs = []
        custodyLog = []
        annotations = []
        caseNotes = CaseNotes()
        enrichmentVerdicts = []
        caseSummary = nil
        correlationFindings = []
        timelinePivot = nil
        activeEvidenceID = nil
        progress = nil
        statusMessage = ""
        errorMessage = nil
        refreshLibrary()   // pick up any case added/synced while one was open
    }

    func saveHosts() {
        guard let bundleURL = currentCaseBundleURL else { return }
        do {
            try CaseStore.writeHosts(evidenceList, in: bundleURL)
        } catch {
            errorMessage = "Failed to save host list: \(error.localizedDescription)"
        }
    }
}
