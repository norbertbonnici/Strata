import Foundation
import SwiftUI
import Combine

/// Per-evidence working set. One of these exists for every `Evidence` the
/// user has ingested in the current session. AppModel composes views across
/// any subset.
///
/// `nonisolated` + `Sendable` (all stored fields are Sendable value types) so a
/// host's working set can be assembled off the main actor in
/// `AppModel.loadEvidenceState` and published back without copying through
/// MainActor isolation.
nonisolated struct EvidenceState: Sendable {
    /// TSK SQLite location, or nil for loose-folder hosts that have no image
    /// to back a TSK database - their files are read straight off disk.
    var dbURL: URL?
    var files: [FileEntry] = []
    var volumes: [VolumeInfo] = []   // filesystems in the image (empty for loose folders)
    var events: [EventLogRecord] = []
    var timeline: [TimelineEvent] = []
    var registryValues: [RegistryValue] = []
    var prefetch: [PrefetchEntry] = []
    var amcache: [AmcacheEntry] = []
    var shimcache: [ShimcacheEntry] = []
    var lnk: [LnkEntry] = []
    var jumpList: [JumpListEntry] = []
    var usn: [UsnRecord] = []
    var srum: [SrumEntry] = []
    var browserHistory: [BrowserHistoryEntry] = []
    var mft: [MftEntry] = []
    var wmi: [WmiPersistenceEntry] = []
    // Linux artifacts (empty on Windows evidence - the parsers no-op).
    var authLog: [AuthLogEntry] = []
    var logins: [UtmpRecord] = []
    var shellHistory: [ShellHistoryEntry] = []
    var linuxPersistence: [LinuxPersistenceEntry] = []
    var linuxInfo: LinuxHostInfo?
    var linuxAccess: LinuxAccessInfo?
    var webAccess: [WebAccessLogEntry] = []
    var packages: [PackageEvent] = []
    var findings: [Finding] = []
    var iocMatches: [IOCMatch] = []
    /// OS families detected for this host (from volume fs-types, or a file-tree
    /// sniff for loose folders). Empty = couldn't tell. Drives per-OS tab
    /// hiding. Computed once when the working set is assembled.
    var osFamilies: Set<OSFamily> = []

    /// Whether any Linux artifact has been parsed for this host - the
    /// "already done" guard `parseLinux` uses (mirrors the per-artifact
    /// `state.X.isEmpty` guards of the Windows parsers).
    var hasLinuxArtifacts: Bool {
        !authLog.isEmpty || !logins.isEmpty || !shellHistory.isEmpty
            || !linuxPersistence.isEmpty || linuxInfo != nil || linuxAccess != nil
            || !webAccess.isEmpty || !packages.isEmpty
    }
}

/// A one-shot "reveal this range on the Timeline tab" request. The token makes
/// consecutive pivots to the same range distinguishable for `.onChange`.
nonisolated struct TimelinePivot: Equatable, Sendable {
    let token: UUID
    let range: ClosedRange<Date>
}

/// Everything the annotation editor sheet needs to create or edit a bookmark:
/// the target's stable identity plus the display snapshot that gets
/// denormalized into the `Annotation`. Resolved by the presenting view (which
/// has the live Finding / TimelineEvent in hand) so the sheet stays dumb.
nonisolated struct AnnotationDraft: Identifiable, Hashable, Sendable {
    let targetKind: Annotation.TargetKind
    let targetKey: String
    let evidenceID: UUID?
    let title: String
    let timestamp: Date?
    let sourceLabel: String

    var id: String { targetKey }

    init(finding: Finding, evidenceID: UUID?) {
        targetKind = .finding
        targetKey = finding.id.uuidString
        self.evidenceID = evidenceID
        title = finding.title
        timestamp = finding.timestamp
        sourceLabel = "Finding"
    }

    init(event: TimelineEvent, evidenceID: UUID?) {
        targetKind = .timelineEvent
        targetKey = event.stableKey
        self.evidenceID = evidenceID
        title = event.path
        timestamp = event.date
        sourceLabel = event.source.label
    }

    /// Re-edit a stored annotation from its denormalized snapshot - used when
    /// the live target isn't loaded (or no longer resolves).
    init(stored annotation: Annotation) {
        targetKind = annotation.targetKind
        targetKey = annotation.targetKey
        evidenceID = annotation.evidenceID
        title = annotation.title
        timestamp = annotation.timestamp
        sourceLabel = annotation.sourceLabel
    }
}

@MainActor
final class AppModel: ObservableObject {
    /// The case currently open in the app. nil = show the WelcomeView.
    @Published var currentCase: ForensicCase?
    /// Filesystem location of the .strata bundle backing `currentCase`.
    @Published var currentCaseBundleURL: URL?
    /// Recently opened case bundles - powers the welcome screen list.
    @Published var recentCases: [URL] = RecentCases.load()
    /// Single sheet binding for the top-level modal stack. Two adjacent
    /// .sheet(isPresented:) modifiers on the same view can SIGABRT in
    /// SwiftUI when their bindings transition in the same render pass; one
    /// .sheet(item:) is the safe pattern.
    @Published var activeSheet: ActiveSheet?
    /// IOCs the analyst has loaded for the current case. Persisted to
    /// iocs.json inside the bundle. Empty by default - IOC matching never
    /// runs unless the user has loaded at least one.
    @Published var iocs: [IOC] = []
    /// Append-only chain-of-custody ledger for the open case (custody.json).
    /// Case-wide, so it lives here rather than in per-host `EvidenceState`.
    @Published private(set) var custodyLog: [CustodyEvent] = []

    /// Analyst bookmarks/tags (case-wide, `annotations.json`). The index is
    /// rebuilt on every change so timeline rows can do O(1) "is this event
    /// bookmarked" lookups across 20k-row tables.
    @Published private(set) var annotations: [Annotation] = [] {
        didSet {
            annotationsByTargetKey = Dictionary(annotations.map { ($0.targetKey, $0) },
                                                uniquingKeysWith: { first, _ in first })
        }
    }
    private(set) var annotationsByTargetKey: [String: Annotation] = [:]

    /// Free-form case narrative (`notes.json`). Mutate via `updateCaseNotes`.
    @Published private(set) var caseNotes = CaseNotes()

    /// One-shot "reveal this range on the Timeline tab" request - set by the
    /// Annotations list / findings, consumed by `TimelineView` (which clears
    /// it after applying). The token forces `.onChange` to fire for repeat
    /// pivots to the same range.
    @Published var timelinePivot: TimelinePivot?
    /// Which picker WelcomeView should present. A SINGLE `.fileImporter` is
    /// driven off this: SwiftUI only honors one `.fileImporter` per view tree,
    /// so separate per-button flags silently no-op (that's why "Set Case
    /// Library Folder" did nothing).
    enum FileImport: Equatable { case openCase, setLibrary }
    /// Mode and presentation are kept SEPARATE: SwiftUI clears an isPresented
    /// binding on dismiss, which races onCompletion - if the mode lived in the
    /// presentation binding it would read back nil there (that's why picking a
    /// library folder silently did nothing).
    @Published var fileImportMode: FileImport = .openCase
    @Published var fileImportPresented = false
    /// Toggled by the "Add Host..." toolbar item so ContentView can drive a
    /// `.fileImporter`. On iOS the toolbar item is hidden and this flag
    /// stays false.
    @Published var showAddHostPicker = false

    /// The Case Library: a remembered folder (iCloud Drive, an SMB/WebDAV share,
    /// or local) holding `.strata` cases. nil until the user picks one.
    @Published var libraryURL: URL? = CaseLibrary.savedURL()
    /// Cases discovered in the library folder (incl. not-yet-downloaded iCloud
    /// placeholders).
    @Published private(set) var libraryCases: [LibraryCase] = []

    enum ActiveSheet: Identifiable, Hashable {
        case newCase
        case enrichment
        case export
        case acquisitionEditor(UUID)
        case annotationEditor(AnnotationDraft)
        var id: Int { hashValue }
    }

    /// Ingested evidence in the order it was added. Drives the toolbar picker.
    @Published private(set) var evidenceList: [Evidence] = []

    /// Per-evidence state, keyed by Evidence.id.
    @Published private(set) var states: [UUID: EvidenceState] = [:] {
        didSet { invalidateDerived() }
    }

    /// `nil` = combined view across every loaded evidence.
    /// A UUID = scope every view to just that evidence.
    @Published var activeEvidenceID: UUID? {
        didSet { invalidateDerived() }
    }

    @Published var isWorking = false
    @Published var statusMessage = ""
    @Published var errorMessage: String?

    /// Set during long-running operations that know their total (event log
    /// parsing, registry hive parsing). The status bar renders a determinate
    /// progress bar when this is non-nil. Operations that don't know the
    /// total (TSK ingest, analyzers) leave it nil and rely on isWorking
    /// driving an indeterminate spinner.
    @Published var progress: ProgressInfo?

    private let analysisEngine = AnalysisEngine()

    public struct ProgressInfo: Equatable {
        public var current: Int
        public var total: Int
        public var label: String
        public var fraction: Double {
            total == 0 ? 0 : min(1.0, Double(current) / Double(total))
        }
        public var percent: Int { Int(fraction * 100) }
    }

    init() { refreshLibrary() }

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
                case .skippedSilently:
                    break
                case .skipped(let message):
                    statusMessage = message
                }
            }

            // Case-wide indicators + custody ledger + analyst annotations,
            // also decoded off-main.
            let caseWide = await Task.detached(priority: .userInitiated) {
                (iocs: (try? CaseStore.readIOCs(in: bundleURL)) ?? [],
                 custody: (try? CaseStore.readCustody(in: bundleURL)) ?? [],
                 annotations: (try? CaseStore.readAnnotations(in: bundleURL)) ?? [],
                 notes: (try? CaseStore.readNotes(in: bundleURL)) ?? CaseNotes())
            }.value
            iocs = caseWide.iocs
            custodyLog = caseWide.custody
            annotations = caseWide.annotations
            caseNotes = caseWide.notes

            RecentCases.record(bundleURL)
            recentCases = RecentCases.load()
            statusMessage = "Loaded case '\(theCase.name)' (\(hosts.count) host\(hosts.count == 1 ? "" : "s"))."
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
            if evidence.kind == .kapeLooseFolder {
                let root = evidence.sourceURL
                guard FileManager.default.fileExists(atPath: root.path) else {
                    return .skipped("\(evidence.displayName): source folder missing at \(root.path)")
                }
                var files = KapeFolderIngestor().ingest(folderAt: root)
                #if !os(macOS)
                files.removeAll(where: TimelineBuilder.isSlackEntry)
                #endif
                state = EvidenceState(dbURL: nil)
                state.files = files
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
                timeline.sort { $0.date < $1.date }
            }
            state.timeline = timeline
            state.registryValues = (try? CaseStore.readRegistry(forHostID: evidence.id, in: bundleURL)) ?? []
            state.prefetch = (try? CaseStore.readPrefetch(forHostID: evidence.id, in: bundleURL)) ?? []
            state.amcache = (try? CaseStore.readAmcache(forHostID: evidence.id, in: bundleURL)) ?? []
            state.shimcache = (try? CaseStore.readShimcache(forHostID: evidence.id, in: bundleURL)) ?? []
            // Backfill the registry-derived artifacts: a case whose registry was
            // parsed before Amcache/Shimcache existed (or before they were
            // persisted) has registry values but no amcache/shimcache JSON. Both
            // reconstruct purely from the loaded registry values, so regenerate
            // them here rather than forcing a re-parse. (Amcache still needs a
            // forced re-parse on pre-feature cases whose registry.json never
            // captured Amcache.hve - there are simply no AMCACHE values to map.)
            if state.amcache.isEmpty {
                state.amcache = AmcacheEntry.reconstruct(from: state.registryValues)
            }
            if state.shimcache.isEmpty {
                state.shimcache = ShimcacheParser.fromRegistry(state.registryValues)
            }
            state.lnk = (try? CaseStore.readLnk(forHostID: evidence.id, in: bundleURL)) ?? []
            state.jumpList = (try? CaseStore.readJumpList(forHostID: evidence.id, in: bundleURL)) ?? []
            // Fold the registry/prefetch/LNK/JumpList-derived timestamps back
            // into the timeline (mirrors the evtx splice): registry key writes,
            // prefetch runs, shimcache/amcache presence, LNK target MACs, and
            // JumpList accesses. One sort at the end covers the lot. The
            // registry slice is macOS-only, like the FS MACB timeline - a big
            // SOFTWARE hive expands to a phone-hostile row count.
            #if os(macOS)
            state.timeline.append(contentsOf: TimelineBuilder.build(from: state.registryValues))
            #endif
            state.timeline.append(contentsOf: TimelineBuilder.build(from: state.prefetch))
            state.timeline.append(contentsOf: TimelineBuilder.build(from: state.amcache))
            state.timeline.append(contentsOf: TimelineBuilder.build(from: state.shimcache))
            state.timeline.append(contentsOf: TimelineBuilder.build(from: state.lnk))
            state.timeline.append(contentsOf: TimelineBuilder.build(from: state.jumpList))
            state.timeline.sort { $0.date < $1.date }
            state.usn = (try? CaseStore.readUsn(forHostID: evidence.id, in: bundleURL)) ?? []
            // Fold USN journal rows back into the timeline so the Source filter
            // works without re-parsing on every case open (mirrors the evtx splice).
            if !state.usn.isEmpty {
                state.timeline.append(contentsOf: TimelineBuilder.build(from: state.usn))
                state.timeline.sort { $0.date < $1.date }
            }
            state.srum = (try? CaseStore.readSrum(forHostID: evidence.id, in: bundleURL)) ?? []
            // Fold SRUM rows back into the timeline so the Source filter works
            // without re-parsing on every case open (mirrors the USN splice).
            if !state.srum.isEmpty {
                state.timeline.append(contentsOf: TimelineBuilder.build(from: state.srum))
                state.timeline.sort { $0.date < $1.date }
            }
            state.browserHistory = (try? CaseStore.readBrowserHistory(forHostID: evidence.id, in: bundleURL)) ?? []
            // Fold browser-history rows back into the timeline (mirrors the SRUM splice).
            if !state.browserHistory.isEmpty {
                state.timeline.append(contentsOf: TimelineBuilder.build(from: state.browserHistory))
                state.timeline.sort { $0.date < $1.date }
            }
            state.mft = (try? CaseStore.readMft(forHostID: evidence.id, in: bundleURL)) ?? []
            // Fold $MFT $SI MACB onto the timeline only for loose folders (an
            // image's FS source already carries those TSK times); mirrors parseMft.
            if !state.mft.isEmpty, evidence.kind == .kapeLooseFolder {
                state.timeline.append(contentsOf: TimelineBuilder.build(from: state.mft))
                state.timeline.sort { $0.date < $1.date }
            }
            state.wmi = (try? CaseStore.readWmi(forHostID: evidence.id, in: bundleURL)) ?? []
            // Linux artifacts: rehydrate + splice the timestamped ones onto the
            // timeline (mirrors the evtx splice). Cheap on Windows hosts (all
            // empty). One sort covers the three.
            state.authLog = (try? CaseStore.readAuthLog(forHostID: evidence.id, in: bundleURL)) ?? []
            state.logins = (try? CaseStore.readLogins(forHostID: evidence.id, in: bundleURL)) ?? []
            state.shellHistory = (try? CaseStore.readShellHistory(forHostID: evidence.id, in: bundleURL)) ?? []
            state.linuxPersistence = (try? CaseStore.readLinuxPersistence(forHostID: evidence.id, in: bundleURL)) ?? []
            state.linuxInfo = try? CaseStore.readLinuxInfo(forHostID: evidence.id, in: bundleURL)
            state.linuxAccess = try? CaseStore.readLinuxAccess(forHostID: evidence.id, in: bundleURL)
            state.webAccess = (try? CaseStore.readWebAccess(forHostID: evidence.id, in: bundleURL)) ?? []
            state.packages = (try? CaseStore.readPackages(forHostID: evidence.id, in: bundleURL)) ?? []
            if !state.authLog.isEmpty || !state.logins.isEmpty || !state.shellHistory.isEmpty
                || !state.webAccess.isEmpty || !state.packages.isEmpty {
                state.timeline.append(contentsOf: TimelineBuilder.build(from: state.authLog))
                state.timeline.append(contentsOf: TimelineBuilder.build(from: state.logins))
                state.timeline.append(contentsOf: TimelineBuilder.build(from: state.shellHistory))
                state.timeline.append(contentsOf: TimelineBuilder.build(from: state.webAccess))
                state.timeline.append(contentsOf: TimelineBuilder.build(from: state.packages))
                state.timeline.sort { $0.date < $1.date }
            }
            state.findings = (try? CaseStore.readFindings(forHostID: evidence.id, in: bundleURL)) ?? []
            state.iocMatches = (try? CaseStore.readIOCMatches(forHostID: evidence.id, in: bundleURL)) ?? []
            state.osFamilies = OSFamily.detect(volumes: state.volumes, files: state.files)
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
        currentCase = nil
        currentCaseBundleURL = nil
        evidenceList = []
        states = [:]
        iocs = []
        custodyLog = []
        annotations = []
        caseNotes = CaseNotes()
        timelinePivot = nil
        activeEvidenceID = nil
        progress = nil
        statusMessage = ""
        errorMessage = nil
        refreshLibrary()   // pick up any case added/synced while one was open
    }

    private func saveHosts() {
        guard let bundleURL = currentCaseBundleURL else { return }
        do {
            try CaseStore.writeHosts(evidenceList, in: bundleURL)
        } catch {
            errorMessage = "Failed to save host list: \(error.localizedDescription)"
        }
    }

    // MARK: - Annotations (analyst bookmarks + case narrative)

    /// The annotation pinned to a target, if any. `key` is `Finding.id
    /// .uuidString` or `TimelineEvent.stableKey`.
    func annotation(forTargetKey key: String) -> Annotation? {
        annotationsByTargetKey[key]
    }

    /// Create or update the bookmark for `draft`'s target. One annotation per
    /// target: editing an existing bookmark updates its tag/note in place.
    func upsertAnnotation(for draft: AnnotationDraft, tag: AnalystTag?, note: String) {
        let author = currentCase?.examiner ?? ""
        if let index = annotations.firstIndex(where: { $0.targetKey == draft.targetKey }) {
            annotations[index].tag = tag
            annotations[index].note = note
            annotations[index].modifiedAt = Date()
            if !author.isEmpty { annotations[index].author = author }
        } else {
            annotations.append(Annotation(author: author,
                                          targetKind: draft.targetKind,
                                          targetKey: draft.targetKey,
                                          evidenceID: draft.evidenceID,
                                          tag: tag, note: note,
                                          title: draft.title,
                                          timestamp: draft.timestamp,
                                          sourceLabel: draft.sourceLabel))
        }
        saveAnnotations()
    }

    func removeAnnotation(_ id: UUID) {
        annotations.removeAll { $0.id == id }
        saveAnnotations()
    }

    private func saveAnnotations() {
        guard let bundleURL = currentCaseBundleURL else { return }
        do {
            try CaseStore.writeAnnotations(annotations, in: bundleURL)
        } catch {
            errorMessage = "Failed to save annotations: \(error.localizedDescription)"
        }
    }

    /// Replace the case narrative and persist. No-op when unchanged so the
    /// editor's debounced auto-save doesn't churn `notes.json`.
    func updateCaseNotes(_ text: String) {
        guard caseNotes.text != text else { return }
        caseNotes = CaseNotes(text: text, modifiedAt: Date(),
                              author: currentCase?.examiner ?? "")
        guard let bundleURL = currentCaseBundleURL else { return }
        do {
            try CaseStore.writeNotes(caseNotes, in: bundleURL)
        } catch {
            errorMessage = "Failed to save case notes: \(error.localizedDescription)"
        }
    }

    /// Ask the Timeline tab to reveal `date` with ±30 min of context.
    func pivotToTimeline(around date: Date) {
        let pad: TimeInterval = 30 * 60
        timelinePivot = TimelinePivot(token: UUID(),
                                      range: date.addingTimeInterval(-pad)...date.addingTimeInterval(pad))
    }

    /// Owning host for a finding. Findings are few, so the scan is cheap -
    /// unlike timeline events, whose host attribution comes from the active
    /// scope instead.
    func evidenceID(forFinding id: UUID) -> UUID? {
        states.first { $0.value.findings.contains { $0.id == id } }?.key
    }

    // MARK: - IOC management

    /// Parse a free-form paste, classify each token, dedupe against the
    /// existing list, and persist. Tokens separated by any whitespace,
    /// comma, or semicolon; lines starting with # are dropped as comments.
    func addIOCs(from pasted: String) {
        let separators = CharacterSet(charactersIn: ",;\n\r\t ")
        let cleaned = pasted
            .components(separatedBy: "\n")
            .filter { !$0.trimmingCharacters(in: .whitespaces).hasPrefix("#") }
            .joined(separator: "\n")
        let tokens = cleaned
            .components(separatedBy: separators)
            .map { $0.trimmingCharacters(in: .whitespacesAndNewlines)
                     .trimmingCharacters(in: CharacterSet(charactersIn: "\"'<>")) }
            .filter { !$0.isEmpty }

        var seen = Set(iocs.map { $0.value.lowercased() })
        var added: [IOC] = []
        for token in tokens {
            let key = token.lowercased()
            if seen.contains(key) { continue }
            seen.insert(key)
            added.append(IOC(kind: IOCKind.classify(token), value: token))
        }
        iocs.append(contentsOf: added)
        saveIOCs()
        statusMessage = "Added \(added.count) IOC\(added.count == 1 ? "" : "s") (\(iocs.count) total)."
    }

    func removeIOC(_ id: UUID) {
        iocs.removeAll { $0.id == id }
        saveIOCs()
    }

    private func saveIOCs() {
        guard let bundleURL = currentCaseBundleURL else { return }
        do {
            try CaseStore.writeIOCs(iocs, in: bundleURL)
        } catch {
            errorMessage = "Failed to save IOCs: \(error.localizedDescription)"
        }
    }

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
    private func recordIngestIntegrityEvents(for evidence: Evidence) {
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
                                  annotations: annotationsForExport)

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

    // MARK: - Computed views consumed by every screen
    //
    // The per-evidence arrays change rarely (ingest / parse / scope switch) but
    // are read many times per render across every screen. Re-flatMapping and
    // re-sorting the full dataset on every access was the dominant cost on the
    // million-event cases this tool targets, so we roll the result up once and
    // cache it, invalidating only when `states` or `activeEvidenceID` actually
    // change (see their didSet -> invalidateDerived()).

    /// Evidence the UI is currently scoped to, or nil when "All" is active.
    var selectedEvidence: Evidence? {
        guard let id = activeEvidenceID else { return nil }
        return evidenceList.first { $0.id == id }
    }

    private struct Derived {
        var files: [FileEntry] = []
        var events: [EventLogRecord] = []
        var timeline: [TimelineEvent] = []
        var findings: [Finding] = []
        var registryValues: [RegistryValue] = []
        var prefetch: [PrefetchEntry] = []
        var amcache: [AmcacheEntry] = []
        var shimcache: [ShimcacheEntry] = []
        var lnk: [LnkEntry] = []
        var jumpList: [JumpListEntry] = []
        var usn: [UsnRecord] = []
        var srum: [SrumEntry] = []
        var browserHistory: [BrowserHistoryEntry] = []
        var mft: [MftEntry] = []
        var wmi: [WmiPersistenceEntry] = []
        var authLog: [AuthLogEntry] = []
        var logins: [UtmpRecord] = []
        var shellHistory: [ShellHistoryEntry] = []
        var linuxPersistence: [LinuxPersistenceEntry] = []
        var webAccess: [WebAccessLogEntry] = []
        var packages: [PackageEvent] = []
        var iocMatches: [IOCMatch] = []
    }
    private var derivedCache: Derived?
    private var lateralGraphCache: LateralGraph?

    /// Monotonic token bumped whenever the derived data changes. Use it as a
    /// `.task(id:)` / `.onChange(of:)` key instead of reading a heavy
    /// collection's `.count` (which used to force a full sort just to count).
    private(set) var dataVersion = 0

    private func invalidateDerived() {
        derivedCache = nil
        lateralGraphCache = nil
        dataVersion &+= 1
    }

    /// Lateral-movement graph for the active scope, cached. Building it sorts
    /// the event set and compiles a regex per 4624/4625, so the views (macOS
    /// canvas, iOS drill, the More-tab hop count) share this one build instead
    /// of each reconstructing it every render.
    var lateralGraph: LateralGraph {
        if let cached = lateralGraphCache { return cached }
        let graph = LateralGraph.build(from: events)
        lateralGraphCache = graph
        return graph
    }

    private func derived() -> Derived {
        if let cached = derivedCache { return cached }
        let built = buildDerived()
        derivedCache = built
        return built
    }

    private func buildDerived() -> Derived {
        var d = Derived()
        if let id = activeEvidenceID {
            // Single-evidence scope: the per-state arrays are already stored in
            // display order (events/timeline sorted at parse, findings by the
            // analysis engine), so hand them back without re-sorting.
            guard let s = states[id] else { return d }
            d.files = s.files
            d.events = s.events
            d.timeline = s.timeline
            d.findings = s.findings
            d.registryValues = s.registryValues
            d.prefetch = s.prefetch
            d.amcache = s.amcache
            d.shimcache = s.shimcache
            d.lnk = s.lnk
            d.jumpList = s.jumpList
            d.usn = s.usn
            d.srum = s.srum
            d.browserHistory = s.browserHistory
            d.mft = s.mft
            d.wmi = s.wmi
            d.authLog = s.authLog
            d.logins = s.logins
            d.shellHistory = s.shellHistory
            d.linuxPersistence = s.linuxPersistence
            d.webAccess = s.webAccess
            d.packages = s.packages
            d.iocMatches = s.iocMatches
            return d
        }
        // Combined ("All") scope: merge every host, then sort the ordered ones.
        for evidence in evidenceList {
            guard let s = states[evidence.id] else { continue }
            d.files.append(contentsOf: s.files)
            d.events.append(contentsOf: s.events)
            d.timeline.append(contentsOf: s.timeline)
            d.findings.append(contentsOf: s.findings)
            d.registryValues.append(contentsOf: s.registryValues)
            d.prefetch.append(contentsOf: s.prefetch)
            d.amcache.append(contentsOf: s.amcache)
            d.shimcache.append(contentsOf: s.shimcache)
            d.lnk.append(contentsOf: s.lnk)
            d.jumpList.append(contentsOf: s.jumpList)
            d.usn.append(contentsOf: s.usn)
            d.srum.append(contentsOf: s.srum)
            d.browserHistory.append(contentsOf: s.browserHistory)
            d.mft.append(contentsOf: s.mft)
            d.wmi.append(contentsOf: s.wmi)
            d.authLog.append(contentsOf: s.authLog)
            d.logins.append(contentsOf: s.logins)
            d.shellHistory.append(contentsOf: s.shellHistory)
            d.linuxPersistence.append(contentsOf: s.linuxPersistence)
            d.webAccess.append(contentsOf: s.webAccess)
            d.packages.append(contentsOf: s.packages)
            d.iocMatches.append(contentsOf: s.iocMatches)
        }
        d.events.sort { $0.writtenAt < $1.writtenAt }
        d.timeline.sort { $0.date < $1.date }
        d.findings.sort { $0.severity > $1.severity }
        d.prefetch.sort { ($0.lastRun ?? .distantPast) > ($1.lastRun ?? .distantPast) }
        d.amcache.sort { ($0.registeredAt ?? .distantPast) > ($1.registeredAt ?? .distantPast) }
        // insertionOrder is per-host; across hosts order by last-modified instead.
        d.shimcache.sort { ($0.lastModified ?? .distantPast) > ($1.lastModified ?? .distantPast) }
        d.lnk.sort { ($0.targetModified ?? .distantPast) > ($1.targetModified ?? .distantPast) }
        d.jumpList.sort { ($0.lastAccessed ?? .distantPast) > ($1.lastAccessed ?? .distantPast) }
        d.usn.sort { ($0.timestamp ?? .distantPast) > ($1.timestamp ?? .distantPast) }
        d.srum.sort { ($0.timestamp ?? .distantPast) > ($1.timestamp ?? .distantPast) }
        d.browserHistory.sort { ($0.timestamp ?? .distantPast) > ($1.timestamp ?? .distantPast) }
        d.mft.sort { $0.recordNumber < $1.recordNumber }
        d.authLog.sort { ($0.timestamp ?? .distantPast) > ($1.timestamp ?? .distantPast) }
        d.logins.sort { ($0.timestamp ?? .distantPast) > ($1.timestamp ?? .distantPast) }
        d.shellHistory.sort { ($0.timestamp ?? .distantPast) > ($1.timestamp ?? .distantPast) }
        d.webAccess.sort { ($0.timestamp ?? .distantPast) > ($1.timestamp ?? .distantPast) }
        d.packages.sort { ($0.timestamp ?? .distantPast) > ($1.timestamp ?? .distantPast) }
        return d
    }

    var files: [FileEntry] { derived().files }
    /// Volumes for the active scope (small; not worth caching). Combined "All"
    /// scope concatenates per-host volume lists.
    var volumes: [VolumeInfo] {
        if let id = activeEvidenceID { return states[id]?.volumes ?? [] }
        return evidenceList.flatMap { states[$0.id]?.volumes ?? [] }
    }
    var events: [EventLogRecord] { derived().events }
    var timeline: [TimelineEvent] { derived().timeline }
    var findings: [Finding] { derived().findings }
    var registryValues: [RegistryValue] { derived().registryValues }
    var prefetch: [PrefetchEntry] { derived().prefetch }
    var amcache: [AmcacheEntry] { derived().amcache }
    var shimcache: [ShimcacheEntry] { derived().shimcache }
    var lnk: [LnkEntry] { derived().lnk }
    var jumpList: [JumpListEntry] { derived().jumpList }
    var usn: [UsnRecord] { derived().usn }
    var srum: [SrumEntry] { derived().srum }
    var browserHistory: [BrowserHistoryEntry] { derived().browserHistory }
    var mft: [MftEntry] { derived().mft }
    var wmi: [WmiPersistenceEntry] { derived().wmi }
    var authLog: [AuthLogEntry] { derived().authLog }
    var logins: [UtmpRecord] { derived().logins }
    var shellHistory: [ShellHistoryEntry] { derived().shellHistory }
    var linuxPersistence: [LinuxPersistenceEntry] { derived().linuxPersistence }
    var webAccess: [WebAccessLogEntry] { derived().webAccess }
    var packages: [PackageEvent] { derived().packages }
    /// Linux host info for the active scope (tiny; not worth caching). In the
    /// combined scope the first host that has one wins.
    var linuxInfo: LinuxHostInfo? {
        if let id = activeEvidenceID { return states[id]?.linuxInfo }
        return evidenceList.lazy.compactMap { self.states[$0.id]?.linuxInfo }.first
    }
    /// Access/privilege artifacts for the active scope (tiny; not cached). In
    /// the combined scope the first host that has them wins.
    var linuxAccess: LinuxAccessInfo? {
        if let id = activeEvidenceID { return states[id]?.linuxAccess }
        return evidenceList.lazy.compactMap { self.states[$0.id]?.linuxAccess }.first
    }
    var sshKeyCount: Int {
        if let id = activeEvidenceID { return states[id]?.linuxAccess?.sshKeys.count ?? 0 }
        return evidenceList.reduce(0) { $0 + (states[$1.id]?.linuxAccess?.sshKeys.count ?? 0) }
    }
    var iocMatches: [IOCMatch] { derived().iocMatches }

    // Count-only accessors: sum per-host counts without building or sorting the
    // rolled-up arrays. For stat tiles / titles that only need a number.
    var fileCount: Int { scopedCount(\.files.count) }
    var eventCount: Int { scopedCount(\.events.count) }
    var timelineCount: Int { scopedCount(\.timeline.count) }
    var findingCount: Int { scopedCount(\.findings.count) }
    var registryValueCount: Int { scopedCount(\.registryValues.count) }
    var prefetchCount: Int { scopedCount(\.prefetch.count) }
    var amcacheCount: Int { scopedCount(\.amcache.count) }
    var shimcacheCount: Int { scopedCount(\.shimcache.count) }
    var lnkCount: Int { scopedCount(\.lnk.count) }
    var jumpListCount: Int { scopedCount(\.jumpList.count) }
    var usnCount: Int { scopedCount(\.usn.count) }
    var srumCount: Int { scopedCount(\.srum.count) }
    var browserHistoryCount: Int { scopedCount(\.browserHistory.count) }
    var mftCount: Int { scopedCount(\.mft.count) }
    var wmiCount: Int { scopedCount(\.wmi.count) }
    var authLogCount: Int { scopedCount(\.authLog.count) }
    var loginsCount: Int { scopedCount(\.logins.count) }
    var shellHistoryCount: Int { scopedCount(\.shellHistory.count) }
    var linuxPersistenceCount: Int { scopedCount(\.linuxPersistence.count) }
    var webAccessCount: Int { scopedCount(\.webAccess.count) }
    var packageCount: Int { scopedCount(\.packages.count) }
    var iocMatchCount: Int { scopedCount(\.iocMatches.count) }

    private func scopedCount(_ kp: KeyPath<EvidenceState, Int>) -> Int {
        if let id = activeEvidenceID { return states[id]?[keyPath: kp] ?? 0 }
        return evidenceList.reduce(0) { $0 + (states[$1.id]?[keyPath: kp] ?? 0) }
    }

    // MARK: - Per-OS tab visibility

    /// When true, every artifact tab is shown regardless of the evidence OS -
    /// the escape hatch for mis-detection or an unusual collection. Session-
    /// scoped; the analyst flips it from the sidebar / More tab.
    @Published var showAllArtifactTabs = false

    /// OS families present in the current scope: the active host's, or the
    /// union across every host under "All". Empty when nothing is loaded or
    /// the OS couldn't be determined - which the visibility check treats as
    /// "show everything".
    func scopeOSFamilies() -> Set<OSFamily> {
        if let id = activeEvidenceID { return states[id]?.osFamilies ?? [] }
        return evidenceList.reduce(into: Set<OSFamily>()) { acc, evidence in
            if let families = states[evidence.id]?.osFamilies { acc.formUnion(families) }
        }
    }

    /// Whether artifacts of `osFamily` should be shown in the current scope.
    /// A nil family (cross-platform tab) is always shown; an undetermined
    /// scope (empty set) shows everything rather than hide on a guess.
    func shows(osFamily: OSFamily?) -> Bool {
        guard !showAllArtifactTabs else { return true }
        guard let osFamily else { return true }
        let families = scopeOSFamilies()
        return families.isEmpty || families.contains(osFamily)
    }

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

                // E01 carries acquisition metadata + acquisition hashes in its
                // header - read them (cheap) instead of rehashing the image.
                if evidence.kind == .e01 {
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
            // Offer post-ingest enrichments (currently just IOC matching).
            // Skip the popup when there's nothing to opt into - prompting
            // about an empty list is just friction.
            if !iocs.isEmpty {
                activeSheet = .enrichment
            }
        } catch {
            self.errorMessage = error.localizedDescription
            self.statusMessage = ""
        }
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

    // MARK: - Source-hash integrity (compute / verify)

    #if os(macOS)

    /// In-flight hashing task, exposed so a Cancel control can stop a long pass.
    private var hashTask: Task<FileHasher.Result, Error>?

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
    private static func applyEWFMetadata(_ meta: EWFInfo.Metadata, to evidence: inout Evidence) {
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

    // MARK: - Event-log parsing

    #if os(macOS)

    /// One-stop button: parse event logs, registry hives, prefetch, and LNK
    /// shortcuts, then run the detection engine over the combined evidence.
    func parseArtifacts() async {
        await parseEventLogs()
        await parseRegistry()
        await parsePrefetch()
        await parseLnk()
        await parseJumpList()
        await parseUsn()
        await parseSrum()
        await parseBrowserHistory()
        await parseMft()
        await parseWmi()
        await parseLinux()
        await runAnalyzers()
    }

    /// Parse every .evtx in every loaded evidence that doesn't already have
    /// events. Does NOT run analyzers - the caller is expected to use
    /// `parseArtifacts()` if it wants the full pipeline.
    func parseEventLogs() async {
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

        // Pre-compute the work total across every evidence so the bar is
        // accurate end-to-end, not just per-host.
        let totalCandidates = evidenceList.reduce(0) { acc, evidence in
            guard let state = states[evidence.id], state.events.isEmpty else { return acc }
            return acc + state.files.filter {
                $0.fileExtension == "evtx" && !$0.isDeleted && $0.size > 0
            }.count
        }
        guard totalCandidates > 0 else {
            statusMessage = "No new .evtx files to parse."
            return
        }
        progress = ProgressInfo(current: 0, total: totalCandidates, label: "Parsing event logs")
        var completed = 0

        do {
            let tskEnv = try TSKEnvironment.discover()
            let evtxEnv = try EVTXEnvironment.discover()
            let parser = EVTXParser(environment: evtxEnv)

            for evidence in evidenceList {
                guard var state = states[evidence.id] else { continue }
                if !state.events.isEmpty { continue }

                let candidates = state.files.filter {
                    $0.fileExtension == "evtx" && !$0.isDeleted && $0.size > 0
                }
                guard !candidates.isEmpty else { continue }

                // Image hosts need TSK to pull each .evtx out of the image;
                // loose folders read the file in place, so skip all of that.
                let isLoose = evidence.kind == .kapeLooseFolder
                var database: TSKDatabase?
                var extractor: TSKFileExtractor?
                var scratch: URL?
                if !isLoose {
                    guard let dbURL = state.dbURL else { continue }
                    database = try TSKDatabase(path: dbURL)
                    extractor = TSKFileExtractor(
                        environment: tskEnv,
                        imageURL: evidence.sourceURL,
                        imageType: TSKImageIngestor.imageType(for: evidence.sourceURL))
                    guard let bundleURL = currentCaseBundleURL else { continue }
                    let dir = CaseStore.eventScratchDirectory(forHostID: evidence.id, in: bundleURL)
                    try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
                    scratch = dir
                }

                var collected: [EventLogRecord] = []
                for entry in candidates {
                    progress = ProgressInfo(
                        current: completed,
                        total: totalCandidates,
                        label: "\(evidence.displayName): \(entry.name)")
                    // Resolve the .evtx to a readable path: the collected file
                    // itself (loose) or an icat extraction into scratch (image).
                    let fileURL: URL
                    if isLoose {
                        guard let disk = entry.diskURL,
                              FileManager.default.fileExists(atPath: disk.path) else {
                            completed += 1; continue
                        }
                        fileURL = disk
                    } else {
                        guard let info = try database!.fetchExtractInfo(forFileID: entry.id) else {
                            completed += 1; continue
                        }
                        let outURL = scratch!.appendingPathComponent("\(entry.id)-\(entry.name)")
                        try await extractor!.extract(metaAddr: info.metaAddr,
                                                     imageOffsetSectors: info.imageOffsetSectors,
                                                     to: outURL)
                        fileURL = outURL
                    }
                    let parsed = try await parser.parse(fileAt: fileURL)
                    collected.append(contentsOf: parsed)
                    completed += 1
                }
                collected.sort { $0.writtenAt < $1.writtenAt }
                state.events = collected
                // Drop any prior evtx slice (paranoia for re-parses) and
                // splice the freshly built evtx timeline back in, sorted.
                state.timeline.removeAll { $0.source == .evtx }
                state.timeline.append(contentsOf: TimelineBuilder.build(from: collected))
                state.timeline.sort { $0.date < $1.date }
                states[evidence.id] = state
                if let bundleURL = currentCaseBundleURL {
                    try? CaseStore.writeEvents(collected, forHostID: evidence.id, in: bundleURL)
                }
            }
            progress = ProgressInfo(current: completed, total: totalCandidates,
                                    label: "Event log parse complete")
        } catch {
            self.errorMessage = error.localizedDescription
            self.statusMessage = ""
        }
    }

    // MARK: - LNK parsing

    /// Parse every `.lnk` shortcut in every loaded evidence that doesn't already
    /// have LNK results - extracting with icat for image hosts, or reading the
    /// collected file in place for loose folders. Each `.lnk` yields one
    /// `LnkEntry`. Mirrors `parseEventLogs`; does NOT run analyzers.
    func parseLnk() async {
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
            state.files.filter { $0.fileExtension == "lnk" && !$0.isDirectory && !$0.isDeleted && $0.size > 0 }
        }

        let totalCandidates = evidenceList.reduce(0) { acc, evidence in
            guard let state = states[evidence.id], state.lnk.isEmpty else { return acc }
            return acc + candidates(state).count
        }
        guard totalCandidates > 0 else {
            statusMessage = "No new .lnk files to parse."
            return
        }
        progress = ProgressInfo(current: 0, total: totalCandidates, label: "Parsing shortcuts")
        var completed = 0

        do {
            let tskEnv = try TSKEnvironment.discover()
            let lnkEnv = try LnkEnvironment.discover()
            let parser = LnkParser(environment: lnkEnv)

            for evidence in evidenceList {
                guard var state = states[evidence.id] else { continue }
                if !state.lnk.isEmpty { continue }

                let found = candidates(state)
                guard !found.isEmpty else { continue }

                let isLoose = evidence.kind == .kapeLooseFolder
                var database: TSKDatabase?
                var extractor: TSKFileExtractor?
                var scratch: URL?
                if !isLoose {
                    guard let dbURL = state.dbURL else { continue }
                    database = try TSKDatabase(path: dbURL)
                    extractor = TSKFileExtractor(
                        environment: tskEnv,
                        imageURL: evidence.sourceURL,
                        imageType: TSKImageIngestor.imageType(for: evidence.sourceURL))
                    guard let bundleURL = currentCaseBundleURL else { continue }
                    let dir = CaseStore.lnkScratchDirectory(forHostID: evidence.id, in: bundleURL)
                    try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
                    scratch = dir
                }

                var collected: [LnkEntry] = []
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
                    } else {
                        guard let info = try database!.fetchExtractInfo(forFileID: entry.id) else {
                            completed += 1; continue
                        }
                        let outURL = scratch!.appendingPathComponent("\(entry.id)-\(entry.name)")
                        try await extractor!.extract(metaAddr: info.metaAddr,
                                                     imageOffsetSectors: info.imageOffsetSectors,
                                                     to: outURL)
                        fileURL = outURL
                    }
                    // Record the .lnk's own full path as the source so the table
                    // shows where the shortcut lived, not the scratch copy.
                    if let parsed = try? await parser.parse(fileAt: fileURL) {
                        collected.append(Self.rehome(parsed, sourceFile: entry.fullPath))
                    }
                    completed += 1
                }
                collected.sort { ($0.targetModified ?? .distantPast) > ($1.targetModified ?? .distantPast) }
                state.lnk = collected
                // Splice target MAC times onto the timeline (mirrors evtx).
                state.timeline.removeAll { $0.source == .lnk }
                state.timeline.append(contentsOf: TimelineBuilder.build(from: collected))
                state.timeline.sort { $0.date < $1.date }
                states[evidence.id] = state
                if let bundleURL = currentCaseBundleURL {
                    try? CaseStore.writeLnk(collected, forHostID: evidence.id, in: bundleURL)
                }
            }
            progress = ProgressInfo(current: completed, total: totalCandidates,
                                    label: "Shortcut parse complete")
        } catch {
            self.errorMessage = error.localizedDescription
            self.statusMessage = ""
        }
    }

    /// Replace the parser's scratch-path sourceFile with the artifact's real
    /// in-image path (the value-type copy keeps everything else).
    private nonisolated static func rehome(_ entry: LnkEntry, sourceFile: String) -> LnkEntry {
        LnkEntry(id: entry.id, sourceFile: sourceFile, localPath: entry.localPath,
                 networkPath: entry.networkPath, description: entry.description,
                 arguments: entry.arguments, workingDirectory: entry.workingDirectory,
                 iconLocation: entry.iconLocation, targetSize: entry.targetSize,
                 targetCreated: entry.targetCreated, targetModified: entry.targetModified,
                 targetAccessed: entry.targetAccessed, driveType: entry.driveType,
                 volumeLabel: entry.volumeLabel, volumeSerial: entry.volumeSerial,
                 machineIdentifier: entry.machineIdentifier)
    }

    // MARK: - JumpList parsing

    /// Parse every JumpList (*.automaticDestinations-ms / *.customDestinations-ms)
    /// in every loaded evidence that doesn't already have results. Automatic lists
    /// are cracked with olecfexport (OLE) and their embedded LNKs + DestList
    /// metadata merged; custom lists are a flat LNK sequence. Each file yields
    /// multiple JumpListEntry. Mirrors parseLnk; does NOT run analyzers.
    func parseJumpList() async {
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
                let ext = $0.fileExtension
                return (ext == "automaticdestinations-ms" || ext == "customdestinations-ms")
                    && !$0.isDirectory && !$0.isDeleted && $0.size > 0
            }
        }

        let totalCandidates = evidenceList.reduce(0) { acc, evidence in
            guard let state = states[evidence.id], state.jumpList.isEmpty else { return acc }
            return acc + candidates(state).count
        }
        guard totalCandidates > 0 else {
            statusMessage = "No new JumpLists to parse."
            return
        }
        progress = ProgressInfo(current: 0, total: totalCandidates, label: "Parsing JumpLists")
        var completed = 0

        do {
            let tskEnv = try TSKEnvironment.discover()
            let lnkEnv = try LnkEnvironment.discover()
            let jlEnv = try JumpListEnvironment.discover()
            let parser = JumpListParser(environment: jlEnv, lnkParser: LnkParser(environment: lnkEnv))

            for evidence in evidenceList {
                guard var state = states[evidence.id] else { continue }
                if !state.jumpList.isEmpty { continue }

                let found = candidates(state)
                guard !found.isEmpty else { continue }

                let isLoose = evidence.kind == .kapeLooseFolder
                var database: TSKDatabase?
                var extractor: TSKFileExtractor?
                var scratch: URL?
                if !isLoose {
                    guard let dbURL = state.dbURL else { continue }
                    database = try TSKDatabase(path: dbURL)
                    extractor = TSKFileExtractor(
                        environment: tskEnv,
                        imageURL: evidence.sourceURL,
                        imageType: TSKImageIngestor.imageType(for: evidence.sourceURL))
                    guard let bundleURL = currentCaseBundleURL else { continue }
                    let dir = CaseStore.jumpListScratchDirectory(forHostID: evidence.id, in: bundleURL)
                    try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
                    scratch = dir
                }

                var collected: [JumpListEntry] = []
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
                    } else {
                        guard let info = try database!.fetchExtractInfo(forFileID: entry.id) else {
                            completed += 1; continue
                        }
                        let outURL = scratch!.appendingPathComponent("\(entry.id)-\(entry.name)")
                        try await extractor!.extract(metaAddr: info.metaAddr,
                                                     imageOffsetSectors: info.imageOffsetSectors,
                                                     to: outURL)
                        fileURL = outURL
                    }
                    let appID = JumpListAppID.appID(fromFilename: entry.name)
                    let isAutomatic = entry.fileExtension == "automaticdestinations-ms"
                    if let parsed = try? await parser.parse(fileAt: fileURL, appID: appID,
                                                            sourceFile: entry.fullPath,
                                                            isAutomatic: isAutomatic) {
                        collected.append(contentsOf: parsed)
                    }
                    completed += 1
                }
                collected.sort { ($0.lastAccessed ?? .distantPast) > ($1.lastAccessed ?? .distantPast) }
                state.jumpList = collected
                // Splice DestList access times onto the timeline (mirrors evtx).
                state.timeline.removeAll { $0.source == .jumplist }
                state.timeline.append(contentsOf: TimelineBuilder.build(from: collected))
                state.timeline.sort { $0.date < $1.date }
                states[evidence.id] = state
                if let bundleURL = currentCaseBundleURL {
                    try? CaseStore.writeJumpList(collected, forHostID: evidence.id, in: bundleURL)
                }
            }
            progress = ProgressInfo(current: completed, total: totalCandidates,
                                    label: "JumpList parse complete")
        } catch {
            self.errorMessage = error.localizedDescription
            self.statusMessage = ""
        }
    }

    // MARK: - USN journal parsing

    /// Is this tsk_files / loose-folder name the NTFS change journal's `$J`
    /// data stream? On an image it appears as the named ADS `$UsnJrnl:$J`;
    /// KAPE collections name it `$J` or URL-encode the colon (`$UsnJrnl%3A$J`).
    private nonisolated static func isUsnJournalName(_ name: String) -> Bool {
        let n = name.lowercased()
        return n == "$j"
            || n == "$usnjrnl:$j" || n.hasSuffix("$usnjrnl:$j")
            || n == "$usnjrnl%3a$j" || n.hasSuffix("$usnjrnl%3a$j")
    }

    /// Parse the NTFS USN change journal (`$Extend\$UsnJrnl:$J`) for every
    /// loaded evidence that doesn't already have USN results. The journal is a
    /// single (often huge, sparse) named alternate data stream per volume, so:
    ///  - image hosts extract it with icat's `meta-type-id` ADS address form,
    ///    using `-h` so the leading sparse region isn't materialised as zeros;
    ///  - loose folders read the collected `$J` in place.
    /// The byte-parse runs OFF the main actor (`$J` can be 100 MB+). Mirrors
    /// `parseEventLogs` for timeline splicing; does NOT run analyzers.
    func parseUsn() async {
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
                !$0.isDirectory && $0.size > 0 && Self.isUsnJournalName($0.name)
            }
        }

        let totalCandidates = evidenceList.reduce(0) { acc, evidence in
            guard let state = states[evidence.id], state.usn.isEmpty else { return acc }
            return acc + candidates(state).count
        }
        guard totalCandidates > 0 else {
            statusMessage = "No new USN journal to parse."
            return
        }
        progress = ProgressInfo(current: 0, total: totalCandidates, label: "Parsing USN journal")
        var completed = 0

        do {
            let tskEnv = try TSKEnvironment.discover()

            for evidence in evidenceList {
                guard var state = states[evidence.id] else { continue }
                if !state.usn.isEmpty { continue }

                let found = candidates(state)
                guard !found.isEmpty else { continue }

                let isLoose = evidence.kind == .kapeLooseFolder
                var database: TSKDatabase?
                var extractor: TSKFileExtractor?
                var scratch: URL?
                if !isLoose {
                    guard let dbURL = state.dbURL else { continue }
                    database = try TSKDatabase(path: dbURL)
                    extractor = TSKFileExtractor(
                        environment: tskEnv,
                        imageURL: evidence.sourceURL,
                        imageType: TSKImageIngestor.imageType(for: evidence.sourceURL))
                    guard let bundleURL = currentCaseBundleURL else { continue }
                    let dir = CaseStore.usnScratchDirectory(forHostID: evidence.id, in: bundleURL)
                    try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
                    scratch = dir
                }

                var collected: [UsnRecord] = []
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
                    } else {
                        guard let info = try database!.fetchAttrExtractInfo(forFileID: entry.id) else {
                            completed += 1; continue
                        }
                        let outURL = scratch!.appendingPathComponent("\(entry.id)-usnjrnl-J.bin")
                        try await extractor!.extractStream(metaAddr: info.metaAddr,
                                                           attrType: info.attrType,
                                                           attrId: info.attrId,
                                                           imageOffsetSectors: info.imageOffsetSectors,
                                                           to: outURL)
                        fileURL = outURL
                    }

                    // Read the (potentially huge) stream and parse it off the
                    // main actor so the UI stays responsive.
                    guard let data = try? Data(contentsOf: fileURL, options: .mappedIfSafe) else {
                        completed += 1; continue
                    }
                    let bytes = [UInt8](data)
                    let source = entry.fullPath
                    let parsed = await Task.detached(priority: .userInitiated) {
                        UsnJournalParser.parse(bytes: bytes, sourceFile: source)
                    }.value
                    collected.append(contentsOf: parsed)
                    completed += 1
                }

                collected.sort { ($0.timestamp ?? .distantPast) > ($1.timestamp ?? .distantPast) }
                state.usn = collected
                // Drop any prior USN slice (paranoia for re-parses) and splice the
                // freshly built USN timeline back in, sorted.
                state.timeline.removeAll { $0.source == .usn }
                state.timeline.append(contentsOf: TimelineBuilder.build(from: collected))
                state.timeline.sort { $0.date < $1.date }
                states[evidence.id] = state
                if let bundleURL = currentCaseBundleURL {
                    try? CaseStore.writeUsn(collected, forHostID: evidence.id, in: bundleURL)
                }
            }
            progress = ProgressInfo(current: completed, total: totalCandidates,
                                    label: "USN journal parse complete")
        } catch {
            self.errorMessage = error.localizedDescription
            self.statusMessage = ""
        }
    }

    // MARK: - SRUM parsing

    /// Parse the Windows SRUM database (`SRUDB.dat`, an ESE database under
    /// `\Windows\System32\sru\`) for every loaded evidence that doesn't already
    /// have SRUM results. SRUDB.dat is an ordinary file (not a sparse ADS like
    /// `$J`), so it is extracted with the plain icat path that registry/prefetch
    /// use. The actual ESE parse is delegated to `SrumParser`, an actor that
    /// shells out to libesedb's `esedbexport` (so it already runs off the main
    /// actor). Mirrors `parseEventLogs` for timeline splicing; does NOT run analyzers.
    func parseSrum() async {
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
                !$0.isDirectory && $0.size > 0 && $0.name.lowercased() == "srudb.dat"
            }
        }

        let totalCandidates = evidenceList.reduce(0) { acc, evidence in
            guard let state = states[evidence.id], state.srum.isEmpty else { return acc }
            return acc + candidates(state).count
        }
        guard totalCandidates > 0 else {
            statusMessage = "No new SRUM database to parse."
            return
        }
        progress = ProgressInfo(current: 0, total: totalCandidates, label: "Parsing SRUM")
        var completed = 0

        do {
            let tskEnv = try TSKEnvironment.discover()
            let srumEnv = try SRUMEnvironment.discover()
            let parser = SrumParser(environment: srumEnv)

            for evidence in evidenceList {
                guard var state = states[evidence.id] else { continue }
                if !state.srum.isEmpty { continue }

                let found = candidates(state)
                guard !found.isEmpty else { continue }

                let isLoose = evidence.kind == .kapeLooseFolder
                var database: TSKDatabase?
                var extractor: TSKFileExtractor?
                var scratch: URL?
                if !isLoose {
                    guard let dbURL = state.dbURL else { continue }
                    database = try TSKDatabase(path: dbURL)
                    extractor = TSKFileExtractor(
                        environment: tskEnv,
                        imageURL: evidence.sourceURL,
                        imageType: TSKImageIngestor.imageType(for: evidence.sourceURL))
                    guard let bundleURL = currentCaseBundleURL else { continue }
                    let dir = CaseStore.srumScratchDirectory(forHostID: evidence.id, in: bundleURL)
                    try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
                    scratch = dir
                }

                var collected: [SrumEntry] = []
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
                    } else {
                        guard let info = try database!.fetchExtractInfo(forFileID: entry.id) else {
                            completed += 1; continue
                        }
                        let outURL = scratch!.appendingPathComponent("\(entry.id)-SRUDB.dat")
                        try await extractor!.extract(metaAddr: info.metaAddr,
                                                     imageOffsetSectors: info.imageOffsetSectors,
                                                     to: outURL)
                        fileURL = outURL
                    }
                    // SrumParser is an actor that shells out to esedbexport, so
                    // the heavy ESE work is already off the main actor. A single
                    // unreadable/dirty SRUDB.dat shouldn't abort the whole run.
                    let parsed = (try? await parser.parse(fileAt: fileURL, sourceFile: entry.fullPath)) ?? []
                    collected.append(contentsOf: parsed)
                    completed += 1
                }

                collected.sort { ($0.timestamp ?? .distantPast) > ($1.timestamp ?? .distantPast) }
                state.srum = collected
                // Drop any prior SRUM slice (paranoia for re-parses) and splice the
                // freshly built SRUM timeline back in, sorted.
                state.timeline.removeAll { $0.source == .srum }
                state.timeline.append(contentsOf: TimelineBuilder.build(from: collected))
                state.timeline.sort { $0.date < $1.date }
                states[evidence.id] = state
                if let bundleURL = currentCaseBundleURL {
                    try? CaseStore.writeSrum(collected, forHostID: evidence.id, in: bundleURL)
                }
            }
            progress = ProgressInfo(current: completed, total: totalCandidates,
                                    label: "SRUM parse complete")
        } catch {
            self.errorMessage = error.localizedDescription
            self.statusMessage = ""
        }
    }

    // MARK: - Browser history parsing

    /// Parse web-browser history databases (Chromium `History`, Firefox
    /// `places.sqlite`) for every loaded evidence that doesn't already have
    /// results. These are ordinary SQLite files (not sparse ADSes), so they're
    /// extracted with the plain icat path that registry/prefetch/SRUM use. The
    /// SQLite read itself (`BrowserHistoryParser`, GRDB) is run off the main
    /// actor in a detached task. Mirrors `parseSrum`; does NOT run analyzers.
    func parseBrowserHistory() async {
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
                return n == "history" || n == "places.sqlite"
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

            for evidence in evidenceList {
                guard var state = states[evidence.id] else { continue }
                if !state.browserHistory.isEmpty { continue }

                let found = candidates(state)
                guard !found.isEmpty else { continue }
                hostsTouched += 1

                let isLoose = evidence.kind == .kapeLooseFolder
                var database: TSKDatabase?
                var extractor: TSKFileExtractor?
                var scratch: URL?
                if !isLoose {
                    guard let dbURL = state.dbURL else { continue }
                    database = try TSKDatabase(path: dbURL)
                    extractor = TSKFileExtractor(
                        environment: tskEnv,
                        imageURL: evidence.sourceURL,
                        imageType: TSKImageIngestor.imageType(for: evidence.sourceURL))
                    guard let bundleURL = currentCaseBundleURL else { continue }
                    let dir = CaseStore.browserHistoryScratchDirectory(forHostID: evidence.id, in: bundleURL)
                    try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
                    scratch = dir
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
                    } else {
                        guard let info = try database!.fetchExtractInfo(forFileID: entry.id) else {
                            completed += 1; continue
                        }
                        let outURL = scratch!.appendingPathComponent("\(entry.id)-\(entry.name)")
                        try await extractor!.extract(metaAddr: info.metaAddr,
                                                     imageOffsetSectors: info.imageOffsetSectors,
                                                     to: outURL)
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
                    do {
                        let parsed = try await Task.detached(priority: .userInitiated) {
                            try BrowserHistoryParser.parse(fileAt: fileURL, sourceFile: source)
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
            if hostsTouched > 0, hostsCollected == 0 {
                errorMessage = "Browser history parse extracted no entries - check that the History / places.sqlite databases are accessible and not corrupt."
            }
        } catch {
            self.errorMessage = error.localizedDescription
            self.statusMessage = ""
        }
    }

    // MARK: - MFT parsing

    /// Parse the NTFS `$MFT` for every loaded evidence that doesn't already have
    /// results. `$MFT` is an ordinary file (record 0's `$DATA`), so it's extracted
    /// with the plain icat path that registry/SRUM use. The (large) byte parse runs
    /// off the main actor in a detached task (like USN). Yields both `$SI` and
    /// `$FN` MACB so the timestomp analyzer can compare them; spliced onto the
    /// timeline as the true NTFS file MACB. Mirrors `parseUsn`; does NOT run analyzers.
    func parseMft() async {
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
                !$0.isDirectory && $0.size > 0 && $0.name.lowercased() == "$mft"
            }
        }

        let totalCandidates = evidenceList.reduce(0) { acc, evidence in
            guard let state = states[evidence.id], state.mft.isEmpty else { return acc }
            return acc + candidates(state).count
        }
        guard totalCandidates > 0 else {
            statusMessage = "No new $MFT to parse."
            return
        }
        progress = ProgressInfo(current: 0, total: totalCandidates, label: "Parsing $MFT")
        var completed = 0

        do {
            let tskEnv = try TSKEnvironment.discover()

            for evidence in evidenceList {
                guard var state = states[evidence.id] else { continue }
                if !state.mft.isEmpty { continue }

                let found = candidates(state)
                guard !found.isEmpty else { continue }

                let isLoose = evidence.kind == .kapeLooseFolder
                var database: TSKDatabase?
                var extractor: TSKFileExtractor?
                var scratch: URL?
                if !isLoose {
                    guard let dbURL = state.dbURL else { continue }
                    database = try TSKDatabase(path: dbURL)
                    extractor = TSKFileExtractor(
                        environment: tskEnv,
                        imageURL: evidence.sourceURL,
                        imageType: TSKImageIngestor.imageType(for: evidence.sourceURL))
                    guard let bundleURL = currentCaseBundleURL else { continue }
                    let dir = CaseStore.mftScratchDirectory(forHostID: evidence.id, in: bundleURL)
                    try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
                    scratch = dir
                }

                var collected: [MftEntry] = []
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
                    } else {
                        guard let info = try database!.fetchExtractInfo(forFileID: entry.id) else {
                            completed += 1; continue
                        }
                        let outURL = scratch!.appendingPathComponent("\(entry.id)-MFT.bin")
                        do {
                            try await extractor!.extract(metaAddr: info.metaAddr,
                                                         imageOffsetSectors: info.imageOffsetSectors,
                                                         to: outURL)
                        } catch {
                            statusMessage = "\(evidence.displayName): $MFT extract failed (\(error.localizedDescription))"
                            completed += 1; continue
                        }
                        fileURL = outURL
                    }
                    // Read the (potentially large) $MFT and parse it off the main
                    // actor so the UI stays responsive. Scope `data` so the mapped
                    // region is released before the parse — it isn't held alongside
                    // the [UInt8] copy and the parser's own allocations.
                    let bytes: [UInt8]
                    if let data = try? Data(contentsOf: fileURL, options: .mappedIfSafe) {
                        bytes = [UInt8](data)
                    } else {
                        completed += 1; continue
                    }
                    let source = entry.fullPath
                    // Per-volume label so a multi-NTFS image (system + recovery)
                    // shows one tree per volume rather than merging identical paths.
                    let volLabel: String
                    if let fs = entry.fsID, let vi = state.volumes.first(where: { $0.id == fs }) {
                        volLabel = vi.label
                    } else if isLoose {
                        volLabel = "Collected $MFT"
                    } else if let fs = entry.fsID {
                        volLabel = "Volume \(fs)"
                    } else {
                        volLabel = "$MFT"
                    }
                    let parsed = await Task.detached(priority: .userInitiated) {
                        MftParser.parse(bytes: bytes, sourceFile: source, volume: volLabel)
                    }.value
                    collected.append(contentsOf: parsed)
                    completed += 1
                }

                collected.sort { $0.recordNumber < $1.recordNumber }
                state.mft = collected
                // Drop any prior MFT slice (paranoia for re-parses). Splice the $SI
                // MACB onto the timeline only for loose folders: an image's FS
                // source already carries those times from TSK, so adding them for
                // images would just double the (often millions of) rows.
                state.timeline.removeAll { $0.source == .mft }
                if isLoose {
                    state.timeline.append(contentsOf: TimelineBuilder.build(from: collected))
                    state.timeline.sort { $0.date < $1.date }
                }
                states[evidence.id] = state
                if let bundleURL = currentCaseBundleURL {
                    try? CaseStore.writeMft(collected, forHostID: evidence.id, in: bundleURL)
                }
            }
            progress = ProgressInfo(current: completed, total: totalCandidates,
                                    label: "$MFT parse complete")
        } catch {
            self.errorMessage = error.localizedDescription
            self.statusMessage = ""
        }
    }

    // MARK: - WMI persistence parsing

    /// Carve the WMI CIM repository (`OBJECTS.DATA`, under
    /// `\Windows\System32\wbem\Repository\`) for event-subscription persistence
    /// for every loaded evidence without results. An ordinary file, extracted with
    /// the plain icat path; the byte carve (`WmiRepositoryParser`) runs off the
    /// main actor. Mirrors `parseMft`; does NOT run analyzers or splice the timeline.
    func parseWmi() async {
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
                !$0.isDirectory && $0.size > 0 && $0.name.lowercased() == "objects.data"
            }
        }

        let totalCandidates = evidenceList.reduce(0) { acc, evidence in
            guard let state = states[evidence.id], state.wmi.isEmpty else { return acc }
            return acc + candidates(state).count
        }
        guard totalCandidates > 0 else {
            statusMessage = "No new WMI repository to parse."
            return
        }
        progress = ProgressInfo(current: 0, total: totalCandidates, label: "Parsing WMI repository")
        var completed = 0

        do {
            let tskEnv = try TSKEnvironment.discover()

            for evidence in evidenceList {
                guard var state = states[evidence.id] else { continue }
                if !state.wmi.isEmpty { continue }

                let found = candidates(state)
                guard !found.isEmpty else { continue }

                let isLoose = evidence.kind == .kapeLooseFolder
                var database: TSKDatabase?
                var extractor: TSKFileExtractor?
                var scratch: URL?
                if !isLoose {
                    guard let dbURL = state.dbURL else { continue }
                    database = try TSKDatabase(path: dbURL)
                    extractor = TSKFileExtractor(
                        environment: tskEnv,
                        imageURL: evidence.sourceURL,
                        imageType: TSKImageIngestor.imageType(for: evidence.sourceURL))
                    guard let bundleURL = currentCaseBundleURL else { continue }
                    let dir = CaseStore.wmiScratchDirectory(forHostID: evidence.id, in: bundleURL)
                    try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
                    scratch = dir
                }

                var collected: [WmiPersistenceEntry] = []
                for entry in found {
                    progress = ProgressInfo(current: completed, total: totalCandidates,
                                            label: "\(evidence.displayName): WMI repository")
                    let fileURL: URL
                    if isLoose {
                        guard let disk = entry.diskURL,
                              FileManager.default.fileExists(atPath: disk.path) else {
                            completed += 1; continue
                        }
                        fileURL = disk
                    } else {
                        guard let info = try database!.fetchExtractInfo(forFileID: entry.id) else {
                            completed += 1; continue
                        }
                        let outURL = scratch!.appendingPathComponent("\(entry.id)-OBJECTS.DATA")
                        do {
                            try await extractor!.extract(metaAddr: info.metaAddr,
                                                         imageOffsetSectors: info.imageOffsetSectors,
                                                         to: outURL)
                        } catch {
                            statusMessage = "\(evidence.displayName): OBJECTS.DATA extract failed (\(error.localizedDescription))"
                            completed += 1; continue
                        }
                        fileURL = outURL
                    }
                    // Carve the repository off the main actor (scope the mapped
                    // region so it isn't held alongside the [UInt8] copy).
                    let bytes: [UInt8]
                    if let data = try? Data(contentsOf: fileURL, options: .mappedIfSafe) {
                        bytes = [UInt8](data)
                    } else {
                        completed += 1; continue
                    }
                    let source = entry.fullPath
                    let parsed = await Task.detached(priority: .userInitiated) {
                        WmiRepositoryParser.parse(bytes: bytes, sourceFile: source)
                    }.value
                    collected.append(contentsOf: parsed)
                    completed += 1
                }

                state.wmi = collected
                states[evidence.id] = state
                if let bundleURL = currentCaseBundleURL {
                    try? CaseStore.writeWmi(collected, forHostID: evidence.id, in: bundleURL)
                }
            }
            progress = ProgressInfo(current: completed, total: totalCandidates,
                                    label: "WMI repository parse complete")
        } catch {
            self.errorMessage = error.localizedDescription
            self.statusMessage = ""
        }
    }

    // MARK: - Registry parsing

    /// Locate the standard Windows registry hives in each evidence's file
    /// system and parse them with regfexport - extracting with icat for image
    /// hosts, or reading the collected hive in place for loose folders.
    /// Findings are NOT regenerated here - call `runAnalyzers()` (or
    /// `parseArtifacts`) to surface results.
    func parseRegistry(force: Bool = false) async {
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

        // Pre-flight: an old case re-opened on a different machine often has
        // an evidence.sourceURL (image or loose folder) that no longer
        // resolves. Extraction would just fail silently per hive; surface it
        // up front instead.
        // Hives discovered for an evidence that still need parsing: every
        // standard hive on a first run, or - on a re-run - only those whose
        // label isn't already represented in the parsed values. This lets a case
        // whose registry was parsed *before* a hive (notably Amcache.hve) was
        // captured pick that hive up on a later "Parse artifacts" instead of
        // being permanently skipped by a coarse "registry already parsed" guard.
        func pendingHives(_ id: UUID) -> [HiveCandidate] {
            guard let state = states[id] else { return [] }
            let all = Self.discoverHives(in: state.files)
            guard !force else { return all }
            let present = Set(state.registryValues.map(\.hive))
            return all.filter { !present.contains($0.label) }
        }
        let candidates = evidenceList.filter { !pendingHives($0.id).isEmpty }
        let missingSources = candidates.filter {
            !FileManager.default.fileExists(atPath: $0.sourceURL.path)
        }
        if !missingSources.isEmpty, missingSources.count == candidates.count {
            errorMessage = "Source not found: \(missingSources[0].sourceURL.path). Re-add the host or restore the source to its original path."
            return
        }

        let totalCandidates = evidenceList.reduce(0) { $0 + pendingHives($1.id).count }
        guard totalCandidates > 0 else {
            statusMessage = force
                ? "No registry hives discovered in the file system."
                : "No new registry hives to parse."
            return
        }
        progress = ProgressInfo(current: 0, total: totalCandidates, label: "Parsing registry hives")
        var completed = 0

        do {
            let tskEnv = try TSKEnvironment.discover()
            let regEnv = try RegistryEnvironment.discover()
            let parser = RegistryHiveParser(environment: regEnv)

            var hostsTouched = 0
            var hostsCollected = 0
            var amcacheReadButEmpty = false
            for evidence in evidenceList {
                guard var state = states[evidence.id] else { continue }

                // Only the hives not already represented in registryValues (all
                // of them when `force`). A fully-parsed host yields an empty list
                // and is skipped; a host missing just Amcache re-parses just that.
                let candidates = pendingHives(evidence.id)
                guard !candidates.isEmpty else { continue }

                guard FileManager.default.fileExists(atPath: evidence.sourceURL.path) else {
                    statusMessage = "\(evidence.displayName): source missing at \(evidence.sourceURL.path)"
                    completed += candidates.count
                    continue
                }
                hostsTouched += 1

                // Image hosts extract each hive from the image with icat into a
                // scratch dir; loose folders parse the collected hive in place.
                let isLoose = evidence.kind == .kapeLooseFolder
                var database: TSKDatabase?
                var extractor: TSKFileExtractor?
                var scratch: URL?
                if !isLoose {
                    guard let dbURL = state.dbURL else { continue }
                    database = try TSKDatabase(path: dbURL)
                    extractor = TSKFileExtractor(
                        environment: tskEnv,
                        imageURL: evidence.sourceURL,
                        imageType: TSKImageIngestor.imageType(for: evidence.sourceURL))
                    guard let bundleURL = currentCaseBundleURL else { continue }
                    let dir = CaseStore.registryScratchDirectory(forHostID: evidence.id, in: bundleURL)
                    try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
                    scratch = dir
                }

                // Keep the values already parsed (so a re-run that only fills in
                // a previously-missing hive doesn't drop the rest); `force`
                // re-parses every hive from scratch.
                var collected: [RegistryValue] = force ? [] : state.registryValues
                let baselineValueCount = collected.count   // values carried in from prior runs
                for candidate in candidates {
                    progress = ProgressInfo(
                        current: completed,
                        total: totalCandidates,
                        label: "\(evidence.displayName): \(candidate.label)")
                    // Resolve the hive to a readable path.
                    let hiveURL: URL
                    if isLoose {
                        guard let disk = candidate.entry.diskURL,
                              FileManager.default.fileExists(atPath: disk.path) else {
                            completed += 1; continue
                        }
                        hiveURL = disk
                    } else {
                        guard let info = try database!.fetchExtractInfo(forFileID: candidate.entry.id) else {
                            completed += 1; continue
                        }
                        let outURL = scratch!.appendingPathComponent("\(candidate.entry.id)-\(candidate.entry.name)")
                        do {
                            try await extractor!.extract(metaAddr: info.metaAddr,
                                                         imageOffsetSectors: info.imageOffsetSectors,
                                                         to: outURL)
                        } catch {
                            statusMessage = "\(evidence.displayName): \(candidate.label) failed (\(error.localizedDescription))"
                            completed += 1; continue
                        }
                        hiveURL = outURL
                    }
                    do {
                        let values = try await parser.parse(hiveAt: hiveURL, hiveLabel: candidate.label)
                        collected.append(contentsOf: values)
                    } catch {
                        // A locked / corrupt hive shouldn't kill the whole
                        // run - log and continue. Common for SAM / SECURITY
                        // which are ACL'd and may produce odd output.
                        statusMessage = "\(evidence.displayName): \(candidate.label) failed (\(error.localizedDescription))"
                    }
                    completed += 1
                }
                state.registryValues = collected
                // Reconstruct Amcache entries from the AMCACHE-tagged values
                // (pure; no extra extraction). Shimcache is derived the same way
                // from the SYSTEM AppCompatCache blob.
                let amcache = AmcacheEntry.reconstruct(from: collected)
                state.amcache = amcache
                // Note the silent "hive read but nothing came back" case so an
                // empty Amcache tab isn't indistinguishable from "never parsed";
                // surfaced once after the loop (a mid-loop statusMessage would be
                // clobbered by the next parser in the parseArtifacts chain).
                if candidates.contains(where: { $0.label == "AMCACHE" }), amcache.isEmpty {
                    amcacheReadButEmpty = true
                }
                let shimcache = ShimcacheParser.fromRegistry(collected)
                state.shimcache = shimcache
                // Drop any prior registry-derived slices (paranoia for
                // re-parses) and splice key-write / amcache / shimcache times
                // back onto the timeline (mirrors the evtx splice).
                state.timeline.removeAll {
                    $0.source == .registry || $0.source == .amcache || $0.source == .shimcache
                }
                state.timeline.append(contentsOf: TimelineBuilder.build(from: collected))
                state.timeline.append(contentsOf: TimelineBuilder.build(from: amcache))
                state.timeline.append(contentsOf: TimelineBuilder.build(from: shimcache))
                state.timeline.sort { $0.date < $1.date }
                states[evidence.id] = state
                if let bundleURL = currentCaseBundleURL {
                    try? CaseStore.writeRegistry(collected, forHostID: evidence.id, in: bundleURL)
                    try? CaseStore.writeAmcache(amcache, forHostID: evidence.id, in: bundleURL)
                    try? CaseStore.writeShimcache(shimcache, forHostID: evidence.id, in: bundleURL)
                }
                // Count the host only if THIS run gained values (not the ones
                // carried in from a prior run), so an all-failed partial re-run
                // still trips the louder aggregate error below.
                if collected.count > baselineValueCount { hostsCollected += 1 }
            }
            progress = ProgressInfo(current: completed, total: totalCandidates,
                                    label: "Registry parse complete")
            // If every host we tried extracted nothing, the user's silent-no-op
            // experience needs a louder signal than the flickering statusMessage.
            if hostsTouched > 0, hostsCollected == 0 {
                errorMessage = "Registry parse extracted no values - check that sources are accessible and hives aren't locked."
            } else if amcacheReadButEmpty {
                errorMessage = "Amcache.hve was read but produced no entries - it may be from an unsupported Windows build or be corrupt."
            }
        } catch {
            self.errorMessage = error.localizedDescription
            self.statusMessage = ""
        }
    }

    private struct HiveCandidate {
        let entry: FileEntry
        let label: String   // "SYSTEM", "NTUSER (jdoe)", ...
    }

    /// Standard hive locations on a Windows install. Per-user NTUSER.DAT and
    /// UsrClass.dat get tagged with the owning user's name so analyzers can
    /// attribute findings.
    private static func discoverHives(in files: [FileEntry]) -> [HiveCandidate] {
        var out: [HiveCandidate] = []
        for entry in files where !entry.isDeleted && !entry.isDirectory && entry.size > 0 {
            let upperName = entry.name.uppercased()
            let lowerPath = entry.fullPath.lowercased()
            if lowerPath.hasSuffix("/windows/system32/config/system") {
                out.append(.init(entry: entry, label: "SYSTEM"))
            } else if lowerPath.hasSuffix("/windows/system32/config/software") {
                out.append(.init(entry: entry, label: "SOFTWARE"))
            } else if lowerPath.hasSuffix("/windows/system32/config/sam") {
                out.append(.init(entry: entry, label: "SAM"))
            } else if lowerPath.hasSuffix("/windows/system32/config/security") {
                out.append(.init(entry: entry, label: "SECURITY"))
            } else if lowerPath.hasSuffix("/windows/system32/config/default") {
                out.append(.init(entry: entry, label: "DEFAULT"))
            } else if upperName == "NTUSER.DAT", let user = extractUser(from: entry.fullPath) {
                out.append(.init(entry: entry, label: "NTUSER (\(user))"))
            } else if upperName == "USRCLASS.DAT", let user = extractUser(from: entry.fullPath) {
                out.append(.init(entry: entry, label: "USRCLASS (\(user))"))
            } else if upperName == "AMCACHE.HVE"
                        || lowerPath.hasSuffix("/windows/appcompat/programs/amcache.hve") {
                // Amcache rides the same regfexport pipeline; its values are
                // tagged AMCACHE and reconstructed into AmcacheEntry after parse.
                // Matched by filename too (it's distinctive) so non-standard
                // collection layouts still find it.
                out.append(.init(entry: entry, label: "AMCACHE"))
            }
        }
        // The broadened (by-filename) Amcache match can surface the canonical
        // hive *and* a stray/backup copy, which would merge under one "AMCACHE"
        // label and double-count entries. Keep a single candidate, preferring the
        // one at the canonical AppCompat\Programs path.
        let amcacheHits = out.filter { $0.label == "AMCACHE" }
        if amcacheHits.count > 1 {
            out.removeAll { $0.label == "AMCACHE" }
            let canonical = amcacheHits.first {
                $0.entry.fullPath.lowercased().hasSuffix("/windows/appcompat/programs/amcache.hve")
            }
            out.append(canonical ?? amcacheHits[0])
        }
        return out
    }

    /// Extract `<user>` from paths like "/Users/<user>/NTUSER.DAT" or
    /// "/Users/<user>/AppData/Local/Microsoft/Windows/UsrClass.dat".
    private static func extractUser(from path: String) -> String? {
        let parts = path.split(separator: "/").map(String.init)
        guard let usersIdx = parts.firstIndex(where: { $0.lowercased() == "users" }),
              usersIdx + 1 < parts.count else { return nil }
        return parts[usersIdx + 1]
    }

    // MARK: - Prefetch parsing

    /// Parse every `.pf` under `\Windows\Prefetch\` in every loaded evidence
    /// that doesn't already have prefetch - extracting with icat for image
    /// hosts, or reading the collected file in place for loose folders. Each
    /// `.pf` yields one `PrefetchEntry`. Does NOT run analyzers; use
    /// `parseArtifacts()` for the full pipeline.
    func parsePrefetch() async {
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
                $0.fileExtension == "pf" && !$0.isDirectory && !$0.isDeleted && $0.size > 0
                    && $0.fullPath.lowercased().contains("/prefetch/")
            }
        }

        let totalCandidates = evidenceList.reduce(0) { acc, evidence in
            guard let state = states[evidence.id], state.prefetch.isEmpty else { return acc }
            return acc + candidates(state).count
        }
        guard totalCandidates > 0 else {
            statusMessage = "No new prefetch files to parse."
            return
        }
        progress = ProgressInfo(current: 0, total: totalCandidates, label: "Parsing prefetch")
        var completed = 0

        do {
            let tskEnv = try TSKEnvironment.discover()
            let prefetchEnv = try PrefetchEnvironment.discover()
            let parser = PrefetchParser(environment: prefetchEnv)

            for evidence in evidenceList {
                guard var state = states[evidence.id] else { continue }
                if !state.prefetch.isEmpty { continue }

                let found = candidates(state)
                guard !found.isEmpty else { continue }

                // Image hosts need TSK to pull each .pf out of the image;
                // loose folders read the file in place, so skip all of that.
                let isLoose = evidence.kind == .kapeLooseFolder
                var database: TSKDatabase?
                var extractor: TSKFileExtractor?
                var scratch: URL?
                if !isLoose {
                    guard let dbURL = state.dbURL else { continue }
                    database = try TSKDatabase(path: dbURL)
                    extractor = TSKFileExtractor(
                        environment: tskEnv,
                        imageURL: evidence.sourceURL,
                        imageType: TSKImageIngestor.imageType(for: evidence.sourceURL))
                    guard let bundleURL = currentCaseBundleURL else { continue }
                    let dir = CaseStore.prefetchScratchDirectory(forHostID: evidence.id, in: bundleURL)
                    try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
                    scratch = dir
                }

                var collected: [PrefetchEntry] = []
                for entry in found {
                    progress = ProgressInfo(
                        current: completed,
                        total: totalCandidates,
                        label: "\(evidence.displayName): \(entry.name)")
                    let fileURL: URL
                    if isLoose {
                        guard let disk = entry.diskURL,
                              FileManager.default.fileExists(atPath: disk.path) else {
                            completed += 1; continue
                        }
                        fileURL = disk
                    } else {
                        guard let info = try database!.fetchExtractInfo(forFileID: entry.id) else {
                            completed += 1; continue
                        }
                        let outURL = scratch!.appendingPathComponent("\(entry.id)-\(entry.name)")
                        try await extractor!.extract(metaAddr: info.metaAddr,
                                                     imageOffsetSectors: info.imageOffsetSectors,
                                                     to: outURL)
                        fileURL = outURL
                    }
                    // A malformed .pf shouldn't abort the whole run.
                    if let parsed = try? await parser.parse(fileAt: fileURL) {
                        collected.append(parsed)
                    }
                    completed += 1
                }
                // Most-recent execution first.
                collected.sort { ($0.lastRun ?? .distantPast) > ($1.lastRun ?? .distantPast) }
                state.prefetch = collected
                // Splice recorded run times onto the timeline (mirrors evtx).
                state.timeline.removeAll { $0.source == .prefetch }
                state.timeline.append(contentsOf: TimelineBuilder.build(from: collected))
                state.timeline.sort { $0.date < $1.date }
                states[evidence.id] = state
                if let bundleURL = currentCaseBundleURL {
                    try? CaseStore.writePrefetch(collected, forHostID: evidence.id, in: bundleURL)
                }
            }
            progress = ProgressInfo(current: completed, total: totalCandidates,
                                    label: "Prefetch parse complete")
        } catch {
            self.errorMessage = error.localizedDescription
            self.statusMessage = ""
        }
    }

    // MARK: - Linux artifact parsing

    /// Parse the Linux triage artifacts in every loaded evidence that doesn't
    /// already have them: auth logs (`auth.log`/`secure`), wtmp/btmp login
    /// records, per-user shell history, cron + systemd persistence, and the
    /// host-info files (os-release / hostname / passwd / timezone). All
    /// parsers are pure Swift (text or fixed-layout binary - no vendored
    /// tool); extraction mirrors `parsePrefetch` (icat for images, in-place
    /// for loose folders, e.g. a UAC collection). A Windows host has no
    /// candidates and is skipped silently, so this is safe in the standard
    /// `parseArtifacts` chain. Does NOT run analyzers.
    func parseLinux() async {
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

        enum LinuxKind {
            case auth, utmp, shellHistory, cron, systemd, sysinfo
            case sshAuthorized, sshKnown, sshdConfig, sudoers, group, shadow
            case webAccess
            case systemdTimer, initScript, shellInit, xdgAutostart, ldPreload
            case packageDpkg, packageApt, packageYum, packageDnf
        }

        func classify(_ entry: FileEntry) -> LinuxKind? {
            guard !entry.isDirectory, !entry.isDeleted, entry.size > 0 else { return nil }
            let path = entry.fullPath.lowercased()
            let name = entry.name.lowercased()
            let isGz = name.hasSuffix(".gz")
            if path.contains("/var/log/") {
                // auth.log / secure incl. rotations (auth.log.2.gz) - the gz is
                // decompressed in the handler. Other .gz logs aren't parsed here.
                if name.hasPrefix("auth.log") || name.hasPrefix("secure") {
                    return .auth
                }
                if !isGz, name == "wtmp" || name == "btmp"
                    || name.hasPrefix("wtmp.") || name.hasPrefix("btmp.") {
                    return .utmp
                }
                // nginx/apache access logs (incl. .gz rotations + vhost-named
                // *access*.log) under their server dirs.
                if name.contains("access"), name.contains(".log"),
                   path.contains("/nginx/") || path.contains("/apache2/")
                    || path.contains("/httpd/") {
                    return .webAccess
                }
                // Package-manager logs (incl. .gz rotations).
                if name.hasPrefix("dpkg.log") { return .packageDpkg }
                if path.contains("/apt/") && name.hasPrefix("history.log") { return .packageApt }
                if name.hasPrefix("yum.log") { return .packageYum }
                if name.hasPrefix("dnf.rpm.log") { return .packageDnf }
            }
            if isGz { return nil }   // only specific rotations are read compressed
            // Persistence: systemd timers (anywhere under systemd dirs incl. user units).
            if entry.fileExtension == "timer",
               path.contains("/systemd/system") || path.contains("/.config/systemd/") {
                return .systemdTimer
            }
            // User systemd service units (system .service handled below).
            if entry.fileExtension == "service", path.contains("/.config/systemd/") {
                return .systemd
            }
            if path.hasSuffix("/etc/ld.so.preload") { return .ldPreload }
            if path.hasSuffix("/.config/autostart") == false, name.hasSuffix(".desktop"),
               path.contains("/autostart/") {
                return .xdgAutostart
            }
            // Boot / periodic shell scripts.
            if path.hasSuffix("/etc/rc.local") || path.contains("/etc/init.d/")
                || path.contains("/etc/cron.hourly/") || path.contains("/etc/cron.daily/")
                || path.contains("/etc/cron.weekly/") || path.contains("/etc/cron.monthly/") {
                return .initScript
            }
            // Shell-init files (exec-line filtered in the handler).
            if name == ".bashrc" || name == ".bash_profile" || name == ".profile"
                || name == ".bash_login" || path.contains("/etc/profile.d/")
                || path.hasSuffix("/etc/bash.bashrc") || path.hasSuffix("/etc/profile") {
                return .shellInit
            }
            if name == ".bash_history" || name == ".zsh_history" {
                return .shellHistory
            }
            // SSH trust artifacts.
            if name == "authorized_keys" || name == "authorized_keys2" {
                return .sshAuthorized
            }
            if name == "known_hosts" || path.hasSuffix("/etc/ssh/ssh_known_hosts") {
                return .sshKnown
            }
            if path.hasSuffix("/etc/ssh/sshd_config") { return .sshdConfig }
            // Privilege.
            if path.hasSuffix("/etc/sudoers") || path.contains("/etc/sudoers.d/") {
                return .sudoers
            }
            if path.hasSuffix("/etc/group") { return .group }
            if path.hasSuffix("/etc/shadow") { return .shadow }
            if path.hasSuffix("/etc/crontab") || path.contains("/etc/cron.d/")
                || path.contains("/var/spool/cron") {
                return .cron
            }
            if entry.fileExtension == "service", path.contains("/etc/systemd/system") {
                return .systemd
            }
            if path.hasSuffix("/etc/os-release") || path.hasSuffix("/usr/lib/os-release")
                || path.hasSuffix("/etc/hostname") || path.hasSuffix("/etc/passwd")
                || path.hasSuffix("/etc/timezone") {
                return .sysinfo
            }
            return nil
        }

        func candidates(_ state: EvidenceState) -> [(FileEntry, LinuxKind)] {
            state.files.compactMap { entry in classify(entry).map { (entry, $0) } }
        }

        let totalCandidates = evidenceList.reduce(0) { acc, evidence in
            guard let state = states[evidence.id], !state.hasLinuxArtifacts else { return acc }
            return acc + candidates(state).count
        }
        guard totalCandidates > 0 else {
            statusMessage = "No new Linux artifacts to parse."
            return
        }
        progress = ProgressInfo(current: 0, total: totalCandidates, label: "Parsing Linux artifacts")
        var completed = 0

        do {
            let tskEnv = try TSKEnvironment.discover()

            for evidence in evidenceList {
                guard var state = states[evidence.id] else { continue }
                if state.hasLinuxArtifacts { continue }
                let found = candidates(state)
                guard !found.isEmpty else { continue }

                // Image hosts need TSK to pull each file out of the image;
                // loose folders read the file in place.
                let isLoose = evidence.kind == .kapeLooseFolder
                var database: TSKDatabase?
                var extractor: TSKFileExtractor?
                var scratch: URL?
                if !isLoose {
                    guard let dbURL = state.dbURL else { continue }
                    database = try TSKDatabase(path: dbURL)
                    extractor = TSKFileExtractor(
                        environment: tskEnv,
                        imageURL: evidence.sourceURL,
                        imageType: TSKImageIngestor.imageType(for: evidence.sourceURL))
                    guard let bundleURL = currentCaseBundleURL else { continue }
                    let dir = CaseStore.linuxScratchDirectory(forHostID: evidence.id, in: bundleURL)
                    try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
                    scratch = dir
                }

                var authLog: [AuthLogEntry] = []
                var logins: [UtmpRecord] = []
                var shellHistory: [ShellHistoryEntry] = []
                var persistence: [LinuxPersistenceEntry] = []
                var info = LinuxHostInfo()
                var access = LinuxAccessInfo()
                var web: [WebAccessLogEntry] = []
                var packages: [PackageEvent] = []

                for (entry, kind) in found {
                    progress = ProgressInfo(
                        current: completed,
                        total: totalCandidates,
                        label: "\(evidence.displayName): \(entry.name)")
                    defer { completed += 1 }

                    let fileURL: URL
                    if isLoose {
                        guard let disk = entry.diskURL,
                              FileManager.default.fileExists(atPath: disk.path) else { continue }
                        fileURL = disk
                    } else {
                        guard let extractInfo = try database!.fetchExtractInfo(forFileID: entry.id) else {
                            continue
                        }
                        let outURL = scratch!.appendingPathComponent("\(entry.id)-\(entry.name)")
                        try await extractor!.extract(metaAddr: extractInfo.metaAddr,
                                                     imageOffsetSectors: extractInfo.imageOffsetSectors,
                                                     to: outURL)
                        fileURL = outURL
                    }
                    // A malformed file shouldn't abort the whole run.
                    guard let rawData = try? Data(contentsOf: fileURL) else { continue }
                    // Transparently gunzip rotated auth logs (auth.log.2.gz).
                    let data: Data = entry.name.lowercased().hasSuffix(".gz")
                        ? ((try? GzipDecoder.decompress(rawData)) ?? rawData)
                        : rawData
                    func text() -> String { String(decoding: data, as: UTF8.self) }
                    let owner = ShellHistoryParser.user(fromPath: entry.fullPath)

                    switch kind {
                    case .utmp:
                        let isBtmp = entry.name.lowercased().hasPrefix("btmp")
                        logins.append(contentsOf: UtmpParser.parse(
                            data: data, sourceFile: entry.fullPath, isFailedLogin: isBtmp))
                    case .auth:
                        authLog.append(contentsOf: AuthLogParser.parse(
                            text: text(),
                            sourceFile: entry.fullPath,
                            anchor: entry.modified))
                    case .shellHistory:
                        let shell: ShellHistoryEntry.Shell =
                            entry.name.lowercased().contains("zsh") ? .zsh : .bash
                        shellHistory.append(contentsOf: ShellHistoryParser.parse(
                            text: String(decoding: data, as: UTF8.self),
                            user: ShellHistoryParser.user(fromPath: entry.fullPath),
                            shell: shell, sourceFile: entry.fullPath))
                    case .cron:
                        let isSpool = entry.fullPath.lowercased().contains("/var/spool/cron")
                        persistence.append(contentsOf: LinuxPersistenceParser.parseCrontab(
                            text: String(decoding: data, as: UTF8.self),
                            sourceFile: entry.fullPath,
                            hasUserField: !isSpool,
                            defaultUser: isSpool ? entry.name : nil))
                    case .systemdTimer:
                        if let timer = LinuxPersistenceParser.parseSystemdTimer(
                            text: text(), sourceFile: entry.fullPath) {
                            persistence.append(timer)
                        }
                    case .ldPreload:
                        persistence.append(contentsOf: LinuxPersistenceParser.parseLdPreload(
                            text: text(), sourceFile: entry.fullPath))
                    case .xdgAutostart:
                        if let auto = LinuxPersistenceParser.parseAutostart(
                            text: text(), sourceFile: entry.fullPath) {
                            persistence.append(auto)
                        }
                    case .initScript:
                        persistence.append(contentsOf: LinuxPersistenceParser.parseScript(
                            text: text(), kind: .initScript, sourceFile: entry.fullPath,
                            suspiciousOnly: false))
                    case .shellInit:
                        persistence.append(contentsOf: LinuxPersistenceParser.parseScript(
                            text: text(), kind: .shellInit, sourceFile: entry.fullPath,
                            user: owner, suspiciousOnly: true))
                    case .packageDpkg:
                        packages.append(contentsOf: PackageParser.parseDpkgLog(
                            text: text(), sourceFile: entry.fullPath))
                    case .packageApt:
                        packages.append(contentsOf: PackageParser.parseAptHistory(
                            text: text(), sourceFile: entry.fullPath))
                    case .packageYum:
                        packages.append(contentsOf: PackageParser.parseYumLog(
                            text: text(), sourceFile: entry.fullPath, anchor: entry.modified, manager: .yum))
                    case .packageDnf:
                        packages.append(contentsOf: PackageParser.parseYumLog(
                            text: text(), sourceFile: entry.fullPath, anchor: entry.modified, manager: .dnf))
                    case .systemd:
                        if let unit = LinuxPersistenceParser.parseSystemdUnit(
                            text: String(decoding: data, as: UTF8.self),
                            sourceFile: entry.fullPath) {
                            persistence.append(unit)
                        }
                    case .sysinfo:
                        let body = text()
                        let path = entry.fullPath.lowercased()
                        if path.hasSuffix("os-release") {
                            LinuxHostInfoParser.applyOSRelease(body, to: &info)
                        } else if path.hasSuffix("hostname") {
                            LinuxHostInfoParser.applyHostname(body, to: &info)
                        } else if path.hasSuffix("passwd") {
                            LinuxHostInfoParser.applyPasswd(body, to: &info)
                        } else if path.hasSuffix("timezone") {
                            LinuxHostInfoParser.applyTimezone(body, to: &info)
                        }
                    case .sshAuthorized:
                        access.sshKeys.append(contentsOf: LinuxAccessParser.parseAuthorizedKeys(
                            text: text(), user: owner, sourceFile: entry.fullPath))
                    case .sshKnown:
                        access.sshKeys.append(contentsOf: LinuxAccessParser.parseKnownHosts(
                            text: text(), user: owner, sourceFile: entry.fullPath))
                    case .sshdConfig:
                        access.sshdSettings.merge(LinuxAccessParser.parseSSHDConfig(text: text())) { _, new in new }
                        access.sshdSourceFile = entry.fullPath
                    case .sudoers:
                        access.sudoRules.append(contentsOf: LinuxAccessParser.parseSudoers(
                            text: text(), sourceFile: entry.fullPath))
                    case .group:
                        access.groups = LinuxAccessParser.parseGroup(text: text())
                    case .shadow:
                        access.shadow = LinuxAccessParser.parseShadow(text: text())
                    case .webAccess:
                        let server: WebAccessLogEntry.Server =
                            entry.fullPath.lowercased().contains("/nginx/") ? .nginx
                            : (entry.fullPath.lowercased().contains("/apache2/")
                               || entry.fullPath.lowercased().contains("/httpd/")) ? .apache
                            : .unknown
                        web.append(contentsOf: WebLogParser.parseAccess(
                            text: text(), sourceFile: entry.fullPath, server: server))
                    }
                }

                // Newest-first for the list views; shell history keeps file +
                // line order (undated bash entries have no clock to sort by).
                authLog.sort { ($0.timestamp ?? .distantPast) > ($1.timestamp ?? .distantPast) }
                logins.sort { ($0.timestamp ?? .distantPast) > ($1.timestamp ?? .distantPast) }

                state.authLog = authLog
                state.logins = logins
                state.shellHistory = shellHistory
                web.sort { ($0.timestamp ?? .distantPast) > ($1.timestamp ?? .distantPast) }
                packages.sort { ($0.timestamp ?? .distantPast) > ($1.timestamp ?? .distantPast) }
                state.linuxPersistence = persistence
                state.linuxInfo = info.isEmpty ? nil : info
                state.linuxAccess = access.isEmpty ? nil : access
                state.webAccess = web
                state.packages = packages
                // Splice the timestamped Linux sources onto the timeline
                // (mirrors evtx; persistence entries carry no timestamps).
                state.timeline.removeAll {
                    $0.source == .authlog || $0.source == .logins
                        || $0.source == .shellHistory || $0.source == .weblog
                        || $0.source == .package
                }
                state.timeline.append(contentsOf: TimelineBuilder.build(from: authLog))
                state.timeline.append(contentsOf: TimelineBuilder.build(from: logins))
                state.timeline.append(contentsOf: TimelineBuilder.build(from: shellHistory))
                state.timeline.append(contentsOf: TimelineBuilder.build(from: web))
                state.timeline.append(contentsOf: TimelineBuilder.build(from: packages))
                state.timeline.sort { $0.date < $1.date }
                states[evidence.id] = state
                if let bundleURL = currentCaseBundleURL {
                    try? CaseStore.writeAuthLog(authLog, forHostID: evidence.id, in: bundleURL)
                    try? CaseStore.writeLogins(logins, forHostID: evidence.id, in: bundleURL)
                    try? CaseStore.writeShellHistory(shellHistory, forHostID: evidence.id, in: bundleURL)
                    try? CaseStore.writeLinuxPersistence(persistence, forHostID: evidence.id, in: bundleURL)
                    if let linuxInfo = state.linuxInfo {
                        try? CaseStore.writeLinuxInfo(linuxInfo, forHostID: evidence.id, in: bundleURL)
                    }
                    if let linuxAccess = state.linuxAccess {
                        try? CaseStore.writeLinuxAccess(linuxAccess, forHostID: evidence.id, in: bundleURL)
                    }
                    try? CaseStore.writeWebAccess(web, forHostID: evidence.id, in: bundleURL)
                    try? CaseStore.writePackages(packages, forHostID: evidence.id, in: bundleURL)
                }
            }
            progress = ProgressInfo(current: completed, total: totalCandidates,
                                    label: "Linux artifact parse complete")
        } catch {
            self.errorMessage = error.localizedDescription
            self.statusMessage = ""
        }
    }

    #endif

    // MARK: - Analysis

    /// Run analyzers against each evidence's own context, then store the
    /// findings on that evidence. "All" mode unions the per-evidence buckets
    /// via the computed `findings` property.
    func runAnalyzers() async {
        statusMessage = "Running analyzers..."
        var total = 0
        for evidence in evidenceList {
            guard var state = states[evidence.id] else { continue }
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
                                          packages: state.packages)
            let results = await analysisEngine.run(on: context)
            state.findings = results
            states[evidence.id] = state
            if let bundleURL = currentCaseBundleURL {
                try? CaseStore.writeFindings(results, forHostID: evidence.id, in: bundleURL)
            }
            total += results.count
        }
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
        appendCustody(.analysed,
                      detail: "Ran detection analyzers across \(evidenceList.count) host\(evidenceList.count == 1 ? "" : "s") → \(total) finding\(total == 1 ? "" : "s").")
    }
}
