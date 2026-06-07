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
    var findings: [Finding] = []
    var iocMatches: [IOCMatch] = []
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

            // Case-wide indicators + custody ledger, also decoded off-main.
            let caseWide = await Task.detached(priority: .userInitiated) {
                (iocs: (try? CaseStore.readIOCs(in: bundleURL)) ?? [],
                 custody: (try? CaseStore.readCustody(in: bundleURL)) ?? [])
            }.value
            iocs = caseWide.iocs
            custodyLog = caseWide.custody

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
            state.findings = (try? CaseStore.readFindings(forHostID: evidence.id, in: bundleURL)) ?? []
            state.iocMatches = (try? CaseStore.readIOCMatches(forHostID: evidence.id, in: bundleURL)) ?? []
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
                sourceHashes: evidence.sourceHashes)
        }
        let now = Date()
        // Custody log is case-wide; include the entries for the selected hosts
        // plus case-level (nil-evidence) events.
        let selectedIDs = Set(selectedHosts.map(\.id))
        let custodyForExport = custodyLog.filter { $0.evidenceID == nil || selectedIDs.contains($0.evidenceID!) }
        let inputs = ReportInputs(caseName: theCase.name, examiner: theCase.examiner,
                                  createdAt: theCase.createdAt, generatedAt: now,
                                  hosts: hosts, custodyLog: custodyForExport)

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
            d.iocMatches.append(contentsOf: s.iocMatches)
        }
        d.events.sort { $0.writtenAt < $1.writtenAt }
        d.timeline.sort { $0.date < $1.date }
        d.findings.sort { $0.severity > $1.severity }
        d.prefetch.sort { ($0.lastRun ?? .distantPast) > ($1.lastRun ?? .distantPast) }
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
    var iocMatches: [IOCMatch] { derived().iocMatches }

    // Count-only accessors: sum per-host counts without building or sorting the
    // rolled-up arrays. For stat tiles / titles that only need a number.
    var fileCount: Int { scopedCount(\.files.count) }
    var eventCount: Int { scopedCount(\.events.count) }
    var timelineCount: Int { scopedCount(\.timeline.count) }
    var findingCount: Int { scopedCount(\.findings.count) }
    var registryValueCount: Int { scopedCount(\.registryValues.count) }
    var prefetchCount: Int { scopedCount(\.prefetch.count) }
    var iocMatchCount: Int { scopedCount(\.iocMatches.count) }

    private func scopedCount(_ kp: KeyPath<EvidenceState, Int>) -> Int {
        if let id = activeEvidenceID { return states[id]?[keyPath: kp] ?? 0 }
        return evidenceList.reduce(0) { $0 + (states[$1.id]?[keyPath: kp] ?? 0) }
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

            let state: EvidenceState
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

    /// One-stop button: parse event logs, registry hives, and prefetch, then
    /// run the detection engine over the combined evidence.
    func parseArtifacts() async {
        await parseEventLogs()
        await parseRegistry()
        await parsePrefetch()
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
        let candidates = evidenceList.filter { evidence in
            guard let state = states[evidence.id] else { return false }
            return force || state.registryValues.isEmpty
        }
        let missingSources = candidates.filter {
            !FileManager.default.fileExists(atPath: $0.sourceURL.path)
        }
        if !missingSources.isEmpty, missingSources.count == candidates.count {
            errorMessage = "Source not found: \(missingSources[0].sourceURL.path). Re-add the host or restore the source to its original path."
            return
        }

        let totalCandidates = candidates.reduce(0) { acc, evidence in
            guard let state = states[evidence.id] else { return acc }
            return acc + Self.discoverHives(in: state.files).count
        }
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
            for evidence in evidenceList {
                guard var state = states[evidence.id] else { continue }
                if !force, !state.registryValues.isEmpty { continue }

                let candidates = Self.discoverHives(in: state.files)
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

                var collected: [RegistryValue] = []
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
                states[evidence.id] = state
                if let bundleURL = currentCaseBundleURL {
                    try? CaseStore.writeRegistry(collected, forHostID: evidence.id, in: bundleURL)
                }
                if !collected.isEmpty { hostsCollected += 1 }
            }
            progress = ProgressInfo(current: completed, total: totalCandidates,
                                    label: "Registry parse complete")
            // If every host we tried extracted nothing, the user's silent-no-op
            // experience needs a louder signal than the flickering statusMessage.
            if hostsTouched > 0, hostsCollected == 0 {
                errorMessage = "Registry parse extracted no values - check that sources are accessible and hives aren't locked."
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
            }
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
                                          prefetch: state.prefetch)
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
