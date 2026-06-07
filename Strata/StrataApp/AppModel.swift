import Foundation
import SwiftUI
import Combine

/// Per-evidence working set. One of these exists for every `Evidence` the
/// user has ingested in the current session. AppModel composes views across
/// any subset.
struct EvidenceState {
    /// TSK SQLite location, or nil for loose-folder hosts that have no image
    /// to back a TSK database - their files are read straight off disk.
    var dbURL: URL?
    var files: [FileEntry] = []
    var volumes: [VolumeInfo] = []   // filesystems in the image (empty for loose folders)
    var events: [EventLogRecord] = []
    var timeline: [TimelineEvent] = []
    var registryValues: [RegistryValue] = []
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

    enum ActiveSheet: Identifiable {
        case newCase
        case enrichment
        case export
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
            activeEvidenceID = nil
            statusMessage = "Created case '\(name)'."
        } catch {
            errorMessage = "Failed to create case: \(error.localizedDescription)"
        }
    }

    /// Open an existing bundle and rehydrate per-host state. Event-log and
    /// registry parsing are NOT replayed - the user clicks Parse on the
    /// Events / Overview screen to do that. File listings (cheap SQLite
    /// reads) are loaded immediately so the Evidence and Timeline tabs
    /// aren't empty.
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
            // iOS memory is tight enough that we cannot replay the macOS load
            // path verbatim: dropping the trailing-slack pseudo-entries and
            // skipping the full file-MACB timeline (200k+ files × 4 stamps =
            // millions of TimelineEvents) is the difference between opening
            // a real case and an OOM kill. macOS keeps the full fidelity.
            for evidence in hosts {
                do {
                    // Rebuild the file listing from the source, mirroring how it
                    // was first ingested: re-walk a loose folder, or re-read the
                    // TSK database for an image. Either way the listing is cheap
                    // and reproducible, so it's never persisted in the bundle.
                    var state: EvidenceState
                    var timeline: [TimelineEvent]
                    if evidence.kind == .kapeLooseFolder {
                        let root = evidence.sourceURL
                        guard FileManager.default.fileExists(atPath: root.path) else {
                            statusMessage = "\(evidence.displayName): source folder missing at \(root.path)"
                            continue
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
                        guard FileManager.default.fileExists(atPath: dbURL.path) else { continue }
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
                    // Rehydrate cached parse output. Missing files mean the
                    // user hasn't run Parse on this host yet (or pre-dates
                    // the caching format) - either way, fall back to empty.
                    // Lean mode drops the per-event XML payload (the bulk of
                    // each EventLogRecord's footprint) so the events array
                    // fits even for million-event cases.
                    #if os(macOS)
                    state.events = (try? CaseStore.readEvents(forHostID: evidence.id,
                                                              in: bundleURL)) ?? []
                    #else
                    state.events = (try? CaseStore.readEventsLite(forHostID: evidence.id,
                                                                  in: bundleURL)) ?? []
                    #endif
                    // Fold evtx records back into the timeline so the
                    // sessions panel and Source filter work without
                    // re-parsing on every case open.
                    if !state.events.isEmpty {
                        timeline.append(contentsOf: TimelineBuilder.build(from: state.events))
                        timeline.sort { $0.date < $1.date }
                    }
                    state.timeline = timeline
                    state.registryValues = (try? CaseStore.readRegistry(forHostID: evidence.id,
                                                                        in: bundleURL)) ?? []
                    state.findings = (try? CaseStore.readFindings(forHostID: evidence.id,
                                                                  in: bundleURL)) ?? []
                    state.iocMatches = (try? CaseStore.readIOCMatches(forHostID: evidence.id,
                                                                      in: bundleURL)) ?? []
                    states[evidence.id] = state
                } catch {
                    // Skip this host but keep going so a single corrupted DB
                    // doesn't block the whole case from opening.
                    statusMessage = "Failed to load \(evidence.displayName): \(error.localizedDescription)"
                }
            }
            iocs = (try? CaseStore.readIOCs(in: bundleURL)) ?? []
            activeEvidenceID = hosts.first?.id
            RecentCases.record(bundleURL)
            recentCases = RecentCases.load()
            statusMessage = "Loaded case '\(theCase.name)' (\(hosts.count) host\(hosts.count == 1 ? "" : "s"))."
        } catch {
            errorMessage = "Failed to open case: \(error.localizedDescription)"
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

    /// Generate the selected report/export artifacts for the whole case and
    /// write them as one timestamped set into `folder`. Returns the created
    /// export folder on success (so the sheet can reveal it in Finder), or nil.
    ///
    /// Mirrors `runIOCMatch`: snapshot the (Sendable) per-host data on the main
    /// actor, then build + write off the main actor so a large timeline doesn't
    /// stall the UI. The export always covers every host, regardless of the
    /// current scope selection.
    @discardableResult
    func exportSet(_ selection: ExportSelection, to folder: URL) async -> URL? {
        guard !isWorking else { return nil }
        guard let theCase = currentCase, !selection.isEmpty else { return nil }
        errorMessage = nil
        isWorking = true
        defer { isWorking = false }
        statusMessage = "Generating export…"

        let hosts: [ReportInputs.Host] = evidenceList.map { evidence in
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
                eventCount: state?.events.count ?? 0)
        }
        let now = Date()
        let inputs = ReportInputs(caseName: theCase.name, examiner: theCase.examiner,
                                  createdAt: theCase.createdAt, generatedAt: now,
                                  hosts: hosts)

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
            d.iocMatches.append(contentsOf: s.iocMatches)
        }
        d.events.sort { $0.writtenAt < $1.writtenAt }
        d.timeline.sort { $0.date < $1.date }
        d.findings.sort { $0.severity > $1.severity }
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
    var iocMatches: [IOCMatch] { derived().iocMatches }

    // Count-only accessors: sum per-host counts without building or sorting the
    // rolled-up arrays. For stat tiles / titles that only need a number.
    var fileCount: Int { scopedCount(\.files.count) }
    var eventCount: Int { scopedCount(\.events.count) }
    var timelineCount: Int { scopedCount(\.timeline.count) }
    var findingCount: Int { scopedCount(\.findings.count) }
    var registryValueCount: Int { scopedCount(\.registryValues.count) }
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
            }

            self.evidenceList.append(evidence)
            self.states[evidence.id] = state
            self.activeEvidenceID = evidence.id
            saveHosts()
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

    // MARK: - Event-log parsing

    #if os(macOS)

    /// One-stop button: parse event logs and registry hives, then run the
    /// detection engine over the combined evidence.
    func parseArtifacts() async {
        await parseEventLogs()
        await parseRegistry()
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
                                          registryValues: state.registryValues)
            let results = await analysisEngine.run(on: context)
            state.findings = results
            states[evidence.id] = state
            if let bundleURL = currentCaseBundleURL {
                try? CaseStore.writeFindings(results, forHostID: evidence.id, in: bundleURL)
            }
            total += results.count
        }
        statusMessage = total == 0 ? "No detections." : "Surfaced \(total) findings."
    }
}
