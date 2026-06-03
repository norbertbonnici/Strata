import Foundation
import SwiftUI
import Combine

/// Per-evidence working set. One of these exists for every `Evidence` the
/// user has ingested in the current session. AppModel composes views across
/// any subset.
struct EvidenceState {
    var dbURL: URL
    var files: [FileEntry] = []
    var events: [EventLogRecord] = []
    var timeline: [TimelineEvent] = []
    var registryValues: [RegistryValue] = []
    var findings: [Finding] = []
}

@MainActor
final class AppModel: ObservableObject {
    /// The case currently open in the app. nil = show the WelcomeView.
    @Published var currentCase: ForensicCase?
    /// Filesystem location of the .strata bundle backing `currentCase`.
    @Published var currentCaseBundleURL: URL?
    /// Recently opened case bundles - powers the welcome screen list.
    @Published var recentCases: [URL] = RecentCases.load()
    /// Drives the New Case sheet. Settable from menu commands and the
    /// welcome screen's New Case button.
    @Published var showingNewCaseSheet = false

    /// Ingested evidence in the order it was added. Drives the toolbar picker.
    @Published private(set) var evidenceList: [Evidence] = []

    /// Per-evidence state, keyed by Evidence.id.
    @Published private(set) var states: [UUID: EvidenceState] = [:]

    /// `nil` = combined view across every loaded evidence.
    /// A UUID = scope every view to just that evidence.
    @Published var activeEvidenceID: UUID?

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

    init() {}

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
            for evidence in hosts {
                let dbURL = CaseStore.tskDatabaseURL(forHostID: evidence.id, in: bundleURL)
                guard FileManager.default.fileExists(atPath: dbURL.path) else { continue }
                do {
                    let database = try TSKDatabase(path: dbURL)
                    let files = try database.fetchFiles()
                    let timeline = TimelineBuilder.build(from: files)
                    var state = EvidenceState(dbURL: dbURL)
                    state.files = files
                    state.timeline = timeline
                    // Rehydrate cached parse output. Missing files mean the
                    // user hasn't run Parse on this host yet (or pre-dates
                    // the caching format) - either way, fall back to empty.
                    state.events = (try? CaseStore.readEvents(forHostID: evidence.id,
                                                              in: bundleURL)) ?? []
                    state.registryValues = (try? CaseStore.readRegistry(forHostID: evidence.id,
                                                                        in: bundleURL)) ?? []
                    state.findings = (try? CaseStore.readFindings(forHostID: evidence.id,
                                                                  in: bundleURL)) ?? []
                    states[evidence.id] = state
                } catch {
                    // Skip this host but keep going so a single corrupted DB
                    // doesn't block the whole case from opening.
                    statusMessage = "Failed to load \(evidence.displayName): \(error.localizedDescription)"
                }
            }
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
        activeEvidenceID = nil
        progress = nil
        statusMessage = ""
        errorMessage = nil
    }

    private func saveHosts() {
        guard let bundleURL = currentCaseBundleURL else { return }
        do {
            try CaseStore.writeHosts(evidenceList, in: bundleURL)
        } catch {
            errorMessage = "Failed to save host list: \(error.localizedDescription)"
        }
    }

    // MARK: - Menu command entry points

    /// Triggered by File > New Case (Cmd-N). Closes any open case so the
    /// New Case sheet binds to a clean state, then shows the sheet.
    func requestNewCase() {
        if currentCase != nil { closeCase() }
        showingNewCaseSheet = true
    }

    /// Triggered by File > Open Case... (Cmd-O). Closes any open case before
    /// presenting the picker so the user doesn't end up with mismatched
    /// state if the open fails partway through.
    func requestOpenCase() {
        if currentCase != nil { closeCase() }
        let panel = NSOpenPanel()
        panel.canChooseFiles = false
        panel.canChooseDirectories = true
        panel.treatsFilePackagesAsDirectories = false
        panel.message = "Choose a .strata case bundle."
        guard panel.runModal() == .OK, let url = panel.url else { return }
        Task { await openCase(at: url) }
    }

    // MARK: - Computed views consumed by every screen

    /// Evidence the UI is currently scoped to, or nil when "All" is active.
    var selectedEvidence: Evidence? {
        guard let id = activeEvidenceID else { return nil }
        return evidenceList.first { $0.id == id }
    }

    var files: [FileEntry] { collect(\.files) }

    var events: [EventLogRecord] {
        collect(\.events).sorted { $0.writtenAt < $1.writtenAt }
    }

    var timeline: [TimelineEvent] {
        collect(\.timeline).sorted { $0.date < $1.date }
    }

    var findings: [Finding] {
        collect(\.findings).sorted { $0.severity > $1.severity }
    }

    var registryValues: [RegistryValue] { collect(\.registryValues) }

    private func collect<T>(_ kp: KeyPath<EvidenceState, [T]>) -> [T] {
        if let id = activeEvidenceID {
            return states[id]?[keyPath: kp] ?? []
        }
        return evidenceList.flatMap { states[$0.id]?[keyPath: kp] ?? [] }
    }

    // MARK: - Ingest

    /// Add a new host to the current case. The TSK SQLite output lands inside
    /// the case bundle so the case stays self-contained. After ingest the new
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
            var evidence = try KapeImporter.makeEvidence(from: sourceURL)
            let hostDir = CaseStore.hostDirectory(forHostID: evidence.id, in: bundleURL)
            try FileManager.default.createDirectory(at: hostDir, withIntermediateDirectories: true)
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
            let timeline = TimelineBuilder.build(from: loaded)

            var state = EvidenceState(dbURL: dbURL)
            state.files = loaded
            state.timeline = timeline

            self.evidenceList.append(evidence)
            self.states[evidence.id] = state
            self.activeEvidenceID = evidence.id
            saveHosts()
            self.statusMessage = "Loaded \(loaded.count) files from \(evidence.displayName)."
        } catch {
            self.errorMessage = error.localizedDescription
            self.statusMessage = ""
        }
    }

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

                let database = try TSKDatabase(path: state.dbURL)
                let extractor = TSKFileExtractor(
                    environment: tskEnv,
                    imageURL: evidence.sourceURL,
                    imageType: TSKImageIngestor.imageType(for: evidence.sourceURL))

                guard let bundleURL = currentCaseBundleURL else { continue }
                let scratch = CaseStore.eventScratchDirectory(forHostID: evidence.id,
                                                              in: bundleURL)
                try FileManager.default.createDirectory(at: scratch, withIntermediateDirectories: true)

                var collected: [EventLogRecord] = []
                for entry in candidates {
                    progress = ProgressInfo(
                        current: completed,
                        total: totalCandidates,
                        label: "\(evidence.displayName): \(entry.name)")
                    guard let info = try database.fetchExtractInfo(forFileID: entry.id) else {
                        completed += 1; continue
                    }
                    let outURL = scratch.appendingPathComponent("\(entry.id)-\(entry.name)")
                    try await extractor.extract(metaAddr: info.metaAddr,
                                                imageOffsetSectors: info.imageOffsetSectors,
                                                to: outURL)
                    let parsed = try await parser.parse(fileAt: outURL)
                    collected.append(contentsOf: parsed)
                    completed += 1
                }
                collected.sort { $0.writtenAt < $1.writtenAt }
                state.events = collected
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
    /// system, extract them with icat, and parse with regfexport. Findings
    /// are NOT regenerated here - call `runAnalyzers()` (or `parseArtifacts`)
    /// to surface results.
    func parseRegistry() async {
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

        let totalCandidates = evidenceList.reduce(0) { acc, evidence in
            guard let state = states[evidence.id], state.registryValues.isEmpty else { return acc }
            return acc + Self.discoverHives(in: state.files).count
        }
        guard totalCandidates > 0 else {
            statusMessage = "No new registry hives to parse."
            return
        }
        progress = ProgressInfo(current: 0, total: totalCandidates, label: "Parsing registry hives")
        var completed = 0

        do {
            let tskEnv = try TSKEnvironment.discover()
            let regEnv = try RegistryEnvironment.discover()
            let parser = RegistryHiveParser(environment: regEnv)

            for evidence in evidenceList {
                guard var state = states[evidence.id] else { continue }
                if !state.registryValues.isEmpty { continue }

                let candidates = Self.discoverHives(in: state.files)
                guard !candidates.isEmpty else { continue }

                let database = try TSKDatabase(path: state.dbURL)
                let extractor = TSKFileExtractor(
                    environment: tskEnv,
                    imageURL: evidence.sourceURL,
                    imageType: TSKImageIngestor.imageType(for: evidence.sourceURL))

                guard let bundleURL = currentCaseBundleURL else { continue }
                let scratch = CaseStore.registryScratchDirectory(forHostID: evidence.id,
                                                                 in: bundleURL)
                try FileManager.default.createDirectory(at: scratch, withIntermediateDirectories: true)

                var collected: [RegistryValue] = []
                for candidate in candidates {
                    progress = ProgressInfo(
                        current: completed,
                        total: totalCandidates,
                        label: "\(evidence.displayName): \(candidate.label)")
                    guard let info = try database.fetchExtractInfo(forFileID: candidate.entry.id) else {
                        completed += 1; continue
                    }
                    let outURL = scratch.appendingPathComponent("\(candidate.entry.id)-\(candidate.entry.name)")
                    do {
                        try await extractor.extract(metaAddr: info.metaAddr,
                                                    imageOffsetSectors: info.imageOffsetSectors,
                                                    to: outURL)
                        let values = try await parser.parse(hiveAt: outURL,
                                                            hiveLabel: candidate.label)
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
            }
            progress = ProgressInfo(current: completed, total: totalCandidates,
                                    label: "Registry parse complete")
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
