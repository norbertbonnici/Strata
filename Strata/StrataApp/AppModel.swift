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
    var recycleBin: [RecycleBinEntry] = []
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
    var journald: [JournaldEntry] = []
    var audit: [AuditEvent] = []
    var syslog: [SyslogEntry] = []
    var lastlog: [LastlogEntry] = []
    var launchItems: [LaunchItemEntry] = []
    var quarantine: [QuarantineEvent] = []
    var macPersistence: [MacPersistenceItem] = []
    var fsEvents: [FSEventRecord] = []
    var unifiedLog: [UnifiedLogEntry] = []
    var tcc: [TCCAccess] = []
    var knowledgeC: [KnowledgeEntry] = []
    var macRecentItems: [MacRecentItem] = []
    var macSecurityEvents: [MacSecurityEvent] = []
    // Files recovered by raw-image signature carving (no filesystem, no times).
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
    // macOS host identity (empty on non-macOS evidence).
    var macInfo: MacHostInfo?
    var findings: [Finding] = []
    var iocMatches: [IOCMatch] = []
    /// OS families detected for this host (from volume fs-types, or a file-tree
    /// sniff for loose folders). Empty = couldn't tell. Drives per-OS tab
    /// hiding. Computed once when the working set is assembled.
    var osFamilies: Set<OSFamily> = []

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
    /// The bundle whose security scope is currently held (recents / library /
    /// iCloud bookmarks), retained for the whole case lifetime so off-main host
    /// loads AND the detached open-time backfill can read it; released in
    /// closeCase / on re-open. nil when no scope is held (a plain local path).
    var caseSecurityScopeURL: URL?
    /// Recently opened case bundles - powers the welcome screen list.
    @Published var recentCases: [URL] = RecentCases.load()
    /// Single sheet binding for the top-level modal stack. Two adjacent
    /// .sheet(isPresented:) modifiers on the same view can SIGABRT in
    /// SwiftUI when their bindings transition in the same render pass; one
    /// .sheet(item:) is the safe pattern.
    @Published var activeSheet: ActiveSheet?
    /// FileVault unlock secrets supplied for encrypted APFS volumes, keyed by
    /// evidence id. **In-memory only — never persisted** (forensic
    /// confidentiality); used by the APFS metadata + content-extraction paths.
    @Published var fileVaultCredentials: [UUID: FileVaultCredential] = [:]
    /// APFS volumes that came back FileVault-locked at ingest, keyed by evidence
    /// id, so the UI can prompt for a password and re-ingest. Cleared on a
    /// successful unlock.
    @Published var lockedApfsVolumes: [UUID: [ApfsLockedVolume]] = [:]
    /// IOCs the analyst has loaded for the current case. Persisted to
    /// iocs.json inside the bundle. Empty by default - IOC matching never
    /// runs unless the user has loaded at least one.
    @Published var iocs: [IOC] = []
    /// Append-only chain-of-custody ledger for the open case (custody.json).
    /// Case-wide, so it lives here rather than in per-host `EvidenceState`.
    @Published var custodyLog: [CustodyEvent] = []

    /// Analyst bookmarks/tags (case-wide, `annotations.json`). The index is
    /// rebuilt on every change so timeline rows can do O(1) "is this event
    /// bookmarked" lookups across 20k-row tables.
    @Published var annotations: [Annotation] = [] {
        didSet {
            annotationsByTargetKey = Dictionary(annotations.map { ($0.targetKey, $0) },
                                                uniquingKeysWith: { first, _ in first })
        }
    }
    private(set) var annotationsByTargetKey: [String: Annotation] = [:]

    /// Free-form case narrative (`notes.json`). Mutate via `updateCaseNotes`.
    @Published var caseNotes = CaseNotes()

    /// CTI enrichment verdicts (case-wide, provenance-stamped, `enrichment.json`).
    /// Indexed by `EnrichmentVerdict.key(kind:value:)` for O(1) UI joins against
    /// IOCs / matches. Produced by `enrichIndicators()`.
    @Published var enrichmentVerdicts: [EnrichmentVerdict] = [] {
        didSet {
            enrichmentByKey = Dictionary(enrichmentVerdicts.map { ($0.id, $0) },
                                         uniquingKeysWith: { _, new in new })
        }
    }
    private(set) var enrichmentByKey: [String: EnrichmentVerdict] = [:]

    /// On-device (Apple Intelligence) executive summary of the case findings,
    /// case-wide (`summary.json`). Generated on macOS via `generateSummary()`;
    /// the iOS viewer only displays it. `nil` until first generated.
    @Published var caseSummary: CaseSummary?

    /// Case-wide multi-host correlation findings (roadmap #8) — shared IOCs,
    /// pivoting source IPs, reused accounts across ≥2 hosts. Recomputed by
    /// `runAnalyzers`; surfaced in the combined "All" scope only (each finding
    /// spans multiple hosts).
    @Published var correlationFindings: [Finding] = []

    /// Examiner-level CTI config (which tiers are on + the NSRL file path).
    /// Tokens live in the Keychain; this persists to UserDefaults (it's
    /// examiner config, not case data), so it survives across cases.
    @Published var ctiConfig: CTIConfiguration = AppModel.loadCTIConfig() {
        didSet { AppModel.saveCTIConfig(ctiConfig) }
    }

    /// Verdict for a given indicator, if one has been fetched.
    func enrichment(for value: String, kind: IOCKind) -> EnrichmentVerdict? {
        enrichmentByKey[EnrichmentVerdict.key(kind: kind, value: value)]
    }

    private static let ctiConfigDefaultsKey = "strata.cti.configuration"
    private static func loadCTIConfig() -> CTIConfiguration {
        guard let data = UserDefaults.standard.data(forKey: ctiConfigDefaultsKey),
              let cfg = try? JSONDecoder().decode(CTIConfiguration.self, from: data)
        else { return CTIConfiguration() }
        return cfg
    }
    private static func saveCTIConfig(_ cfg: CTIConfiguration) {
        if let data = try? JSONEncoder().encode(cfg) {
            UserDefaults.standard.set(data, forKey: ctiConfigDefaultsKey)
        }
    }

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
    @Published var libraryCases: [LibraryCase] = []

    enum ActiveSheet: Identifiable, Hashable {
        case newCase
        case enrichment
        case export
        case acquisitionEditor(UUID)
        case annotationEditor(AnnotationDraft)
        case fileVaultUnlock(UUID)
        /// Where summary inference runs (on-device ↔ cloud) + cloud credentials.
        case inferenceSettings
        /// First-run "evidence-derived data will leave this Mac" confirmation,
        /// carrying the action to run once the analyst acknowledges it.
        case cloudInferenceConfirm(PendingCloudAction)
        var id: Int { hashValue }
    }

    /// A summary action deferred behind the cloud-egress confirmation, so the
    /// confirm sheet knows what to resume.
    enum PendingCloudAction: Hashable {
        case generateSummary
        case runEval
    }

    /// Ingested evidence in the order it was added. Drives the toolbar picker.
    @Published var evidenceList: [Evidence] = []

    /// Per-evidence state, keyed by Evidence.id.
    @Published var states: [UUID: EvidenceState] = [:] {
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

    let analysisEngine = AnalysisEngine()

    public struct ProgressInfo: Equatable {
        public var current: Int
        public var total: Int
        public var label: String
        public var fraction: Double {
            total == 0 ? 0 : min(1.0, Double(current) / Double(total))
        }
        public var percent: Int { Int(fraction * 100) }
    }


    // MARK: - Cached inference status (lives here as stored state; refreshed off the render path)
#if os(macOS)
    /// Cached inference status for the configured backend, so SwiftUI `body`
    /// never rebuilds the backend or hits the Keychain (the "no heavy work in
    /// body" rule). Refreshed by `refreshInferenceConfig()` on the summary card's
    /// appearance / a config change - never per render.
    @Published private(set) var summaryAvailability: SummarizerAvailability = FindingsSummarizer.availability
    @Published private(set) var summaryIsSovereign: Bool = true
    /// The configured backend's sovereignty tier, for three-way UI labeling
    /// (on-device / Apple Private Cloud / third-party cloud). `summaryIsSovereign`
    /// stays as the binary "nothing leaves the host" used by prewarm/help text.
    @Published private(set) var summarySovereignty: SovereigntyTier = .onDevice
    @Published private(set) var summaryBackendLabel: String = FindingsSummarizer.modelLabel
    /// Last summary self-eval report (markdown), for display / the talk.
    @Published var summaryEvalMarkdown: String?

    /// Resolve the configured backend once and cache its status off the render
    /// path. Building the backend can read the Keychain (cloud mode), so this
    /// must not run in `body`.
    func refreshInferenceConfig() {
        let backend = InferenceConfiguration.load().makeBackend(credentials: KeychainCredentialStore())
        summaryAvailability = backend.availability()
        summaryIsSovereign = backend.isSovereign
        summarySovereignty = backend.sovereignty
        summaryBackendLabel = backend.label
    }
#endif

    // MARK: - In-flight hashing task (stored state for the source-hash pass)
#if os(macOS)
    /// In-flight hashing task, exposed so a Cancel control can stop a long pass.
    var hashTask: Task<FileHasher.Result, Error>?
#endif
    init() { refreshLibrary() }

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
        var recycleBin: [RecycleBinEntry] = []
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
        var journald: [JournaldEntry] = []
        var audit: [AuditEvent] = []
        var syslog: [SyslogEntry] = []
        var lastlog: [LastlogEntry] = []
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
            d.recycleBin = s.recycleBin
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
            d.journald = s.journald
            d.audit = s.audit
            d.syslog = s.syslog
            d.lastlog = s.lastlog
            d.launchItems = s.launchItems
            d.quarantine = s.quarantine
            d.macPersistence = s.macPersistence
            d.fsEvents = s.fsEvents
            d.unifiedLog = s.unifiedLog
            d.tcc = s.tcc
            d.knowledgeC = s.knowledgeC
            d.macRecentItems = s.macRecentItems
            d.macSecurityEvents = s.macSecurityEvents
            d.carvedFiles = s.carvedFiles
            d.kexts = s.kexts
            d.backgroundItems = s.backgroundItems
            d.messages = s.messages
            d.mail = s.mail
            d.network = s.network
            d.userActivity = s.userActivity
            d.documentVersions = s.documentVersions
            d.notifications = s.notifications
            d.powerlog = s.powerlog
            d.macConfig = s.macConfig
            d.installHistory = s.installHistory
            d.whereFroms = s.whereFroms
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
            d.recycleBin.append(contentsOf: s.recycleBin)
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
            d.journald.append(contentsOf: s.journald)
            d.audit.append(contentsOf: s.audit)
            d.syslog.append(contentsOf: s.syslog)
            d.lastlog.append(contentsOf: s.lastlog)
            d.launchItems.append(contentsOf: s.launchItems)
            d.quarantine.append(contentsOf: s.quarantine)
            d.macPersistence.append(contentsOf: s.macPersistence)
            d.fsEvents.append(contentsOf: s.fsEvents)
            d.unifiedLog.append(contentsOf: s.unifiedLog)
            d.tcc.append(contentsOf: s.tcc)
            d.knowledgeC.append(contentsOf: s.knowledgeC)
            d.macRecentItems.append(contentsOf: s.macRecentItems)
            d.macSecurityEvents.append(contentsOf: s.macSecurityEvents)
            d.carvedFiles.append(contentsOf: s.carvedFiles)
            d.kexts.append(contentsOf: s.kexts)
            d.backgroundItems.append(contentsOf: s.backgroundItems)
            d.messages.append(contentsOf: s.messages)
            d.mail.append(contentsOf: s.mail)
            d.network.append(contentsOf: s.network)
            d.userActivity.append(contentsOf: s.userActivity)
            d.documentVersions.append(contentsOf: s.documentVersions)
            d.notifications.append(contentsOf: s.notifications)
            d.powerlog.append(contentsOf: s.powerlog)
            d.macConfig.append(contentsOf: s.macConfig)
            d.installHistory.append(contentsOf: s.installHistory)
            d.whereFroms.append(contentsOf: s.whereFroms)
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
        d.recycleBin.sort { ($0.deletedAt ?? .distantPast) > ($1.deletedAt ?? .distantPast) }
        d.srum.sort { ($0.timestamp ?? .distantPast) > ($1.timestamp ?? .distantPast) }
        d.browserHistory.sort { ($0.timestamp ?? .distantPast) > ($1.timestamp ?? .distantPast) }
        d.mft.sort { $0.recordNumber < $1.recordNumber }
        d.authLog.sort { ($0.timestamp ?? .distantPast) > ($1.timestamp ?? .distantPast) }
        d.logins.sort { ($0.timestamp ?? .distantPast) > ($1.timestamp ?? .distantPast) }
        d.shellHistory.sort { ($0.timestamp ?? .distantPast) > ($1.timestamp ?? .distantPast) }
        d.webAccess.sort { ($0.timestamp ?? .distantPast) > ($1.timestamp ?? .distantPast) }
        d.packages.sort { ($0.timestamp ?? .distantPast) > ($1.timestamp ?? .distantPast) }
        d.journald.sort { ($0.timestamp ?? .distantPast) > ($1.timestamp ?? .distantPast) }
        d.audit.sort { ($0.timestamp ?? .distantPast) > ($1.timestamp ?? .distantPast) }
        d.syslog.sort { ($0.timestamp ?? .distantPast) > ($1.timestamp ?? .distantPast) }
        d.lastlog.sort { ($0.timestamp ?? .distantPast) > ($1.timestamp ?? .distantPast) }
        // Launch items carry no timestamp - order by label. Quarantine by
        // download time, newest first (matches the per-host parse-time sort).
        d.launchItems.sort { $0.label.localizedCaseInsensitiveCompare($1.label) == .orderedAscending }
        d.quarantine.sort { ($0.timestamp ?? .distantPast) > ($1.timestamp ?? .distantPast) }
        // No timestamps; group by kind, then by display title for stable order.
        d.macPersistence.sort {
            $0.kind.rawValue == $1.kind.rawValue
                ? $0.title.localizedCaseInsensitiveCompare($1.title) == .orderedAscending
                : $0.kind.rawValue < $1.kind.rawValue
        }
        // FSEvents has no timestamp; the event ID is the monotonic order.
        d.fsEvents.sort { $0.eventID < $1.eventID }
        d.unifiedLog.sort { ($0.timestamp ?? .distantPast) > ($1.timestamp ?? .distantPast) }
        d.tcc.sort { ($0.lastModified ?? .distantPast) > ($1.lastModified ?? .distantPast) }
        d.knowledgeC.sort { ($0.startDate ?? .distantPast) > ($1.startDate ?? .distantPast) }
        d.macRecentItems.sort { ($0.timestamp ?? .distantPast) > ($1.timestamp ?? .distantPast) }
        d.macSecurityEvents.sort { ($0.timestamp ?? .distantPast) > ($1.timestamp ?? .distantPast) }
        return d
    }

    var files: [FileEntry] { derived().files }
    /// Volumes for the active scope (small; not worth caching). Combined "All"
    /// scope concatenates per-host volume lists.
    var volumes: [VolumeInfo] {
        if let id = activeEvidenceID { return states[id]?.volumes ?? [] }
        return evidenceList.flatMap { states[$0.id]?.volumes ?? [] }
    }
    /// One host's files + volumes, kept un-flattened so the evidence tree can
    /// render a per-host subtree. The rolled-up `files`/`volumes` collide on the
    /// per-host TSK `fs_obj_id` in the combined scope, so a multi-host file tree
    /// must build each host from its own state.
    func hostFileTree(_ id: UUID) -> (files: [FileEntry], volumes: [VolumeInfo]) {
        let state = states[id]
        return (state?.files ?? [], state?.volumes ?? [])
    }
    var events: [EventLogRecord] { derived().events }
    var timeline: [TimelineEvent] { derived().timeline }
    var findings: [Finding] {
        // Case-wide correlation findings join the per-host findings only in the
        // combined "All" scope (they describe relationships across hosts).
        activeEvidenceID == nil ? derived().findings + correlationFindings : derived().findings
    }
    var registryValues: [RegistryValue] { derived().registryValues }
    var prefetch: [PrefetchEntry] { derived().prefetch }
    var amcache: [AmcacheEntry] { derived().amcache }
    var shimcache: [ShimcacheEntry] { derived().shimcache }
    var lnk: [LnkEntry] { derived().lnk }
    var jumpList: [JumpListEntry] { derived().jumpList }
    var usn: [UsnRecord] { derived().usn }
    var recycleBin: [RecycleBinEntry] { derived().recycleBin }
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
    var journald: [JournaldEntry] { derived().journald }
    var audit: [AuditEvent] { derived().audit }
    var syslog: [SyslogEntry] { derived().syslog }
    var lastlog: [LastlogEntry] { derived().lastlog }
    var launchItems: [LaunchItemEntry] { derived().launchItems }
    var quarantine: [QuarantineEvent] { derived().quarantine }
    var macPersistence: [MacPersistenceItem] { derived().macPersistence }
    var fsEvents: [FSEventRecord] { derived().fsEvents }
    var unifiedLog: [UnifiedLogEntry] { derived().unifiedLog }
    var tcc: [TCCAccess] { derived().tcc }
    var knowledgeC: [KnowledgeEntry] { derived().knowledgeC }
    var macRecentItems: [MacRecentItem] { derived().macRecentItems }
    var macSecurityEvents: [MacSecurityEvent] { derived().macSecurityEvents }
    var carvedFiles: [CarvedFile] { derived().carvedFiles }
    var kexts: [MacKextEntry] { derived().kexts }
    var backgroundItems: [MacBackgroundItem] { derived().backgroundItems }
    var messages: [MessageEntry] { derived().messages }
    var mail: [MailMessageEntry] { derived().mail }
    var network: [MacNetworkItem] { derived().network }
    var userActivity: [MacActivityItem] { derived().userActivity }
    var documentVersions: [MacDocumentVersion] { derived().documentVersions }
    var notifications: [MacNotification] { derived().notifications }
    var powerlog: [PowerlogEntry] { derived().powerlog }
    var macConfig: [MacConfigSetting] { derived().macConfig }
    var installHistory: [MacInstallEntry] { derived().installHistory }
    var whereFroms: [MacWhereFrom] { derived().whereFroms }
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
    var recycleBinCount: Int { scopedCount(\.recycleBin.count) }
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
    var journaldCount: Int { scopedCount(\.journald.count) }
    var auditCount: Int { scopedCount(\.audit.count) }
    var syslogCount: Int { scopedCount(\.syslog.count) }
    var lastlogCount: Int { scopedCount(\.lastlog.count) }
    var launchItemCount: Int { scopedCount(\.launchItems.count) }
    var quarantineCount: Int { scopedCount(\.quarantine.count) }
    var macPersistenceCount: Int { scopedCount(\.macPersistence.count) }
    var fsEventCount: Int { scopedCount(\.fsEvents.count) }
    var unifiedLogCount: Int { scopedCount(\.unifiedLog.count) }
    var tccCount: Int { scopedCount(\.tcc.count) }
    var knowledgeCCount: Int { scopedCount(\.knowledgeC.count) }
    var macRecentItemCount: Int { scopedCount(\.macRecentItems.count) }
    var macSecurityEventCount: Int { scopedCount(\.macSecurityEvents.count) }
    var carvedFileCount: Int { scopedCount(\.carvedFiles.count) }
    var kextCount: Int { scopedCount(\.kexts.count) }
    var backgroundItemCount: Int { scopedCount(\.backgroundItems.count) }
    var messageCount: Int { scopedCount(\.messages.count) }
    var mailCount: Int { scopedCount(\.mail.count) }
    var networkCount: Int { scopedCount(\.network.count) }
    var userActivityCount: Int { scopedCount(\.userActivity.count) }
    var documentVersionCount: Int { scopedCount(\.documentVersions.count) }
    var notificationCount: Int { scopedCount(\.notifications.count) }
    var powerlogCount: Int { scopedCount(\.powerlog.count) }
    var macConfigCount: Int { scopedCount(\.macConfig.count) }
    var installHistoryCount: Int { scopedCount(\.installHistory.count) }
    var whereFromsCount: Int { scopedCount(\.whereFroms.count) }
    var iocMatchCount: Int { scopedCount(\.iocMatches.count) }

    /// True once the Linux log parse has produced *something* in the active
    /// scope - the high-volume logs (auth/logins/journal/syslog) are present on
    /// essentially every Linux host. The per-artifact tabs use this to tell
    /// "not parsed yet" (offer the Parse button) from "parsed, but this
    /// artifact isn't on the host" (explain why it's empty).
    var hasParsedLinuxLogs: Bool {
        authLogCount > 0 || loginsCount > 0 || journaldCount > 0 || syslogCount > 0
    }

    private func scopedCount(_ kp: KeyPath<EvidenceState, Int>) -> Int {
        if let id = activeEvidenceID { return states[id]?[keyPath: kp] ?? 0 }
        return evidenceList.reduce(0) { $0 + (states[$1.id]?[keyPath: kp] ?? 0) }
    }

    /// The Timeline's first-render source selection. The unbounded sources
    /// (filesystem MACB, USN, MFT, registry) are deliberately excluded - they
    /// expand to millions of rows and make the table sluggish for no immediate
    /// value - so we default to the *bounded, high-signal* sources that are
    /// actually populated for this case: Event Log on Windows, the auth/journal/
    /// syslog/package/login set on Linux, plus prefetch/browser/SRUM. Derived
    /// from the cheap per-artifact counts (no timeline scan). Falls back to
    /// Event Log, then filesystem, so the timeline is never blank when data
    /// exists.
    var defaultTimelineSources: Set<TimelineSource> {
        var s: Set<TimelineSource> = []
        if eventCount > 0 { s.insert(.evtx) }
        // Linux (all bounded).
        if authLogCount > 0 { s.insert(.authlog) }
        if loginsCount > 0 { s.insert(.logins) }
        if journaldCount > 0 { s.insert(.journald) }
        if syslogCount > 0 { s.insert(.syslog) }
        if auditCount > 0 { s.insert(.auditd) }
        if packageCount > 0 { s.insert(.package) }
        if lastlogCount > 0 { s.insert(.lastlog) }
        if webAccessCount > 0 { s.insert(.weblog) }
        if shellHistoryCount > 0 { s.insert(.shellHistory) }
        // macOS unified log — the primary macOS telemetry (high volume; the
        // Source filter lets the analyst toggle it off).
        if unifiedLogCount > 0 { s.insert(.unifiedLog) }
        if tccCount > 0 { s.insert(.tcc) }
        if knowledgeCCount > 0 { s.insert(.knowledgeC) }
        if macRecentItemCount > 0 { s.insert(.macRecent) }
        if macSecurityEventCount > 0 { s.insert(.macSecurity) }
        // Windows bounded execution / usage.
        if prefetchCount > 0 { s.insert(.prefetch) }
        if browserHistoryCount > 0 { s.insert(.browser) }
        if messageCount > 0 { s.insert(.messages) }
        if mailCount > 0 { s.insert(.mail) }
        if networkCount > 0 { s.insert(.network) }
        if userActivityCount > 0 { s.insert(.userActivity) }
        if documentVersionCount > 0 { s.insert(.docRevisions) }
        if notificationCount > 0 { s.insert(.notifications) }
        if powerlogCount > 0 { s.insert(.powerlog) }
        if installHistoryCount > 0 { s.insert(.install) }
        if srumCount > 0 { s.insert(.srum) }
        if s.isEmpty { s.insert(eventCount > 0 ? .evtx : .filesystem) }
        return s
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

    /// Whether a tab that applies to **any** of `families` should be shown — for
    /// the artifacts that span more than one OS (shell history exists on both
    /// Linux and macOS). Empty `families` = cross-platform = always shown; an
    /// undetermined scope shows everything.
    func shows(anyOf families: Set<OSFamily>) -> Bool {
        guard !showAllArtifactTabs else { return true }
        guard !families.isEmpty else { return true }
        let scope = scopeOSFamilies()
        return scope.isEmpty || !scope.isDisjoint(with: families)
    }

}
