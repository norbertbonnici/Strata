import Foundation

/// Inputs that any analyzer can see. Adding a new evidence source (registry
/// hives, MFT $J, prefetch, etc.) means extending this struct, not changing
/// every existing analyzer.
public nonisolated struct AnalysisContext: Sendable {
    public let files: [FileEntry]
    public let events: [EventLogRecord]
    public let timeline: [TimelineEvent]
    public let registryValues: [RegistryValue]
    public let prefetch: [PrefetchEntry]
    public let amcache: [AmcacheEntry]
    public let shimcache: [ShimcacheEntry]
    public let lnk: [LnkEntry]

    public init(files: [FileEntry], events: [EventLogRecord],
                timeline: [TimelineEvent], registryValues: [RegistryValue],
                prefetch: [PrefetchEntry] = [], amcache: [AmcacheEntry] = [],
                shimcache: [ShimcacheEntry] = [], lnk: [LnkEntry] = []) {
        self.files = files
        self.events = events
        self.timeline = timeline
        self.registryValues = registryValues
        self.prefetch = prefetch
        self.amcache = amcache
        self.shimcache = shimcache
        self.lnk = lnk
    }
}

/// A detection rule. Pure function from evidence to findings - no I/O, no
/// state, so we can run analyzers in parallel and reorder them freely.
public protocol Analyzer: Sendable {
    nonisolated var name: String { get }
    nonisolated func analyze(context: AnalysisContext) -> [Finding]
}
