import Foundation

/// Immutable, `Sendable` snapshot of everything the report/export generators
/// need. `AppModel` assembles it on the main actor from its per-evidence
/// `states`, then hands it to the (nonisolated) generators so the heavy
/// string-building runs off the main actor - the same pattern `runIOCMatch`
/// uses to stay off the UI thread.
///
/// Keeping the generators behind this struct (rather than reaching into
/// `AppModel`) is what makes them pure and unit-testable.
public nonisolated struct ReportInputs: Sendable {
    /// One host's slice of the case. The registry values are carried verbatim
    /// so the builder can derive a `HostProfile` without the app layer.
    public struct Host: Sendable {
        public let displayName: String
        public let kindLabel: String
        public let sourcePath: String
        public let registryValues: [RegistryValue]
        public let findings: [Finding]
        public let iocMatches: [IOCMatch]
        public let timeline: [TimelineEvent]
        public let fileCount: Int
        public let eventCount: Int
        // Chain-of-custody fields. Defaulted so non-CoC callers (and tests) need
        // not supply them; `evidenceID` lets the CoC report tie ledger entries
        // back to a host.
        public let evidenceID: UUID?
        public let acquisition: AcquisitionInfo?
        public let sourceHashes: [SourceHash]
        /// Linux host-info (os-release/hostname/passwd) - the profile source
        /// when the registry walk yields nothing. nil for Windows evidence.
        public let linuxInfo: LinuxHostInfo?

        public init(displayName: String, kindLabel: String, sourcePath: String,
                    registryValues: [RegistryValue], findings: [Finding],
                    iocMatches: [IOCMatch], timeline: [TimelineEvent],
                    fileCount: Int, eventCount: Int,
                    evidenceID: UUID? = nil, acquisition: AcquisitionInfo? = nil,
                    sourceHashes: [SourceHash] = [], linuxInfo: LinuxHostInfo? = nil) {
            self.displayName = displayName
            self.kindLabel = kindLabel
            self.sourcePath = sourcePath
            self.registryValues = registryValues
            self.findings = findings
            self.iocMatches = iocMatches
            self.timeline = timeline
            self.fileCount = fileCount
            self.eventCount = eventCount
            self.evidenceID = evidenceID
            self.acquisition = acquisition
            self.sourceHashes = sourceHashes
            self.linuxInfo = linuxInfo
        }
    }

    public let caseName: String
    public let examiner: String
    public let createdAt: Date
    public let generatedAt: Date
    public let hosts: [Host]
    /// Case-wide custody ledger, for the chain-of-custody report. Defaulted
    /// empty for callers that only export the examiner report / data.
    public let custodyLog: [CustodyEvent]
    /// The analyst's case narrative (free-form notes), surfaced in the
    /// examiner report. Defaulted empty for non-narrative callers.
    public let caseNotes: String
    /// Analyst bookmarks (tagged findings / timeline events), for the report's
    /// bookmarked-items section and the annotations data export.
    public let annotations: [Annotation]

    public init(caseName: String, examiner: String, createdAt: Date,
                generatedAt: Date, hosts: [Host], custodyLog: [CustodyEvent] = [],
                caseNotes: String = "", annotations: [Annotation] = []) {
        self.caseName = caseName
        self.examiner = examiner
        self.createdAt = createdAt
        self.generatedAt = generatedAt
        self.hosts = hosts
        self.custodyLog = custodyLog
        self.caseNotes = caseNotes
        self.annotations = annotations
    }
}
