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

        public init(displayName: String, kindLabel: String, sourcePath: String,
                    registryValues: [RegistryValue], findings: [Finding],
                    iocMatches: [IOCMatch], timeline: [TimelineEvent],
                    fileCount: Int, eventCount: Int) {
            self.displayName = displayName
            self.kindLabel = kindLabel
            self.sourcePath = sourcePath
            self.registryValues = registryValues
            self.findings = findings
            self.iocMatches = iocMatches
            self.timeline = timeline
            self.fileCount = fileCount
            self.eventCount = eventCount
        }
    }

    public let caseName: String
    public let examiner: String
    public let createdAt: Date
    public let generatedAt: Date
    public let hosts: [Host]

    public init(caseName: String, examiner: String, createdAt: Date,
                generatedAt: Date, hosts: [Host]) {
        self.caseName = caseName
        self.examiner = examiner
        self.createdAt = createdAt
        self.generatedAt = generatedAt
        self.hosts = hosts
    }
}
