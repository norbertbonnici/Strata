import Foundation

/// One reconstructed item from the WMI CIM repository (`OBJECTS.DATA`) relevant
/// to **event-subscription persistence** (MITRE T1546.003).
///
/// A WMI persistence is three linked objects: an `__EventFilter` (a WQL query
/// that says *when* to fire), an `__EventConsumer` (what to run — most often a
/// `CommandLineEventConsumer` or `ActiveScriptEventConsumer`), and a
/// `__FilterToConsumerBinding` that ties them together. Attackers register these
/// to run code on a trigger (boot, logon, an interval) entirely within WMI,
/// leaving little on disk.
///
/// `OBJECTS.DATA` is a proprietary CIM database; full parsing needs the page +
/// `INDEX.BTR` B-tree machinery. Like the industry-standard PyWMIPersistenceFinder
/// (FireEye), Strata instead **carves** the repository for the high-signal
/// strings — binding references, the WQL query, the command line, and embedded
/// script payloads — which is what `WmiRepositoryParser` produces.
public nonisolated struct WmiPersistenceEntry: Identifiable, Hashable, Sendable, Codable {
    public enum Kind: String, Sendable, Codable, CaseIterable {
        /// A `__FilterToConsumerBinding` — a confirmed subscription.
        case binding
        /// Script content carved from a consumer (surfaced even when its binding
        /// couldn't be tied back, e.g. a deleted/unallocated subscription).
        case scriptConsumer

        public var label: String {
            switch self {
            case .binding:        return "Binding"
            case .scriptConsumer: return "Script consumer"
            }
        }
    }

    public let id: UUID
    public let kind: Kind
    // Binding:
    public let consumerName: String?
    /// e.g. `CommandLineEventConsumer`, `ActiveScriptEventConsumer`.
    public let consumerType: String?
    public let filterName: String?
    /// The `__EventFilter` WQL trigger query.
    public let query: String?
    /// A `CommandLineEventConsumer`'s command line.
    public let command: String?
    // Script consumer:
    public let scriptEngine: String?
    /// Captured script text (capped); e.g. an `ActiveScriptEventConsumer` payload.
    public let scriptText: String?
    /// `BVTConsumer`/`SCM Event Log` — Microsoft's built-in subscriptions, noted
    /// so they can be de-emphasised (also the canonical PoC names, so not ignored).
    public let isCommonBenign: Bool
    public let sourceFile: String

    public init(id: UUID = UUID(), kind: Kind,
                consumerName: String? = nil, consumerType: String? = nil,
                filterName: String? = nil, query: String? = nil, command: String? = nil,
                scriptEngine: String? = nil, scriptText: String? = nil,
                isCommonBenign: Bool = false, sourceFile: String) {
        self.id = id
        self.kind = kind
        self.consumerName = consumerName
        self.consumerType = consumerType
        self.filterName = filterName
        self.query = query
        self.command = command
        self.scriptEngine = scriptEngine
        self.scriptText = scriptText
        self.isCommonBenign = isCommonBenign
        self.sourceFile = sourceFile
    }

    /// One-line title for lists.
    public var title: String {
        switch kind {
        case .binding:
            return "\(consumerName ?? "?")  ←  \(filterName ?? "?")"
        case .scriptConsumer:
            return "Script consumer\(consumerName.map { ": \($0)" } ?? "")"
        }
    }

    /// The most action-relevant payload string (command, query, or script head).
    public var detailSummary: String {
        if let command, !command.isEmpty { return command }
        if let query, !query.isEmpty { return query }
        if let scriptText, !scriptText.isEmpty {
            return String(scriptText.prefix(120)).replacingOccurrences(of: "\n", with: " ")
        }
        return consumerType ?? kind.label
    }
}
