import Foundation

/// One macOS **software-install** record — from the system install history
/// (`/Library/Receipts/InstallHistory.plist`) or a PackageKit receipt
/// (`/private/var/db/receipts/<id>.plist`). Together these reconstruct *what*
/// software/OS/profile was installed, *when*, and *by which process* — the
/// canonical structured record (complementing the verbose `install.log` stream
/// the MacSecurityParser reads).
///
/// Pure / `Sendable` / `Codable`. The macOS-only `MacInstallHistoryParser`
/// produces these; `MacInstallAnalyzer` flags abnormal installers.
public nonisolated struct MacInstallEntry: Identifiable, Hashable, Sendable, Codable {
    public enum Source: String, Sendable, Codable, CaseIterable {
        case installHistory   // /Library/Receipts/InstallHistory.plist
        case receipt          // /private/var/db/receipts/<id>.plist

        public nonisolated var label: String {
            switch self {
            case .installHistory: return "Install History"
            case .receipt:        return "Receipt"
            }
        }
    }

    public let id: UUID
    public let displayName: String?
    public let packageIdentifiers: [String]
    public let version: String?
    public let date: Date?
    public let processName: String?
    /// InstallHistory `contentType` (package / softwareUpdate / macOSInstall / …).
    public let contentType: String?
    /// Receipt `PackageFileName` (the installed .pkg name/path), when present.
    public let packageFile: String?
    /// Receipt `InstallPrefixPath`, when present.
    public let installPrefix: String?
    public let source: Source
    public let scope: String
    public let sourceFile: String

    public init(id: UUID = UUID(), displayName: String? = nil,
                packageIdentifiers: [String] = [], version: String? = nil,
                date: Date? = nil, processName: String? = nil, contentType: String? = nil,
                packageFile: String? = nil, installPrefix: String? = nil,
                source: Source, scope: String, sourceFile: String) {
        self.id = id
        self.displayName = displayName
        self.packageIdentifiers = packageIdentifiers
        self.version = version
        self.date = date
        self.processName = processName
        self.contentType = contentType
        self.packageFile = packageFile
        self.installPrefix = installPrefix
        self.source = source
        self.scope = scope
        self.sourceFile = sourceFile
    }

    public var timestamp: Date? { date }

    public var displayTitle: String {
        if let n = displayName, !n.isEmpty { return n }
        if let p = packageIdentifiers.first, !p.isEmpty { return p }
        return "install"
    }

    public var timelineSummary: String {
        let who = displayTitle
        let by = processName.map { " by \($0)" } ?? ""
        let ver = version.map { " \($0)" } ?? ""
        return "[Install] \(who)\(ver)\(by)"
    }
}
