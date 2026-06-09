import Foundation

/// One reconstructed row from the Windows SRUM database (`SRUDB.dat`, the System
/// Resource Usage Monitor, an ESE database at `C:\Windows\System32\sru\`).
///
/// SRUM is forensic gold for **execution + network attribution**: it records, in
/// ~hourly buckets, which application (resolved to its full on-disk path) sent /
/// received how many bytes over which interface, and which applications ran under
/// which user SID. Because it survives independently of Prefetch / Amcache and
/// carries *byte volumes*, it is a primary source for **data-exfiltration sizing**
/// and for proving a binary executed.
///
/// We unify the three highest-value provider tables into one row type; `kind`
/// says which table it came from and which optional fields are populated.
public nonisolated struct SrumEntry: Identifiable, Hashable, Sendable, Codable {
    /// Which SRUM provider table this row came from.
    public enum Kind: String, Sendable, Codable, CaseIterable {
        /// Network Data Usage `{973F5D5C-1D90-4944-BE8E-24B94231A174}` — bytes
        /// sent/received per app per interface.
        case networkData
        /// Application Resource Usage `{D10CA2FE-6FCF-4F6D-848E-B2E99266FA89}` —
        /// app execution + disk I/O.
        case appResourceUsage
        /// Network Connectivity Usage `{DD6636C4-8929-4683-974E-22C046A43763}` —
        /// per-app interface connection sessions.
        case networkConnectivity

        public var label: String {
            switch self {
            case .networkData:         return "Network usage"
            case .appResourceUsage:    return "App execution"
            case .networkConnectivity: return "Network connection"
            }
        }
    }

    public let id: UUID
    public let kind: Kind
    /// The per-row TimeStamp (decoded from the OLE-automation-date column); the
    /// ~hourly bucket the activity was recorded in. nil if unparseable.
    public let timestamp: Date?
    /// AppId resolved via SruDbIdMapTable to the application's full path/moniker.
    public let application: String?
    /// UserId resolved via SruDbIdMapTable to a Windows SID.
    public let userSID: String?
    // Network Data Usage:
    public let bytesSent: Int64?
    public let bytesReceived: Int64?
    public let interfaceLuid: Int64?
    // Application Resource Usage (foreground + background totals):
    public let bytesRead: Int64?
    public let bytesWritten: Int64?
    // Network Connectivity Usage:
    public let connectStart: Date?
    public let connectedSeconds: Int64?
    /// The source `SRUDB.dat` path the row was parsed from.
    public let sourceFile: String

    public init(id: UUID = UUID(), kind: Kind, timestamp: Date?,
                application: String?, userSID: String?,
                bytesSent: Int64? = nil, bytesReceived: Int64? = nil,
                interfaceLuid: Int64? = nil,
                bytesRead: Int64? = nil, bytesWritten: Int64? = nil,
                connectStart: Date? = nil, connectedSeconds: Int64? = nil,
                sourceFile: String) {
        self.id = id
        self.kind = kind
        self.timestamp = timestamp
        self.application = application
        self.userSID = userSID
        self.bytesSent = bytesSent
        self.bytesReceived = bytesReceived
        self.interfaceLuid = interfaceLuid
        self.bytesRead = bytesRead
        self.bytesWritten = bytesWritten
        self.connectStart = connectStart
        self.connectedSeconds = connectedSeconds
        self.sourceFile = sourceFile
    }

    /// Leaf name of the resolved application path (handles Windows `\` and `/`).
    public var appShortName: String {
        guard let application, !application.isEmpty else { return "—" }
        let parts = application.split(whereSeparator: { $0 == "\\" || $0 == "/" })
        return parts.last.map(String.init) ?? application
    }

    /// One-line, kind-specific summary for table rows.
    public var detailSummary: String {
        switch kind {
        case .networkData:
            return "↑ \(Self.humanBytes(bytesSent ?? 0))   ↓ \(Self.humanBytes(bytesReceived ?? 0))"
        case .appResourceUsage:
            return "read \(Self.humanBytes(bytesRead ?? 0))   written \(Self.humanBytes(bytesWritten ?? 0))"
        case .networkConnectivity:
            let s = connectedSeconds ?? 0
            return "connected \(Self.humanDuration(s))"
        }
    }

    /// Pure byte formatter (avoids ByteCountFormatter so the value type stays
    /// trivially `nonisolated`/`Sendable` and unit-testable off-main).
    public static func humanBytes(_ n: Int64) -> String {
        let units = ["B", "KB", "MB", "GB", "TB"]
        var value = Double(max(0, n))
        var unit = 0
        while value >= 1024 && unit < units.count - 1 { value /= 1024; unit += 1 }
        if unit == 0 { return "\(n) B" }
        return String(format: "%.1f %@", value, units[unit])
    }

    public static func humanDuration(_ seconds: Int64) -> String {
        if seconds < 60 { return "\(seconds)s" }
        if seconds < 3600 { return "\(seconds / 60)m \(seconds % 60)s" }
        let h = seconds / 3600, m = (seconds % 3600) / 60
        return "\(h)h \(m)m"
    }
}
