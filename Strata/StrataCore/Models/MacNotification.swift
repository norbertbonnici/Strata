import Foundation

/// One macOS **Notification Center** record (`db2/db`) — a notification the
/// system delivered, with its app, title/body, and time.
///
/// Forensic context: corroborates app activity (what ran and notified, and when),
/// and the title/body can preserve message previews, 2FA codes, or phishing /
/// social-engineering content. Pure / `Sendable` / no I/O — the macOS-only
/// `NotificationParser` reads the SQLite store via GRDB and recovers the body
/// from the per-record `data` bplist via `BinaryPlist`.
public nonisolated struct MacNotification: Identifiable, Hashable, Sendable, Codable {
    public let id: UUID
    /// Emitting app's bundle identifier.
    public let appID: String?
    public let title: String?
    public let body: String?
    public let deliveredDate: Date?
    public let scope: String
    public let sourceFile: String

    public init(id: UUID = UUID(), appID: String? = nil, title: String? = nil,
                body: String? = nil, deliveredDate: Date? = nil, scope: String, sourceFile: String) {
        self.id = id
        self.appID = appID
        self.title = title
        self.body = body
        self.deliveredDate = deliveredDate
        self.scope = scope
        self.sourceFile = sourceFile
    }

    public var timestamp: Date? { deliveredDate }

    public var displayTitle: String {
        if let t = title, !t.isEmpty { return t }
        if let b = body, !b.isEmpty { return b }
        return appID ?? "notification"
    }

    public var timelineSummary: String {
        let who = appID ?? "app"
        let what = [title, body].compactMap { $0 }.first { !$0.isEmpty } ?? ""
        return "[Notification] \(who): \(what)"
    }
}
