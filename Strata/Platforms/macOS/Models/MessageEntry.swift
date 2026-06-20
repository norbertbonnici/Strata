import Foundation

/// One reconstructed row from the macOS **Messages** database
/// (`~/Library/Messages/chat.db`) — an iMessage / SMS message with its direction,
/// counterpart handle, text, and timestamp.
///
/// Messages are high-value for **delivery** (phishing links, malicious
/// attachments), insider-threat / exfil-over-messaging, and the social graph
/// around an incident. `chat.db` is SQLite, so — like browser history — there's
/// no vendored tool; the macOS-only `MessagesParser` reads it with GRDB and
/// builds these value types (pure / `Sendable` / no I/O, so they're testable
/// off-main and usable on iOS).
public nonisolated struct MessageEntry: Identifiable, Hashable, Sendable, Codable {
    public let id: UUID
    public let guid: String?
    /// Delivery service, e.g. "iMessage" or "SMS".
    public let service: String?
    /// The other party's handle (phone number / Apple ID email).
    public let handle: String?
    /// True for messages sent *from* this Mac's owner.
    public let isFromMe: Bool
    public let text: String?
    public let timestamp: Date?
    public let hasAttachment: Bool
    /// Group-chat display name, when the message belongs to a named chat.
    public let chatName: String?
    public let scope: String
    public let sourceFile: String

    public init(id: UUID = UUID(), guid: String? = nil, service: String? = nil,
                handle: String? = nil, isFromMe: Bool, text: String? = nil,
                timestamp: Date?, hasAttachment: Bool = false, chatName: String? = nil,
                scope: String, sourceFile: String) {
        self.id = id
        self.guid = guid
        self.service = service
        self.handle = handle
        self.isFromMe = isFromMe
        self.text = text
        self.timestamp = timestamp
        self.hasAttachment = hasAttachment
        self.chatName = chatName
        self.scope = scope
        self.sourceFile = sourceFile
    }

    public var direction: String { isFromMe ? "Sent" : "Received" }

    /// The conversation counterpart: the handle, else the group-chat name.
    public var counterpart: String {
        if let h = handle, !h.isEmpty { return h }
        if let c = chatName, !c.isEmpty { return c }
        return "unknown"
    }

    /// Short one-line body for tables/timeline (attachment-only rows are labelled).
    public var preview: String {
        if let t = text, !t.isEmpty {
            let flat = t.replacingOccurrences(of: "\n", with: " ")
            return flat.count > 140 ? String(flat.prefix(140)) + "…" : flat
        }
        return hasAttachment ? "(attachment)" : "(no text)"
    }

    public var timelineSummary: String {
        "[Messages\(service.map { " \($0)" } ?? "")] \(direction) \(counterpart): \(preview)"
    }

    // MARK: - Pure decoder (testable; no I/O)

    /// Convert a `chat.db` `message.date` to a `Date`. Modern Messages stores
    /// **nanoseconds** since the 2001-01-01 `CFAbsoluteTime` epoch; pre-10.13
    /// stored **seconds**. A recent nanosecond value is ~1e18 while a recent
    /// second value is ~7e8, so a 1e11 threshold disambiguates them. Returns nil
    /// for 0 / negative.
    public static func appleTime(_ raw: Int64?) -> Date? {
        guard let raw, raw > 0 else { return nil }
        let seconds = raw > 100_000_000_000 ? Double(raw) / 1_000_000_000 : Double(raw)
        return Date(timeIntervalSince1970: seconds + 978_307_200)
    }
}
