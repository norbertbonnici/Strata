import Foundation

/// One message summarised from the macOS **Mail** `Envelope Index` database
/// (`~/Library/Mail/V*/MailData/Envelope Index`) — sender, recipients, subject,
/// dates, and the owning mailbox.
///
/// The Envelope Index is Mail's SQLite index over every message (the bodies live
/// in per-message `.emlx` files); it's the efficient forensic summary of mail
/// activity — communications, phishing delivery, exfil-over-email, and the social
/// graph — without walking thousands of message files. Pure / `Sendable` / no I/O
/// (the macOS-only `MailParser` reads the SQLite database via GRDB).
public nonisolated struct MailMessageEntry: Identifiable, Hashable, Sendable, Codable {
    public let id: UUID
    public let subject: String?
    /// Sender email address.
    public let sender: String?
    /// Sender display name (the address-book comment), when present.
    public let senderDisplay: String?
    /// Aggregated recipient addresses (to + cc).
    public let recipients: String?
    public let dateSent: Date?
    public let dateReceived: Date?
    /// Owning mailbox URL — `imap://user@host/INBOX`, a local path, etc. Encodes
    /// the account + folder (Inbox / Sent / Junk …).
    public let mailbox: String?
    public let scope: String
    public let sourceFile: String

    public init(id: UUID = UUID(), subject: String? = nil, sender: String? = nil,
                senderDisplay: String? = nil, recipients: String? = nil,
                dateSent: Date? = nil, dateReceived: Date? = nil, mailbox: String? = nil,
                scope: String, sourceFile: String) {
        self.id = id
        self.subject = subject
        self.sender = sender
        self.senderDisplay = senderDisplay
        self.recipients = recipients
        self.dateSent = dateSent
        self.dateReceived = dateReceived
        self.mailbox = mailbox
        self.scope = scope
        self.sourceFile = sourceFile
    }

    public var timestamp: Date? { dateReceived ?? dateSent }

    /// A message in a "Sent" mailbox is outbound; everything else inbound.
    public var isSent: Bool {
        guard let m = mailbox?.lowercased() else { return false }
        return m.contains("/sent") || m.hasSuffix("sent messages") || m.hasSuffix("sent")
    }

    public var direction: String { isSent ? "Sent" : "Received" }

    /// The other party: recipients for a sent message, the sender for a received.
    public var counterpart: String {
        let other = isSent ? recipients : sender
        if let other, !other.isEmpty { return other }
        return "unknown"
    }

    public var displaySubject: String {
        if let s = subject, !s.isEmpty { return s }
        return "(no subject)"
    }

    public var timelineSummary: String {
        "[Mail] \(direction) \(isSent ? "to" : "from") \(counterpart): \(displaySubject)"
    }

    // MARK: - Pure decoder (testable; no I/O)

    /// Convert an Envelope Index `date_sent` / `date_received` (Unix epoch
    /// seconds) to a `Date`. Returns nil for 0 / negative.
    public static func mailTime(_ raw: Int64?) -> Date? {
        guard let raw, raw > 0 else { return nil }
        return Date(timeIntervalSince1970: Double(raw))
    }
}
