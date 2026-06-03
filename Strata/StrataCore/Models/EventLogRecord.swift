import Foundation

/// A single Windows Event Log record parsed out of an .evtx file.
/// Channel + provider + eventID identify what kind of event; payload holds
/// the EventData/UserData XML fragment for analyzer rules to consume.
public nonisolated struct EventLogRecord: Identifiable, Hashable, Sendable, Codable {
    public let id: UUID
    public let recordNumber: UInt64
    public let writtenAt: Date
    public let eventID: UInt32
    public let level: UInt8           // 1=Critical, 2=Error, 3=Warning, 4=Info, 5=Verbose
    public let channel: String        // e.g. "Security", "Microsoft-Windows-Sysmon/Operational"
    public let provider: String       // e.g. "Microsoft-Windows-Security-Auditing"
    public let computer: String
    public let payloadXML: String     // the inner <EventData>/<UserData> block, verbatim
    public let sourceFile: String     // path of the .evtx the record came from

    public init(id: UUID = UUID(), recordNumber: UInt64, writtenAt: Date,
                eventID: UInt32, level: UInt8, channel: String, provider: String,
                computer: String, payloadXML: String, sourceFile: String) {
        self.id = id
        self.recordNumber = recordNumber
        self.writtenAt = writtenAt
        self.eventID = eventID
        self.level = level
        self.channel = channel
        self.provider = provider
        self.computer = computer
        self.payloadXML = payloadXML
        self.sourceFile = sourceFile
    }
}
