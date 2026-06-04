import Foundation

/// Kind of indicator the analyst has loaded. Drives both display (badge,
/// colour) and which matching strategy applies - IPs get an exact-match
/// fast path against structured logon fields, the rest are substring scans.
public enum IOCKind: String, CaseIterable, Codable, Sendable, Hashable {
    case ip
    case domain
    case url
    case hash

    public var label: String {
        switch self {
        case .ip:     return "IP"
        case .domain: return "Domain"
        case .url:    return "URL"
        case .hash:   return "Hash"
        }
    }

    /// Best-guess classification for a raw pasted token. We default to
    /// .domain because most "loose" pastes from threat reports are domains
    /// (everything else - URLs, hashes, IPs - has a recognisable shape).
    public static func classify(_ token: String) -> IOCKind {
        let s = token.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        if s.hasPrefix("http://") || s.hasPrefix("https://") { return .url }
        if isHash(s) { return .hash }
        if isIPv4(s) || isIPv6(s) { return .ip }
        return .domain
    }

    private static func isHash(_ s: String) -> Bool {
        let hex = CharacterSet(charactersIn: "0123456789abcdef")
        return [32, 40, 64].contains(s.count)
            && s.unicodeScalars.allSatisfy { hex.contains($0) }
    }

    private static func isIPv4(_ s: String) -> Bool {
        let parts = s.split(separator: ".")
        guard parts.count == 4 else { return false }
        return parts.allSatisfy { p in
            guard let n = Int(p), (0...255).contains(n) else { return false }
            return true
        }
    }

    private static func isIPv6(_ s: String) -> Bool {
        // Cheap heuristic so we don't depend on Network.framework here -
        // colons plus only hex/colon chars rules in :: addresses but rules
        // out anything else.
        if !s.contains(":") { return false }
        let allowed = CharacterSet(charactersIn: "0123456789abcdef:")
        return s.unicodeScalars.allSatisfy { allowed.contains($0) }
    }
}

public struct IOC: Identifiable, Hashable, Sendable, Codable {
    public let id: UUID
    public var kind: IOCKind
    public var value: String
    public var note: String

    public init(id: UUID = UUID(), kind: IOCKind, value: String, note: String = "") {
        self.id = id; self.kind = kind; self.value = value; self.note = note
    }
}

/// Where in the case an IOC was found. Holds enough back-reference to let
/// the UI link the user to the originating event / registry value / file.
public struct IOCMatch: Identifiable, Hashable, Sendable, Codable {
    public let id: UUID
    public let iocValue: String
    public let iocKind: IOCKind
    public let location: Location
    public let context: String
    public let timestamp: Date?

    public enum Location: Hashable, Sendable, Codable {
        case event(eventID: UInt32, recordNumber: UInt64, channel: String, sourceFile: String)
        case registry(hive: String, path: String, name: String)
        case file(path: String)
    }

    public init(id: UUID = UUID(), iocValue: String, iocKind: IOCKind,
                location: Location, context: String, timestamp: Date?) {
        self.id = id; self.iocValue = iocValue; self.iocKind = iocKind
        self.location = location; self.context = context; self.timestamp = timestamp
    }

    public var summary: String {
        switch location {
        case .event(let eid, _, let channel, _):
            return "\(channel) EID \(eid)"
        case .registry(_, let path, let name):
            return name.isEmpty ? path : "\(path)\\\(name)"
        case .file(let path):
            return path
        }
    }
}
