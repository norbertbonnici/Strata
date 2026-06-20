import Foundation

/// One entry from the macOS **Background Task Management** store (`*.btm`,
/// macOS 13+) — the authoritative modern inventory of registered login items,
/// launch agents, and daemons. It captures user-approved background items and
/// developer-registered agents that a raw launchd-plist sweep can miss, so a
/// non-Apple one (especially in a staging path, or disabled) is a persistence /
/// evasion signal (ATT&CK T1547.015 Login Items / T1543).
///
/// The `.btm` is an NSKeyedArchiver graph of Apple-private classes, so fields are
/// recovered **leniently** (by ivar-name) and may be partial; there's no reliable
/// per-item timestamp, so no timeline projection.
public nonisolated struct MacBackgroundItem: Identifiable, Hashable, Sendable, Codable {
    public let id: UUID
    public let name: String
    /// Executable URL / path, when recovered.
    public let executable: String?
    public let bundleID: String?
    public let developerName: String?
    public let teamID: String?
    /// Raw BTM type bitmask (app / login item / agent / daemon — approximate).
    public let typeRaw: Int?
    /// Raw BTM disposition bitmask (bit 0 = enabled).
    public let disposition: Int?
    public let scope: String
    public let sourceFile: String

    public init(id: UUID = UUID(), name: String, executable: String? = nil,
                bundleID: String? = nil, developerName: String? = nil, teamID: String? = nil,
                typeRaw: Int? = nil, disposition: Int? = nil, scope: String, sourceFile: String) {
        self.id = id
        self.name = name
        self.executable = executable
        self.bundleID = bundleID
        self.developerName = developerName
        self.teamID = teamID
        self.typeRaw = typeRaw
        self.disposition = disposition
        self.scope = scope
        self.sourceFile = sourceFile
    }

    /// BTM disposition bit 0 is the enabled flag (nil when disposition unknown).
    public var enabled: Bool? { disposition.map { ($0 & 0x1) != 0 } }

    public var isApple: Bool {
        if bundleID?.lowercased().hasPrefix("com.apple.") == true { return true }
        if developerName?.lowercased() == "apple" { return true }
        return false
    }

    public var title: String {
        if !name.isEmpty { return name }
        return bundleID ?? executable ?? "Background item"
    }

    /// Coarse type hint from the (approximate) BTM type bitmask.
    public var typeLabel: String {
        guard let t = typeRaw else { return "—" }
        var parts: [String] = []
        if t & 0x2 != 0 { parts.append("app") }
        if t & 0x4 != 0 { parts.append("login item") }
        if t & 0x8 != 0 { parts.append("agent") }
        if t & 0x10 != 0 { parts.append("daemon") }
        return parts.isEmpty ? "type \(t)" : parts.joined(separator: "/")
    }
}
