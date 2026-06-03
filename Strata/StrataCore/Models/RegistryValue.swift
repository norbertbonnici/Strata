import Foundation

/// A single key/value pair extracted from a Windows registry hive.
/// `path` is the full backslash-delimited key path (e.g.
/// "Microsoft\\Windows\\CurrentVersion\\Run"); `name` is the value name
/// inside that key ("" for the key's default value).
public nonisolated struct RegistryValue: Identifiable, Hashable, Sendable, Codable {
    public let id: UUID
    public let hive: String              // "SYSTEM", "SOFTWARE", "NTUSER", ...
    public let path: String              // key path inside the hive
    public let name: String              // value name, empty for default
    public let type: ValueType
    public let data: String              // string-rendered for now; raw bytes can come later
    public let lastWritten: Date?        // key's last-written time, when libregf surfaces it
    public let sourceFile: String        // hive path inside the image

    public init(id: UUID = UUID(), hive: String, path: String, name: String,
                type: ValueType, data: String, lastWritten: Date? = nil,
                sourceFile: String) {
        self.id = id; self.hive = hive; self.path = path; self.name = name
        self.type = type; self.data = data; self.lastWritten = lastWritten
        self.sourceFile = sourceFile
    }

    public var fullPath: String {
        let trimmed = path.trimmingCharacters(in: CharacterSet(charactersIn: "\\/"))
        return "\(hive)\\\(trimmed)"
    }

    /// Subset of REG_* types we surface. Anything libregf prints that isn't
    /// here lands in `.other` so we don't lose visibility.
    public enum ValueType: String, Sendable, Codable {
        case sz             = "REG_SZ"
        case expandSz       = "REG_EXPAND_SZ"
        case binary         = "REG_BINARY"
        case dword          = "REG_DWORD"
        case dwordBigEndian = "REG_DWORD_BIG_ENDIAN"
        case multiSz        = "REG_MULTI_SZ"
        case qword          = "REG_QWORD"
        case none           = "REG_NONE"
        case other          = "OTHER"

        public init(label: String) {
            self = ValueType(rawValue: label.uppercased()) ?? .other
        }
    }
}
