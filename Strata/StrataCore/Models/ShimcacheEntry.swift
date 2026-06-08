import Foundation

/// One entry from the Windows Application Compatibility Cache ("Shimcache" /
/// AppCompatCache), stored as a single REG_BINARY value in the SYSTEM hive at
/// `ControlSet00x\Control\Session Manager\AppCompatCache`.
///
/// Forensic meaning — read this carefully: Shimcache proves a file was
/// **present / known to the system** (its path was seen by the application-
/// compatibility subsystem), NOT that it executed. There is no reliable
/// execution flag (none at all on Win10/11), so we never surface one. The
/// `lastModified` time is the file's `$STANDARD_INFORMATION` modified time at
/// cache time — timestomp-susceptible — not a run time. The one tamper-resistant
/// signal is `insertionOrder`: the cache is maintained most-recently-inserted
/// first, independent of file timestamps.
public nonisolated struct ShimcacheEntry: Identifiable, Hashable, Sendable, Codable {
    public enum Version: String, Sendable, Codable {
        case windows10, windows81, windows8, windows7, windowsXP, unknown
    }

    public let id: UUID
    /// Executable path as recorded (often a full path, sometimes an NT device path).
    public let path: String
    /// File `$SI` modified time at cache time — NOT an execution time; nil when
    /// unset or implausible.
    public let lastModified: Date?
    /// Position in the cache, 0 == most recently inserted. Independent of file
    /// timestamps, so resistant to timestomping.
    public let insertionOrder: Int
    /// Format this entry was decoded with.
    public let version: Version
    /// Source hive path.
    public let sourceFile: String

    public init(id: UUID = UUID(), path: String, lastModified: Date?, insertionOrder: Int,
                version: Version, sourceFile: String) {
        self.id = id
        self.path = path
        self.lastModified = lastModified
        self.insertionOrder = insertionOrder
        self.version = version
        self.sourceFile = sourceFile
    }

    /// Display name: the path's last component.
    public var name: String {
        path.split(whereSeparator: { $0 == "\\" || $0 == "/" }).last.map(String.init) ?? path
    }
}
