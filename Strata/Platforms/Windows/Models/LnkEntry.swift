import Foundation

/// A parsed Windows Shell Link (`.lnk`) — a shortcut file.
///
/// LNKs are high-signal in DFIR for two reasons. First, they're **file-access
/// evidence**: Windows auto-creates them in `Recent\` when a user opens a
/// document, recording the target's path, size, and MAC timestamps *as of the
/// access* — which survives the target's deletion. Second, malicious LNKs are a
/// common delivery lure, smuggling a payload in their **command-line arguments**
/// (e.g. a one-liner `powershell -enc ...`) behind an innocuous icon.
///
/// Distributed-link-tracking data can also tie the shortcut to the **machine**
/// it was created on (NetBIOS name) and the source volume (serial/label) —
/// useful for correlating movement across hosts.
///
/// Produced by `LnkParser` (liblnk's `lnkinfo`); persisted per host as `lnk.json`.
public nonisolated struct LnkEntry: Identifiable, Hashable, Sendable, Codable {
    public let id: UUID
    /// Path of the `.lnk` file itself.
    public let sourceFile: String
    /// Target local path (e.g. `C:\Windows\System32\cmd.exe`), if present.
    public let localPath: String?
    /// Target UNC/network path (e.g. `\\server\share\x.exe`), if present.
    public let networkPath: String?
    public let description: String?
    /// Command-line arguments embedded in the shortcut — the prime malicious-LNK
    /// signal.
    public let arguments: String?
    public let workingDirectory: String?
    public let iconLocation: String?
    /// Target file size recorded in the link.
    public let targetSize: Int64?
    public let targetCreated: Date?
    public let targetModified: Date?
    public let targetAccessed: Date?
    public let driveType: String?
    public let volumeLabel: String?
    public let volumeSerial: String?
    /// NetBIOS name of the machine where the shortcut was created (from the
    /// distributed-link-tracking block), if present.
    public let machineIdentifier: String?

    public init(id: UUID = UUID(), sourceFile: String, localPath: String? = nil,
                networkPath: String? = nil, description: String? = nil, arguments: String? = nil,
                workingDirectory: String? = nil, iconLocation: String? = nil, targetSize: Int64? = nil,
                targetCreated: Date? = nil, targetModified: Date? = nil, targetAccessed: Date? = nil,
                driveType: String? = nil, volumeLabel: String? = nil, volumeSerial: String? = nil,
                machineIdentifier: String? = nil) {
        self.id = id
        self.sourceFile = sourceFile
        self.localPath = localPath
        self.networkPath = networkPath
        self.description = description
        self.arguments = arguments
        self.workingDirectory = workingDirectory
        self.iconLocation = iconLocation
        self.targetSize = targetSize
        self.targetCreated = targetCreated
        self.targetModified = targetModified
        self.targetAccessed = targetAccessed
        self.driveType = driveType
        self.volumeLabel = volumeLabel
        self.volumeSerial = volumeSerial
        self.machineIdentifier = machineIdentifier
    }

    /// Best target path: local first, then network.
    public var targetPath: String? { localPath ?? networkPath }

    /// Display name: the `.lnk` file's own name (without extension), falling back
    /// to the target's last path component.
    public var name: String {
        let lnk = sourceFile.split(whereSeparator: { $0 == "\\" || $0 == "/" }).last.map(String.init)
        if let lnk, !lnk.isEmpty {
            return lnk.lowercased().hasSuffix(".lnk") ? String(lnk.dropLast(4)) : lnk
        }
        return targetPath?.split(whereSeparator: { $0 == "\\" || $0 == "/" }).last.map(String.init) ?? "(shortcut)"
    }
}
