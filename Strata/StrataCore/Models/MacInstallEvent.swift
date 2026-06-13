import Foundation

/// One entry from the macOS software **install history**
/// (`/Library/Receipts/InstallHistory.plist`): an OS update, an App Store app,
/// or a `.pkg` installer run, with the date and the process that did it.
///
/// Forensically this is a software-install timeline (T1072 / supply-chain
/// context) **and** the most reliable on-disk record of the host's macOS
/// version when the sealed System volume's `SystemVersion.plist` can't be read
/// (its content lives in an APFS snapshot libfsapfs cannot open).
public nonisolated struct MacInstallEvent: Identifiable, Hashable, Sendable, Codable {
    public let id: UUID
    public let date: Date?
    /// `displayName`, e.g. "macOS 12.7.6", "Xcode", "Safari".
    public let name: String
    /// `displayVersion`, e.g. "12.7.6", "16.2".
    public let version: String?
    /// `processName` that performed the install (`softwareupdated`,
    /// `installer`, `storedownloadd`, …).
    public let process: String?
    public let sourceFile: String

    public init(id: UUID = UUID(), date: Date?, name: String, version: String?,
                process: String?, sourceFile: String) {
        self.id = id
        self.date = date
        self.name = name
        self.version = version
        self.process = process
        self.sourceFile = sourceFile
    }

    /// True when this entry records a macOS install/update (vs an app/pkg).
    public var isOSInstall: Bool {
        let n = name.lowercased()
        return n.hasPrefix("macos") || n.hasPrefix("os x") || n.hasPrefix("mac os x")
    }
}
