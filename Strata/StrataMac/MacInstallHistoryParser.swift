import Foundation

/// Pure parser for macOS `/Library/Receipts/InstallHistory.plist` — an array of
/// install records (`date`, `displayName`, `displayVersion`, `processName`).
/// Cross-platform / no I/O: the caller supplies the raw plist bytes (extracted
/// via `fsapfscat`/`icat` for images, or read in place for a loose collection).
public enum MacInstallHistoryParser {

    /// Parse the plist into install events, newest first.
    public static func parse(_ data: Data, sourceFile: String) -> [MacInstallEvent] {
        guard let array = (try? PropertyListSerialization.propertyList(from: data, options: [], format: nil))
                as? [[String: Any]] else { return [] }
        let events = array.compactMap { dict -> MacInstallEvent? in
            guard let name = (dict["displayName"] as? String)?
                .trimmingCharacters(in: .whitespacesAndNewlines), !name.isEmpty else { return nil }
            return MacInstallEvent(
                date: dict["date"] as? Date,
                name: name,
                version: nonEmpty(dict["displayVersion"] as? String),
                process: nonEmpty(dict["processName"] as? String),
                sourceFile: sourceFile)
        }
        return events.sorted { ($0.date ?? .distantPast) > ($1.date ?? .distantPast) }
    }

    /// The host's macOS version from the install history: the most recent macOS
    /// install/update entry's version (e.g. "12.7.6"). nil if none recorded.
    /// Used as the OS-version fallback for the Overview host card when the
    /// sealed System volume's `SystemVersion.plist` is unreadable.
    public static func latestOSVersion(in events: [MacInstallEvent]) -> String? {
        events
            .filter { $0.isOSInstall }
            .max { ($0.date ?? .distantPast) < ($1.date ?? .distantPast) }?
            .version
    }

    /// Fold the recovered OS version into a `MacHostInfo` when it doesn't
    /// already have one (SystemVersion.plist takes precedence when available).
    public static func applyOSVersion(_ events: [MacInstallEvent], to info: inout MacHostInfo) {
        guard info.productVersion == nil, let version = latestOSVersion(in: events) else { return }
        info.productVersion = version
        if info.productName == nil { info.productName = "macOS" }
    }

    private static func nonEmpty(_ s: String?) -> String? {
        guard let s, !s.isEmpty else { return nil }
        return s
    }
}
