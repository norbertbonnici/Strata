import Foundation

/// One `.strata` case discovered in the Case Library folder.
struct LibraryCase: Identifiable, Hashable, Sendable {
    let url: URL            // the .strata bundle URL (may not exist on disk yet if !isDownloaded)
    let isDownloaded: Bool  // false for an iCloud/Files-provider placeholder not yet pulled local
    var name: String { url.deletingPathExtension().lastPathComponent }
    var id: String { url.standardizedFileURL.path }
}

/// The "Case Library" - a single user-chosen folder that holds `.strata` cases,
/// remembered as a security-scoped bookmark. It is transport-agnostic: the
/// folder can live in iCloud Drive, on a mounted SMB/WebDAV share, or locally.
/// macOS saves new cases here and both apps list cases from it.
enum CaseLibrary {
    private static let key = "StrataCaseLibraryBookmark"

    // MARK: Remembered location (security-scoped bookmark)

    static func savedURL() -> URL? {
        guard let data = UserDefaults.standard.data(forKey: key) else { return nil }
        var stale = false
        let url = try? URL(resolvingBookmarkData: data, options: [],
                           relativeTo: nil, bookmarkDataIsStale: &stale)
        return url
    }

    static func setURL(_ url: URL) {
        if let data = bookmark(for: url) {
            UserDefaults.standard.set(data, forKey: key)
        }
    }

    static func clear() { UserDefaults.standard.removeObject(forKey: key) }

    private static func bookmark(for url: URL) -> Data? {
        #if os(macOS)
        // Plain bookmark: a security-scoped one needs the App Sandbox + entitlement
        // this (non-sandboxed) build doesn't have. The library folder is read via
        // normal file access.
        return try? url.bookmarkData(includingResourceValuesForKeys: nil, relativeTo: nil)
        #else
        return try? url.bookmarkData(options: .minimalBookmark,
                                     includingResourceValuesForKeys: nil, relativeTo: nil)
        #endif
    }

    // MARK: Listing

    /// `.strata` cases inside `folder`, including iCloud/Files-provider items that
    /// haven't been downloaded yet (surfaced as placeholders so the UI can offer
    /// to download them). Caller holds the security scope on `folder` if needed.
    static func cases(in folder: URL) -> [LibraryCase] {
        let fm = FileManager.default
        guard let entries = try? fm.contentsOfDirectory(
            at: folder, includingPropertiesForKeys: [.isDirectoryKey], options: []
        ) else { return [] }

        var result: [LibraryCase] = []
        for entry in entries {
            let name = entry.lastPathComponent
            if name.hasSuffix(".strata") {
                result.append(LibraryCase(url: entry, isDownloaded: true))
            } else if let realName = placeholderCaseName(name) {
                // Not-yet-downloaded iCloud item: ".<Name>.strata.icloud"
                result.append(LibraryCase(url: folder.appendingPathComponent(realName),
                                          isDownloaded: false))
            }
        }
        return result.sorted { $0.name.localizedStandardCompare($1.name) == .orderedAscending }
    }

    /// Map an iCloud placeholder filename (".Case.strata.icloud") back to the real
    /// bundle name ("Case.strata"); nil if it isn't such a placeholder.
    static func placeholderCaseName(_ filename: String) -> String? {
        guard filename.hasPrefix("."), filename.hasSuffix(".strata.icloud") else { return nil }
        let inner = filename.dropFirst().dropLast(".icloud".count)   // "Case.strata"
        return inner.hasSuffix(".strata") ? String(inner) : nil
    }

    // MARK: Convenience default (macOS)

    /// The user's iCloud Drive root, if present - a reasonable default library
    /// location to offer on macOS (non-sandboxed, so the path is directly
    /// readable). iOS picks its library via the document picker instead.
    static var iCloudDriveURL: URL? {
        #if os(macOS)
        let path = ("~/Library/Mobile Documents/com~apple~CloudDocs" as NSString).expandingTildeInPath
        let url = URL(fileURLWithPath: path, isDirectory: true)
        return FileManager.default.fileExists(atPath: url.path) ? url : nil
        #else
        return nil
        #endif
    }
}
