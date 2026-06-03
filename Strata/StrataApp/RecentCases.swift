import Foundation

/// Tracks the last ~10 case bundles the user opened, keyed in UserDefaults
/// as plain filesystem paths. Entries whose bundle no longer exists are
/// filtered on read so stale ones don't appear in the welcome list.
enum RecentCases {
    private static let key = "StrataRecentCasePaths"
    private static let limit = 10

    static func load() -> [URL] {
        guard let paths = UserDefaults.standard.array(forKey: key) as? [String] else { return [] }
        return paths.compactMap { path in
            let url = URL(fileURLWithPath: path)
            return FileManager.default.fileExists(atPath: url.path) ? url : nil
        }
    }

    static func record(_ url: URL) {
        var paths = (UserDefaults.standard.array(forKey: key) as? [String]) ?? []
        paths.removeAll { $0 == url.path }
        paths.insert(url.path, at: 0)
        if paths.count > limit { paths = Array(paths.prefix(limit)) }
        UserDefaults.standard.set(paths, forKey: key)
    }
}
