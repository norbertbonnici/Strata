import Foundation

/// Tracks the last ~10 case bundles the user opened, stored in UserDefaults as
/// security-scoped bookmarks rather than raw paths. On iOS (mandatorily
/// sandboxed) a raw path can't reopen a bundle outside the app container, so
/// the recents list silently dropped every out-of-container case; a bookmark
/// resolves back to an accessible, security-scoped URL. On the (currently
/// non-sandboxed) macOS build a plain bookmark behaves like a path and keeps
/// working, while being forward-compatible if the App Sandbox is enabled later.
enum RecentCases {
    private static let key = "StrataRecentCaseBookmarks"
    private static let limit = 10

    static func load() -> [URL] {
        guard let datas = UserDefaults.standard.array(forKey: key) as? [Data] else { return [] }
        return datas.compactMap { resolve($0) }
    }

    static func record(_ url: URL) {
        guard let data = bookmark(for: url) else { return }   // skip silently on failure
        var datas = (UserDefaults.standard.array(forKey: key) as? [Data]) ?? []
        let target = url.standardizedFileURL
        datas.removeAll { resolve($0)?.standardizedFileURL == target }
        datas.insert(data, at: 0)
        if datas.count > limit { datas = Array(datas.prefix(limit)) }
        UserDefaults.standard.set(datas, forKey: key)
    }

    private static func bookmark(for url: URL) -> Data? {
        #if os(macOS)
        // Security-scoped bookmarks require the App Sandbox + entitlement, which
        // this build doesn't have, so a plain bookmark is correct here.
        return try? url.bookmarkData(includingResourceValuesForKeys: nil, relativeTo: nil)
        #else
        return try? url.bookmarkData(options: .minimalBookmark,
                                     includingResourceValuesForKeys: nil, relativeTo: nil)
        #endif
    }

    private static func resolve(_ data: Data) -> URL? {
        var stale = false
        let url = try? URL(resolvingBookmarkData: data, options: [],
                           relativeTo: nil, bookmarkDataIsStale: &stale)
        #if os(macOS)
        // On a non-sandboxed build the resolved path is directly readable, so we
        // can prune bundles that have since been deleted/moved-away.
        if let url, !FileManager.default.fileExists(atPath: url.path) { return nil }
        #endif
        return url
    }
}
