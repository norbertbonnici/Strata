import Foundation

/// Pure, cross-platform parser for a macOS launchd `.plist` job description.
///
/// launchd job files come in **both** XML and binary property-list encodings
/// (Apple's stock jobs are frequently binary; hand-authored / dropped malware
/// plists are often XML). `PropertyListSerialization` transparently decodes
/// either, so a single code path covers both. No I/O — the caller hands us the
/// raw bytes (extracted via icat for images, or read in place for a loose
/// collection) plus the on-disk path the bytes came from.
public enum LaunchItemParser {
    /// Parse one launchd plist. Returns `nil` only when the bytes aren't a
    /// dictionary property list at all (an empty/corrupt file). A valid plist
    /// missing individual keys still yields an entry — absence is itself signal.
    ///
    /// - Parameters:
    ///   - data: raw `.plist` bytes (XML or binary).
    ///   - plistPath: the path the bytes were read from; the launchd *scope* is
    ///     derived from it.
    public static func parse(data: Data, plistPath: String) -> LaunchItemEntry? {
        guard
            let object = try? PropertyListSerialization.propertyList(from: data, options: [], format: nil),
            let dict = object as? [String: Any]
        else { return nil }

        let scope = self.scope(for: plistPath)

        let label = (dict["Label"] as? String)?.trimmingCharacters(in: .whitespacesAndNewlines)
        let resolvedLabel = (label?.isEmpty == false ? label! : (plistPath as NSString).lastPathComponent)

        let program = (dict["Program"] as? String).flatMap { $0.isEmpty ? nil : $0 }

        // ProgramArguments is an array of strings; tolerate stray non-strings.
        let programArguments = (dict["ProgramArguments"] as? [Any])?
            .compactMap { $0 as? String } ?? []

        let runAtLoad = boolValue(dict["RunAtLoad"])

        let startInterval = intValue(dict["StartInterval"])

        let watchPaths = (dict["WatchPaths"] as? [Any])?
            .compactMap { $0 as? String } ?? []

        return LaunchItemEntry(
            label: resolvedLabel,
            program: program,
            programArguments: programArguments,
            runAtLoad: runAtLoad,
            startInterval: startInterval,
            watchPaths: watchPaths,
            scope: scope,
            plistPath: plistPath)
    }

    /// Map an on-disk launchd path to its domain. Order matters: the
    /// system-wide `/Library/LaunchAgents` and a user `~/Library/LaunchAgents`
    /// both end in `Library/LaunchAgents`, so the absolute-system case is tested
    /// first and the home-relative case catches the rest.
    static func scope(for path: String) -> LaunchItemEntry.Scope {
        let lower = path.lowercased()
        if lower.contains("/library/launchdaemons/") || lower.hasPrefix("/library/launchdaemons") {
            return .systemDaemon
        }
        if lower.hasPrefix("/library/launchagents") || lower.contains("/system/library/launchagents") {
            return .systemAgent
        }
        // Anything else carrying Library/LaunchAgents is a per-user agent
        // (e.g. /Users/alice/Library/LaunchAgents, /private/var/root/…).
        if lower.contains("/library/launchagents") {
            return .userAgent
        }
        // Daemons can also surface under non-root system trees; default the
        // remainder to a daemon only when the path names LaunchDaemons, else
        // treat an unknown launchd path as a user agent (least-privilege guess).
        if lower.contains("/library/launchdaemons") { return .systemDaemon }
        return .userAgent
    }

    /// launchd accepts `<true/>`/`<false/>`, but also numeric/string truthy
    /// forms in hand-edited plists — coerce all of them.
    private static func boolValue(_ value: Any?) -> Bool {
        switch value {
        case let b as Bool:   return b
        case let n as NSNumber: return n.boolValue
        case let s as String: return ["true", "yes", "1"].contains(s.lowercased())
        default:              return false
        }
    }

    private static func intValue(_ value: Any?) -> Int? {
        switch value {
        case let n as NSNumber: return n.intValue
        case let i as Int:      return i
        case let s as String:   return Int(s)
        default:                return nil
        }
    }
}
