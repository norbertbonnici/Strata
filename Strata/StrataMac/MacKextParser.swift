import Foundation

/// Parses macOS kernel-extension + System-Extension inventory:
///
///  - A **kext bundle** `Info.plist` (`Foo.kext/Contents/Info.plist`) → one
///    `MacKextEntry` from `CFBundleIdentifier` / `CFBundleName` / version.
///  - The **System Extensions database** (`/Library/SystemExtensions/db.plist`),
///    walked leniently (like the recent-items parser) for any dict carrying an
///    `identifier`, so the parser survives the format drift across macOS releases.
public enum MacKextParser {

    /// One kext bundle's `Info.plist` → a `.kext` entry (nil if no bundle id).
    public static func parseKextInfo(data: Data, sourceFile: String, scope: String) -> MacKextEntry? {
        guard let dict = (try? PropertyListSerialization.propertyList(from: data, options: [], format: nil)) as? [String: Any],
              let bundleID = (dict["CFBundleIdentifier"] as? String), !bundleID.isEmpty else {
            return nil
        }
        let name = (dict["CFBundleName"] as? String)
            ?? (dict["CFBundleExecutable"] as? String)
            ?? bundleName(fromKextPath: sourceFile)
            ?? bundleID
        let version = (dict["CFBundleShortVersionString"] as? String) ?? (dict["CFBundleVersion"] as? String)
        return MacKextEntry(kind: .kext, bundleID: bundleID, name: name, version: version,
                            teamID: nil, path: kextBundlePath(sourceFile), enabled: nil,
                            scope: scope, sourceFile: sourceFile)
    }

    /// The System Extensions `db.plist` → `.systemExtension` entries.
    public static func parseSystemExtensionsDB(data: Data, sourceFile: String, scope: String) -> [MacKextEntry] {
        guard let root = try? PropertyListSerialization.propertyList(from: data, options: [], format: nil) else {
            return []
        }
        var out: [MacKextEntry] = []
        var seen = Set<String>()
        walk(root) { dict in
            guard let identifier = (dict["identifier"] as? String) ?? (dict["bundleIdentifier"] as? String),
                  !identifier.isEmpty else { return }
            let path = (dict["bundlePath"] as? String) ?? (dict["container"] as? [String: Any]).flatMap { $0["bundlePath"] as? String }
            let team = (dict["teamID"] as? String) ?? (dict["teamIdentifier"] as? String)
            let version = versionString(dict["bundleVersion"]) ?? (dict["version"] as? String)
            let stateStr = ((dict["state"] as? String) ?? "").lowercased()
            let enabled = stateStr.contains("enabled") || stateStr.contains("activated")
            let key = identifier + "|" + (path ?? "")
            guard seen.insert(key).inserted else { return }
            out.append(MacKextEntry(kind: .systemExtension, bundleID: identifier,
                                    name: (path.flatMap(leafName)) ?? identifier,
                                    version: version, teamID: team, path: path,
                                    enabled: enabled, scope: scope, sourceFile: sourceFile))
        }
        return out
    }

    // MARK: - Helpers

    /// Recursively visit every dictionary in a plist tree.
    private static func walk(_ object: Any, visit: ([String: Any]) -> Void) {
        if let dict = object as? [String: Any] {
            visit(dict)
            for value in dict.values { walk(value, visit: visit) }
        } else if let array = object as? [Any] {
            for value in array { walk(value, visit: visit) }
        } else if let nsdict = object as? NSDictionary {
            var swift: [String: Any] = [:]
            for (k, v) in nsdict where k is String { swift[k as! String] = v }
            walk(swift, visit: visit)
        } else if let nsarray = object as? NSArray {
            walk(nsarray.map { $0 }, visit: visit)
        }
    }

    /// `bundleVersion` is sometimes a dict (CFBundle keys), sometimes a string.
    private static func versionString(_ value: Any?) -> String? {
        if let s = value as? String { return s }
        if let d = value as? [String: Any] {
            return (d["CFBundleShortVersionString"] as? String) ?? (d["CFBundleVersion"] as? String)
        }
        return nil
    }

    /// `…/Foo.kext/Contents/Info.plist` → `…/Foo.kext`.
    private static func kextBundlePath(_ infoPlistPath: String) -> String? {
        guard let range = infoPlistPath.range(of: "/Contents/Info.plist",
                                              options: [.caseInsensitive, .backwards]) else { return nil }
        return String(infoPlistPath[infoPlistPath.startIndex..<range.lowerBound])
    }

    /// `…/Foo.kext/Contents/Info.plist` → `Foo`.
    private static func bundleName(fromKextPath path: String) -> String? {
        guard let bundle = kextBundlePath(path) else { return nil }
        let leaf = (bundle as NSString).lastPathComponent
        return leaf.hasSuffix(".kext") ? String(leaf.dropLast(5)) : leaf
    }

    private static func leafName(_ path: String) -> String {
        (path as NSString).lastPathComponent
    }
}
