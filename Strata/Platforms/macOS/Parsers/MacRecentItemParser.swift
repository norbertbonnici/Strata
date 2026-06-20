import Foundation

/// Lenient parser for macOS recent-item stores (`.sfl`, `.sfl2`, `.sfl3`, and
/// plist variants). These files are binary property lists / keyed archives whose
/// private class layout changes across macOS releases, so the parser avoids
/// binding to private classes and instead extracts path/URL/app-looking strings
/// from each plist object with nearby dates when present.
public enum MacRecentItemParser {
    public static func parse(data: Data, sourceFile: String, scope: String) -> [MacRecentItem] {
        guard let object = try? PropertyListSerialization.propertyList(from: data, options: [], format: nil) else {
            return []
        }
        let kind = listKind(sourceFile)
        var emitted = Set<String>()
        var out: [MacRecentItem] = []
        collect(from: object, inheritedDate: nil) { value, timestamp in
            guard let normalized = normalizeCandidate(value, kind: kind), emitted.insert(normalized).inserted else {
                return
            }
            out.append(MacRecentItem(kind: kind,
                                     title: title(for: normalized),
                                     value: normalized,
                                     timestamp: timestamp,
                                     scope: scope,
                                     sourceFile: sourceFile))
        }
        return out.sorted {
            if ($0.timestamp ?? .distantPast) != ($1.timestamp ?? .distantPast) {
                return ($0.timestamp ?? .distantPast) > ($1.timestamp ?? .distantPast)
            }
            return $0.title.localizedCaseInsensitiveCompare($1.title) == .orderedAscending
        }
    }

    private static func listKind(_ path: String) -> MacRecentItem.ListKind {
        let p = path.lowercased()
        if p.contains("recentapplications") || p.contains("recent applications") { return .applications }
        if p.contains("recentdocuments") || p.contains("recent documents") { return .documents }
        if p.contains("recentservers") || p.contains("recent servers") { return .servers }
        if p.contains("favoritehosts") || p.contains("favorite hosts") { return .hosts }
        if p.contains("favoritevolumes") || p.contains("favorite volumes") { return .volumes }
        if p.contains("favorites") || p.contains("sidebarlists") { return .favorites }
        return .other
    }

    private static func collect(from object: Any, inheritedDate: Date?, emit: (String, Date?) -> Void) {
        if let date = object as? Date {
            _ = date
            return
        }
        if let string = object as? String {
            emit(string, inheritedDate)
            return
        }
        if let array = object as? [Any] {
            let localDate = newestDate(in: array) ?? inheritedDate
            for item in array { collect(from: item, inheritedDate: localDate, emit: emit) }
            return
        }
        if let dict = object as? [String: Any] {
            let localDate = newestDate(in: dict) ?? inheritedDate
            let preferredKeys = ["Name", "name", "displayName", "DisplayName", "URL", "url", "path", "Path", "target", "Target"]
            for key in preferredKeys {
                if let string = dict[key] as? String { emit(string, localDate) }
            }
            for value in dict.values { collect(from: value, inheritedDate: localDate, emit: emit) }
            return
        }
        if let dict = object as? NSDictionary {
            var swift: [String: Any] = [:]
            for (key, value) in dict {
                if let key = key as? String { swift[key] = value }
            }
            collect(from: swift, inheritedDate: inheritedDate, emit: emit)
            return
        }
        if let array = object as? NSArray {
            collect(from: array.map { $0 }, inheritedDate: inheritedDate, emit: emit)
        }
    }

    private static func newestDate(in object: Any) -> Date? {
        var newest: Date?
        func visit(_ value: Any) {
            if let date = value as? Date {
                if newest == nil || date > newest! { newest = date }
            } else if let array = value as? [Any] {
                array.forEach(visit)
            } else if let dict = value as? [String: Any] {
                dict.values.forEach(visit)
            } else if let array = value as? NSArray {
                array.forEach(visit)
            } else if let dict = value as? NSDictionary {
                dict.allValues.forEach(visit)
            }
        }
        visit(object)
        return newest
    }

    private static func normalizeCandidate(_ value: String, kind: MacRecentItem.ListKind) -> String? {
        let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
        guard trimmed.count >= 3 else { return nil }
        let lower = trimmed.lowercased()
        if lower.hasPrefix("$"), lower.contains("class") { return nil }
        if lower.hasPrefix("ns.") || lower.hasPrefix("_ns") { return nil }
        if lower.contains("sfl") && lower.contains("class") { return nil }
        if lower == "root" || lower == "objects" || lower == "archiver" { return nil }

        if lower.contains("://") { return trimmed }
        if lower.hasPrefix("/") || lower.hasPrefix("~/") { return trimmed }
        if lower.hasSuffix(".app") || lower.contains(".app/") { return trimmed }
        if kind == .applications, looksLikeBundleID(trimmed) { return trimmed }
        if kind == .servers, trimmed.contains(".") && !trimmed.contains(" ") { return trimmed }
        return nil
    }

    private static func looksLikeBundleID(_ value: String) -> Bool {
        let parts = value.split(separator: ".")
        guard parts.count >= 3 else { return false }
        return parts.allSatisfy { part in
            !part.isEmpty && part.allSatisfy { ch in
                ch.isLetter || ch.isNumber || ch == "-" || ch == "_"
            }
        }
    }

    private static func title(for value: String) -> String {
        if let url = URL(string: value), let host = url.host, url.path.isEmpty || url.path == "/" {
            return host
        }
        if let url = URL(string: value), !url.lastPathComponent.isEmpty {
            return url.lastPathComponent.removingPercentEncoding ?? url.lastPathComponent
        }
        let leaf = (value as NSString).lastPathComponent
        return leaf.isEmpty || leaf == "/" ? value : leaf
    }
}
