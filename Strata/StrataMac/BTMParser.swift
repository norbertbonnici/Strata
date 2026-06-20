import Foundation

/// Parses the macOS **Background Task Management** store (`*.btm`) into
/// `MacBackgroundItem`s. The `.btm` is an NSKeyedArchiver graph of Apple-private
/// classes (`BTMStore` / `ItemRecord` …), so this decodes the keyed archive with
/// `BinaryPlist` (UID-aware) and walks the object table **leniently**: every
/// archived object that looks like an item record (carries a `type`/`disposition`
/// plus a name / url / bundle id) becomes an entry. Fields are matched by ivar
/// name so the parser survives the per-release format/class churn.
public enum BTMParser {
    public static func parse(data: Data, sourceFile: String, scope: String) -> [MacBackgroundItem] {
        guard let root = BinaryPlist.parse(data)?.dictValue,
              let objects = root["$objects"]?.arrayValue else { return [] }

        // Resolve a UID reference (or pass a literal through).
        func resolve(_ v: PlistValue?) -> PlistValue? {
            if case .uid(let i)? = v, i >= 0, i < objects.count { return objects[i] }
            return v
        }

        // Normalise an archived object to an ivar dict: an archived NSDictionary
        // uses NS.keys/NS.objects; a custom class uses its ivar names as keys.
        func normalized(_ obj: PlistValue?) -> [String: PlistValue]? {
            guard let d = resolve(obj)?.dictValue else { return nil }
            if let keys = d["NS.keys"]?.arrayValue, let vals = d["NS.objects"]?.arrayValue,
               keys.count == vals.count {
                var out: [String: PlistValue] = [:]
                for (k, v) in zip(keys, vals) where resolve(k)?.stringValue != nil {
                    out[resolve(k)!.stringValue!] = v
                }
                return out
            }
            return d
        }

        // A string behind a UID / NSString / NSURL (NS.relative [+ NS.base]).
        func string(_ v: PlistValue?, depth: Int = 0) -> String? {
            guard depth < 6, let r = resolve(v) else { return nil }
            if let s = r.stringValue { return s.isEmpty ? nil : s }
            if let d = normalized(r) {
                if let rel = string(d["NS.relative"], depth: depth + 1) {
                    if let base = string(d["NS.base"], depth: depth + 1) { return base + "/" + rel }
                    return rel
                }
            }
            return nil
        }

        func firstString(_ rec: [String: PlistValue], contains needles: [String],
                         excluding excl: [String] = []) -> String? {
            for (k, v) in rec {
                let lk = k.lowercased()
                guard needles.contains(where: lk.contains), !excl.contains(where: lk.contains) else { continue }
                if let s = string(v) { return s }
            }
            return nil
        }
        func firstInt(_ rec: [String: PlistValue], contains needles: [String]) -> Int? {
            for (k, v) in rec where needles.contains(where: k.lowercased().contains) {
                if let i = resolve(v)?.intValue { return i }
            }
            return nil
        }

        var out: [MacBackgroundItem] = []
        var seen = Set<String>()
        for obj in objects {
            guard let rec = normalized(obj) else { continue }
            let lowerKeys = Set(rec.keys.map { $0.lowercased() })
            // Record shape: a type/disposition plus an identity (name / url / bundle).
            let hasState = lowerKeys.contains { $0.contains("type") || $0.contains("disposition") }
            let hasIdentity = lowerKeys.contains {
                $0.contains("name") || $0.contains("url") || $0.contains("path") || $0.contains("bundle")
            }
            guard hasState, hasIdentity else { continue }

            let name = firstString(rec, contains: ["name"], excluding: ["developer", "team", "class", "user"]) ?? ""
            let executable = firstString(rec, contains: ["url", "executable", "path"])
            let bundleID = firstString(rec, contains: ["bundleidentifier", "identifier", "bundle"])
            let developer = firstString(rec, contains: ["developer"])
            let team = firstString(rec, contains: ["team"])
            let type = firstInt(rec, contains: ["type"])
            let disposition = firstInt(rec, contains: ["disposition", "flags"])

            // Need at least one concrete identity to be worth surfacing.
            guard !(name.isEmpty && executable == nil && bundleID == nil) else { continue }
            let key = "\(bundleID ?? "")|\(executable ?? "")|\(name)"
            guard seen.insert(key).inserted else { continue }

            out.append(MacBackgroundItem(name: name, executable: executable, bundleID: bundleID,
                                         developerName: developer, teamID: team, typeRaw: type,
                                         disposition: disposition, scope: scope, sourceFile: sourceFile))
        }
        return out.sorted { $0.title.localizedCaseInsensitiveCompare($1.title) == .orderedAscending }
    }
}
