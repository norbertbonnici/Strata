import Foundation

/// Parses Linux package-manager logs into `PackageEvent` rows. Pure. Covers the
/// Debian/Ubuntu (`dpkg.log`, `apt/history.log`) and RHEL/Fedora (`yum.log`,
/// `dnf.rpm.log`) families.
public nonisolated enum PackageParser {

    // MARK: - dpkg.log

    /// `2026-06-10 12:00:01 install nginx:amd64 <none> 1.18.0-0ubuntu1`
    /// The action is the second field; we keep install/remove/purge/upgrade and
    /// drop the noisy status/configure/trigproc lines. The local timestamp has
    /// no timezone, so it's interpreted as UTC.
    public static func parseDpkgLog(text: String, sourceFile: String) -> [PackageEvent] {
        var events: [PackageEvent] = []
        for rawLine in text.split(separator: "\n", omittingEmptySubsequences: true) {
            let parts = rawLine.split(separator: " ", omittingEmptySubsequences: true).map(String.init)
            guard parts.count >= 4 else { continue }
            let action: PackageEvent.Action
            switch parts[2] {
            case "install": action = .install
            case "upgrade": action = .upgrade
            case "remove":  action = .remove
            case "purge":   action = .purge
            default: continue   // status / configure / trigproc
            }
            let date = isoLocal("\(parts[0]) \(parts[1])")
            let pkg = parts[3].split(separator: ":").first.map(String.init) ?? parts[3]
            // dpkg upgrade lines carry "<old> <new>"; install "<none> <new>".
            let version = parts.count >= 6 ? parts[5] : (parts.count >= 5 ? parts[4] : nil)
            events.append(PackageEvent(timestamp: date, action: action, package: pkg,
                                       version: version == "<none>" ? nil : version,
                                       manager: .dpkg, sourceFile: sourceFile))
        }
        return events
    }

    // MARK: - apt history.log

    /// Block format:
    ///
    ///     Start-Date: 2026-06-10  12:00:00
    ///     Commandline: apt install nginx
    ///     Install: nginx:amd64 (1.18.0), libx:amd64 (1.0, automatic)
    ///     Remove: oldpkg:amd64 (1.0)
    ///     End-Date: 2026-06-10  12:00:05
    public static func parseAptHistory(text: String, sourceFile: String) -> [PackageEvent] {
        var events: [PackageEvent] = []
        var blockDate: Date?
        for rawLine in text.split(separator: "\n", omittingEmptySubsequences: false) {
            let line = rawLine.trimmingCharacters(in: .whitespaces)
            if line.isEmpty { blockDate = nil; continue }
            if line.hasPrefix("Start-Date:") {
                blockDate = isoLocal(String(line.dropFirst("Start-Date:".count))
                    .trimmingCharacters(in: .whitespaces).replacingOccurrences(of: "  ", with: " "))
            } else if let action = aptAction(line) {
                let payload = line.drop { $0 != ":" }.dropFirst()
                events.append(contentsOf: parseAptPackageList(String(payload), action: action,
                                                              date: blockDate, sourceFile: sourceFile))
            }
        }
        return events
    }

    private static func aptAction(_ line: String) -> PackageEvent.Action? {
        if line.hasPrefix("Install:")   { return .install }
        if line.hasPrefix("Remove:")    { return .remove }
        if line.hasPrefix("Purge:")     { return .purge }
        if line.hasPrefix("Upgrade:")   { return .upgrade }
        if line.hasPrefix("Reinstall:") { return .reinstall }
        if line.hasPrefix("Downgrade:") { return .downgrade }
        return nil
    }

    /// `nginx:amd64 (1.18.0), libx:amd64 (1.0, automatic)` → events. Splits on
    /// commas that sit *outside* the parentheses.
    private static func parseAptPackageList(_ payload: String, action: PackageEvent.Action,
                                            date: Date?, sourceFile: String) -> [PackageEvent] {
        var items: [String] = []
        var current = ""
        var depth = 0
        for c in payload {
            if c == "(" { depth += 1 } else if c == ")" { depth -= 1 }
            if c == "," && depth == 0 { items.append(current); current = "" } else { current.append(c) }
        }
        if !current.isEmpty { items.append(current) }

        return items.compactMap { item -> PackageEvent? in
            let trimmed = item.trimmingCharacters(in: .whitespaces)
            guard !trimmed.isEmpty else { return nil }
            let name = trimmed.split(separator: " ").first.map(String.init) ?? trimmed
            let pkg = name.split(separator: ":").first.map(String.init) ?? name
            var version: String?
            if let open = trimmed.firstIndex(of: "("), let close = trimmed.firstIndex(of: ")") {
                version = trimmed[trimmed.index(after: open)..<close]
                    .split(separator: ",").first.map { $0.trimmingCharacters(in: .whitespaces) }
            }
            return PackageEvent(timestamp: date, action: action, package: pkg,
                                version: version, manager: .apt, sourceFile: sourceFile)
        }
    }

    // MARK: - yum.log / dnf.rpm.log

    /// yum: `Jun 10 12:00:00 Installed: nginx-1.18.0-1.x86_64` (classic syslog
    /// date, no year → inferred from `anchor`). dnf.rpm.log uses an RFC-3339
    /// prefix and the same `Installed:`/`Erased:`/`Upgraded:` verbs.
    public static func parseYumLog(text: String, sourceFile: String,
                                   anchor: Date?, manager: PackageEvent.Manager) -> [PackageEvent] {
        var events: [PackageEvent] = []
        for rawLine in text.split(separator: "\n", omittingEmptySubsequences: true) {
            let line = String(rawLine)
            guard let verbRange = line.range(of: #"(Installed|Erased|Removed|Updated|Upgraded|Reinstalled|Downgraded): "#,
                                             options: .regularExpression) else { continue }
            let verb = line[verbRange].trimmingCharacters(in: CharacterSet(charactersIn: ": "))
            let action: PackageEvent.Action
            switch verb {
            case "Installed":   action = .install
            case "Erased", "Removed": action = .remove
            case "Updated", "Upgraded": action = .upgrade
            case "Reinstalled": action = .reinstall
            case "Downgraded":  action = .downgrade
            default: continue
            }
            let nevra = line[verbRange.upperBound...].trimmingCharacters(in: .whitespaces)
            let (pkg, version) = splitNEVRA(nevra)
            let date = yumDate(String(line[..<verbRange.lowerBound]), anchor: anchor)
            events.append(PackageEvent(timestamp: date, action: action, package: pkg,
                                       version: version, manager: manager, sourceFile: sourceFile))
        }
        return events
    }

    /// `nginx-1.18.0-1.x86_64` → ("nginx", "1.18.0-1"). Best-effort: the name is
    /// everything before the first `-<digit>` segment.
    private static func splitNEVRA(_ nevra: String) -> (String, String?) {
        let cleaned = nevra.hasPrefix("1:") ? String(nevra.dropFirst(2)) : nevra
        let parts = cleaned.split(separator: "-")
        guard parts.count >= 2,
              let verIdx = parts.firstIndex(where: { $0.first?.isNumber == true }) else {
            return (cleaned, nil)
        }
        let name = parts[0..<verIdx].joined(separator: "-")
        var version = parts[verIdx...].joined(separator: "-")
        if let dot = version.range(of: #"\.(x86_64|noarch|i686|aarch64|amd64)$"#, options: .regularExpression) {
            version = String(version[..<dot.lowerBound])
        }
        return (name.isEmpty ? cleaned : name, version.isEmpty ? nil : version)
    }

    // MARK: - Dates

    private static let isoLocalFormatter: DateFormatter = {
        let f = DateFormatter()
        f.locale = Locale(identifier: "en_US_POSIX")
        f.timeZone = TimeZone(identifier: "UTC")
        f.dateFormat = "yyyy-MM-dd HH:mm:ss"
        return f
    }()

    static func isoLocal(_ s: String) -> Date? { isoLocalFormatter.date(from: s) }

    private static let monthNames: [String: Int] = [
        "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
        "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
    ]

    /// yum's classic-syslog date (`Jun 10 12:00:00`, no year) or dnf's RFC-3339
    /// prefix. Year inferred from `anchor` (the file's mtime).
    private static func yumDate(_ prefix: String, anchor: Date?) -> Date? {
        let trimmed = prefix.trimmingCharacters(in: .whitespaces)
        // dnf.rpm.log: "2026-06-10T12:00:00+0000" prefix.
        if trimmed.count >= 19, trimmed[trimmed.index(trimmed.startIndex, offsetBy: 4)] == "-" {
            let iso = ISO8601DateFormatter()
            if let d = iso.date(from: trimmed.replacingOccurrences(of: " ", with: "")) { return d }
        }
        let tokens = trimmed.split(separator: " ", omittingEmptySubsequences: true)
        guard tokens.count >= 3, let month = monthNames[String(tokens[0])],
              let day = Int(tokens[1]) else { return nil }
        let clock = tokens[2].split(separator: ":")
        guard clock.count == 3, let h = Int(clock[0]), let m = Int(clock[1]), let sec = Int(clock[2])
        else { return nil }
        var cal = Calendar(identifier: .gregorian)
        cal.timeZone = TimeZone(identifier: "UTC")!
        let anchorDate = anchor ?? Date(timeIntervalSinceReferenceDate: 0)
        let year = cal.component(.year, from: anchorDate)
        var date = cal.date(from: DateComponents(year: year, month: month, day: day,
                                                 hour: h, minute: m, second: sec))
        if let d = date, let anchor, d > anchor.addingTimeInterval(2 * 86_400) {
            date = cal.date(from: DateComponents(year: year - 1, month: month, day: day,
                                                 hour: h, minute: m, second: sec))
        }
        return date
    }
}
