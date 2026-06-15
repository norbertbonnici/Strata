import Foundation

/// Lenient parser for durable macOS security logs: Gatekeeper / syspolicyd,
/// XProtect, XProtect Remediator, MRT, and install.log rows that mention them.
public enum MacSecurityParser {
    public static func parse(data: Data, sourceFile: String, scope: String) -> [MacSecurityEvent] {
        let text = String(decoding: data, as: UTF8.self)
        return parse(text: text, sourceFile: sourceFile, scope: scope)
    }

    public static func parse(text: String, sourceFile: String, scope: String) -> [MacSecurityEvent] {
        let sourceKind = kind(fromSource: sourceFile)
        let sourceIsSecurityLog = sourceKind != .other
        var emitted = Set<String>()
        var out: [MacSecurityEvent] = []

        for rawLine in text.split(whereSeparator: \ .isNewline) {
            let line = rawLine.trimmingCharacters(in: .whitespacesAndNewlines)
            guard line.count >= 4 else { continue }
            guard sourceIsSecurityLog || isRelevant(line) else { continue }
            let parsed = parseTimestamp(line)
            let body = parsed.remainder.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !body.isEmpty else { continue }
            let kind = kind(fromLine: body, fallback: sourceKind)
            let severity = severity(from: body)
            let process = processName(in: body)
            let path = firstPath(in: body)
            let signature = signatureName(in: body)
            let key = "\(parsed.date?.timeIntervalSinceReferenceDate.bitPattern ?? 0)|\(kind.rawValue)|\(body)"
            guard emitted.insert(key).inserted else { continue }
            out.append(MacSecurityEvent(kind: kind,
                                        severity: severity,
                                        timestamp: parsed.date,
                                        process: process,
                                        message: body,
                                        path: path,
                                        signature: signature,
                                        scope: scope,
                                        sourceFile: sourceFile))
        }

        return out.sorted {
            if ($0.timestamp ?? .distantPast) != ($1.timestamp ?? .distantPast) {
                return ($0.timestamp ?? .distantPast) > ($1.timestamp ?? .distantPast)
            }
            return $0.message.localizedCaseInsensitiveCompare($1.message) == .orderedAscending
        }
    }

    private static func isRelevant(_ line: String) -> Bool {
        let lower = line.lowercased()
        return lower.contains("xprotect")
            || lower.contains("xprotectremediator")
            || lower.contains("mrt")
            || lower.contains("gatekeeper")
            || lower.contains("syspolicyd")
            || lower.contains("spctl")
            || lower.contains("malware")
            || lower.contains("notarization")
    }

    private static func kind(fromSource sourceFile: String) -> MacSecurityEvent.Kind {
        let lower = sourceFile.lowercased()
        if lower.contains("xprotectremediator") { return .xprotectRemediator }
        if lower.contains("xprotect") { return .xprotect }
        if lower.contains("mrt") { return .mrt }
        if lower.contains("gatekeeper") { return .gatekeeper }
        if lower.contains("syspolicyd") { return .syspolicyd }
        return .other
    }

    private static func kind(fromLine line: String, fallback: MacSecurityEvent.Kind) -> MacSecurityEvent.Kind {
        let lower = line.lowercased()
        if lower.contains("xprotectremediator") { return .xprotectRemediator }
        if lower.contains("xprotect") { return .xprotect }
        if lower.contains("mrt") { return .mrt }
        if lower.contains("gatekeeper") || lower.contains("spctl") { return .gatekeeper }
        if lower.contains("syspolicyd") { return .syspolicyd }
        return fallback
    }

    private static func severity(from line: String) -> MacSecurityEvent.Severity {
        let lower = line.lowercased()
        if lower.contains("detected") || lower.contains("malware") || lower.contains("threat") {
            return .detected
        }
        if lower.contains("blocked") || lower.contains("denied") || lower.contains("rejected") || lower.contains("quarantine") {
            return .blocked
        }
        if lower.contains("remediated") || lower.contains("removed") || lower.contains("cleaned") || lower.contains("deleted") {
            return .remediated
        }
        if lower.contains("warning") || lower.contains("failed") || lower.contains("error") || lower.contains("invalid") {
            return .warning
        }
        if lower.contains("allowed") || lower.contains("accepted") || lower.contains("notarized") || lower.contains("passed") {
            return .allowed
        }
        return .info
    }

    private static func parseTimestamp(_ line: String) -> (date: Date?, remainder: String) {
        if line.count >= 20 {
            let prefix = String(line.prefix(20))
            if let date = isoDate(prefix) {
                return (date, String(line.dropFirst(20)))
            }
        }
        if line.count >= 19 {
            let prefix = String(line.prefix(19))
            if let date = localDate(prefix, format: "yyyy-MM-dd HH:mm:ss") {
                return (date, String(line.dropFirst(19)))
            }
            if let date = localDate(prefix, format: "yyyy/MM/dd HH:mm:ss") {
                return (date, String(line.dropFirst(19)))
            }
        }
        if line.count >= 15 {
            let prefix = String(line.prefix(15))
            if let date = syslogDate(prefix) {
                return (date, String(line.dropFirst(15)))
            }
        }
        return (nil, line)
    }

    private static func isoDate(_ prefix: String) -> Date? {
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        if let date = formatter.date(from: prefix) { return date }
        formatter.formatOptions = [.withInternetDateTime]
        return formatter.date(from: prefix)
    }

    private static func localDate(_ prefix: String, format: String) -> Date? {
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.timeZone = TimeZone(secondsFromGMT: 0)
        formatter.dateFormat = format
        return formatter.date(from: prefix)
    }

    private static func syslogDate(_ prefix: String) -> Date? {
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.timeZone = TimeZone(secondsFromGMT: 0)
        formatter.dateFormat = "yyyy MMM d HH:mm:ss"
        let year = Calendar(identifier: .gregorian).component(.year, from: Date())
        return formatter.date(from: "\(year) \(prefix)")
    }

    private static func processName(in line: String) -> String? {
        guard let bracket = line.firstIndex(of: "[") else { return nil }
        let before = line[..<bracket].trimmingCharacters(in: .whitespacesAndNewlines)
        guard let process = before.split(separator: " ").last, !process.isEmpty else { return nil }
        return String(process)
    }

    private static func firstPath(in line: String) -> String? {
        let separators = CharacterSet.whitespacesAndNewlines.union(CharacterSet(charactersIn: "\"'()[]{}<>,;"))
        for token in line.components(separatedBy: separators) {
            let clean = token.trimmingCharacters(in: .punctuationCharacters)
            let lower = clean.lowercased()
            if clean.hasPrefix("/") || clean.hasPrefix("~/") || lower.contains(".app/") || lower.hasSuffix(".app") {
                return clean
            }
        }
        return nil
    }

    private static func signatureName(in line: String) -> String? {
        let lower = line.lowercased()
        for marker in ["signature:", "malware:", "threat:", "name:"] {
            guard let range = lower.range(of: marker) else { continue }
            let suffix = line[range.upperBound...]
                .trimmingCharacters(in: .whitespacesAndNewlines)
            let value = suffix.split(separator: ",").first.map(String.init) ?? suffix
            let trimmed = value.trimmingCharacters(in: CharacterSet(charactersIn: " \t\"'[](){}"))
            if trimmed.count >= 2 { return trimmed }
        }
        return nil
    }
}
