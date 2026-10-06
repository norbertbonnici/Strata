import Foundation

/// Scans the events, registry values, and files of a single host for any
/// IOC value the analyst has loaded. Pure / Sendable so it can be invoked
/// from a detached Task without bouncing back to the main actor.
///
/// Matching strategy:
///   - IPs get an exact-match against structured IpAddress fields in 4624 /
///     4625 logon events (highest-signal hits).
///   - Every kind additionally gets a case-insensitive substring scan over
///     event payload XML, registry value data, and file paths. This catches
///     IOCs that appear free-form (eg. command-line args, registry blobs).
public nonisolated struct IOCMatcher: Sendable {
    public let iocs: [IOC]

    private struct Needle: Sendable {
        let ioc: IOC
        let lowered: String
    }

    private let ipSet: Set<String>
    private let needles: [Needle]

    public init(iocs: [IOC]) {
        self.iocs = iocs
        var ipSet = Set<String>()
        var needles: [Needle] = []
        for ioc in iocs {
            let lower = ioc.value.lowercased()
            if lower.isEmpty { continue }
            if ioc.kind == .ip { ipSet.insert(lower) }
            needles.append(Needle(ioc: ioc, lowered: lower))
        }
        self.ipSet = ipSet
        self.needles = needles
    }

    public func match(events: [EventLogRecord],
                      registry: [RegistryValue],
                      files: [FileEntry]) -> [IOCMatch] {
        guard !needles.isEmpty else { return [] }
        var matches: [IOCMatch] = []

        for event in events {
            // Structured IP fast path - higher signal than the substring
            // scan, so emit a separate match the analyst can sort to the top.
            if !ipSet.isEmpty,
               (event.eventID == 4624 || event.eventID == 4625),
               let ip = event.data("IpAddress")?.lowercased(),
               ipSet.contains(ip)
            {
                matches.append(IOCMatch(
                    iocValue: ip, iocKind: .ip,
                    location: .event(eventID: event.eventID,
                                     recordNumber: event.recordNumber,
                                     channel: event.channel,
                                     sourceFile: event.sourceFile),
                    context: "Structured logon source \(ip)",
                    timestamp: event.writtenAt))
            }
            // Entity-decode the payload: evtxexport escapes `&`/`<`/`>`/quotes,
            // so a URL IOC with a query string (`?a=1&b=2`) would never match
            // the raw `&amp;` text.
            let haystack = XMLEntityDecoder.decode(event.payloadXML).lowercased()
            guard !haystack.isEmpty else { continue }
            for needle in needles {
                guard let range = Self.matchRange(of: needle, in: haystack) else { continue }
                matches.append(IOCMatch(
                    iocValue: needle.ioc.value, iocKind: needle.ioc.kind,
                    location: .event(eventID: event.eventID,
                                     recordNumber: event.recordNumber,
                                     channel: event.channel,
                                     sourceFile: event.sourceFile),
                    context: snippet(around: range, in: haystack),
                    timestamp: event.writtenAt))
            }
        }

        for value in registry {
            let haystack = (value.data + " " + value.fullPath).lowercased()
            guard !haystack.isEmpty else { continue }
            for needle in needles where Self.matchRange(of: needle, in: haystack) != nil {
                matches.append(IOCMatch(
                    iocValue: needle.ioc.value, iocKind: needle.ioc.kind,
                    location: .registry(hive: value.hive,
                                        path: value.path,
                                        name: value.name),
                    context: String(value.data.prefix(160)),
                    timestamp: value.lastWritten))
            }
        }

        for file in files {
            let haystack = file.fullPath.lowercased()
            for needle in needles where Self.matchRange(of: needle, in: haystack) != nil {
                matches.append(IOCMatch(
                    iocValue: needle.ioc.value, iocKind: needle.ioc.kind,
                    location: .file(path: file.fullPath),
                    context: file.fullPath,
                    timestamp: file.modified ?? file.created))
            }
        }
        return matches
    }

    /// Where `needle` occurs in `haystack` (both lowercased), or nil. Domains,
    /// hashes and URLs match as plain substrings; an IP must stand on its own —
    /// a bare substring test would let `10.0.0.1` hit `10.0.0.15`, `10.0.0.123`
    /// or `110.0.0.1`, inventing IOC hits (and cross-host "shared indicator"
    /// correlations) from unrelated addresses.
    private static func matchRange(of needle: Needle, in haystack: String) -> Range<String.Index>? {
        guard needle.ioc.kind == .ip else { return haystack.range(of: needle.lowered) }
        let ipv6 = needle.lowered.contains(":")
        var from = haystack.startIndex
        while let range = haystack.range(of: needle.lowered, range: from..<haystack.endIndex) {
            if isStandaloneAddress(range, in: haystack, ipv6: ipv6) { return range }
            from = haystack.index(after: range.lowerBound)
        }
        return nil
    }

    /// True when the address at `range` isn't the middle of a longer address:
    /// no adjoining digit (IPv4) or hex digit / colon (IPv6), and for IPv4 no
    /// adjoining `.<digit>` octet. A sentence-ending "10.0.0.1." still matches.
    private static func isStandaloneAddress(_ range: Range<String.Index>, in s: String, ipv6: Bool) -> Bool {
        func continuesAddress(_ c: Character) -> Bool {
            ipv6 ? (c.isHexDigit || c == ":") : (c.isASCII && c.isNumber)
        }
        if range.lowerBound > s.startIndex {
            let beforeIndex = s.index(before: range.lowerBound)
            let before = s[beforeIndex]
            if continuesAddress(before) { return false }
            if !ipv6, before == ".", beforeIndex > s.startIndex,
               continuesAddress(s[s.index(before: beforeIndex)]) { return false }
        }
        if range.upperBound < s.endIndex {
            let after = s[range.upperBound]
            if continuesAddress(after) { return false }
            let next = s.index(after: range.upperBound)
            if !ipv6, after == ".", next < s.endIndex, continuesAddress(s[next]) { return false }
        }
        return true
    }

    private func snippet(around range: Range<String.Index>, in haystack: String, span: Int = 80) -> String {
        let lower = haystack.index(range.lowerBound,
                                    offsetBy: -span,
                                    limitedBy: haystack.startIndex) ?? haystack.startIndex
        let upper = haystack.index(range.upperBound,
                                    offsetBy: span,
                                    limitedBy: haystack.endIndex) ?? haystack.endIndex
        return String(haystack[lower..<upper])
    }
}
