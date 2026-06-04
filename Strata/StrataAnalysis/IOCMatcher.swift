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
public struct IOCMatcher: Sendable {
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
            let haystack = event.payloadXML.lowercased()
            guard !haystack.isEmpty else { continue }
            for needle in needles where haystack.contains(needle.lowered) {
                matches.append(IOCMatch(
                    iocValue: needle.ioc.value, iocKind: needle.ioc.kind,
                    location: .event(eventID: event.eventID,
                                     recordNumber: event.recordNumber,
                                     channel: event.channel,
                                     sourceFile: event.sourceFile),
                    context: snippet(around: needle.lowered, in: haystack),
                    timestamp: event.writtenAt))
            }
        }

        for value in registry {
            let haystack = (value.data + " " + value.fullPath).lowercased()
            guard !haystack.isEmpty else { continue }
            for needle in needles where haystack.contains(needle.lowered) {
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
            for needle in needles where haystack.contains(needle.lowered) {
                matches.append(IOCMatch(
                    iocValue: needle.ioc.value, iocKind: needle.ioc.kind,
                    location: .file(path: file.fullPath),
                    context: file.fullPath,
                    timestamp: file.modified ?? file.created))
            }
        }
        return matches
    }

    private func snippet(around needle: String, in haystack: String, span: Int = 80) -> String {
        guard let range = haystack.range(of: needle) else { return "" }
        let lower = haystack.index(range.lowerBound,
                                    offsetBy: -span,
                                    limitedBy: haystack.startIndex) ?? haystack.startIndex
        let upper = haystack.index(range.upperBound,
                                    offsetBy: span,
                                    limitedBy: haystack.endIndex) ?? haystack.endIndex
        return String(haystack[lower..<upper])
    }
}
