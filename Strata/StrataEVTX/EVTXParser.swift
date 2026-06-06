import Foundation

#if os(macOS)

/// Parses a Windows .evtx file into `EventLogRecord`s by shelling out to
/// libevtx's `evtxexport -f xml`. evtxexport emits one XML document per event;
/// we split on the record boundary and pull fields out with simple regexes
/// (a full XMLParser pass would be slower and the format is rigid).
public actor EVTXParser {
    private let environment: EVTXEnvironment

    public init(environment: EVTXEnvironment) { self.environment = environment }

    public func parse(fileAt fileURL: URL) async throws -> [EventLogRecord] {
        let tool = try environment.url(for: "evtxexport")

        // Write stdout straight to a temp file. Using a Pipe deadlocks:
        // evtxexport produces megabytes of XML per .evtx, the kernel pipe
        // buffer (~16-64 KB) fills, the child blocks on write, and the
        // parent's terminationHandler never fires because the process never
        // exits. A regular file has no such limit.
        let tempURL = FileManager.default.temporaryDirectory
            .appendingPathComponent("strata-evtx-\(UUID().uuidString).xml")
        FileManager.default.createFile(atPath: tempURL.path, contents: nil)
        let outHandle = try FileHandle(forWritingTo: tempURL)
        defer { try? FileManager.default.removeItem(at: tempURL) }

        let process = Process()
        process.executableURL = tool
        process.arguments = ["-f", "xml", fileURL.path]
        process.standardOutput = outHandle

        // Drain stderr continuously - same deadlock risk if we let it back up.
        let stderrPipe = Pipe()
        process.standardError = stderrPipe
        let stderrCollector = StderrCollector()
        stderrPipe.fileHandleForReading.readabilityHandler = { handle in
            let chunk = handle.availableData
            guard !chunk.isEmpty else { return }
            stderrCollector.append(String(decoding: chunk, as: UTF8.self))
        }

        try process.run()
        await withCheckedContinuation { continuation in
            process.terminationHandler = { _ in continuation.resume() }
        }
        stderrPipe.fileHandleForReading.readabilityHandler = nil
        try? outHandle.close()

        guard process.terminationStatus == 0 else {
            throw EVTXError.parseFailed(exitCode: process.terminationStatus,
                                        stderr: stderrCollector.text)
        }

        let xml = (try? String(contentsOf: tempURL, encoding: .utf8)) ?? ""
        return Self.records(from: xml, sourceFile: fileURL.path)
    }

    nonisolated static func records(from xml: String, sourceFile: String) -> [EventLogRecord] {
        // evtxexport's XML output is one <Event ...>...</Event> per record,
        // separated by blank lines and a header line for each record.
        let chunks = xml.components(separatedBy: "<Event ")
            .dropFirst()
            .map { "<Event " + $0 }

        return chunks.compactMap { chunk -> EventLogRecord? in
            guard let end = chunk.range(of: "</Event>") else { return nil }
            let event = String(chunk[..<end.upperBound])
            return parseSingle(event: event, sourceFile: sourceFile)
        }
    }

    private nonisolated static func parseSingle(event: String, sourceFile: String) -> EventLogRecord? {
        func extract(_ pattern: String) -> String? {
            guard let regex = try? NSRegularExpression(pattern: pattern, options: [.dotMatchesLineSeparators]),
                  let match = regex.firstMatch(in: event, range: NSRange(event.startIndex..., in: event)),
                  match.numberOfRanges > 1,
                  let range = Range(match.range(at: 1), in: event)
            else { return nil }
            return String(event[range])
        }

        let eventID    = extract(#"<EventID[^>]*>(\d+)</EventID>"#).flatMap(UInt32.init) ?? 0
        let level      = extract(#"<Level>(\d+)</Level>"#).flatMap(UInt8.init) ?? 0
        let recordNum  = extract(#"<EventRecordID>(\d+)</EventRecordID>"#).flatMap(UInt64.init) ?? 0
        let channel    = extract(#"<Channel>([^<]*)</Channel>"#) ?? ""
        let computer   = extract(#"<Computer>([^<]*)</Computer>"#) ?? ""
        let provider   = extract(#"<Provider\s+Name="([^"]+)""#) ?? ""
        let timeISO    = extract(#"<TimeCreated\s+SystemTime="([^"]+)""#) ?? ""
        let payload    = extract(#"(<EventData[^>]*>.*?</EventData>|<UserData[^>]*>.*?</UserData>)"#) ?? ""

        let written = parseTimestamp(timeISO)

        return EventLogRecord(recordNumber: recordNum, writtenAt: written,
                              eventID: eventID, level: level, channel: channel,
                              provider: provider, computer: computer,
                              payloadXML: payload, sourceFile: sourceFile)
    }

    /// ISO8601DateFormatter isn't Sendable, so we can't cache it as a
    /// nonisolated static. Allocating per record is fine - this only runs
    /// during an EVTX parse, not on a hot path.
    private nonisolated static func parseTimestamp(_ value: String) -> Date {
        let plain = ISO8601DateFormatter()
        plain.formatOptions = [.withInternetDateTime]
        if let d = plain.date(from: value) { return d }
        let fractional = ISO8601DateFormatter()
        fractional.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        return fractional.date(from: value) ?? Date(timeIntervalSince1970: 0)
    }
}

/// Thread-safe stderr accumulator used by the readability handler.
private nonisolated final class StderrCollector: @unchecked Sendable {
    private let lock = NSLock()
    private var buffer = ""
    func append(_ s: String) { lock.lock(); buffer += s; lock.unlock() }
    var text: String {
        lock.lock(); defer { lock.unlock() }
        return buffer.trimmingCharacters(in: .whitespacesAndNewlines)
    }
}

#endif

