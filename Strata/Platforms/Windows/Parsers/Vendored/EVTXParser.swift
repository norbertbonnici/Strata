import Foundation

#if os(macOS)

/// Parses a Windows .evtx file into `EventLogRecord`s by shelling out to
/// libevtx's `evtxexport -f xml`. evtxexport emits one XML document per event;
/// we split on the record boundary and pull fields out with simple regexes
/// (a full XMLParser pass would be slower and the format is rigid).
public actor EVTXParser {
    private let environment: VendoredTool

    public init(environment: VendoredTool) { self.environment = environment }

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
        let stderrCollector = PipeTextCollector()
        stderrPipe.fileHandleForReading.readabilityHandler = { handle in
            let chunk = handle.availableData
            guard !chunk.isEmpty else { return }
            stderrCollector.append(String(decoding: chunk, as: UTF8.self))
        }

        try await process.runAndWait()
        stderrPipe.fileHandleForReading.readabilityHandler = nil
        try? outHandle.close()

        guard process.terminationStatus == 0 else {
            throw VendoredToolError.parseFailed(tool: "evtxexport", exitCode: process.terminationStatus,
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

    // Field patterns, compiled once. `parseSingle` used to build all eight per
    // record — millions of regex compilations for one large Security.evtx.
    // NSRegularExpression is immutable and documented thread-safe.
    private nonisolated static func compile(_ pattern: String) -> NSRegularExpression? {
        try? NSRegularExpression(pattern: pattern, options: [.dotMatchesLineSeparators])
    }
    private nonisolated static let eventIDPattern    = compile(#"<EventID[^>]*>(\d+)</EventID>"#)
    private nonisolated static let levelPattern      = compile(#"<Level>(\d+)</Level>"#)
    private nonisolated static let recordIDPattern   = compile(#"<EventRecordID>(\d+)</EventRecordID>"#)
    private nonisolated static let channelPattern    = compile(#"<Channel>([^<]*)</Channel>"#)
    private nonisolated static let computerPattern   = compile(#"<Computer>([^<]*)</Computer>"#)
    private nonisolated static let providerPattern   = compile(#"<Provider\s+Name="([^"]+)""#)
    private nonisolated static let timeCreatedPattern = compile(#"<TimeCreated\s+SystemTime="([^"]+)""#)
    private nonisolated static let payloadPattern    =
        compile(#"(<EventData[^>]*>.*?</EventData>|<UserData[^>]*>.*?</UserData>)"#)

    private nonisolated static func parseSingle(event: String, sourceFile: String) -> EventLogRecord? {
        func extract(_ regex: NSRegularExpression?) -> String? {
            guard let regex,
                  let match = regex.firstMatch(in: event, range: NSRange(event.startIndex..., in: event)),
                  match.numberOfRanges > 1,
                  let range = Range(match.range(at: 1), in: event)
            else { return nil }
            return String(event[range])
        }

        let eventID    = extract(eventIDPattern).flatMap(UInt32.init) ?? 0
        let level      = extract(levelPattern).flatMap(UInt8.init) ?? 0
        let recordNum  = extract(recordIDPattern).flatMap(UInt64.init) ?? 0
        let channel    = extract(channelPattern) ?? ""
        let computer   = extract(computerPattern) ?? ""
        let provider   = extract(providerPattern) ?? ""
        let timeISO    = extract(timeCreatedPattern) ?? ""
        let payload    = extract(payloadPattern) ?? ""

        let written = parseTimestamp(timeISO)

        return EventLogRecord(recordNumber: recordNum, writtenAt: written,
                              eventID: eventID, level: level, channel: channel,
                              provider: provider, computer: computer,
                              payloadXML: payload, sourceFile: sourceFile)
    }

    /// `SystemTime` → Date. evtxexport always writes UTC with a 9-digit
    /// fraction (`2026-03-17T16:09:31.055125500Z`), which `parseSystemTime`
    /// decodes without allocating. Anything else falls back to
    /// ISO8601DateFormatter (two allocations, as every record used to pay).
    nonisolated static func parseTimestamp(_ value: String) -> Date {
        if let fast = parseSystemTime(value) { return fast }
        let plain = ISO8601DateFormatter()
        plain.formatOptions = [.withInternetDateTime]
        if let d = plain.date(from: value) { return d }
        let fractional = ISO8601DateFormatter()
        fractional.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        return fractional.date(from: value) ?? Date(timeIntervalSince1970: 0)
    }

    /// `YYYY-MM-DDTHH:MM:SS[.f…]Z`, or nil for any other shape. The fraction is
    /// truncated to milliseconds and the Date built the same way, so the result
    /// is bit-identical to ISO8601DateFormatter with `.withFractionalSeconds`.
    nonisolated static func parseSystemTime(_ value: String) -> Date? {
        let u = Array(value.utf8)
        guard u.count >= 20, u[4] == 0x2D, u[7] == 0x2D, u[10] == 0x54,   // - - T
              u[13] == 0x3A, u[16] == 0x3A, u[u.count - 1] == 0x5A else { return nil } // : : Z
        func number(_ range: Range<Int>) -> Int? {
            var v = 0
            for k in range {
                guard (0x30...0x39).contains(u[k]) else { return nil }
                v = v * 10 + Int(u[k] - 0x30)
            }
            return v
        }
        guard let year = number(0..<4), let month = number(5..<7), let day = number(8..<10),
              let hour = number(11..<13), let minute = number(14..<16), let second = number(17..<19),
              (1...12).contains(month), (1...31).contains(day), hour < 24, minute < 60, second < 60
        else { return nil }

        var millis = 0
        if u.count > 20 {                                // a fraction: ".f…Z"
            let fraction = 20..<(u.count - 1)
            guard u[19] == 0x2E, !fraction.isEmpty,
                  fraction.allSatisfy({ (0x30...0x39).contains(u[$0]) }) else { return nil }
            // First three digits (zero-padded) — truncation, as the formatter does.
            for k in 0..<3 {
                let index = fraction.lowerBound + k
                millis = millis * 10 + (index < fraction.upperBound ? Int(u[index] - 0x30) : 0)
            }
        }

        // Days since 1970-01-01 for a proleptic-Gregorian civil date (H. Hinnant).
        let y = month <= 2 ? year - 1 : year
        let era = (y >= 0 ? y : y - 399) / 400
        let yearOfEra = y - era * 400
        let dayOfYear = (153 * ((month + 9) % 12) + 2) / 5 + day - 1
        let dayOfEra = yearOfEra * 365 + yearOfEra / 4 - yearOfEra / 100 + dayOfYear
        let days = era * 146_097 + dayOfEra - 719_468

        let seconds = days * 86_400 + hour * 3_600 + minute * 60 + second
        return Date(timeIntervalSince1970: Double(seconds) + Double(millis) / 1_000)
    }
}

#endif

