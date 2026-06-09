import Foundation

#if os(macOS)

/// Reads acquisition metadata + embedded hashes from an EWF (E01) container via
/// the vendored `ewfinfo`, and verifies integrity via `ewfverify`. We trust the
/// hashes the imaging tool embedded rather than rehashing a multi-GB image at
/// ingest; `verify` is the explicit, expensive re-check.
///
/// Parsing is split into pure static helpers (`parseDFXML`/`parseText`/
/// `parseVerify`) so they can be unit-tested against captured tool output with
/// no real E01 present.
public actor EWFInfo {
    private let environment: TSKEnvironment

    public init(environment: TSKEnvironment) { self.environment = environment }

    /// Acquisition metadata + embedded digests parsed from `ewfinfo`.
    public struct Metadata: Sendable, Equatable {
        public var caseNumber: String?
        public var evidenceNumber: String?
        public var descriptionText: String?
        public var examinerName: String?
        public var notes: String?
        public var acquisitionDate: Date?
        public var operatingSystem: String?      // acquisition_system
        public var acquisitionVersion: String?   // software version used
        public var mediaSerial: String?
        public var storedMD5: String?
        public var storedSHA1: String?

        public init() {}

        /// True when nothing useful parsed - the cue to try the text fallback.
        public var isEmpty: Bool {
            storedMD5 == nil && storedSHA1 == nil && examinerName == nil
                && acquisitionDate == nil && caseNumber == nil
        }
    }

    /// Outcome of an `ewfverify` integrity pass.
    public struct VerifyResult: Sendable, Equatable {
        public var passed: Bool
        public var storedMD5: String?
        public var calculatedMD5: String?
        public var storedSHA1: String?
        public var calculatedSHA1: String?

        public init(passed: Bool = false) { self.passed = passed }
    }

    // MARK: - Public API

    /// Run `ewfinfo -f dfxml`; fall back to the plain text format if the dfxml
    /// output is unusable (older libewf builds).
    public func read(imageAt url: URL) async throws -> Metadata {
        let dfxml = try await run("ewfinfo", ["-f", "dfxml", "-d", "iso8601", url.path])
        var meta = Self.parseDFXML(dfxml.stdout)
        if meta.isEmpty {
            let text = try await run("ewfinfo", ["-d", "iso8601", url.path])
            meta = Self.parseText(text.stdout)
        }
        return meta
    }

    /// Run `ewfverify` (recomputes the stored digests and compares). The textual
    /// SUCCESS/FAILURE verdict is authoritative; a mismatch is reported, not
    /// thrown. `progress` receives raw status lines from the tool.
    public func verify(imageAt url: URL,
                       progress: ((String) -> Void)? = nil) async throws -> VerifyResult {
        let result = try await run("ewfverify", [url.path], progress: progress)
        return Self.parseVerify(result.stdout)
    }

    // MARK: - Process plumbing

    private struct ProcResult { let stdout: String; let stderr: String; let status: Int32 }

    /// Run a vendored tool, capturing stdout in full (for parsing) and streaming
    /// stderr lines to `progress`. Does NOT throw on a non-zero exit - callers
    /// like `verify` need to read the output even when the tool reports failure.
    /// Throws only if the binary is missing or fails to launch.
    private func run(_ tool: String, _ args: [String],
                     progress: ((String) -> Void)? = nil) async throws -> ProcResult {
        let toolURL = try environment.url(for: tool)
        let process = Process()
        process.executableURL = toolURL
        process.arguments = args

        let outPipe = Pipe()
        let errPipe = Pipe()
        process.standardOutput = outPipe
        process.standardError = errPipe

        let out = PipeTextCollector()
        let err = PipeTextCollector()
        outPipe.fileHandleForReading.readabilityHandler = { handle in
            let chunk = handle.availableData
            guard !chunk.isEmpty else { return }
            out.append(String(decoding: chunk, as: UTF8.self))
        }
        errPipe.fileHandleForReading.readabilityHandler = { handle in
            let chunk = handle.availableData
            guard !chunk.isEmpty else { return }
            let text = String(decoding: chunk, as: UTF8.self)
            err.append(text)
            text.split(whereSeparator: \.isNewline).forEach { progress?(String($0)) }
        }

        try process.run()
        await withCheckedContinuation { continuation in
            process.terminationHandler = { _ in continuation.resume() }
        }
        outPipe.fileHandleForReading.readabilityHandler = nil
        errPipe.fileHandleForReading.readabilityHandler = nil

        return ProcResult(stdout: out.raw, stderr: err.raw, status: process.terminationStatus)
    }

    // MARK: - Pure parsers (testable)

    /// Parse the `ewfinfo -f dfxml` document. libewf emits an `<image_filenames>`
    /// fragment BEFORE the `<?xml?>` declaration, so the raw stdout isn't
    /// well-formed - we parse from the declaration onward. The root element is
    /// `<ewfobjects>` (not `<dfxml>`).
    public static func parseDFXML(_ xml: String) -> Metadata {
        guard let range = xml.range(of: "<?xml") else { return Metadata() }
        let cleaned = String(xml[range.lowerBound...])
        let collector = DFXMLCollector()
        let parser = XMLParser(data: Data(cleaned.utf8))
        parser.delegate = collector
        guard parser.parse() else { return Metadata() }

        var m = Metadata()
        func nonEmpty(_ s: String?) -> String? {
            guard let s, !s.isEmpty else { return nil }
            return s
        }
        m.caseNumber = nonEmpty(collector.elements["case_number"])
        m.evidenceNumber = nonEmpty(collector.elements["evidence_number"])
        m.descriptionText = nonEmpty(collector.elements["description"])
        m.examinerName = nonEmpty(collector.elements["examiner_name"])
        m.notes = nonEmpty(collector.elements["notes"])
        m.operatingSystem = nonEmpty(collector.elements["acquisition_system"])
        m.acquisitionVersion = nonEmpty(collector.elements["acquisition_version"])
        m.mediaSerial = nonEmpty(collector.elements["serial_number"])
        m.acquisitionDate = acquisitionDate(collector.elements["acquisition_date"])
        m.storedMD5 = normalizedHash(collector.hashes["md5"])
        m.storedSHA1 = normalizedHash(collector.hashes["sha1"])
        return m
    }

    /// Parse the human-readable `ewfinfo` text format: tab-indented `Key:  Value`
    /// lines grouped under section headers.
    public static func parseText(_ text: String) -> Metadata {
        var kv: [String: String] = [:]
        for rawLine in text.split(whereSeparator: \.isNewline) {
            let line = String(rawLine)
            guard let colon = line.firstIndex(of: ":") else { continue }
            let key = line[..<colon]
                .trimmingCharacters(in: .whitespaces)
                .lowercased()
            let value = line[line.index(after: colon)...]
                .trimmingCharacters(in: .whitespaces)
            guard !key.isEmpty, !value.isEmpty else { continue }
            // First occurrence wins (section headers have no value and are skipped).
            if kv[key] == nil { kv[key] = value }
        }

        var m = Metadata()
        func val(_ k: String) -> String? {
            guard let v = kv[k], v != "N/A" else { return nil }
            return v
        }
        m.caseNumber = val("case number")
        m.evidenceNumber = val("evidence number")
        m.descriptionText = val("description")
        m.examinerName = val("examiner name")
        m.notes = val("notes")
        m.operatingSystem = val("operating system used")
        m.acquisitionVersion = val("software version used")
        m.mediaSerial = val("serial number")
        m.acquisitionDate = acquisitionDate(val("acquisition date"))
        m.storedMD5 = normalizedHash(val("md5"))
        m.storedSHA1 = normalizedHash(val("sha1"))
        return m
    }

    /// Parse `ewfverify` output. The trailing `ewfverify: SUCCESS` / `FAILURE`
    /// line is the authoritative verdict; stored/calculated pairs are captured
    /// when present.
    public static func parseVerify(_ text: String) -> VerifyResult {
        var r = VerifyResult()
        if text.contains("ewfverify: SUCCESS") { r.passed = true }
        else if text.contains("ewfverify: FAILURE") { r.passed = false }

        for rawLine in text.split(whereSeparator: \.isNewline) {
            let line = String(rawLine)
            guard let colon = line.firstIndex(of: ":") else { continue }
            let label = line[..<colon].trimmingCharacters(in: .whitespaces).lowercased()
            let value = line[line.index(after: colon)...].trimmingCharacters(in: .whitespaces)
            let hash = normalizedHash(value)
            switch label {
            case "md5 hash stored in file":         r.storedMD5 = hash
            case "md5 hash calculated over data":   r.calculatedMD5 = hash
            case "sha1 hash stored in file":        r.storedSHA1 = hash
            case "sha1 hash calculated over data":  r.calculatedSHA1 = hash
            default: break
            }
        }
        return r
    }

    /// EWF acquisition dates print without a timezone (e.g. `2026-06-07T14:43:34`).
    /// Parsed as UTC for determinism.
    static func acquisitionDate(_ s: String?) -> Date? {
        guard let s, !s.isEmpty else { return nil }
        let f = DateFormatter()
        f.locale = Locale(identifier: "en_US_POSIX")
        f.timeZone = TimeZone(identifier: "UTC")
        f.dateFormat = "yyyy-MM-dd'T'HH:mm:ss"
        return f.date(from: s)
    }

    /// Validate + lowercase a hex digest, rejecting placeholders / junk.
    static func normalizedHash(_ s: String?) -> String? {
        guard let s else { return nil }
        let lower = s.lowercased()
        let hex = CharacterSet(charactersIn: "0123456789abcdef")
        guard [32, 40, 64].contains(lower.count),
              lower.unicodeScalars.allSatisfy({ hex.contains($0) }) else { return nil }
        return lower
    }
}

/// XMLParser delegate that flattens leaf element text + hashdigest attributes
/// into dictionaries. Last value wins per element name, which is fine for the
/// flat acquiry/media sections of ewfinfo's dfxml.
// `nonisolated`: a synchronous XMLParser accumulator used inside the
// (nonisolated) pure parser. XMLParser drives its delegate on the parse thread,
// not the main actor, so main-actor isolation here was both wrong and the source
// of "cannot be referenced from a nonisolated context" warnings.
private nonisolated final class DFXMLCollector: NSObject, XMLParserDelegate {
    var elements: [String: String] = [:]
    var hashes: [String: String] = [:]   // keyed by lowercased `type` attribute

    private var currentElement = ""
    private var currentHashType: String?
    private var buffer = ""

    func parser(_ parser: XMLParser, didStartElement elementName: String,
                namespaceURI: String?, qualifiedName qName: String?,
                attributes attributeDict: [String: String]) {
        currentElement = elementName
        buffer = ""
        if elementName == "hashdigest" {
            currentHashType = attributeDict["type"]?.lowercased()
        }
    }

    func parser(_ parser: XMLParser, foundCharacters string: String) {
        buffer += string
    }

    func parser(_ parser: XMLParser, didEndElement elementName: String,
                namespaceURI: String?, qualifiedName qName: String?) {
        let text = buffer.trimmingCharacters(in: .whitespacesAndNewlines)
        if elementName == "hashdigest", let type = currentHashType {
            hashes[type] = text
            currentHashType = nil
        } else if !text.isEmpty {
            elements[elementName] = text
        }
        buffer = ""
    }
}

#endif
