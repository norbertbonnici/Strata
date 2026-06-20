import Foundation

#if os(macOS)

/// Parses a Windows Shell Link (`.lnk`) into a `LnkEntry` by shelling out to
/// liblnk's `lnkinfo`. One `.lnk` describes one shortcut, so each parse yields a
/// single entry (or nil if nothing useful decoded).
public actor LnkParser {
    private let environment: VendoredTool

    public init(environment: VendoredTool) { self.environment = environment }

    public func parse(fileAt fileURL: URL) async throws -> LnkEntry? {
        let tool = try environment.url(for: "lnkinfo")

        let tempURL = FileManager.default.temporaryDirectory
            .appendingPathComponent("strata-lnk-\(UUID().uuidString).txt")
        FileManager.default.createFile(atPath: tempURL.path, contents: nil)
        let outHandle = try FileHandle(forWritingTo: tempURL)
        defer { try? FileManager.default.removeItem(at: tempURL) }

        let process = Process()
        process.executableURL = tool
        process.arguments = [fileURL.path]
        process.standardOutput = outHandle

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
            throw VendoredToolError.parseFailed(tool: "lnkinfo", exitCode: process.terminationStatus,
                                                stderr: stderrCollector.text)
        }

        let text = (try? String(contentsOf: tempURL, encoding: .utf8)) ?? ""
        return Self.entry(from: text, sourceFile: fileURL.path)
    }

    /// Pure parse of one `lnkinfo` report. Split out + `nonisolated` so it's
    /// unit-testable without the binary. Each line is "<label><tabs>: <value>";
    /// we split on the FIRST ": " (labels never contain it) so a value that does
    /// — e.g. command-line args or a URL — is preserved intact.
    nonisolated static func entry(from output: String, sourceFile: String) -> LnkEntry? {
        var fields: [String: String] = [:]
        for rawLine in output.split(whereSeparator: \.isNewline) {
            let line = String(rawLine)
            guard let sep = line.range(of: ": ") else { continue }
            let label = line[..<sep.lowerBound].trimmingCharacters(in: .whitespaces)
            let value = line[sep.upperBound...].trimmingCharacters(in: .whitespaces)
            guard !label.isEmpty, !value.isEmpty else { continue }
            // First occurrence wins (the same label can recur across sections).
            // lnkinfo escapes every backslash as "\\" in its output, so un-double
            // them — otherwise paths read "C:\\Windows\\..." and break matching.
            if fields[label] == nil { fields[label] = unescape(value) }
        }

        let localPath = fields["Local path"]
        let networkPath = fields["Network path"]
        let description = fields["Description"]
        let arguments = fields["Command line arguments"]
        // A shortcut with none of these decoded is almost certainly a parse miss.
        guard localPath != nil || networkPath != nil || arguments != nil || description != nil else {
            return nil
        }

        return LnkEntry(
            sourceFile: sourceFile,
            localPath: localPath,
            networkPath: networkPath,
            description: description,
            arguments: arguments,
            workingDirectory: fields["Working directory"],
            iconLocation: fields["Icon location"],
            targetSize: fields["File size"].flatMap(parseSize),
            targetCreated: parseCTime(fields["Creation time"]),
            targetModified: parseCTime(fields["Modification time"]),
            targetAccessed: parseCTime(fields["Access time"]),
            driveType: fields["Drive type"],
            volumeLabel: fields["Volume label"],
            volumeSerial: fields["Drive serial number"],
            machineIdentifier: fields["Machine identifier"])
    }

    /// lnkinfo doubles every backslash in its output; restore single ones.
    private nonisolated static func unescape(_ s: String) -> String {
        s.replacingOccurrences(of: #"\\"#, with: #"\"#)
    }

    /// "12345" (optionally with a trailing " bytes") -> 12345.
    private nonisolated static func parseSize(_ s: String) -> Int64? {
        let digits = s.prefix { $0.isNumber }
        return digits.isEmpty ? nil : Int64(digits)
    }

    /// liblnk prints timestamps in libfdatetime CTIME form, e.g.
    /// "Mar 12, 2024 10:30:45.000000000 UTC"; "Not set (0)" -> nil. Sub-second
    /// precision is dropped (not needed here).
    private nonisolated static func parseCTime(_ value: String?) -> Date? {
        guard let value, !value.hasPrefix("Not set") else { return nil }
        var trimmed = value
        if let utc = trimmed.range(of: " UTC") { trimmed = String(trimmed[..<utc.lowerBound]) }
        if let dot = trimmed.firstIndex(of: ".") { trimmed = String(trimmed[..<dot]) }
        trimmed = trimmed.trimmingCharacters(in: .whitespaces)
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.timeZone = TimeZone(identifier: "UTC")
        formatter.dateFormat = "MMM d, yyyy HH:mm:ss"
        return formatter.date(from: trimmed)
    }
}

#endif
