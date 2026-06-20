import Foundation

#if os(macOS)

/// Parses a Windows Prefetch (`.pf`) file into a `PrefetchEntry` by shelling out
/// to libscca's `sccainfo`. One `.pf` describes one executable, so each parse
/// yields a single entry (or nil if the file carried no executable name).
///
/// sccainfo handles the MAM/Xpress-Huffman decompression that Win10/11 prefetch
/// needs, so we never touch the compressed bytes ourselves - we just read its
/// text report. The report is small (a few KB), but we still spool stdout to a
/// temp file to stay consistent with EVTXParser and sidestep any pipe edge case.
public actor PrefetchParser {
    private let environment: PrefetchEnvironment

    public init(environment: PrefetchEnvironment) { self.environment = environment }

    public func parse(fileAt fileURL: URL) async throws -> PrefetchEntry? {
        let tool = try environment.url(for: "sccainfo")

        let tempURL = FileManager.default.temporaryDirectory
            .appendingPathComponent("strata-scca-\(UUID().uuidString).txt")
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
            throw PrefetchError.parseFailed(exitCode: process.terminationStatus,
                                            stderr: stderrCollector.text)
        }

        let text = (try? String(contentsOf: tempURL, encoding: .utf8)) ?? ""
        return Self.entry(from: text, sourceFile: fileURL.path)
    }

    /// Pure parse of one `sccainfo` report into a `PrefetchEntry`. Split out and
    /// `nonisolated` so it's unit-testable without the binary. Returns nil if the
    /// report carried no executable name (an empty or non-prefetch file).
    nonisolated static func entry(from output: String, sourceFile: String) -> PrefetchEntry? {
        var executableName: String?
        var runCount: UInt32 = 0
        var formatVersion: Int?
        var fileCount = 0
        var volumeCount = 0
        var lastRunTimes: [Date] = []
        var filenames: [String] = []

        for rawLine in output.split(whereSeparator: \.isNewline) {
            let line = String(rawLine)
            // The label/value separator is "<tabs>: ". NT paths ("\DEVICE\...")
            // and CTIME timestamps ("10:30:45") never contain a colon followed
            // by a space, so the LAST ": " is always the real separator - this
            // is what makes "Filename: 1\t\t\t: \DEVICE\..." parse correctly.
            guard let sep = line.range(of: ": ", options: .backwards) else { continue }
            let label = line[..<sep.lowerBound].trimmingCharacters(in: .whitespaces)
            let value = line[sep.upperBound...].trimmingCharacters(in: .whitespaces)
            guard !value.isEmpty else { continue }

            if label.hasPrefix("Executable filename") {
                executableName = value
            } else if label.hasPrefix("Run count") {
                runCount = UInt32(value) ?? 0
            } else if label.hasPrefix("Format version") {
                formatVersion = Int(value)
            } else if label.hasPrefix("Number of filenames") {
                fileCount = Int(value) ?? 0
            } else if label.hasPrefix("Number of volumes") {
                volumeCount = Int(value) ?? 0
            } else if label.hasPrefix("Last run time") {
                if let date = parseCTime(value) { lastRunTimes.append(date) }
            } else if label.hasPrefix("Filename") {
                // A per-file entry ("Filename: 3"), not "Number of filenames".
                filenames.append(value)
            }
        }

        guard let exe = executableName, !exe.isEmpty else { return nil }

        // Recover the executable's full NT path: the metrics array lists every
        // file the program touched at startup, including itself. Match on
        // basename (case-insensitive - prefetch upper-cases the header name).
        let executablePath = filenames.first { path in
            (path.split(separator: "\\").last.map(String.init) ?? path)
                .caseInsensitiveCompare(exe) == .orderedSame
        }

        return PrefetchEntry(executableName: exe,
                             executablePath: executablePath,
                             runCount: runCount,
                             lastRunTimes: lastRunTimes,
                             fileCount: fileCount,
                             volumeCount: volumeCount,
                             formatVersion: formatVersion,
                             sourceFile: sourceFile)
    }

    /// Parse sccainfo's CTIME timestamp, e.g.
    /// "Mar 12, 2024 10:30:45.123456789 UTC". Sub-second precision is dropped
    /// (run times don't need it) and "Not set (0)" returns nil.
    private nonisolated static func parseCTime(_ value: String) -> Date? {
        if value.hasPrefix("Not set") { return nil }
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
