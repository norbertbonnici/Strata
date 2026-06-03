import Foundation

/// Parses a Windows registry hive (SYSTEM / SOFTWARE / NTUSER.DAT / etc.)
/// by shelling out to libregf's `regfexport`. The exporter emits a
/// human-readable text dump organized as key blocks followed by their
/// values; we walk that line-by-line and emit a flat `[RegistryValue]`.
///
/// Why a flat list, not a tree: analyzers only ever ask "is there a value at
/// path X named Y", so a flat list keyed by (path, name) is what they want.
/// If a registry browser view ever needs the tree, build it on demand from
/// the flat list.
public actor RegistryHiveParser {
    private let environment: RegistryEnvironment

    public init(environment: RegistryEnvironment) { self.environment = environment }

    /// Run regfexport against a hive file and parse its output.
    /// `hiveLabel` is the logical hive name we tag every value with
    /// ("SYSTEM", "SOFTWARE", "NTUSER", ...).
    public func parse(hiveAt fileURL: URL,
                      hiveLabel: String) async throws -> [RegistryValue] {
        let tool = try environment.url(for: "regfexport")

        // Same temp-file trick as EVTXParser: regfexport's output is dense
        // text on stdout; a Pipe-based reader would deadlock on large hives.
        let tempURL = FileManager.default.temporaryDirectory
            .appendingPathComponent("strata-regf-\(UUID().uuidString).txt")
        FileManager.default.createFile(atPath: tempURL.path, contents: nil)
        let outHandle = try FileHandle(forWritingTo: tempURL)
        defer { try? FileManager.default.removeItem(at: tempURL) }

        let process = Process()
        process.executableURL = tool
        process.arguments = [fileURL.path]
        process.standardOutput = outHandle

        let stderrPipe = Pipe()
        process.standardError = stderrPipe
        let stderrCollector = RegStderrCollector()
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
            throw RegistryError.parseFailed(exitCode: process.terminationStatus,
                                            stderr: stderrCollector.text)
        }

        let text = (try? String(contentsOf: tempURL, encoding: .utf8)) ?? ""
        return Self.records(from: text, hiveLabel: hiveLabel, sourceFile: fileURL.path)
    }

    /// regfexport prints blocks like:
    ///
    ///     Key: Software\Microsoft\Windows\CurrentVersion\Run
    ///     Last written time: Apr 01, 2024 12:34:56.789 UTC
    ///         Value: Sysmon
    ///             Type: 1 REG_SZ
    ///             Data: C:\Windows\system32\Sysmon.exe
    ///
    /// Format differs slightly across libregf versions. We parse defensively:
    /// any line starting with "Key:" opens a key, any "Value:" opens a value,
    /// and Type / Data / Last written time lines are matched by prefix.
    nonisolated static func records(from text: String,
                                    hiveLabel: String,
                                    sourceFile: String) -> [RegistryValue] {
        var out: [RegistryValue] = []
        var currentKeyPath = ""
        var currentLastWritten: Date?
        var pendingName: String?
        var pendingType: String?
        var pendingData: String?

        func flushValue() {
            guard let name = pendingName else { return }
            let type = RegistryValue.ValueType(label: pendingType ?? "")
            let data = (pendingData ?? "").trimmingCharacters(in: .whitespacesAndNewlines)
            out.append(RegistryValue(
                hive: hiveLabel,
                path: currentKeyPath,
                name: name,
                type: type,
                data: data,
                lastWritten: currentLastWritten,
                sourceFile: sourceFile))
            pendingName = nil; pendingType = nil; pendingData = nil
        }

        for rawLine in text.split(separator: "\n", omittingEmptySubsequences: false) {
            let line = String(rawLine)
            let trimmed = line.trimmingCharacters(in: .whitespaces)

            if let keyPath = extractPrefix("Key:", from: trimmed)
                ?? extractPrefix("Key name:", from: trimmed)
                ?? extractPrefix("Key path:", from: trimmed) {
                flushValue()
                currentKeyPath = keyPath
                currentLastWritten = nil
                continue
            }
            if let written = extractPrefix("Last written time:", from: trimmed) {
                currentLastWritten = parseLibyalDate(written)
                continue
            }
            if let valueName = extractPrefix("Value:", from: trimmed)
                ?? extractPrefix("Value name:", from: trimmed) {
                flushValue()
                pendingName = valueName
                continue
            }
            if let typeLine = extractPrefix("Type:", from: trimmed) {
                // "Type: 1 REG_SZ" - take the REG_ token (or last whitespace-separated word).
                let parts = typeLine.split(separator: " ").map(String.init)
                pendingType = parts.first(where: { $0.hasPrefix("REG_") }) ?? parts.last ?? typeLine
                continue
            }
            if let dataLine = extractPrefix("Data:", from: trimmed) {
                pendingData = dataLine
                continue
            }
        }
        flushValue()
        return out
    }

    /// "Foo: bar" -> "bar"; nil if the prefix doesn't match.
    private nonisolated static func extractPrefix(_ prefix: String, from line: String) -> String? {
        guard line.hasPrefix(prefix) else { return nil }
        return String(line.dropFirst(prefix.count))
            .trimmingCharacters(in: .whitespaces)
    }

    /// libyal renders timestamps as "MMM dd, yyyy HH:mm:ss.SSS UTC". The
    /// fractional seconds and zone abbreviation make `ISO8601DateFormatter`
    /// unsuitable.
    private nonisolated static func parseLibyalDate(_ value: String) -> Date? {
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.dateFormat = "MMM dd, yyyy HH:mm:ss.SSS zzz"
        return formatter.date(from: value)
    }
}

private nonisolated final class RegStderrCollector: @unchecked Sendable {
    private let lock = NSLock()
    private var buffer = ""
    func append(_ s: String) { lock.lock(); buffer += s; lock.unlock() }
    var text: String {
        lock.lock(); defer { lock.unlock() }
        return buffer.trimmingCharacters(in: .whitespacesAndNewlines)
    }
}
