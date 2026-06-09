import Foundation

#if os(macOS)

/// Parses a Windows SRUM database (`SRUDB.dat`) into `[SrumEntry]`.
///
/// `SRUDB.dat` is an ESE (Extensible Storage Engine) B-tree database — far too
/// complex to byte-parse in Swift — so we shell out to libesedb's `esedbexport`,
/// which cracks every table into a headered TSV file under `<base>.export/`. We
/// then hand the relevant tables' text to the pure, cross-platform
/// `SrumExportDecoder`, which resolves the SruDbIdMapTable foreign keys and
/// builds the unified rows. Mirrors `JumpListParser`'s use of `olecfexport`.
public actor SrumParser {
    private let environment: SRUMEnvironment

    public init(environment: SRUMEnvironment) { self.environment = environment }

    public func parse(fileAt fileURL: URL, sourceFile: String) async throws -> [SrumEntry] {
        let tool = try environment.url(for: "esedbexport")
        // esedbexport appends ".export" to the -t basename and refuses to run if
        // that directory already exists, so hand it a fresh unique base.
        let base = FileManager.default.temporaryDirectory
            .appendingPathComponent("strata-srum-\(UUID().uuidString)")
        let exportDir = URL(fileURLWithPath: base.path + ".export")
        defer { try? FileManager.default.removeItem(at: exportDir) }

        let process = Process()
        process.executableURL = tool
        process.arguments = ["-t", base.path, fileURL.path]
        process.standardOutput = FileHandle.nullDevice   // chatty per-table progress
        let stderrPipe = Pipe()
        process.standardError = stderrPipe

        // Drain stderr continuously. esedbexport emits per-record recovery
        // warnings on a dirty/partially-corrupt SRUDB.dat (the common live-system
        // case) - left unread, a chatty run fills the kernel pipe buffer (~16-64
        // KB), blocks the child on write, and hangs forever. Same pattern as the
        // EVTX / LNK / registry shell-out parsers.
        let collector = SrumStderrCollector()
        stderrPipe.fileHandleForReading.readabilityHandler = { handle in
            let chunk = handle.availableData
            guard !chunk.isEmpty else { return }
            collector.append(String(decoding: chunk, as: UTF8.self))
        }

        try process.run()
        await withCheckedContinuation { c in process.terminationHandler = { _ in c.resume() } }
        stderrPipe.fileHandleForReading.readabilityHandler = nil
        guard process.terminationStatus == 0 else {
            throw SRUMError.exportFailed(exitCode: process.terminationStatus, stderr: collector.text)
        }

        let fm = FileManager.default
        let files = (try? fm.contentsOfDirectory(at: exportDir, includingPropertiesForKeys: nil)) ?? []

        // esedbexport names each file `<TableName>.<index>` (no extension); GUIDs
        // contain no dots, so the table name is everything before the last '.'.
        func contents(forTable table: String) -> String? {
            guard let url = files.first(where: {
                Self.tableName(of: $0.lastPathComponent).caseInsensitiveCompare(table) == .orderedSame
            }), let data = try? Data(contentsOf: url) else { return nil }
            return String(decoding: data, as: UTF8.self)
        }

        return SrumExportDecoder.decode(
            idMapTSV: contents(forTable: SrumExportDecoder.idMapTable),
            networkDataTSV: contents(forTable: SrumExportDecoder.networkDataTable),
            appResourceTSV: contents(forTable: SrumExportDecoder.appResourceTable),
            networkConnectivityTSV: contents(forTable: SrumExportDecoder.networkConnectivityTable),
            sourceFile: sourceFile)
    }

    private static func tableName(of filename: String) -> String {
        guard let dot = filename.lastIndex(of: ".") else { return filename }
        return String(filename[..<dot])
    }
}

/// Thread-safe stderr accumulator for the continuous pipe drain (the
/// readabilityHandler fires on an arbitrary queue). Mirrors the collector the
/// other shell-out parsers use.
private nonisolated final class SrumStderrCollector: @unchecked Sendable {
    private let lock = NSLock()
    private var buffer = ""
    func append(_ s: String) { lock.lock(); buffer += s; lock.unlock() }
    var text: String {
        lock.lock(); defer { lock.unlock() }
        return buffer.trimmingCharacters(in: .whitespacesAndNewlines)
    }
}

#endif
