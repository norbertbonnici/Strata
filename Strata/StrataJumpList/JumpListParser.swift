import Foundation

#if os(macOS)

/// Parses a Windows JumpList into `[JumpListEntry]`.
///
/// - `.automaticDestinations-ms` is an OLE compound file: `olecfexport` cracks it
///   into `<base>.export/<stream>/StreamData.bin`. Each hex-named stream is a
///   Shell Link parsed by the reused `LnkParser` (lnkinfo); the `DestList` stream
///   is byte-decoded by `DestListParser` for the MRU metadata (last-access time,
///   access count, hostname, pin), joined to its LNK by entry ID.
/// - `.customDestinations-ms` is a flat sequence of LNKs: `ShellLinkCarver` splits
///   it and each blob is parsed by `LnkParser`. No DestList.
public actor JumpListParser {
    private let environment: JumpListEnvironment   // olecfexport
    private let lnkParser: LnkParser               // reused lnkinfo wrapper

    public init(environment: JumpListEnvironment, lnkParser: LnkParser) {
        self.environment = environment
        self.lnkParser = lnkParser
    }

    /// Parse a readable jumplist file. `appID` comes from the original filename
    /// (the on-disk name is lost once extracted); `sourceFile` is the in-image
    /// path retained for display.
    public func parse(fileAt fileURL: URL, appID: String, sourceFile: String,
                      isAutomatic: Bool) async throws -> [JumpListEntry] {
        isAutomatic
            ? try await parseAutomatic(fileAt: fileURL, appID: appID, sourceFile: sourceFile)
            : try await parseCustom(fileAt: fileURL, appID: appID, sourceFile: sourceFile)
    }

    // MARK: - AutomaticDestinations (OLE)

    private func parseAutomatic(fileAt fileURL: URL, appID: String,
                                sourceFile: String) async throws -> [JumpListEntry] {
        let tool = try environment.url(for: "olecfexport")
        // olecfexport appends ".export" to the -t target and refuses if it
        // exists, so hand it a fresh unique base.
        let base = FileManager.default.temporaryDirectory
            .appendingPathComponent("strata-jl-\(UUID().uuidString)")
        let exportDir = URL(fileURLWithPath: base.path + ".export")
        defer { try? FileManager.default.removeItem(at: exportDir) }

        let process = Process()
        process.executableURL = tool
        process.arguments = ["-t", base.path, fileURL.path]
        process.standardOutput = FileHandle.nullDevice
        let stderrPipe = Pipe()
        process.standardError = stderrPipe

        // Drain stderr continuously. olecfexport can be chatty on a
        // dirty/partially-corrupt OLE container - left unread, a noisy run fills
        // the kernel pipe buffer (~16-64 KB), blocks the child on write, and
        // hangs forever. Same pattern as the EVTX / LNK / registry / SRUM
        // shell-out parsers.
        let collector = PipeTextCollector()
        stderrPipe.fileHandleForReading.readabilityHandler = { handle in
            let chunk = handle.availableData
            guard !chunk.isEmpty else { return }
            collector.append(String(decoding: chunk, as: UTF8.self))
        }

        try process.run()
        await withCheckedContinuation { c in process.terminationHandler = { _ in c.resume() } }
        stderrPipe.fileHandleForReading.readabilityHandler = nil
        guard process.terminationStatus == 0 else {
            throw JumpListError.exportFailed(exitCode: process.terminationStatus, stderr: collector.text)
        }

        let application = JumpListAppID.application(for: appID)
        let fm = FileManager.default
        let streamDirs = (try? fm.contentsOfDirectory(at: exportDir,
                                                      includingPropertiesForKeys: [.isDirectoryKey])) ?? []

        // DestList metadata keyed by entry ID.
        var destByEntry: [Int: DestListRecord] = [:]
        if let destDir = streamDirs.first(where: { $0.lastPathComponent.caseInsensitiveCompare("DestList") == .orderedSame }) {
            let url = destDir.appendingPathComponent("StreamData.bin")
            if let data = try? Data(contentsOf: url) {
                for rec in DestListParser.parse(bytes: [UInt8](data)) { destByEntry[rec.entryID] = rec }
            }
        }

        var out: [JumpListEntry] = []
        for dir in streamDirs {
            let name = dir.lastPathComponent.lowercased()
            // Numbered LNK stream (hex name); skip DestList and any OLE bookkeeping.
            guard let entryID = Int(name, radix: 16) else { continue }
            let streamURL = dir.appendingPathComponent("StreamData.bin")
            let lnk = try? await lnkParser.parse(fileAt: streamURL)   // nil if not a valid LNK
            let dest = destByEntry[entryID]
            // Skip streams that yielded neither a target nor DestList metadata.
            guard lnk?.targetPath != nil || dest != nil else { continue }
            out.append(JumpListEntry(
                appID: appID, application: application, listType: .automatic,
                entryID: entryID,
                targetPath: lnk?.targetPath ?? dest?.path,
                arguments: lnk?.arguments,
                lastAccessed: dest?.lastAccessed,
                accessCount: dest?.accessCount,
                hostname: dest?.hostname,
                pinned: dest?.pinned,
                sourceFile: sourceFile))
        }
        // Most-recently accessed first.
        out.sort { ($0.lastAccessed ?? .distantPast) > ($1.lastAccessed ?? .distantPast) }
        return out
    }

    // MARK: - CustomDestinations (flat LNK sequence)

    private func parseCustom(fileAt fileURL: URL, appID: String,
                             sourceFile: String) async throws -> [JumpListEntry] {
        guard let data = try? Data(contentsOf: fileURL) else { return [] }
        let blobs = ShellLinkCarver.carve([UInt8](data))
        guard !blobs.isEmpty else { return [] }
        let application = JumpListAppID.application(for: appID)

        let scratch = FileManager.default.temporaryDirectory
            .appendingPathComponent("strata-jl-custom-\(UUID().uuidString)", isDirectory: true)
        try? FileManager.default.createDirectory(at: scratch, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: scratch) }

        var out: [JumpListEntry] = []
        for (idx, blob) in blobs.enumerated() {
            let lnkURL = scratch.appendingPathComponent("\(idx).lnk")
            guard (try? Data(blob).write(to: lnkURL)) != nil else { continue }
            guard let lnk = try? await lnkParser.parse(fileAt: lnkURL), lnk.targetPath != nil else { continue }
            out.append(JumpListEntry(
                appID: appID, application: application, listType: .custom,
                entryID: idx,
                targetPath: lnk.targetPath,
                arguments: lnk.arguments,
                sourceFile: sourceFile))
        }
        return out
    }
}

#endif
