import Foundation

#if os(macOS)

/// Ingests **APFS (macOS)** evidence with libyal's `fsapfsinfo` — the path used
/// when `tsk_loaddb` can't (The Sleuth Kit's APFS parser SIGABRTs on real macOS
/// volumes). `fsapfsinfo` reads a **raw** image only, so an E01 is converted to
/// raw with `ewfexport` first; then for each APFS volume we run
/// `fsapfsinfo -f <i> -H -B <bodyfile>` (hierarchy + bodyfile → full paths with
/// MACB) and decode the TSK `mactime` bodyfile (`BodyfileParser`) into
/// `FileEntry`s grouped per volume (`fsID`),
/// plus a `VolumeInfo` per volume. No `tsk.db` is produced (mirrors the loose-
/// folder path); file *content* extraction is a later step.
public actor FsApfsIngestor {
    private let environment: TSKEnvironment
    public init(environment: TSKEnvironment) { self.environment = environment }

    public enum FsApfsError: Error, LocalizedError {
        case noApfsContainer
        case toolFailed(String)
        public var errorDescription: String? {
            switch self {
            case .noApfsContainer: return "No readable APFS container was found in the image."
            case .toolFailed(let s): return "fsapfs ingest failed: \(s)"
            }
        }
    }

    public struct Result: Sendable {
        public let files: [FileEntry]
        public let volumes: [VolumeInfo]
        /// The raw image this ingest read from (the source itself, or a scratch
        /// conversion of an E01). Retained so a later content-extraction step can
        /// reuse it; nil if it was the original source.
        public let rawScratchURL: URL?
        /// Volumes that appear FileVault-encrypted and produced no readable
        /// metadata with the credential supplied (empty if all volumes read).
        /// `ApfsLockedVolume` lives in StrataCore so the UI can use it on iOS.
        public let lockedVolumes: [ApfsLockedVolume]
    }

    /// Run the APFS ingest. `imageType` is the TSK image-type hint
    /// (`TSKImageIngestor.imageType(for:)`): nil/"raw" ⇒ already raw, anything
    /// else (e.g. "ewf") ⇒ convert to raw via `ewfexport` first.
    public func ingest(imageAt imageURL: URL, imageType: String?,
                       scratchDirectory: URL,
                       credential: FileVaultCredential? = nil,
                       progress: ((String) -> Void)? = nil) async throws -> Result {
        try FileManager.default.createDirectory(at: scratchDirectory, withIntermediateDirectories: true)

        // 1. Get raw access.
        let rawURL: URL
        let scratchRaw: URL?
        if imageType == nil || imageType == "raw" {
            rawURL = imageURL
            scratchRaw = nil
        } else {
            progress?("Converting \(imageURL.lastPathComponent) to raw (ewfexport)…")
            let out = scratchDirectory.appendingPathComponent("image_raw")
            try await runEwfExport(imageURL: imageURL, output: out, progress: progress)
            rawURL = URL(fileURLWithPath: out.path + ".raw")
            scratchRaw = rawURL
        }

        // 2. Find the APFS container's byte offset (try each partition from mmls,
        // then offset 0 as a fallback for a bare container image).
        progress?("Locating APFS container…")
        var offset: UInt64?
        for candidate in try await partitionOffsets(rawURL: rawURL) + [0] {
            if (try? await containerVolumeCount(rawURL: rawURL, offset: candidate)) ?? 0 > 0 {
                offset = candidate
                break
            }
        }
        guard let apfsOffset = offset else { throw FsApfsError.noApfsContainer }

        let volumeCount = try await containerVolumeCount(rawURL: rawURL, offset: apfsOffset)

        // 3. Per volume: bodyfile → FileEntry.
        var files: [FileEntry] = []
        var volumes: [VolumeInfo] = []
        var locked: [ApfsLockedVolume] = []
        var nextID: Int64 = 1
        // fsapfsinfo's -f / Volume display are 1-based; fsID stays 0-based.
        for index in 1...volumeCount {
            let fsID = Int64(index - 1)
            let label = (try? await volumeName(rawURL: rawURL, offset: apfsOffset, index: index)) ?? "Volume \(index)"
            progress?("Reading APFS volume \(index)/\(volumeCount): \(label)…")
            let bodyfile = scratchDirectory.appendingPathComponent("vol\(index).body")
            var produced = false
            do {
                try await runBodyfile(rawURL: rawURL, offset: apfsOffset, index: index,
                                      output: bodyfile, credential: credential)
                let text = (try? String(contentsOf: bodyfile, encoding: .utf8)) ?? ""
                for e in BodyfileParser.parse(text) {
                    guard let mapped = Self.fileEntry(from: e, id: nextID, fsID: fsID) else { continue }
                    files.append(mapped)
                    nextID += 1
                    produced = true
                }
            } catch {
                // A FileVault-encrypted volume can't be read without the secret;
                // record it as locked and keep going rather than failing the whole
                // ingest. A non-encryption tool error (only when a credential was
                // supplied, so we expected success) is surfaced.
                if credential != nil, !Self.looksEncrypted(error) { throw error }
            }
            // An empty (or encryption-failed) volume with no usable secret is
            // treated as FileVault-locked so the UI can prompt + re-ingest.
            if !produced { locked.append(ApfsLockedVolume(index: index, name: label)) }
            volumes.append(VolumeInfo(id: fsID, fsType: "APFS",
                                      offsetBytes: Int64(apfsOffset), sizeBytes: 0))
        }
        guard !files.isEmpty || !locked.isEmpty else { throw FsApfsError.noApfsContainer }
        return Result(files: files, volumes: volumes, rawScratchURL: scratchRaw, lockedVolumes: locked)
    }

    /// Heuristic: does this `fsapfsinfo` failure look like a missing/wrong
    /// FileVault secret rather than a genuine tool error?
    static func looksEncrypted(_ error: Error) -> Bool {
        let s = (error as? FsApfsError)?.errorDescription?.lowercased()
            ?? error.localizedDescription.lowercased()
        return s.contains("encrypt") || s.contains("password") || s.contains("unlock")
            || s.contains("unable to read") || s.contains("key")
    }

    // MARK: - BodyfileEntry → FileEntry

    /// Strip an optional `/{uuid}/` volume prefix some libfsapfs paths carry.
    static func cleanPath(_ raw: String) -> String {
        guard raw.hasPrefix("/{"), let close = raw.range(of: "}/") else { return raw }
        return String(raw[close.upperBound...]).hasPrefix("/") ? String(raw[close.upperBound...]) : "/" + String(raw[close.upperBound...])
    }

    static func fileEntry(from e: BodyfileEntry, id: Int64, fsID: Int64) -> FileEntry? {
        var path = cleanPath(e.path)
        if path.isEmpty { return nil }                      // volume root - implied by the tree
        if !path.hasPrefix("/") { path = "/" + path }
        let ns = path as NSString
        let name = ns.lastPathComponent
        guard !name.isEmpty else { return nil }
        var parent = ns.deletingLastPathComponent
        if !parent.hasSuffix("/") { parent += "/" }
        return FileEntry(
            id: id, metaAddr: Int64(bitPattern: e.inode), name: name, parentPath: parent,
            size: e.size, isDirectory: e.isDirectory, isDeleted: false,
            modified: e.modified, accessed: e.accessed, changed: e.changed, created: e.created,
            fsID: fsID, diskURL: nil)
    }

    // MARK: - Tool invocations

    private func runEwfExport(imageURL: URL, output: URL, progress: ((String) -> Void)?) async throws {
        _ = try await runTool("ewfexport",
                              ["-u", "-f", "raw", "-t", output.path, imageURL.path],
                              progress: progress)
    }

    private func runBodyfile(rawURL: URL, offset: UInt64, index: Int, output: URL,
                             credential: FileVaultCredential?) async throws {
        // -H (hierarchy) + -B yields full *paths* + MACB; -E all gives leaf names
        // only (no parent path), so the tree can't be rebuilt from it.
        // -p / -r unlock a FileVault-encrypted volume's metadata.
        var args = ["-o", "\(offset)", "-f", "\(index)"]
        if let password = credential?.password { args.append(contentsOf: ["-p", password]) }
        if let recovery = credential?.recovery { args.append(contentsOf: ["-r", recovery]) }
        args.append(contentsOf: ["-H", "-B", output.path, rawURL.path])
        _ = try await runTool("fsapfsinfo", args, progress: nil)
    }

    /// Partition start byte-offsets parsed from `mmls`.
    private func partitionOffsets(rawURL: URL) async throws -> [UInt64] {
        let out = try await runTool("mmls", ["-i", "raw", rawURL.path], progress: nil)
        var offsets: [UInt64] = []
        for line in out.split(separator: "\n") {
            // "004:  000  0000000040  0000409639  ..." — start sector is column 3.
            let cols = line.split(whereSeparator: { $0 == " " || $0 == "\t" }).map(String.init)
            guard cols.count >= 4, cols[0].hasSuffix(":"),
                  let startSector = UInt64(cols[2]) else { continue }
            offsets.append(startSector * 512)
        }
        return offsets
    }

    /// Number of volumes in the APFS container at `offset`, or 0 if not APFS.
    private func containerVolumeCount(rawURL: URL, offset: UInt64) async throws -> Int {
        let out = (try? await runTool("fsapfsinfo", ["-o", "\(offset)", rawURL.path], progress: nil)) ?? ""
        guard let line = out.split(separator: "\n").first(where: { $0.contains("Number of volumes") }),
              let n = line.split(separator: ":").last.flatMap({ Int($0.trimmingCharacters(in: .whitespaces)) })
        else { return 0 }
        return n
    }

    private func volumeName(rawURL: URL, offset: UInt64, index: Int) async throws -> String? {
        let out = try await runTool("fsapfsinfo", ["-o", "\(offset)", rawURL.path], progress: nil)
        // Find "Volume: <index+1> information:" then its "Name :" line.
        let lines = out.split(separator: "\n").map(String.init)
        guard let start = lines.firstIndex(where: { $0.contains("Volume: \(index) information") }) else { return nil }
        for line in lines[start...].prefix(6) where line.contains("Name") {
            return line.split(separator: ":").last.map { $0.trimmingCharacters(in: .whitespaces) }
        }
        return nil
    }

    /// Run a vendored tool, returning stdout. Throws `toolFailed` on a non-zero
    /// exit (signal or error), surfacing stderr.
    private func runTool(_ name: String, _ args: [String], progress: ((String) -> Void)?) async throws -> String {
        let tool = try environment.url(for: name)
        let process = Process()
        process.executableURL = tool
        process.arguments = args
        let outPipe = Pipe(), errPipe = Pipe()
        process.standardOutput = outPipe
        process.standardError = errPipe
        let errCollector = PipeTextCollector()
        errPipe.fileHandleForReading.readabilityHandler = { h in
            let d = h.availableData
            guard !d.isEmpty else { return }
            let s = String(decoding: d, as: UTF8.self)
            errCollector.append(s)
            s.split(whereSeparator: \.isNewline).forEach { progress?(String($0)) }
        }
        let outData = OutputAccumulator()
        outPipe.fileHandleForReading.readabilityHandler = { h in
            let d = h.availableData
            if !d.isEmpty { outData.append(d) }
        }
        try process.run()
        await withCheckedContinuation { c in process.terminationHandler = { _ in c.resume() } }
        errPipe.fileHandleForReading.readabilityHandler = nil
        outPipe.fileHandleForReading.readabilityHandler = nil
        guard process.terminationReason == .exit, process.terminationStatus == 0 else {
            throw FsApfsError.toolFailed("\(name): \(errCollector.text)")
        }
        return outData.string()
    }
}

/// Thread-safe stdout accumulator for the readability handler.
nonisolated private final class OutputAccumulator: @unchecked Sendable {
    private var data = Data()
    private let lock = NSLock()
    func append(_ d: Data) { lock.lock(); data.append(d); lock.unlock() }
    func string() -> String { lock.lock(); defer { lock.unlock() }; return String(decoding: data, as: UTF8.self) }
}

#endif
