import Foundation

#if os(macOS)

/// Runs `tsk_loaddb` to ingest a disk image into a SQLite database that
/// StrataTSK then queries. This is where TSK does all the forensic file handling.
public actor TSKImageIngestor {
    private let environment: TSKEnvironment

    public init(environment: TSKEnvironment) { self.environment = environment }

    /// `progress` receives raw stderr lines from tsk_loaddb (it reports progress
    /// there) so the UI can surface ingestion status.
    public func ingest(
        imageAt imageURL: URL,
        into databaseURL: URL,
        progress: (@Sendable (String) -> Void)? = nil
    ) async throws {
        let tool = try environment.url(for: "tsk_loaddb")
        try? FileManager.default.removeItem(at: databaseURL)   // overwrite stale DB

        // -d <db>: write to this SQLite file.
        // -i <type>: hint the image format so we don't depend on auto-detection
        // (auto-detect silently treats unknown formats as raw, which produces a
        // single Unalloc entry instead of a real file system).
        var args = ["-d", databaseURL.path]
        if let type = Self.imageType(for: imageURL) {
            args.append(contentsOf: ["-i", type])
        }
        args.append(imageURL.path)

        // tsk_loaddb reports progress on stderr and produces no useful stdout.
        // Run through the shared runner so stderr is drained to EOF (full crash
        // context) and the unused stdout can't fill its pipe buffer and deadlock.
        let capture = try await ProcessRunner.runCapturing(
            executable: tool, arguments: args, onStderrLine: progress)

        // A signal (e.g. SIGABRT from TSK's APFS parser crashing on a macOS
        // image) surfaces as `terminationReason == .uncaughtSignal`, where
        // `terminationStatus` is the *signal number* — not an exit code. Report
        // the two distinctly so a crash isn't mislabelled "exit 6".
        if capture.crashed {
            throw TSKError.ingestionCrashed(signal: capture.terminationStatus,
                                            stderr: capture.stderrText)
        }
        guard capture.succeeded else {
            throw TSKError.ingestionFailed(exitCode: capture.terminationStatus,
                                           stderr: capture.stderrText)
        }
    }

    /// Map a source URL's extension to the TSK image-type argument. Exposed
    /// because file extraction (`icat`) needs the same hint.
    public static func imageType(for url: URL) -> String? {
        switch url.pathExtension.lowercased() {
        case "e01", "ex01", "s01", "l01": return "ewf"
        case "vhd", "vhdx":                return "vhd"
        case "vmdk":                       return "vmdk"
        case "qcow", "qcow2":              return "qcow"
        case "aff", "afm", "afd":          return "aff"
        case "raw", "dd", "img", "bin":    return "raw"
        default:                           return nil
        }
    }
}

#endif

