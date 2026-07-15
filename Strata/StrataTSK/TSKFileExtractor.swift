import Foundation

#if os(macOS)

/// Extracts a single file's bytes out of a forensic image by shelling out to
/// `icat` and redirecting its stdout to a scratch file. Needed because TSK's
/// SQLite database only holds metadata - the actual file content lives in
/// the image and only icat (or libtsk) can decompress / locate it.
public actor TSKFileExtractor {
    private let environment: TSKEnvironment
    private let imageURL: URL
    private let imageType: String?

    public init(environment: TSKEnvironment, imageURL: URL, imageType: String?) {
        self.environment = environment
        self.imageURL = imageURL
        self.imageType = imageType
    }

    /// `imageOffsetSectors` is the partition's start sector inside the image;
    /// without it icat would look at the wrong partition on multi-partition
    /// disks (almost every real Windows image). Passing 0 means "no offset",
    /// which TSK takes as the start of the image.
    public func extract(metaAddr: Int64,
                        imageOffsetSectors: Int64,
                        to destination: URL) async throws {
        try await run(address: "\(metaAddr)", imageOffsetSectors: imageOffsetSectors,
                      to: destination, suppressHoles: false)
    }

    /// Extract a specific NTFS attribute (a named alternate data stream) using
    /// icat's `meta-type-id` address form. `suppressHoles` adds `-h` so a huge
    /// sparse stream (the USN journal's `$J`) doesn't materialise gigabytes of
    /// zeros.
    public func extractStream(metaAddr: Int64, attrType: Int64, attrId: Int64,
                              imageOffsetSectors: Int64, to destination: URL,
                              suppressHoles: Bool = true) async throws {
        try await run(address: "\(metaAddr)-\(attrType)-\(attrId)",
                      imageOffsetSectors: imageOffsetSectors, to: destination,
                      suppressHoles: suppressHoles)
    }

    private func run(address: String, imageOffsetSectors: Int64,
                     to destination: URL, suppressHoles: Bool) async throws {
        let tool = try environment.url(for: "icat")
        try? FileManager.default.removeItem(at: destination)
        FileManager.default.createFile(atPath: destination.path, contents: nil)

        var args: [String] = []
        if suppressHoles { args.append("-h") }   // don't emit sparse holes
        if let imageType { args.append(contentsOf: ["-i", imageType]) }
        if imageOffsetSectors > 0 { args.append(contentsOf: ["-o", "\(imageOffsetSectors)"]) }
        args.append(imageURL.path)
        args.append(address)

        // icat streams the file bytes to stdout → the scratch file; stderr is
        // drained to EOF by the shared runner (which also avoids the classic
        // pipe-buffer deadlock a chatty icat could otherwise cause).
        let outHandle = try FileHandle(forWritingTo: destination)
        defer { try? outHandle.close() }   // close on every path, incl. a launch throw
        let capture = try await ProcessRunner.runCapturing(
            executable: tool, arguments: args, stdoutSink: outHandle)

        // A signal kill (crash) is distinct from a non-zero exit: report it as
        // such rather than as a bogus "exit <signal>" code.
        if capture.crashed {
            throw TSKError.extractionCrashed(signal: capture.terminationStatus,
                                             stderr: capture.stderrText)
        }
        guard capture.succeeded else {
            throw TSKError.ingestionFailed(exitCode: capture.terminationStatus,
                                           stderr: capture.stderrText)
        }
    }
}

#endif

