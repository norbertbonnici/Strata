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

        let process = Process()
        process.executableURL = tool
        process.arguments = args

        let outHandle = try FileHandle(forWritingTo: destination)
        defer { try? outHandle.close() }   // close on every path, incl. a launch throw
        let stderrPipe = Pipe()
        process.standardOutput = outHandle
        process.standardError = stderrPipe

        // Drain stderr continuously. Without this a chatty icat run can fill
        // the kernel pipe buffer (~16-64 KB), block the child on write, and
        // hang the whole subprocess. The classic Unix pipe deadlock.
        let collector = PipeTextCollector()
        stderrPipe.fileHandleForReading.readabilityHandler = { handle in
            let chunk = handle.availableData
            guard !chunk.isEmpty else { return }
            collector.append(String(decoding: chunk, as: UTF8.self))
        }

        try await process.runAndWait()
        stderrPipe.fileHandleForReading.readabilityHandler = nil

        guard process.terminationStatus == 0 else {
            throw TSKError.ingestionFailed(exitCode: process.terminationStatus,
                                           stderr: collector.text)
        }
    }
}

#endif

