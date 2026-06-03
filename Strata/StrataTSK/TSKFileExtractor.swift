import Foundation

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
        let tool = try environment.url(for: "icat")
        try? FileManager.default.removeItem(at: destination)
        FileManager.default.createFile(atPath: destination.path, contents: nil)

        var args: [String] = []
        if let imageType { args.append(contentsOf: ["-i", imageType]) }
        if imageOffsetSectors > 0 { args.append(contentsOf: ["-o", "\(imageOffsetSectors)"]) }
        args.append(imageURL.path)
        args.append("\(metaAddr)")

        let process = Process()
        process.executableURL = tool
        process.arguments = args

        let outHandle = try FileHandle(forWritingTo: destination)
        let stderrPipe = Pipe()
        process.standardOutput = outHandle
        process.standardError = stderrPipe

        // Drain stderr continuously. Without this a chatty icat run can fill
        // the kernel pipe buffer (~16-64 KB), block the child on write, and
        // hang the whole subprocess. The classic Unix pipe deadlock.
        let collector = ExtractorStderrCollector()
        stderrPipe.fileHandleForReading.readabilityHandler = { handle in
            let chunk = handle.availableData
            guard !chunk.isEmpty else { return }
            collector.append(String(decoding: chunk, as: UTF8.self))
        }

        try process.run()
        await withCheckedContinuation { continuation in
            process.terminationHandler = { _ in continuation.resume() }
        }
        stderrPipe.fileHandleForReading.readabilityHandler = nil
        try? outHandle.close()

        guard process.terminationStatus == 0 else {
            throw TSKError.ingestionFailed(exitCode: process.terminationStatus,
                                           stderr: collector.text)
        }
    }
}

private nonisolated final class ExtractorStderrCollector: @unchecked Sendable {
    private let lock = NSLock()
    private var buffer = ""
    func append(_ s: String) { lock.lock(); buffer += s; lock.unlock() }
    var text: String {
        lock.lock(); defer { lock.unlock() }
        return buffer.trimmingCharacters(in: .whitespacesAndNewlines)
    }
}
