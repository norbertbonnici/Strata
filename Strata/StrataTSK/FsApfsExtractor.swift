import Foundation

#if os(macOS)

/// Extracts a single file's bytes out of an **APFS** volume in a raw image by
/// shelling out to our vendored `fsapfscat` tool (libfsapfs) and redirecting its
/// stdout to a scratch file. The macOS-image equivalent of `TSKFileExtractor`
/// (`icat`): The Sleuth Kit crashes on real APFS, so the APFS ingest path reads
/// content via libfsapfs instead.
public actor FsApfsExtractor {
    private let environment: TSKEnvironment
    /// The raw image (the source itself for a raw/dd image, or the `ewfexport`
    /// scratch conversion of an E01).
    private let rawURL: URL
    /// A FileVault secret applied to every extraction, used when a per-call
    /// `password`/`recovery` isn't supplied (the common case).
    private let credential: FileVaultCredential?

    public init(environment: TSKEnvironment, rawURL: URL, credential: FileVaultCredential? = nil) {
        self.environment = environment
        self.rawURL = rawURL
        self.credential = credential
    }

    /// Extract `volumePath` (a volume-relative path, e.g. `/Users/jane/…`) from
    /// the APFS volume at the given 0-based `volumeIndex`, whose container starts
    /// at `offsetBytes` in the raw image. `password`/`recovery` unlock FileVault;
    /// when omitted they fall back to the extractor's stored `credential`.
    ///
    /// When `attribute` is set, the named **extended attribute**'s bytes are
    /// extracted instead of the file's data stream (e.g.
    /// `com.apple.metadata:kMDItemWhereFroms`); a file that lacks the attribute
    /// yields an empty extraction, not an error.
    public func extract(volumePath: String, volumeIndex: Int64, offsetBytes: Int64,
                        to destination: URL, attribute: String? = nil,
                        password: String? = nil, recovery: String? = nil) async throws {
        let tool = try environment.url(for: "fsapfscat")
        try? FileManager.default.removeItem(at: destination)
        FileManager.default.createFile(atPath: destination.path, contents: nil)

        let password = password ?? credential?.password
        let recovery = recovery ?? credential?.recovery
        var args = ["-o", "\(offsetBytes)", "-f", "\(volumeIndex)"]
        if let password { args.append(contentsOf: ["-p", password]) }
        if let recovery { args.append(contentsOf: ["-r", recovery]) }
        if let attribute { args.append(contentsOf: ["-x", attribute]) }
        args.append(rawURL.path)
        args.append(volumePath)

        // fsapfscat streams the file/xattr bytes to stdout → the scratch file;
        // stderr is drained to EOF by the shared runner.
        let outHandle = try FileHandle(forWritingTo: destination)
        defer { try? outHandle.close() }   // close on every path, incl. a launch throw
        let capture = try await ProcessRunner.runCapturing(
            executable: tool, arguments: args, stdoutSink: outHandle)

        // rc 2 == "no such file" (a candidate path that doesn't exist on this
        // volume); rc 3 == "no such extended attribute" - both treated as an
        // empty extraction, not a hard failure.
        if capture.terminationReason == .exit,
           capture.terminationStatus == 2 || capture.terminationStatus == 3 { return }
        if capture.crashed {
            throw TSKError.extractionCrashed(signal: capture.terminationStatus,
                                             stderr: "fsapfscat: \(capture.stderrText)")
        }
        guard capture.succeeded else {
            throw TSKError.ingestionFailed(exitCode: capture.terminationStatus,
                                           stderr: "fsapfscat: \(capture.stderrText)")
        }
    }
}

#endif
