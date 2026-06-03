import Foundation

/// Locates The Sleuth Kit command-line tools installed on the host.
public nonisolated struct TSKEnvironment: Sendable {
    public let binDirectory: URL

    // Fallback Homebrew locations: Apple Silicon, then Intel.
    private static let candidateDirectories = ["/opt/homebrew/bin", "/usr/local/bin"]

    public init(binDirectory: URL) { self.binDirectory = binDirectory }

    /// Discover an install by probing for `tsk_loaddb`. Prefers the binary
    /// bundled inside the app (Contents/Resources/tsk/bin) so shipped builds
    /// have no Homebrew dependency; falls back to system paths in dev.
    public static func discover() throws -> TSKEnvironment {
        if let bundled = Bundle.main.resourceURL?
            .appendingPathComponent("tsk/bin/tsk_loaddb"),
           FileManager.default.isExecutableFile(atPath: bundled.path) {
            return TSKEnvironment(binDirectory: bundled.deletingLastPathComponent())
        }
        for dir in candidateDirectories {
            let candidate = URL(fileURLWithPath: dir).appendingPathComponent("tsk_loaddb")
            if FileManager.default.isExecutableFile(atPath: candidate.path) {
                return TSKEnvironment(binDirectory: URL(fileURLWithPath: dir))
            }
        }
        if let resolved = try which("tsk_loaddb") {
            return TSKEnvironment(binDirectory: resolved.deletingLastPathComponent())
        }
        throw TSKError.binaryNotFound("tsk_loaddb")
    }

    public func url(for tool: String) throws -> URL {
        let candidate = binDirectory.appendingPathComponent(tool)
        guard FileManager.default.isExecutableFile(atPath: candidate.path) else {
            throw TSKError.binaryNotFound(tool)
        }
        return candidate
    }

    private static func which(_ tool: String) throws -> URL? {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/env")
        process.arguments = ["which", tool]
        let pipe = Pipe()
        process.standardOutput = pipe
        try process.run()
        process.waitUntilExit()
        guard process.terminationStatus == 0 else { return nil }
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        let path = String(decoding: data, as: UTF8.self)
            .trimmingCharacters(in: .whitespacesAndNewlines)
        return path.isEmpty ? nil : URL(fileURLWithPath: path)
    }
}
