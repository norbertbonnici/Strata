import Foundation

#if os(macOS)

/// Locates a vendored libyal CLI tool — bundled inside the app (`tsk/bin/`) first,
/// then Homebrew, then PATH — and resolves sibling tool paths in the same dir.
///
/// Replaces the six near-identical `*Environment` structs (libevtx / libregf /
/// libscca / liblnk / libolecf / libesedb). The TSK ingest core keeps its own
/// `TSKEnvironment` (it discovers a wider tool set). Construct one per tool family
/// via `discover(primaryBinary:library:)`; the `library` is used only for error
/// messages.
public nonisolated struct VendoredTool: Sendable {
    public let binDirectory: URL
    public let primaryBinary: String
    public let library: String

    private static let candidateDirectories = ["/opt/homebrew/bin", "/usr/local/bin"]

    public init(binDirectory: URL, primaryBinary: String, library: String) {
        self.binDirectory = binDirectory
        self.primaryBinary = primaryBinary
        self.library = library
    }

    public static func discover(primaryBinary: String, library: String) throws -> VendoredTool {
        if let bundled = Bundle.main.resourceURL?
            .appendingPathComponent("tsk/bin/\(primaryBinary)"),
           FileManager.default.isExecutableFile(atPath: bundled.path) {
            return VendoredTool(binDirectory: bundled.deletingLastPathComponent(),
                                primaryBinary: primaryBinary, library: library)
        }
        for dir in candidateDirectories {
            let candidate = URL(fileURLWithPath: dir).appendingPathComponent(primaryBinary)
            if FileManager.default.isExecutableFile(atPath: candidate.path) {
                return VendoredTool(binDirectory: URL(fileURLWithPath: dir),
                                    primaryBinary: primaryBinary, library: library)
            }
        }
        throw VendoredToolError.binaryNotFound(tool: primaryBinary, library: library)
    }

    public func url(for tool: String) throws -> URL {
        let candidate = binDirectory.appendingPathComponent(tool)
        guard FileManager.default.isExecutableFile(atPath: candidate.path) else {
            throw VendoredToolError.binaryNotFound(tool: tool, library: library)
        }
        return candidate
    }
}

public enum VendoredToolError: Error, LocalizedError {
    case binaryNotFound(tool: String, library: String)
    case parseFailed(tool: String, exitCode: Int32, stderr: String)
    case malformedOutput(tool: String, detail: String)

    public var errorDescription: String? {
        switch self {
        case .binaryNotFound(let tool, let library):
            return "Could not locate the \(library) tool '\(tool)'."
        case .parseFailed(let tool, let code, let stderr):
            return "\(tool) failed (exit \(code)): \(stderr)"
        case .malformedOutput(let tool, let detail):
            return "Unexpected \(tool) output: \(detail)"
        }
    }
}

#endif
