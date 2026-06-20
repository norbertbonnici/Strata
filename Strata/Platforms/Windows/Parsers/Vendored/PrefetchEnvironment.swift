import Foundation

#if os(macOS)

/// Locates the libscca CLI (`sccainfo`) - bundled inside the app first, then
/// Homebrew, then PATH. Mirrors EVTXEnvironment / TSKEnvironment.
public nonisolated struct PrefetchEnvironment: Sendable {
    public let binDirectory: URL

    private static let candidateDirectories = ["/opt/homebrew/bin", "/usr/local/bin"]

    public init(binDirectory: URL) { self.binDirectory = binDirectory }

    public static func discover() throws -> PrefetchEnvironment {
        if let bundled = Bundle.main.resourceURL?
            .appendingPathComponent("tsk/bin/sccainfo"),
           FileManager.default.isExecutableFile(atPath: bundled.path) {
            return PrefetchEnvironment(binDirectory: bundled.deletingLastPathComponent())
        }
        for dir in candidateDirectories {
            let candidate = URL(fileURLWithPath: dir).appendingPathComponent("sccainfo")
            if FileManager.default.isExecutableFile(atPath: candidate.path) {
                return PrefetchEnvironment(binDirectory: URL(fileURLWithPath: dir))
            }
        }
        throw PrefetchError.binaryNotFound("sccainfo")
    }

    public func url(for tool: String) throws -> URL {
        let candidate = binDirectory.appendingPathComponent(tool)
        guard FileManager.default.isExecutableFile(atPath: candidate.path) else {
            throw PrefetchError.binaryNotFound(tool)
        }
        return candidate
    }
}

public enum PrefetchError: Error, LocalizedError {
    case binaryNotFound(String)
    case parseFailed(exitCode: Int32, stderr: String)
    case malformedOutput(String)

    public var errorDescription: String? {
        switch self {
        case .binaryNotFound(let name):
            return "Could not locate the libscca tool '\(name)'."
        case .parseFailed(let code, let stderr):
            return "sccainfo failed (exit \(code)): \(stderr)"
        case .malformedOutput(let detail):
            return "Unexpected sccainfo output: \(detail)"
        }
    }
}

#endif
