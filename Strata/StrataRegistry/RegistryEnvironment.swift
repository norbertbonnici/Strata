import Foundation

/// Locates libregf's `regfexport` binary. Bundle-first (so a shipped app uses
/// the binary we statically linked), then Homebrew, then PATH. Mirrors
/// TSKEnvironment and EVTXEnvironment.
public nonisolated struct RegistryEnvironment: Sendable {
    public let binDirectory: URL

    private static let candidateDirectories = ["/opt/homebrew/bin", "/usr/local/bin"]

    public init(binDirectory: URL) { self.binDirectory = binDirectory }

    public static func discover() throws -> RegistryEnvironment {
        if let bundled = Bundle.main.resourceURL?
            .appendingPathComponent("tsk/bin/regfexport"),
           FileManager.default.isExecutableFile(atPath: bundled.path) {
            return RegistryEnvironment(binDirectory: bundled.deletingLastPathComponent())
        }
        for dir in candidateDirectories {
            let candidate = URL(fileURLWithPath: dir).appendingPathComponent("regfexport")
            if FileManager.default.isExecutableFile(atPath: candidate.path) {
                return RegistryEnvironment(binDirectory: URL(fileURLWithPath: dir))
            }
        }
        throw RegistryError.binaryNotFound("regfexport")
    }

    public func url(for tool: String) throws -> URL {
        let candidate = binDirectory.appendingPathComponent(tool)
        guard FileManager.default.isExecutableFile(atPath: candidate.path) else {
            throw RegistryError.binaryNotFound(tool)
        }
        return candidate
    }
}

public enum RegistryError: Error, LocalizedError {
    case binaryNotFound(String)
    case parseFailed(exitCode: Int32, stderr: String)
    case malformedOutput(String)

    public var errorDescription: String? {
        switch self {
        case .binaryNotFound(let name):
            return "Could not locate the libregf tool '\(name)'."
        case .parseFailed(let code, let stderr):
            return "regfexport failed (exit \(code)): \(stderr)"
        case .malformedOutput(let detail):
            return "Unexpected regfexport output: \(detail)"
        }
    }
}
