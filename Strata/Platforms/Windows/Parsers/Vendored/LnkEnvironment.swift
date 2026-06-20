import Foundation

#if os(macOS)

/// Locates the liblnk CLI (`lnkinfo`) - bundled inside the app first, then
/// Homebrew, then PATH. Mirrors EVTXEnvironment / TSKEnvironment.
public nonisolated struct LnkEnvironment: Sendable {
    public let binDirectory: URL

    private static let candidateDirectories = ["/opt/homebrew/bin", "/usr/local/bin"]

    public init(binDirectory: URL) { self.binDirectory = binDirectory }

    public static func discover() throws -> LnkEnvironment {
        if let bundled = Bundle.main.resourceURL?
            .appendingPathComponent("tsk/bin/lnkinfo"),
           FileManager.default.isExecutableFile(atPath: bundled.path) {
            return LnkEnvironment(binDirectory: bundled.deletingLastPathComponent())
        }
        for dir in candidateDirectories {
            let candidate = URL(fileURLWithPath: dir).appendingPathComponent("lnkinfo")
            if FileManager.default.isExecutableFile(atPath: candidate.path) {
                return LnkEnvironment(binDirectory: URL(fileURLWithPath: dir))
            }
        }
        throw LnkError.binaryNotFound("lnkinfo")
    }

    public func url(for tool: String) throws -> URL {
        let candidate = binDirectory.appendingPathComponent(tool)
        guard FileManager.default.isExecutableFile(atPath: candidate.path) else {
            throw LnkError.binaryNotFound(tool)
        }
        return candidate
    }
}

public enum LnkError: Error, LocalizedError {
    case binaryNotFound(String)
    case parseFailed(exitCode: Int32, stderr: String)

    public var errorDescription: String? {
        switch self {
        case .binaryNotFound(let name):
            return "Could not locate the liblnk tool '\(name)'."
        case .parseFailed(let code, let stderr):
            return "lnkinfo failed (exit \(code)): \(stderr)"
        }
    }
}

#endif
