import Foundation

#if os(macOS)

/// Locates the libolecf CLI (`olecfexport`) used to crack AutomaticDestinations
/// JumpList OLE compound files. Mirrors LnkEnvironment / EVTXEnvironment.
public nonisolated struct JumpListEnvironment: Sendable {
    public let binDirectory: URL

    private static let candidateDirectories = ["/opt/homebrew/bin", "/usr/local/bin"]

    public init(binDirectory: URL) { self.binDirectory = binDirectory }

    public static func discover() throws -> JumpListEnvironment {
        if let bundled = Bundle.main.resourceURL?
            .appendingPathComponent("tsk/bin/olecfexport"),
           FileManager.default.isExecutableFile(atPath: bundled.path) {
            return JumpListEnvironment(binDirectory: bundled.deletingLastPathComponent())
        }
        for dir in candidateDirectories {
            let candidate = URL(fileURLWithPath: dir).appendingPathComponent("olecfexport")
            if FileManager.default.isExecutableFile(atPath: candidate.path) {
                return JumpListEnvironment(binDirectory: URL(fileURLWithPath: dir))
            }
        }
        throw JumpListError.binaryNotFound("olecfexport")
    }

    public func url(for tool: String) throws -> URL {
        let candidate = binDirectory.appendingPathComponent(tool)
        guard FileManager.default.isExecutableFile(atPath: candidate.path) else {
            throw JumpListError.binaryNotFound(tool)
        }
        return candidate
    }
}

public enum JumpListError: Error, LocalizedError {
    case binaryNotFound(String)
    case exportFailed(exitCode: Int32, stderr: String)

    public var errorDescription: String? {
        switch self {
        case .binaryNotFound(let name):
            return "Could not locate the libolecf tool '\(name)'."
        case .exportFailed(let code, let stderr):
            return "olecfexport failed (exit \(code)): \(stderr)"
        }
    }
}

#endif
