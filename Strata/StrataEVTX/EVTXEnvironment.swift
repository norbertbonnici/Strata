import Foundation

/// Locates the libevtx CLI (`evtxexport`) - bundled inside the app first,
/// then Homebrew, then PATH. Mirrors TSKEnvironment.
public nonisolated struct EVTXEnvironment: Sendable {
    public let binDirectory: URL

    private static let candidateDirectories = ["/opt/homebrew/bin", "/usr/local/bin"]

    public init(binDirectory: URL) { self.binDirectory = binDirectory }

    public static func discover() throws -> EVTXEnvironment {
        if let bundled = Bundle.main.resourceURL?
            .appendingPathComponent("tsk/bin/evtxexport"),
           FileManager.default.isExecutableFile(atPath: bundled.path) {
            return EVTXEnvironment(binDirectory: bundled.deletingLastPathComponent())
        }
        for dir in candidateDirectories {
            let candidate = URL(fileURLWithPath: dir).appendingPathComponent("evtxexport")
            if FileManager.default.isExecutableFile(atPath: candidate.path) {
                return EVTXEnvironment(binDirectory: URL(fileURLWithPath: dir))
            }
        }
        throw EVTXError.binaryNotFound("evtxexport")
    }

    public func url(for tool: String) throws -> URL {
        let candidate = binDirectory.appendingPathComponent(tool)
        guard FileManager.default.isExecutableFile(atPath: candidate.path) else {
            throw EVTXError.binaryNotFound(tool)
        }
        return candidate
    }
}

public enum EVTXError: Error, LocalizedError {
    case binaryNotFound(String)
    case parseFailed(exitCode: Int32, stderr: String)
    case malformedOutput(String)

    public var errorDescription: String? {
        switch self {
        case .binaryNotFound(let name):
            return "Could not locate the libevtx tool '\(name)'."
        case .parseFailed(let code, let stderr):
            return "evtxexport failed (exit \(code)): \(stderr)"
        case .malformedOutput(let detail):
            return "Unexpected evtxexport output: \(detail)"
        }
    }
}
