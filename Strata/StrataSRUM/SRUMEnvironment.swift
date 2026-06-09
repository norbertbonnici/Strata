import Foundation

#if os(macOS)

/// Locates the libesedb CLI (`esedbexport`) used to export the SRUM `SRUDB.dat`
/// ESE database to tab-separated text. Mirrors JumpListEnvironment / LnkEnvironment.
public nonisolated struct SRUMEnvironment: Sendable {
    public let binDirectory: URL

    private static let candidateDirectories = ["/opt/homebrew/bin", "/usr/local/bin"]

    public init(binDirectory: URL) { self.binDirectory = binDirectory }

    public static func discover() throws -> SRUMEnvironment {
        if let bundled = Bundle.main.resourceURL?
            .appendingPathComponent("tsk/bin/esedbexport"),
           FileManager.default.isExecutableFile(atPath: bundled.path) {
            return SRUMEnvironment(binDirectory: bundled.deletingLastPathComponent())
        }
        for dir in candidateDirectories {
            let candidate = URL(fileURLWithPath: dir).appendingPathComponent("esedbexport")
            if FileManager.default.isExecutableFile(atPath: candidate.path) {
                return SRUMEnvironment(binDirectory: URL(fileURLWithPath: dir))
            }
        }
        throw SRUMError.binaryNotFound("esedbexport")
    }

    public func url(for tool: String) throws -> URL {
        let candidate = binDirectory.appendingPathComponent(tool)
        guard FileManager.default.isExecutableFile(atPath: candidate.path) else {
            throw SRUMError.binaryNotFound(tool)
        }
        return candidate
    }
}

public enum SRUMError: Error, LocalizedError {
    case binaryNotFound(String)
    case exportFailed(exitCode: Int32, stderr: String)

    public var errorDescription: String? {
        switch self {
        case .binaryNotFound(let name):
            return "Could not locate the libesedb tool '\(name)'."
        case .exportFailed(let code, let stderr):
            return "esedbexport failed (exit \(code)): \(stderr)"
        }
    }
}

#endif
