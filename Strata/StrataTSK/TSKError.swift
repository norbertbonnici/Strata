import Foundation

public enum TSKError: Error, LocalizedError {
    case binaryNotFound(String)
    case ingestionFailed(exitCode: Int32, stderr: String)
    case databaseUnavailable(URL)

    public var errorDescription: String? {
        switch self {
        case .binaryNotFound(let name):
            return "Could not locate the TSK tool '\(name)'. Install The Sleuth Kit (brew install sleuthkit)."
        case .ingestionFailed(let code, let stderr):
            return "tsk_loaddb failed (exit \(code)): \(stderr)"
        case .databaseUnavailable(let url):
            return "TSK database not found at \(url.path). Run ingestion first."
        }
    }
}
