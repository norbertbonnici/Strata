import Foundation

public enum TSKError: Error, LocalizedError {
    case binaryNotFound(String)
    case ingestionFailed(exitCode: Int32, stderr: String)
    case looseFolderNotSupported(URL)
    case databaseUnavailable(URL)

    public var errorDescription: String? {
        switch self {
        case .binaryNotFound(let name):
            return "Could not locate the TSK tool '\(name)'. Install The Sleuth Kit (brew install sleuthkit)."
        case .ingestionFailed(let code, let stderr):
            return "tsk_loaddb failed (exit \(code)): \(stderr)"
        case .looseFolderNotSupported(let url):
            return "\(url.lastPathComponent) is a loose KAPE collection. TSK ingests images, not folders - re-collect with KAPE's --vhd option, or wait for the phase-2 artifact parser."
        case .databaseUnavailable(let url):
            return "TSK database not found at \(url.path). Run ingestion first."
        }
    }
}
