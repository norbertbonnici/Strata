import Foundation

public enum TSKError: Error, LocalizedError {
    case binaryNotFound(String)
    case ingestionFailed(exitCode: Int32, stderr: String)
    /// `tsk_loaddb` was killed by a signal (it crashed) rather than exiting with
    /// a status. The common case is `SIGABRT` (6) inside TSK's APFS parser on a
    /// macOS image — a known Sleuth Kit limitation, not a Strata fault.
    case ingestionCrashed(signal: Int32, stderr: String)
    /// A per-file extraction (`icat` / `fsapfscat`) was killed by a signal
    /// rather than exiting with a status. Reported distinctly so a crash isn't
    /// mislabelled as an ordinary non-zero exit (e.g. "exit 11" for a SIGSEGV).
    case extractionCrashed(signal: Int32, stderr: String)
    case databaseUnavailable(URL)

    public var errorDescription: String? {
        switch self {
        case .binaryNotFound(let name):
            return "Could not locate the TSK tool '\(name)'. Install The Sleuth Kit (brew install sleuthkit)."
        case .ingestionFailed(let code, let stderr):
            return "tsk_loaddb failed (exit \(code)): \(stderr)"
        case .ingestionCrashed(let signal, let stderr):
            var msg = "tsk_loaddb crashed (signal \(signal)\(signal == 6 ? " / SIGABRT" : "")) while parsing the image."
            if signal == 6 {
                msg += " This is a known Sleuth Kit limitation parsing some APFS (macOS) volumes — the volume could not be ingested."
            }
            let trimmed = stderr.trimmingCharacters(in: .whitespacesAndNewlines)
            if !trimmed.isEmpty { msg += "\n\(trimmed)" }
            return msg
        case .extractionCrashed(let signal, let stderr):
            var msg = "File extraction crashed (signal \(signal)\(signal == 6 ? " / SIGABRT" : "")) — the artifact could not be recovered from the image."
            let trimmed = stderr.trimmingCharacters(in: .whitespacesAndNewlines)
            if !trimmed.isEmpty { msg += "\n\(trimmed)" }
            return msg
        case .databaseUnavailable(let url):
            return "TSK database not found at \(url.path). Run ingestion first."
        }
    }
}
