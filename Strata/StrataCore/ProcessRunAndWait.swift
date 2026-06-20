import Foundation

// `Process` (NSTask) is macOS-only; every caller (the vendored-tool parsers /
// ingestors) is itself `#if os(macOS)`-gated, so gate the helper to match.
#if os(macOS)
public extension Process {
    /// Launch the process and suspend until it terminates.
    ///
    /// The `terminationHandler` is installed **before** `run()`, closing a race
    /// the obvious `try run()` / `await withCheckedContinuation { terminationHandler = … }`
    /// ordering leaves open: a fast-exiting child (e.g. a vendored `*export` tool
    /// bailing instantly on a 0-byte/garbage artifact a compromised host planted)
    /// can be reaped *between* `run()` returning and the handler being assigned —
    /// the handler then never fires and the continuation never resumes, hanging
    /// the parse pipeline forever. Installing it first makes that impossible.
    ///
    /// Throws if the process fails to launch (`run()` throws); exactly one of the
    /// handler or the launch-error path resumes the continuation.
    func runAndWait() async throws {
        try await withCheckedThrowingContinuation { (cont: CheckedContinuation<Void, Error>) in
            terminationHandler = { _ in cont.resume() }
            do {
                try run()
            } catch {
                terminationHandler = nil
                cont.resume(throwing: error)
            }
        }
    }
}
#endif
