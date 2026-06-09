import Foundation

/// Thread-safe text accumulator for continuously draining a subprocess pipe from
/// a `FileHandle.readabilityHandler`.
///
/// The shell-out parsers attach one of these to a `Pipe`'s read handle *before*
/// `process.run()` so a chatty child can't fill the kernel pipe buffer
/// (~16-64 KB), block on `write(2)`, and deadlock — the classic Unix pipe
/// deadlock where the child never exits, `terminationHandler` never fires, and
/// the awaiting continuation hangs forever. After the process terminates the
/// handler is set back to `nil` and `text`/`raw` is read.
///
/// `nonisolated` + `@unchecked Sendable`: the readability handler fires on an
/// arbitrary queue and the closure captures the collector across that boundary;
/// the `NSLock` makes the shared mutable buffer safe.
nonisolated final class PipeTextCollector: @unchecked Sendable {
    private let lock = NSLock()
    private var buffer = ""

    /// Append a decoded chunk. Safe to call concurrently from the handler queue.
    func append(_ s: String) { lock.lock(); buffer += s; lock.unlock() }

    /// The accumulated text with leading/trailing whitespace trimmed — the usual
    /// shape for a captured error-message snippet.
    var text: String {
        lock.lock(); defer { lock.unlock() }
        return buffer.trimmingCharacters(in: .whitespacesAndNewlines)
    }

    /// The accumulated text verbatim (no trimming) — for stdout capture where
    /// surrounding whitespace may be significant.
    var raw: String { lock.lock(); defer { lock.unlock() }; return buffer }
}
