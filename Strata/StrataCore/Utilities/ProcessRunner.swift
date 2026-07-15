import Foundation

// `Process` (NSTask) is macOS-only; every caller (the vendored-tool
// ingestors / extractors) is itself `#if os(macOS)`-gated, so gate to match.
#if os(macOS)

/// The result of running a subprocess to completion with its output **fully
/// drained**.
///
/// `terminationStatus` is the exit code when `terminationReason == .exit`, or the
/// *signal number* when `.uncaughtSignal` (a crash) — the two are reported
/// distinctly so a SIGSEGV isn't mislabelled as "exit 11".
public struct ProcessCapture: Sendable {
    public let stdout: Data
    public let stderr: Data
    public let terminationStatus: Int32
    public let terminationReason: Process.TerminationReason

    /// Exited normally with status 0 (not killed by a signal).
    public var succeeded: Bool { terminationReason == .exit && terminationStatus == 0 }
    /// Killed by a signal (crashed) rather than exiting with a status.
    public var crashed: Bool { terminationReason == .uncaughtSignal }
    public var stdoutText: String { String(decoding: stdout, as: UTF8.self) }
    public var stderrText: String { String(decoding: stderr, as: UTF8.self) }
}

/// Runs a vendored CLI tool and returns its output **only after both** the
/// process has terminated **and** every captured pipe has reached EOF.
///
/// This closes a subtle, high-impact race the previous ad-hoc plumbing left
/// open. `readabilityHandler` callbacks and the `terminationHandler` fire on
/// independent, unordered dispatch sources; the old callers resumed on
/// termination, immediately nil'd the handlers, and read the buffer — discarding
/// any bytes still in the kernel pipe when termination won the race. For these
/// tools the load-bearing data is emitted **last** (`ewfverify`'s
/// `SUCCESS`/`FAILURE` verdict, `ewfinfo`'s closing `<hashdigest>`, a volume
/// count / offset line), so a truncated tail could turn an intact image into a
/// false integrity failure or drop an acquisition hash. Waiting for the pipes'
/// EOF callbacks makes that impossible while still draining continuously (so a
/// chatty child can't fill the ~16–64 KB pipe buffer and deadlock).
public enum ProcessRunner {

    /// Launch `executable` with `arguments` and run to completion.
    ///
    /// - `stdoutSink`: when supplied, the child's stdout is written straight to
    ///   this handle (e.g. a scratch file for an `icat` extraction) and
    ///   `ProcessCapture.stdout` is empty; otherwise stdout is captured.
    /// - `onStderrLine`: streamed newline-split stderr, live, for progress UI.
    ///   (`self` is `@MainActor` — hence `Sendable` — so a `Task { @MainActor … }`
    ///   hop satisfies `@Sendable`.)
    ///
    /// Throws only if the process fails to launch.
    public static func runCapturing(
        executable: URL,
        arguments: [String],
        stdoutSink: FileHandle? = nil,
        onStderrLine: (@Sendable (String) -> Void)? = nil
    ) async throws -> ProcessCapture {
        let process = Process()
        process.executableURL = executable
        process.arguments = arguments

        let stdoutBuffer = ByteBuffer()
        let stderrBuffer = ByteBuffer()

        // stdout: a caller-provided file sink, or a pipe we capture + drain.
        let outPipe: Pipe?
        if let stdoutSink {
            process.standardOutput = stdoutSink
            outPipe = nil
        } else {
            let pipe = Pipe()
            process.standardOutput = pipe
            outPipe = pipe
        }
        let errPipe = Pipe()
        process.standardError = errPipe

        // Resume the caller exactly once, after the process has exited AND every
        // captured pipe has signalled EOF (an empty-data readability callback).
        let coordinator = RunCoordinator(pendingEOFs: outPipe == nil ? 1 : 2)

        errPipe.fileHandleForReading.readabilityHandler = { handle in
            let chunk = handle.availableData
            if chunk.isEmpty {
                handle.readabilityHandler = nil    // EOF: write end closed
                coordinator.noteEOF()
            } else {
                stderrBuffer.append(chunk)
                if let onStderrLine {
                    String(decoding: chunk, as: UTF8.self)
                        .split(whereSeparator: \.isNewline)
                        .forEach { onStderrLine(String($0)) }
                }
            }
        }
        outPipe?.fileHandleForReading.readabilityHandler = { handle in
            let chunk = handle.availableData
            if chunk.isEmpty {
                handle.readabilityHandler = nil
                coordinator.noteEOF()
            } else {
                stdoutBuffer.append(chunk)
            }
        }
        // Installed BEFORE run() so a fast-exiting child can't be reaped before
        // the handler is assigned (the continuation would then never resume).
        process.terminationHandler = { _ in coordinator.noteExit() }

        do {
            try process.run()
        } catch {
            outPipe?.fileHandleForReading.readabilityHandler = nil
            errPipe.fileHandleForReading.readabilityHandler = nil
            throw error
        }

        await withCheckedContinuation { (continuation: CheckedContinuation<Void, Never>) in
            coordinator.attach(continuation)
        }

        return ProcessCapture(
            stdout: stdoutBuffer.data,
            stderr: stderrBuffer.data,
            terminationStatus: process.terminationStatus,
            terminationReason: process.terminationReason)
    }
}

/// Thread-safe byte accumulator: the readability handler fires on an arbitrary
/// dispatch queue, so the shared buffer is guarded by a lock.
private final class ByteBuffer: @unchecked Sendable {
    private let lock = NSLock()
    private var storage = Data()
    func append(_ chunk: Data) { lock.lock(); storage.append(chunk); lock.unlock() }
    var data: Data { lock.lock(); defer { lock.unlock() }; return storage }
}

/// Resumes its continuation exactly once — after the process has exited **and**
/// every captured pipe has reached EOF. The pipe/termination callbacks and the
/// `attach` from the awaiting task all race on arbitrary queues, so every field
/// is lock-guarded and the resume is latched by `resumed`.
private final class RunCoordinator: @unchecked Sendable {
    private let lock = NSLock()
    private var pendingEOFs: Int
    private var exited = false
    private var resumed = false
    private var continuation: CheckedContinuation<Void, Never>?

    init(pendingEOFs: Int) { self.pendingEOFs = pendingEOFs }

    func attach(_ continuation: CheckedContinuation<Void, Never>) {
        lock.lock(); self.continuation = continuation; resumeIfReadyLocked(); lock.unlock()
    }
    func noteEOF() { lock.lock(); pendingEOFs -= 1; resumeIfReadyLocked(); lock.unlock() }
    func noteExit() { lock.lock(); exited = true; resumeIfReadyLocked(); lock.unlock() }

    private func resumeIfReadyLocked() {
        guard !resumed, exited, pendingEOFs <= 0, let continuation else { return }
        resumed = true
        self.continuation = nil
        continuation.resume()
    }
}

#endif
