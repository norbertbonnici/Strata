//
//  ProcessRunnerTests.swift
//  StrataTests
//
//  Covers the shared drain-to-EOF subprocess runner (findings A1/A2/A3):
//  full-output capture with no truncated tail, and signal-vs-exit detection so
//  a crash isn't mislabelled as an ordinary non-zero exit.
//

import Testing
import Foundation
@testable import Strata

#if os(macOS)

struct ProcessRunnerTests {
    private static let sh = URL(fileURLWithPath: "/bin/sh")

    /// The tail of a tool's output must survive: the process emits ~100 KB
    /// (several pipe-buffer fills) and exits immediately. If the runner resumed
    /// on termination without waiting for the pipe's EOF, the last chunk would
    /// be lost — this asserts the full length and both ends are intact.
    @Test func capturesFullOutputAcrossManyBufferFills() async throws {
        let cap = try await ProcessRunner.runCapturing(
            executable: Self.sh,
            arguments: ["-c", "i=0; while [ $i -lt 10000 ]; do printf 'abcdefghij'; i=$((i+1)); done"])
        #expect(cap.succeeded)
        #expect(!cap.crashed)
        #expect(cap.stdout.count == 100_000)
        #expect(cap.stdoutText.hasPrefix("abcdefghij"))
        #expect(cap.stdoutText.hasSuffix("abcdefghij"))
    }

    @Test func reportsNonZeroExitStatus() async throws {
        let cap = try await ProcessRunner.runCapturing(
            executable: Self.sh, arguments: ["-c", "exit 3"])
        #expect(!cap.succeeded)
        #expect(!cap.crashed)
        #expect(cap.terminationReason == .exit)
        #expect(cap.terminationStatus == 3)
    }

    /// A signal kill must read as a crash, with `terminationStatus` carrying the
    /// SIGNAL number (9), not a bogus exit code — this is what lets the
    /// extractors throw `.extractionCrashed` instead of "exit 11" for a SIGSEGV.
    @Test func detectsSignalCrashDistinctlyFromExit() async throws {
        let cap = try await ProcessRunner.runCapturing(
            executable: Self.sh, arguments: ["-c", "kill -9 $$"])
        #expect(cap.crashed)
        #expect(!cap.succeeded)
        #expect(cap.terminationReason == .uncaughtSignal)
        #expect(cap.terminationStatus == 9)
    }

    /// stdout routed to a file sink (the extractor path) leaves the captured
    /// stdout buffer empty; stderr is still captured to EOF.
    @Test func writesStdoutToFileSinkAndStillCapturesStderr() async throws {
        let out = FileManager.default.temporaryDirectory
            .appendingPathComponent("strata-runner-\(UUID().uuidString).bin")
        FileManager.default.createFile(atPath: out.path, contents: nil)
        let handle = try FileHandle(forWritingTo: out)
        defer { try? FileManager.default.removeItem(at: out) }

        let cap = try await ProcessRunner.runCapturing(
            executable: Self.sh,
            arguments: ["-c", "printf 'file-bound-stdout'; printf 'to-stderr' 1>&2"],
            stdoutSink: handle)
        try? handle.close()

        #expect(cap.succeeded)
        #expect(cap.stdout.isEmpty)                 // went to the file, not the buffer
        #expect(cap.stderrText == "to-stderr")
        #expect(try String(contentsOf: out, encoding: .utf8) == "file-bound-stdout")
    }

    /// stderr lines are streamed live (the progress channel) as well as captured.
    @Test func streamsStderrLinesLive() async throws {
        let sink = LineSink()
        let cap = try await ProcessRunner.runCapturing(
            executable: Self.sh,
            arguments: ["-c", "printf 'a\\nb\\nc\\n' 1>&2"],
            onStderrLine: { sink.append($0) })
        #expect(cap.succeeded)
        #expect(sink.all.sorted() == ["a", "b", "c"])
    }
}

/// Thread-safe collector for the `@Sendable` onStderrLine callback (fires on an
/// arbitrary dispatch queue).
private final class LineSink: @unchecked Sendable {
    private let lock = NSLock()
    private var lines: [String] = []
    func append(_ s: String) { lock.lock(); lines.append(s); lock.unlock() }
    var all: [String] { lock.lock(); defer { lock.unlock() }; return lines }
}

#endif
