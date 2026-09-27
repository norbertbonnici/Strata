import Foundation

#if os(macOS)

public nonisolated enum YaraRunnerError: LocalizedError, Sendable {
    case compile(String)
    case scan(String)

    public var errorDescription: String? {
        switch self {
        case .compile(let message): return "YARA rule compilation failed: \(message)"
        case .scan(let message): return "YARA scan failed: \(message)"
        }
    }
}

/// Thin, testable wrapper around the bundled upstream YARA command-line tools.
/// Rules are compiled once per scan and the compiled form is reused for every
/// evidence file, avoiding repeated parsing and rejecting invalid rules early.
public nonisolated struct YaraRunner: Sendable {
    private let environment: TSKEnvironment

    public init(environment: TSKEnvironment) { self.environment = environment }

    public func compile(ruleURL: URL, to outputURL: URL) async throws {
        let executable = try environment.url(for: "yarac")
        let result = try await ProcessRunner.runCapturing(
            executable: executable, arguments: [ruleURL.path, outputURL.path])
        guard result.succeeded else {
            throw YaraRunnerError.compile(Self.message(from: result.stderrText))
        }
    }

    public func scan(compiledRules: URL, fileURL: URL, timeoutSeconds: Int) async throws -> [String] {
        let executable = try environment.url(for: "yara")
        let result = try await ProcessRunner.runCapturing(
            executable: executable,
            arguments: ["--compiled-rules", "--no-warnings", "--timeout=\(timeoutSeconds)",
                        compiledRules.path, fileURL.path])
        guard result.succeeded else {
            throw YaraRunnerError.scan(Self.message(from: result.stderrText))
        }
        return Self.parseRules(stdout: result.stdoutText, targetPath: fileURL.path)
    }

    static func parseRules(stdout: String, targetPath: String) -> [String] {
        let suffix = " " + targetPath
        return stdout.split(whereSeparator: \.isNewline).compactMap { raw in
            let line = String(raw)
            guard line.hasSuffix(suffix) else { return nil }
            let rule = String(line.dropLast(suffix.count))
            return rule.isEmpty ? nil : rule
        }
    }

    private static func message(from stderr: String) -> String {
        let value = stderr.trimmingCharacters(in: .whitespacesAndNewlines)
        return value.isEmpty ? "the YARA process exited unexpectedly" : value
    }
}

#endif
