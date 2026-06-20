import Foundation

/// Detects suspicious macOS **launchd** persistence — the macOS counterpart of
/// the Windows Run-key / scheduled-task / service analyzers and the Linux
/// persistence sweep.
///
/// launchd jobs (LaunchAgents/LaunchDaemons) are the dominant macOS auto-start
/// foothold; a stock job runs a signed Apple/vendor binary from a system path.
/// We flag a job when it looks like attacker persistence:
///
///  1. **Staging-path executable** — the program lives in `/tmp`, `/var/tmp`,
///     `/private/tmp`, `/Users/Shared`, a user's home, or a hidden
///     (`/.`-prefixed) directory. Legitimate jobs run from `/usr`, `/System`,
///     `/Library`, or an app bundle.
///  2. **RunAtLoad → script/downloader** — a boot/login-persistent job whose
///     executable is a shell/scripting interpreter or a network downloader
///     (`bash`/`sh`/`zsh`/`python`/`osascript`/`curl`/`wget`).
///  3. **Shell `-c` one-liner** — `ProgramArguments` invokes a shell with `-c`
///     (inline command persistence, the launchd analogue of a `cmd /c` lure).
///  4. **Apple masquerade** — a `Label` posing as `com.apple.*` on a job that
///     runs from a non-system path.
///  5. **Fast beacon** — a small `StartInterval` (≤ 5 min) that re-runs the job
///     on a tight cadence (C2 check-in fingerprint).
///
/// High severity for a clear C2/script/downloader persistence or an Apple
/// masquerade; medium for the softer tells. All tagged **T1543**
/// (Create or Modify System Process), with the agent/daemon sub-technique chosen
/// per scope.
public nonisolated struct MacPersistenceAnalyzer: Analyzer {
    public let name = "macOS Persistence"
    public init() {}

    /// Path prefixes / fragments that mark an executable as living in a
    /// non-standard staging location.
    private static let stagingPaths = [
        "/tmp/", "/private/tmp/", "/var/tmp/", "/private/var/tmp/",
        "/users/shared/", "/users/", "/library/caches/", "/.",
    ]

    /// Interpreters + downloaders that, when launched at load, indicate a
    /// scripted payload rather than a compiled app.
    private static let scriptOrDownloader = [
        "bash", "sh", "zsh", "ksh", "python", "python3", "perl", "ruby",
        "osascript", "curl", "wget", "nc", "ncat", "node",
    ]

    /// Fast-beacon ceiling: launchd `StartInterval` at or below this (5 min) is
    /// treated as a check-in cadence.
    private static let beaconIntervalSeconds = 300

    public func analyze(context: AnalysisContext) -> [Finding] {
        analyze(context.launchItems)
    }

    /// Core detection over a set of parsed launch items. Pure; unit-tested.
    public func analyze(_ items: [LaunchItemEntry]) -> [Finding] {
        var findings: [Finding] = []

        for item in items {
            var reasons: [String] = []
            var high = false

            let exec = item.executable
            let execLower = exec?.lowercased() ?? ""
            let basename = exec.map { ($0 as NSString).lastPathComponent.lowercased() } ?? ""

            // 1. staging-path executable
            if let exec, !exec.isEmpty, Self.isStagingPath(execLower) {
                reasons.append("executable runs from a non-standard path (\(exec))")
                high = true
            }

            // 2. RunAtLoad pointing at a script/downloader
            let isScriptOrDownloader = Self.scriptOrDownloader.contains(basename)
            if item.runAtLoad && isScriptOrDownloader {
                reasons.append("RunAtLoad launches \(basename) at boot/login")
                high = true
            }

            // 3. shell -c inline command
            if Self.invokesShellDashC(item.programArguments) {
                reasons.append("invokes a shell with -c (inline command)")
                high = true
            }

            // 4. Apple masquerade: com.apple.* label from a non-system path
            if item.label.lowercased().hasPrefix("com.apple.")
                && !Self.isSystemPath(item.plistPath.lowercased())
                && !Self.isSystemPath(execLower) {
                reasons.append("Label masquerades as Apple (\(item.label)) but runs from a non-system path")
                high = true
            }

            // 5. fast StartInterval beacon
            if let interval = item.startInterval, interval > 0, interval <= Self.beaconIntervalSeconds {
                reasons.append("re-runs every \(interval)s (beacon cadence)")
            }

            guard !reasons.isEmpty else { continue }

            let severity: Severity = high ? .high : .medium
            let detailCommand = item.commandLine.isEmpty ? "(no program)" : item.commandLine
            findings.append(Finding(
                title: "\(item.scope.label) persistence: \(item.label)",
                detail: "\(item.scope.label) — \(reasons.joined(separator: "; ")).\n\(detailCommand)",
                severity: severity,
                phase: .installation,
                technique: Self.technique(for: item.scope),
                timestamp: nil,
                evidencePaths: [item.plistPath]))
        }

        return findings
    }

    // MARK: - Helpers

    private static func isStagingPath(_ execLower: String) -> Bool {
        guard !execLower.isEmpty else { return false }
        if execLower.contains("/.") { return true }          // hidden dir anywhere
        return stagingPaths.contains { execLower.hasPrefix($0) || execLower.contains($0) }
    }

    /// Standard, trusted macOS executable/plist roots.
    private static func isSystemPath(_ lower: String) -> Bool {
        guard !lower.isEmpty else { return false }
        // A user-home Library path is NOT a system path even though it contains
        // "/library/"; gate that first.
        if lower.contains("/users/") { return false }
        let roots = ["/system/", "/usr/", "/bin/", "/sbin/", "/library/", "/applications/"]
        return roots.contains { lower.hasPrefix($0) || lower.contains($0) }
    }

    /// `ProgramArguments` invokes a shell interpreter with a `-c` inline command.
    private static func invokesShellDashC(_ args: [String]) -> Bool {
        guard let first = args.first else { return false }
        let interp = (first as NSString).lastPathComponent.lowercased()
        let isShell = ["bash", "sh", "zsh", "ksh", "dash"].contains(interp)
        guard isShell else { return false }
        return args.dropFirst().contains { $0 == "-c" }
    }

    private static func technique(for scope: LaunchItemEntry.Scope) -> AttackTechnique {
        switch scope {
        case .systemDaemon:
            return AttackTechnique(attackID: "T1543.004",
                                   name: "Create or Modify System Process: Launch Daemon")
        case .systemAgent, .userAgent:
            return AttackTechnique(attackID: "T1543.001",
                                   name: "Create or Modify System Process: Launch Agent")
        }
    }
}
