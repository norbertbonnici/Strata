import Foundation

/// A parsed macOS **launchd** job (`.plist`) — the primary macOS auto-start
/// mechanism and a prime persistence foothold (T1543.001 LaunchAgent /
/// T1543.004 LaunchDaemon).
///
/// launchd loads property-list job descriptions from a handful of well-known
/// directories; *where* the plist lives determines its privilege and trigger:
///
///  - `/Library/LaunchDaemons`        → runs as **root**, at boot, no user
///    session required (`systemDaemon`).
///  - `/Library/LaunchAgents`         → runs in **every** user's GUI session
///    (`systemAgent`).
///  - `~/Library/LaunchAgents`        → runs in **one** user's session
///    (`userAgent`).
///
/// The high-signal keys for triage are the executable (`Program` /
/// `ProgramArguments`), whether it fires automatically (`RunAtLoad`), how often
/// it beacons (`StartInterval`), and what it watches (`WatchPaths`). The
/// `Label` is launchd's identity for the job and is a common masquerade vector
/// (`com.apple.*` on a job that lives outside a system path).
///
/// Produced by `LaunchItemParser`; one entry per `.plist`.
public nonisolated struct LaunchItemEntry: Identifiable, Hashable, Sendable, Codable {
    /// Which launchd domain the job belongs to, derived from its on-disk path.
    public enum Scope: String, Hashable, Sendable, Codable {
        /// `~/Library/LaunchAgents` — a single user's GUI session.
        case userAgent
        /// `/Library/LaunchAgents` — every user's GUI session.
        case systemAgent
        /// `/Library/LaunchDaemons` — root, at boot.
        case systemDaemon

        public var label: String {
            switch self {
            case .userAgent:    return "User LaunchAgent"
            case .systemAgent:  return "System LaunchAgent"
            case .systemDaemon: return "System LaunchDaemon"
            }
        }

        /// `true` for the root-privileged daemon domain.
        public var isDaemon: Bool { self == .systemDaemon }
    }

    public let id: UUID
    /// launchd's identity for the job (the `Label` key). Falls back to the
    /// plist basename when the key is absent (a malformed but still-loadable job).
    public let label: String
    /// The `Program` key — a single executable path. `nil` when the job uses
    /// `ProgramArguments` instead (the more common form).
    public let program: String?
    /// The `ProgramArguments` array: argv[0] is the executable, the rest are
    /// arguments. Empty when only `Program` is set.
    public let programArguments: [String]
    /// `RunAtLoad` — launchd runs the job as soon as it's loaded (boot / login).
    public let runAtLoad: Bool
    /// `StartInterval` (seconds) — launchd re-runs the job on this cadence. A
    /// small value is a beacon fingerprint. `nil` when not an interval job.
    public let startInterval: Int?
    /// `WatchPaths` — paths whose modification re-launches the job (trigger
    /// persistence).
    public let watchPaths: [String]
    /// Domain the job runs in, derived from `plistPath`.
    public let scope: Scope
    /// Source `.plist` path the entry was parsed from.
    public let plistPath: String

    public init(id: UUID = UUID(), label: String, program: String? = nil,
                programArguments: [String] = [], runAtLoad: Bool = false,
                startInterval: Int? = nil, watchPaths: [String] = [],
                scope: Scope, plistPath: String) {
        self.id = id
        self.label = label
        self.program = program
        self.programArguments = programArguments
        self.runAtLoad = runAtLoad
        self.startInterval = startInterval
        self.watchPaths = watchPaths
        self.scope = scope
        self.plistPath = plistPath
    }

    /// The executable the job runs: `Program` if set, else `ProgramArguments[0]`.
    /// `nil` when neither is present.
    public var executable: String? {
        if let program, !program.isEmpty { return program }
        return programArguments.first
    }

    /// The full argument vector as a single command line, for display/matching.
    /// Uses `Program` + `ProgramArguments` tail when both exist.
    public var commandLine: String {
        if !programArguments.isEmpty { return programArguments.joined(separator: " ") }
        return program ?? ""
    }
}
