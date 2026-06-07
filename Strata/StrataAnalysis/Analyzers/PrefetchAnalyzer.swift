import Foundation

/// Execution-evidence detection over parsed Windows Prefetch.
///
/// Prefetch proves a program *ran* (and when), which makes it ideal for two
/// high-signal triage questions:
///
///  1. Did anything execute from a location attackers favour for dropped
///     payloads - Temp, the Recycle Bin, a user's Downloads, Public, PerfLogs?
///     A `.pf` for `\Users\Public\evil.exe` is hard to explain away.
///  2. Did a known living-off-the-land binary run? Prefetch confirms the launch
///     and pins a timestamp, even if the command line is long gone.
///
/// Kill-chain phase: Exploitation (code execution on the host), matching the
/// process-creation / PowerShell analyzers.
public nonisolated struct PrefetchAnalyzer: Analyzer {
    public let name = "Prefetch Execution"
    public init() {}

    /// Lowercased NT-path fragments that shouldn't normally host an executable.
    /// Backslashes because prefetch records NT device paths
    /// (`\DEVICE\HARDDISKVOLUME3\...`). High = strongly anomalous.
    private static let highRiskFragments = [
        #"\temp\"#,          // \Windows\Temp, \AppData\Local\Temp, any \Temp\
        #"\$recycle.bin\"#,
        #"\users\public\"#,
        #"\perflogs\"#,
    ]
    private static let mediumRiskFragments = [
        #"\downloads\"#,
    ]

    /// Living-off-the-land binaries that are *rare on a normal endpoint*, so a
    /// bare execution is itself worth surfacing. Deliberately curated: the
    /// ubiquitous interpreters/proxies (powershell, rundll32, regsvr32, wmic,
    /// schtasks, cscript, wscript) run constantly on every Windows host, so
    /// flagging their mere execution buries the signal under thousands of
    /// near-zero-value findings - they're still caught by the suspicious-path
    /// rule above when they run from a staging location. Keyed by lowercased
    /// executable name; severity reflects how load-bearing the signal is.
    private static let lolbins: [String: (AttackTechnique, Severity)] = [
        "psexesvc.exe":  (AttackTechnique(attackID: "T1569.002", name: "System Services: Service Execution"), .medium),
        "psexec.exe":    (AttackTechnique(attackID: "T1569.002", name: "System Services: Service Execution"), .medium),
        "mshta.exe":     (AttackTechnique(attackID: "T1218.005", name: "System Binary Proxy Execution: Mshta"), .low),
        "installutil.exe": (AttackTechnique(attackID: "T1218.004", name: "System Binary Proxy Execution: InstallUtil"), .low),
        "cmstp.exe":     (AttackTechnique(attackID: "T1218.003", name: "System Binary Proxy Execution: CMSTP"), .low),
        "msbuild.exe":   (AttackTechnique(attackID: "T1127.001", name: "Trusted Developer Utilities Proxy Execution: MSBuild"), .low),
        "certutil.exe":  (AttackTechnique(attackID: "T1105", name: "Ingress Tool Transfer"), .low),
        "bitsadmin.exe": (AttackTechnique(attackID: "T1197", name: "BITS Jobs"), .low),
    ]

    public func analyze(context: AnalysisContext) -> [Finding] {
        var findings: [Finding] = []
        for entry in context.prefetch {
            // Rule 1: execution from a suspicious directory (keyed on the
            // recovered full path).
            if let path = entry.executablePath?.lowercased() {
                if let frag = Self.highRiskFragments.first(where: { path.contains($0) }) {
                    findings.append(Self.pathFinding(entry, fragment: frag, severity: .high))
                } else if let frag = Self.mediumRiskFragments.first(where: { path.contains($0) }) {
                    findings.append(Self.pathFinding(entry, fragment: frag, severity: .medium))
                }
            }

            // Rule 2: a known LOLBin / dual-use tool ran.
            if let (technique, severity) = Self.lolbins[entry.executableName.lowercased()] {
                findings.append(Finding(
                    title: "LOLBin execution: \(entry.executableName)",
                    detail: "\(entry.executablePath ?? entry.executableName)\n"
                        + Self.runSummary(entry)
                        + "\nKnown living-off-the-land binary - confirm the launch was expected.",
                    severity: severity,
                    phase: .exploitation,
                    technique: technique,
                    timestamp: entry.lastRun,
                    evidencePaths: Self.evidence(entry)))
            }
        }
        return findings
    }

    private static func pathFinding(_ entry: PrefetchEntry, fragment: String, severity: Severity) -> Finding {
        Finding(
            title: "Execution from suspicious path: \(entry.executableName)",
            detail: "\(entry.executablePath ?? entry.executableName)\n"
                + runSummary(entry)
                + "\nRan from \(fragment.replacingOccurrences(of: "\\", with: "")) - a location commonly used to stage dropped payloads.",
            severity: severity,
            phase: .exploitation,
            technique: AttackTechnique(attackID: "T1204.002", name: "User Execution: Malicious File"),
            timestamp: entry.lastRun,
            evidencePaths: evidence(entry))
    }

    private static func runSummary(_ entry: PrefetchEntry) -> String {
        let runs = "Ran \(entry.runCount) time\(entry.runCount == 1 ? "" : "s")"
        guard let last = entry.lastRun else { return runs + "." }
        return runs + "; last run \(last.ISO8601Format())."
    }

    private static func evidence(_ entry: PrefetchEntry) -> [String] {
        var paths = [entry.executablePath ?? entry.executableName]
        if !entry.sourceFile.isEmpty { paths.append(entry.sourceFile) }
        return paths
    }
}
