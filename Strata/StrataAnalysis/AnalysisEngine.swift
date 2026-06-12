import Foundation

/// Runs every registered analyzer against the same context and concatenates
/// their findings. Analyzers are independent, so we fan out with task groups.
public nonisolated struct AnalysisEngine: Sendable {
    public let analyzers: [any Analyzer]

    public init(analyzers: [any Analyzer] = AnalysisEngine.defaultAnalyzers) {
        self.analyzers = analyzers
    }

    public func run(on context: AnalysisContext) async -> [Finding] {
        await withTaskGroup(of: [Finding].self) { group in
            for analyzer in analyzers {
                group.addTask { analyzer.analyze(context: context) }
            }
            var all: [Finding] = []
            for await batch in group { all.append(contentsOf: batch) }
            return all.sorted { $0.severity > $1.severity }
        }
    }

    /// Built-in detection set. Add new analyzers here as they're written.
    public static let defaultAnalyzers: [any Analyzer] = [
        FailedLogonAnalyzer(),
        SuccessfulLogonAnalyzer(),
        PowerShellAnalyzer(),
        ProcessCreationAnalyzer(),
        ServiceInstallAnalyzer(),
        SchTaskAnalyzer(),
        LogClearedAnalyzer(),
        PersistenceFileAnalyzer(),
        RunKeyAnalyzer(),
        ServicesRegistryAnalyzer(),
        USBHistoryAnalyzer(),
        ImpacketRemoteExecAnalyzer(),
        RMMToolAnalyzer(),
        PasswordSprayAnalyzer(),
        CredentialPivotAnalyzer(),
        PrefetchAnalyzer(),
        AmcacheAnalyzer(),
        ShimcacheAnalyzer(),
        LnkAnalyzer(),
        JumpListAnalyzer(),
        UsnAnalyzer(),
        SrumAnalyzer(),
        BrowserHistoryAnalyzer(),
        MftAnalyzer(),
        WmiAnalyzer(),
        AuthLogAnalyzer(),
        ShellHistoryAnalyzer(),
        LinuxPersistenceAnalyzer(),
        LinuxAccessAnalyzer(),
        WebLogAnalyzer(),
        PackageAnalyzer(),
        JournaldAnalyzer(),
        AuditAnalyzer(),
        SyslogAnalyzer(),
        LastlogAnalyzer(),
        // Wave 1 — detection-coverage expansion.
        CredentialDumpingAnalyzer(),
        ImpactDestructionAnalyzer(),
        LateralMovementBreadthAnalyzer(),
        ADReconAnalyzer(),
        WindowsMRUAnalyzer(),
        LinuxAntiForensicsAnalyzer(),
        // Waves 4/6 — Recycle Bin + macOS triage.
        RecycleBinAnalyzer(),
        MacPersistenceAnalyzer(),
        MacPersistenceSweepAnalyzer(),
        MacQuarantineAnalyzer(),
    ]
}
