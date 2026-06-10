import Foundation

/// Turns the raw `ReportInputs` into a `ReportModel`: derives each host's
/// profile, groups findings by kill-chain phase, computes severity rollups, and
/// selects the timeline excerpt. Pure - no I/O, no main-actor state.
public nonisolated enum ReportModelBuilder {
    public static func build(from inputs: ReportInputs,
                             severities: Set<Severity> = Set(Severity.allCases)) -> ReportModel {
        var sections: [ReportModel.HostSection] = []
        var caseSeverity: [Severity: Int] = [:]
        var totalFindings = 0
        var totalIOC = 0

        for host in inputs.hosts {
            // Registry profile for Windows hosts; Linux host-info fallback
            // when the registry walk yields nothing (no hives on ext4).
            var profile = HostProfile.derive(from: host.registryValues)
            if !profile.hasAnyData, let linuxInfo = host.linuxInfo {
                profile = HostProfile.derive(fromLinux: linuxInfo)
            }

            // The report shows only the selected severities; the raw findings
            // export (built elsewhere) keeps every finding.
            let findings = host.findings.filter { severities.contains($0.severity) }

            var byPhase: [KillChainPhase: [Finding]] = [:]
            var hostSeverity: [Severity: Int] = [:]
            for finding in findings {
                byPhase[finding.phase, default: []].append(finding)
                hostSeverity[finding.severity, default: 0] += 1
                caseSeverity[finding.severity, default: 0] += 1
            }

            let phaseGroups = KillChainPhase.allCases.compactMap { phase -> ReportModel.PhaseGroup? in
                guard let group = byPhase[phase], !group.isEmpty else { return nil }
                let sorted = group.sorted { $0.severity > $1.severity }
                return ReportModel.PhaseGroup(phase: phase, findings: sorted)
            }

            let excerpt = findings
                .filter { $0.timestamp != nil }
                .sorted { ($0.timestamp ?? .distantPast) < ($1.timestamp ?? .distantPast) }

            sections.append(ReportModel.HostSection(
                displayName: host.displayName,
                kindLabel: host.kindLabel,
                sourcePath: host.sourcePath,
                profile: profile,
                fileCount: host.fileCount,
                eventCount: host.eventCount,
                registryValueCount: host.registryValues.count,
                findingCount: findings.count,
                iocMatchCount: host.iocMatches.count,
                severityCounts: severityCounts(hostSeverity),
                phaseGroups: phaseGroups,
                iocMatches: host.iocMatches,
                timelineExcerpt: excerpt))

            totalFindings += findings.count
            totalIOC += host.iocMatches.count
        }

        return ReportModel(
            caseName: inputs.caseName,
            examiner: inputs.examiner,
            createdAt: inputs.createdAt,
            generatedAt: inputs.generatedAt,
            narrative: inputs.caseNotes.trimmingCharacters(in: .whitespacesAndNewlines),
            bookmarks: inputs.annotations.sorted {
                ($0.timestamp ?? .distantFuture, $0.createdAt)
                    < ($1.timestamp ?? .distantFuture, $1.createdAt)
            },
            hostSections: sections,
            totalFindings: totalFindings,
            totalIOCMatches: totalIOC,
            caseSeverityCounts: severityCounts(caseSeverity),
            severityFilterNote: severityFilterNote(severities))
    }

    /// "High, Critical" when a strict subset of severities is selected; `nil`
    /// when every severity is included (no filtering to disclose).
    private static func severityFilterNote(_ severities: Set<Severity>) -> String? {
        guard severities.count < Severity.allCases.count else { return nil }
        let included = Severity.allCases.reversed().filter { severities.contains($0) }
        return included.map(\.label).joined(separator: ", ")
    }

    /// Highest → lowest severity, dropping zero counts.
    private static func severityCounts(_ counts: [Severity: Int]) -> [ReportModel.SeverityCount] {
        Severity.allCases.reversed().compactMap { severity in
            let count = counts[severity] ?? 0
            return count > 0 ? ReportModel.SeverityCount(severity: severity, count: count) : nil
        }
    }
}
