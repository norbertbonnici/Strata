#if !os(macOS)
import SwiftUI

/// Vertical kill-chain rail. Each phase is a row with a coloured node and a
/// stack of finding cards underneath. Empty phases are shown so the analyst
/// can see at a glance which parts of the chain *don't* have observed
/// activity — that absence is often more revealing than the hits.
struct KillChainTab: View {
    @EnvironmentObject private var model: AppModel

    private var findingsByPhase: [KillChainPhase: [Finding]] {
        Dictionary(grouping: model.findings, by: \.phase)
    }

    private var maxSeverity: Severity? {
        model.findings.map(\.severity).max()
    }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 0) {
                LargeTitle(
                    title: "Kill Chain",
                    subtitle: "Lockheed Martin · ATT&CK mapped")

                summaryLine

                VStack(alignment: .leading, spacing: 0) {
                    ForEach(Array(KillChainPhase.allCases.enumerated()), id: \.element) { (idx, phase) in
                        phaseRow(phase: phase,
                                 findings: findingsByPhase[phase] ?? [],
                                 isLast: idx == KillChainPhase.allCases.count - 1)
                    }
                }
                .padding(.top, 8)

                Spacer(minLength: 26)
            }
        }
        .background(Theme.bg.ignoresSafeArea())
        .toolbar(.hidden, for: .navigationBar)
    }

    @ViewBuilder private var summaryLine: some View {
        let techniques = Set(model.findings.compactMap { $0.technique?.attackID }).count
        let phases = Set(model.findings.map(\.phase)).count
        HStack(spacing: 4) {
            Text("\(techniques) technique\(techniques == 1 ? "" : "s")")
                .foregroundStyle(Theme.text).bold()
            Text("across")
            Text("\(phases) phase\(phases == 1 ? "" : "s")")
                .foregroundStyle(Theme.text).bold()
            if let sev = maxSeverity {
                Text("· highest severity")
                Text(sev.label)
                    .foregroundStyle(Theme.severityColor(sev)).bold()
            }
        }
        .font(.system(size: 13))
        .foregroundStyle(Theme.text2)
        .padding(.horizontal, 16)
        .padding(.top, 2)
        .frame(maxWidth: .infinity, alignment: .leading)
    }

    /// One phase row = a node + name + findings (or "no activity"). The rail
    /// is drawn as a vertical strip behind the node via `ZStack` so the
    /// finding cards can size themselves naturally.
    private func phaseRow(phase: KillChainPhase, findings: [Finding], isLast: Bool) -> some View {
        let isEmpty = findings.isEmpty
        let nodeColor: Color = {
            if let max = findings.map(\.severity).max() {
                return Theme.severityColor(max)
            }
            return Theme.text3
        }()

        return HStack(alignment: .top, spacing: 0) {
            // Rail + node column
            ZStack(alignment: .top) {
                if !isLast {
                    Rectangle()
                        .fill(Theme.hair)
                        .frame(width: 2)
                        .padding(.top, 14)
                }
                Circle()
                    .stroke(nodeColor, lineWidth: 2)
                    .background(Circle().fill(Theme.bg))
                    .frame(width: 18, height: 18)
                    .overlay(
                        Circle()
                            .fill(isEmpty ? Color.clear : nodeColor.opacity(0.18))
                            .frame(width: 26, height: 26))
                    .padding(.top, 4)
            }
            .frame(width: 40)
            .padding(.leading, 19)

            VStack(alignment: .leading, spacing: 9) {
                HStack(spacing: 8) {
                    Text(phase.title.uppercased())
                        .font(.system(size: 13, weight: .heavy))
                        .tracking(0.6)
                        .foregroundStyle(isEmpty ? Theme.text3 : Theme.text2)
                    Text("\(findings.count)")
                        .font(.system(size: 11, weight: .semibold, design: .monospaced))
                        .foregroundStyle(Theme.text3)
                }

                if isEmpty {
                    Text("No activity observed")
                        .font(.system(size: 12))
                        .foregroundStyle(Theme.text3)
                } else {
                    ForEach(findings) { f in
                        FindingCard(finding: f)
                    }
                }
            }
            .padding(.trailing, 16)
            .padding(.bottom, 14)
        }
    }
}

/// A single finding inside a phase row.
private struct FindingCard: View {
    let finding: Finding

    var body: some View {
        VStack(alignment: .leading, spacing: 5) {
            HStack(spacing: 8) {
                SeverityDot(color: Theme.severityColor(finding.severity))
                Text(finding.title)
                    .font(.system(size: 14, weight: .semibold))
                    .foregroundStyle(Theme.text)
                    .lineLimit(2)
                Spacer(minLength: 0)
                if let t = finding.technique {
                    Pill(text: t.attackID,
                         background: Theme.tealDim,
                         foreground: Theme.teal2)
                }
            }
            Text(finding.detail)
                .font(.system(size: 12.5))
                .foregroundStyle(Theme.text2)
                .lineSpacing(2)
            if let p = finding.evidencePaths.first {
                Text(p)
                    .font(.system(size: 11, design: .monospaced))
                    .foregroundStyle(Theme.text3)
                    .lineLimit(1)
                    .truncationMode(.middle)
                    .padding(.top, 4)
            }
        }
        .padding(.horizontal, 13)
        .padding(.vertical, 11)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Theme.card)
        .overlay(RoundedRectangle(cornerRadius: 13).stroke(Theme.hair, lineWidth: 1))
        .clipShape(RoundedRectangle(cornerRadius: 13))
    }
}
#endif
