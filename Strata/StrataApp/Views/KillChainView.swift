import SwiftUI

/// One column on the Kill Chain view aggregates many findings into a small
/// set of cards keyed by ATT&CK technique. Without this collapse, columns
/// would render thousands of card views (one per analyzer hit), which both
/// looks awful and reliably hangs / crashes SwiftUI on macOS for any non-
/// trivial host.
struct KillChainView: View {
    @EnvironmentObject private var model: AppModel
    @State private var selectedGroupID: String?

    var body: some View {
        // Snapshot findings once and group once per render. Previously the
        // findings collection + the full phase-grouping pipeline ran up to 3x
        // per body (here, plus the inspector's isPresented expr and its content).
        let findings = model.findings
        let groupsByPhase = Self.groupByPhase(findings)
        let selected = Self.group(withID: selectedGroupID, in: groupsByPhase)
        let eventsEmpty = model.eventCount == 0
        return VStack(alignment: .leading, spacing: 0) {
            SummaryBar(findings: findings)
                .padding(.horizontal).padding(.top)

            ScrollView(.horizontal, showsIndicators: true) {
                HStack(alignment: .top, spacing: 0) {
                    ForEach(Array(KillChainPhase.allCases.enumerated()), id: \.element) { index, phase in
                        PhaseColumn(phase: phase,
                                    groups: groupsByPhase[phase] ?? [],
                                    selectedGroupID: $selectedGroupID)
                            .frame(width: 240)
                        if index < KillChainPhase.allCases.count - 1 {
                            Image(systemName: "chevron.compact.right")
                                .font(.title2).foregroundStyle(.tertiary)
                                .frame(width: 24).padding(.top, 60)
                        }
                    }
                }
                .padding()
            }

            HStack {
                Spacer()
                Button {
                    Task { await model.runAnalyzers() }
                } label: {
                    Label("Run analyzers", systemImage: "play.fill")
                }
                .controlSize(.small)
                .disabled(model.isWorking || eventsEmpty)
                .help(eventsEmpty
                      ? "Parse event logs first (Events tab)."
                      : "Run the detection analyzers on the loaded evidence.")
            }
            .padding(.horizontal).padding(.bottom, 8)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
        .navigationTitle("Kill Chain")
        // Real read/write binding so the inspector's own collapse control works
        // (a .constant binding silently discards the dismiss).
        .inspector(isPresented: Binding(
            get: { selectedGroupID != nil },
            set: { if !$0 { selectedGroupID = nil } })) {
            GroupDetailPane(group: selected)
                .inspectorColumnWidth(min: 320, ideal: 400, max: 540)
        }
    }

    private static func group(withID id: String?,
                              in groups: [KillChainPhase: [FindingGroup]]) -> FindingGroup? {
        guard let id else { return nil }
        return groups.values.flatMap { $0 }.first { $0.id == id }
    }

    /// Bucket findings by phase and then by ATT&CK ID. Findings without a
    /// technique each become their own one-element group so they don't all
    /// collapse into an indistinguishable "untagged" pile.
    private static func groupByPhase(_ findings: [Finding]) -> [KillChainPhase: [FindingGroup]] {
        var result: [KillChainPhase: [FindingGroup]] = [:]
        for phase in KillChainPhase.allCases {
            let inPhase = findings.filter { $0.phase == phase }
            let buckets = Dictionary(grouping: inPhase) { f in
                f.technique?.attackID ?? "ungrouped:\(f.id.uuidString)"
            }
            result[phase] = buckets.map { key, items in
                FindingGroup(id: "\(phase.rawValue)|\(key)",
                             phase: phase,
                             technique: items.first?.technique,
                             findings: items.sorted { lhs, rhs in
                                 (lhs.timestamp ?? .distantPast) > (rhs.timestamp ?? .distantPast)
                             })
            }
            .sorted { $0.maxSeverity > $1.maxSeverity }
        }
        return result
    }
}

// MARK: - Model

/// One ATT&CK technique's worth of findings inside a single kill-chain phase.
private struct FindingGroup: Identifiable, Hashable {
    let id: String                      // phase | techniqueID (or ungrouped:UUID)
    let phase: KillChainPhase
    let technique: AttackTechnique?
    let findings: [Finding]

    var maxSeverity: Severity { findings.map(\.severity).max() ?? .info }
    var count: Int { findings.count }
    var title: String {
        technique?.name ?? findings.first?.title ?? "Untagged"
    }
    var subtitle: String {
        if let t = technique { return t.attackID }
        return "No ATT&CK mapping"
    }
}

// MARK: - Header strip

private struct SummaryBar: View {
    let findings: [Finding]
    var body: some View {
        // One grouping pass instead of a filter per severity.
        let counts = Dictionary(grouping: findings, by: \.severity).mapValues(\.count)
        HStack(spacing: 14) {
            ForEach(Severity.allCases.reversed(), id: \.self) { sev in
                let count = counts[sev] ?? 0
                HStack(spacing: 5) {
                    Circle().fill(sev.color).frame(width: 9, height: 9)
                    Text("\(sev.label): \(count)").font(.caption)
                }
            }
            Spacer()
        }
    }
}

// MARK: - Phase column

private struct PhaseColumn: View {
    let phase: KillChainPhase
    let groups: [FindingGroup]
    @Binding var selectedGroupID: String?

    private var totalFindings: Int { groups.reduce(0) { $0 + $1.count } }

    var body: some View {
        VStack(spacing: 10) {
            VStack(spacing: 6) {
                Image(systemName: phase.symbol).font(.title2)
                Text(phase.title).font(.subheadline).bold()
                    .multilineTextAlignment(.center)
                    .fixedSize(horizontal: false, vertical: true)
                Text("\(totalFindings) findings, \(groups.count) techniques")
                    .font(.caption2).foregroundStyle(.secondary)
            }
            .frame(maxWidth: .infinity).frame(height: 100)
            .background(.quaternary, in: RoundedRectangle(cornerRadius: 10))

            if groups.isEmpty {
                Text("No activity").font(.caption).foregroundStyle(.tertiary)
                    .frame(maxWidth: .infinity).padding(.vertical, 12)
            } else {
                // LazyVStack so a column with 1000s of (rarely existent) groups
                // doesn't allocate offscreen views.
                LazyVStack(spacing: 8) {
                    ForEach(groups) { group in
                        GroupCard(group: group, isSelected: selectedGroupID == group.id)
                            .contentShape(Rectangle())
                            .onTapGesture {
                                selectedGroupID = (selectedGroupID == group.id) ? nil : group.id
                            }
                    }
                }
            }
            Spacer(minLength: 0)
        }
    }
}

private struct GroupCard: View {
    let group: FindingGroup
    let isSelected: Bool

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack {
                Circle().fill(group.maxSeverity.color).frame(width: 8, height: 8)
                Text(group.maxSeverity.label).font(.caption2).foregroundStyle(.secondary)
                Spacer()
                Text(group.subtitle).font(.caption2.monospaced())
                    .foregroundStyle(.secondary)
            }
            Text(group.title).font(.caption).bold()
                .fixedSize(horizontal: false, vertical: true)
                .lineLimit(2)
            HStack(spacing: 4) {
                Image(systemName: "number")
                Text("\(group.count) finding\(group.count == 1 ? "" : "s")")
            }
            .font(.caption2).foregroundStyle(.secondary)
        }
        .padding(10)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(group.maxSeverity.color.opacity(0.12),
                    in: RoundedRectangle(cornerRadius: 8))
        .overlay(
            RoundedRectangle(cornerRadius: 8)
                .strokeBorder(isSelected ? group.maxSeverity.color : Color.clear, lineWidth: 2)
        )
    }
}

// MARK: - Inspector

/// Right-hand inspector when a group is selected. Renders the group header
/// plus every underlying finding as an expandable row.
private struct GroupDetailPane: View {
    let group: FindingGroup?
    @State private var expandedFindingID: UUID?

    var body: some View {
        if let group {
            ScrollView {
                LazyVStack(alignment: .leading, spacing: 12) {
                    header(for: group)
                    Divider()
                    ForEach(group.findings) { finding in
                        FindingRow(finding: finding,
                                   isExpanded: expandedFindingID == finding.id) {
                            withAnimation(.easeInOut(duration: 0.15)) {
                                expandedFindingID = (expandedFindingID == finding.id) ? nil : finding.id
                            }
                        }
                    }
                }
                .padding()
                .frame(maxWidth: .infinity, alignment: .leading)
            }
        } else {
            ContentUnavailableView("Select a technique",
                systemImage: "link",
                description: Text("Click an ATT&CK card to see every finding mapped to it."))
        }
    }

    @ViewBuilder
    private func header(for group: FindingGroup) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            Text(group.title).font(.title3).bold()
            HStack(spacing: 12) {
                Label(group.maxSeverity.label, systemImage: "exclamationmark.triangle")
                    .foregroundStyle(group.maxSeverity.color)
                Text(group.phase.title).foregroundStyle(.secondary)
                if let t = group.technique {
                    Text(t.attackID).font(.caption.monospaced())
                        .padding(.horizontal, 6).padding(.vertical, 2)
                        .background(.quaternary, in: Capsule())
                }
            }
            .font(.caption)
            Text("\(group.count) finding\(group.count == 1 ? "" : "s")")
                .font(.caption).foregroundStyle(.secondary)
        }
    }
}

private struct FindingRow: View {
    let finding: Finding
    let isExpanded: Bool
    let toggle: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            Button(action: toggle) {
                HStack(alignment: .top) {
                    Image(systemName: isExpanded ? "chevron.down" : "chevron.right")
                        .foregroundStyle(.secondary)
                        .frame(width: 12)
                    VStack(alignment: .leading, spacing: 2) {
                        Text(finding.title).font(.caption).bold()
                            .multilineTextAlignment(.leading)
                            .lineLimit(2)
                        HStack(spacing: 8) {
                            Circle().fill(finding.severity.color).frame(width: 6, height: 6)
                            Text(finding.severity.label).foregroundStyle(.secondary)
                            if let ts = finding.timestamp {
                                Text(ts.formatted(date: .abbreviated, time: .standard))
                                    .foregroundStyle(.tertiary)
                            }
                        }
                        .font(.caption2)
                    }
                    Spacer()
                }
            }
            .buttonStyle(.plain)

            if isExpanded {
                VStack(alignment: .leading, spacing: 6) {
                    Text(finding.detail)
                        .font(.caption)
                        .textSelection(.enabled)
                        .fixedSize(horizontal: false, vertical: true)
                    if !finding.evidencePaths.isEmpty {
                        Text("Evidence").font(.caption2).bold().foregroundStyle(.secondary)
                        ForEach(finding.evidencePaths, id: \.self) { path in
                            Text(path).font(.caption2.monospaced())
                                .foregroundStyle(.secondary)
                                .textSelection(.enabled)
                                .lineLimit(2).truncationMode(.middle)
                        }
                    }
                }
                .padding(.leading, 18)
                .padding(.top, 4)
            }
        }
        .padding(8)
        .background(.quaternary.opacity(isExpanded ? 0.4 : 0.0),
                    in: RoundedRectangle(cornerRadius: 6))
    }
}

extension Severity {
    var color: Color {
        switch self {
        case .info:     return .gray
        case .low:      return .yellow
        case .medium:   return .orange
        case .high:     return .red
        case .critical: return .pink
        }
    }
}
