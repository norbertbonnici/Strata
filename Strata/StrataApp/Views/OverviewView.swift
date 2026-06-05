import SwiftUI

struct OverviewView: View {
    @EnvironmentObject private var model: AppModel

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 20) {
                header

                HStack(spacing: 16) {
                    StatCard(title: "Files", value: "\(model.files.count)")
                    StatCard(title: "Deleted", value: "\(model.files.filter(\.isDeleted).count)")
                    StatCard(title: "Timeline events", value: "\(model.timeline.count)")
                    StatCard(title: "Log events", value: "\(model.events.count)")
                    StatCard(title: "Registry values", value: "\(model.registryValues.count)")
                    StatCard(title: "Findings", value: "\(model.findings.count)")
                }

                if !model.evidenceList.isEmpty {
                    hostProfiles
                }

                if model.evidenceList.count > 1, model.activeEvidenceID == nil {
                    perEvidenceBreakdown
                }

                Text(model.evidenceList.isEmpty
                     ? "Open an E01 image or KAPE .vhd to begin. The Sleuth Kit ingests the image; Strata reads its database to build the file tree and timeline."
                     : "Use the scope picker in the toolbar to focus on a single evidence source, or keep \"All evidence\" selected for a combined view.")
                    .foregroundStyle(.secondary)
            }
            .padding()
            .frame(maxWidth: .infinity, alignment: .leading)
        }
        .navigationTitle("Overview")
    }

    @ViewBuilder
    private var header: some View {
        if let evidence = model.selectedEvidence {
            VStack(alignment: .leading, spacing: 4) {
                Text(evidence.displayName).font(.title2).bold()
                LabeledContent("Source", value: evidence.sourceURL.path)
                LabeledContent("Type", value: evidence.kind.rawValue)
            }
        } else if model.evidenceList.isEmpty {
            Text("No evidence loaded").font(.title2).bold()
        } else {
            VStack(alignment: .leading, spacing: 4) {
                Text("All evidence").font(.title2).bold()
                Text("Combined view across \(model.evidenceList.count) sources.")
                    .foregroundStyle(.secondary)
            }
        }
    }

    @ViewBuilder
    private var hostProfiles: some View {
        // Scope picker drives this: "All" shows every host, a single
        // selection shows just that one.
        let hosts = model.activeEvidenceID == nil
            ? model.evidenceList
            : model.evidenceList.filter { $0.id == model.activeEvidenceID }
        VStack(alignment: .leading, spacing: 12) {
            Text(hosts.count == 1 ? "Host" : "Hosts").font(.headline)
            ForEach(hosts) { evidence in
                HostProfileCard(
                    evidence: evidence,
                    profile: HostProfile.derive(
                        from: model.states[evidence.id]?.registryValues ?? []),
                    isWorking: model.isWorking,
                    onParseRegistry: { Task { await model.parseRegistry(force: true) } })
            }
        }
    }

    @ViewBuilder
    private var perEvidenceBreakdown: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("Per-evidence breakdown").font(.headline)
            ForEach(model.evidenceList) { evidence in
                let state = model.states[evidence.id]
                HStack(spacing: 16) {
                    Text(evidence.displayName).bold()
                        .frame(maxWidth: .infinity, alignment: .leading)
                    Text("\(state?.files.count ?? 0) files").foregroundStyle(.secondary)
                    Text("\(state?.events.count ?? 0) events").foregroundStyle(.secondary)
                    Text("\(state?.registryValues.count ?? 0) reg vals").foregroundStyle(.secondary)
                    Text("\(state?.findings.count ?? 0) findings").foregroundStyle(.secondary)
                }
                .font(.caption)
                .padding(.vertical, 4)
                Divider()
            }
        }
        .padding()
        .background(.quaternary, in: RoundedRectangle(cornerRadius: 10))
    }
}

private struct StatCard: View {
    let title: String
    let value: String
    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(value).font(.system(size: 28, weight: .semibold, design: .rounded))
            Text(title).font(.caption).foregroundStyle(.secondary)
        }
        .padding()
        .frame(minWidth: 120, alignment: .leading)
        .background(.quaternary, in: RoundedRectangle(cornerRadius: 10))
    }
}

private struct HostProfileCard: View {
    let evidence: Evidence
    let profile: HostProfile
    let isWorking: Bool
    let onParseRegistry: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack(alignment: .firstTextBaseline, spacing: 8) {
                Text(profile.hostname ?? evidence.displayName)
                    .font(.title3).bold()
                if profile.hostname != nil {
                    Text(evidence.displayName)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }
            if profile.hasAnyData {
                Grid(alignment: .leadingFirstTextBaseline,
                     horizontalSpacing: 16, verticalSpacing: 4) {
                    if let os = profile.osSummary { row("OS", os) }
                    if let domain = profile.domain { row("Domain", domain) }
                    if !profile.ipAddresses.isEmpty {
                        row("IP", profile.ipAddresses.joined(separator: ", "))
                    }
                    if let installed = profile.installDate {
                        row("Installed", installed.formatted(date: .abbreviated, time: .shortened))
                    }
                    if let lastShutdown = profile.lastShutdown {
                        row("Last shutdown", lastShutdown.formatted(date: .abbreviated, time: .shortened))
                    }
                    if let primary = profile.primaryUser { row("Primary user", primary) }
                    if let tz = profile.timeZone { row("Time zone", tz) }
                }
                .font(.callout)
            } else {
                HStack(spacing: 12) {
                    Text("Registry not parsed yet.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                    Button(action: onParseRegistry) {
                        Label("Parse registry", systemImage: "play.fill")
                    }
                    .disabled(isWorking)
                    .controlSize(.small)
                }
            }
        }
        .padding()
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(.quaternary, in: RoundedRectangle(cornerRadius: 10))
    }

    private func row(_ label: String, _ value: String) -> some View {
        GridRow {
            Text(label).foregroundStyle(.secondary)
            Text(value).textSelection(.enabled)
        }
    }
}
