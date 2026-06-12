import SwiftUI

struct OverviewView: View {
    @EnvironmentObject private var model: AppModel

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 20) {
                header

                HStack(spacing: 16) {
                    // Snapshot files once (needed for the deleted filter); use
                    // count-only accessors for the rest so we never build/sort
                    // the million-row collections just to show a number.
                    let files = model.files
                    StatCard(title: "Files", value: "\(files.count)")
                    StatCard(title: "Deleted", value: "\(files.lazy.filter(\.isDeleted).count)")
                    StatCard(title: "Timeline events", value: "\(model.timelineCount)")
                    StatCard(title: "Log events", value: "\(model.eventCount)")
                    StatCard(title: "Registry values", value: "\(model.registryValueCount)")
                    StatCard(title: "Findings", value: "\(model.findingCount)")
                }

                if !model.evidenceList.isEmpty {
                    CaseSummaryCard()
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
                LabeledContent("Type", value: evidence.kind.label)
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
                    profile: profile(for: evidence),
                    isWorking: model.isWorking,
                    onParseRegistry: {
                        #if os(macOS)
                        Task { await model.parseRegistry(force: true) }
                        #endif
                    })
            }
        }
    }

    /// Registry-derived profile for Windows evidence; fall back to the Linux
    /// host-info files (os-release/hostname/passwd) when the registry walk
    /// yields nothing - a Linux host has no hives.
    private func profile(for evidence: Evidence) -> HostProfile {
        let registryProfile = HostProfile.derive(
            from: model.states[evidence.id]?.registryValues ?? [])
        if registryProfile.hasAnyData { return registryProfile }
        if let info = model.states[evidence.id]?.linuxInfo {
            return HostProfile.derive(fromLinux: info)
        }
        if let mac = model.states[evidence.id]?.macInfo {
            return HostProfile.derive(fromMac: mac)
        }
        return registryProfile
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
                    #if os(macOS)
                    Button(action: onParseRegistry) {
                        Label("Parse registry", systemImage: "play.fill")
                    }
                    .disabled(isWorking)
                    .controlSize(.small)
                    #endif
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
