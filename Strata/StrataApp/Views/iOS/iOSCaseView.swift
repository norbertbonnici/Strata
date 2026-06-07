#if !os(macOS)
import SwiftUI

/// Root of the iOS case-viewer experience. macOS continues to use the
/// `NavigationSplitView`-based ContentView; iOS gets a TabView so the five
/// most-used screens are one tap apart, matching the mockup.
struct iOSCaseView: View {
    @EnvironmentObject private var model: AppModel
    @State private var tab: TabID = .overview

    enum TabID: Hashable { case overview, timeline, killChain, events, more }

    var body: some View {
        TabView(selection: $tab) {
            NavigationStack { OverviewTab() }
                .tabItem { Label("Overview", systemImage: "square.stack.3d.up") }
                .tag(TabID.overview)

            NavigationStack { TimelineTab() }
                .tabItem { Label("Timeline", systemImage: "clock") }
                .tag(TabID.timeline)

            NavigationStack { KillChainTab() }
                .tabItem { Label("Kill Chain", systemImage: "link") }
                .tag(TabID.killChain)

            NavigationStack { EventsTab() }
                .tabItem { Label("Events", systemImage: "doc.text.magnifyingglass") }
                .tag(TabID.events)

            NavigationStack { MoreTab() }
                .tabItem { Label("More", systemImage: "ellipsis.circle") }
                .tag(TabID.more)
        }
        .tint(Theme.teal2)
    }
}

// MARK: - Overview tab

/// Top-level case dashboard: critical banner (if any), Host + Evidence cards,
/// stat tiles, and a free-form summary. All the data is read off AppModel's
/// already-computed properties so nothing here triggers a parse.
struct OverviewTab: View {
    @EnvironmentObject private var model: AppModel

    /// Single evidence to anchor the host card off, or nil if multiple
    /// evidences are loaded. The mockup pictures a single-host case; when
    /// multiple hosts are loaded we pick the active scope, else fall back to
    /// the first.
    private var primaryEvidence: Evidence? {
        model.selectedEvidence ?? model.evidenceList.first
    }

    /// Cached host profile, recomputed only when the data/scope changes.
    /// HostProfile.derive linearly scans registryValues (tens of thousands of
    /// rows); it was running twice per render off a computed property.
    @State private var hostProfile: HostProfile?

    private func recomputeProfile() {
        guard let id = primaryEvidence?.id,
              let regs = model.states[id]?.registryValues else { hostProfile = nil; return }
        hostProfile = HostProfile.derive(from: regs)
    }

    private var criticalFindings: [Finding] {
        model.findings.filter { $0.severity >= .high }
    }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 0) {
                LargeTitle(
                    title: "Evidence",
                    subtitle: subtitle)

                if !criticalFindings.isEmpty {
                    CriticalBanner(
                        title: criticalBannerTitle,
                        message: criticalBannerBody)
                        .padding(.bottom, 8)
                }

                Section { hostCard }            header: { SectionHeader(label: "Host") }
                Section { evidenceCard }        header: { SectionHeader(label: "Evidence").padding(.top, 14) }

                StatTiles(tiles: tiles)

                if !summary.isEmpty {
                    Text(summary)
                        .font(.system(size: 13.5))
                        .lineSpacing(3)
                        .foregroundStyle(Theme.text2)
                        .padding(.horizontal, 16)
                        .padding(.top, 12)
                }

                Spacer(minLength: 26)
            }
        }
        .background(Theme.bg.ignoresSafeArea())
        .toolbar(.hidden, for: .navigationBar)
        .task(id: model.dataVersion) { recomputeProfile() }
    }

    private var subtitle: String {
        let host = hostProfile?.hostname ?? primaryEvidence?.displayName ?? "—"
        let caseName = model.currentCase?.name ?? ""
        return caseName.isEmpty ? host : "\(host) · case \(caseName)"
    }

    private var criticalBannerTitle: String {
        criticalFindings.contains(where: { $0.severity == .critical })
            ? "Critical activity detected"
            : "High-severity activity detected"
    }

    private var criticalBannerBody: String {
        let phaseCount = Set(criticalFindings.map(\.phase)).count
        let n = criticalFindings.count
        return "\(n) finding\(n == 1 ? "" : "s") across \(phaseCount) kill-chain phase\(phaseCount == 1 ? "" : "s")."
    }

    @ViewBuilder private var hostCard: some View {
        Card {
            let p = hostProfile
            KVRow(key: "Hostname", value: p?.hostname ?? primaryEvidence?.displayName ?? "—", mono: true)
            if let ip = p?.ipAddresses.first {
                KVRow(key: "IP address", value: ip, mono: true)
            }
            KVRow(key: "Operating system", value: osLine(p))
            if let build = p?.osBuild {
                KVRow(key: "Build", value: build, mono: true)
            }
            KVRow(key: "Domain", value: p?.domain ?? "—", mono: true, showDivider: false)
        }
    }

    private func osLine(_ p: HostProfile?) -> String {
        let product = p?.osProductName ?? "Unknown"
        if let v = p?.osDisplayVersion, !v.isEmpty { return "\(product) · \(v)" }
        return product
    }

    @ViewBuilder private var evidenceCard: some View {
        Card {
            if let ev = primaryEvidence {
                KVRow(key: "Image", value: ev.sourceURL.lastPathComponent, mono: true)
                KVRow(key: "Type", value: evidenceKindLabel(ev.kind))
            }
            if let c = model.currentCase {
                KVRow(key: "Examiner", value: c.examiner.isEmpty ? "—" : c.examiner)
                KVRow(key: "Created", value: c.createdAt.formatted(date: .abbreviated, time: .shortened),
                      mono: true, showDivider: false)
            }
        }
    }

    private func evidenceKindLabel(_ k: EvidenceKind) -> String {
        switch k {
        case .e01:             return "EnCase E01"
        case .kapeVHD:         return "KAPE VHD/VHDX"
        case .raw:             return "Raw image"
        case .kapeLooseFolder: return "Loose KAPE folder"
        }
    }

    private var tiles: [StatTiles.Tile] {
        [
            .init(value: humanCount(model.fileCount),      label: "Files enumerated", color: Theme.text),
            .init(value: humanCount(model.timelineCount),  label: "Timeline events",  color: Theme.teal2),
            .init(value: "\(model.findingCount)",          label: "Findings",         color: Theme.crit),
            .init(value: "\(model.iocs.count)",            label: "Indicators",       color: Theme.amber),
        ]
    }

    private func humanCount(_ n: Int) -> String {
        switch n {
        case 1_000_000...:
            return String(format: "%.2fM", Double(n) / 1_000_000)
        case 999_950...:
            // Below 1M but rounds to "1000.0K" at one decimal - promote to M.
            return String(format: "%.1fM", Double(n) / 1_000_000)
        case 100_000...:
            return String(format: "%.1fK", Double(n) / 1_000)
        case 1_000...:
            // 412,883 style
            let fmt = NumberFormatter()
            fmt.numberStyle = .decimal
            return fmt.string(from: NSNumber(value: n)) ?? "\(n)"
        default:
            return "\(n)"
        }
    }

    /// Summary paragraph drawn from the most severe findings, ordered by
    /// timestamp where available. Falls back to empty when no findings exist
    /// so the section doesn't show an empty title.
    private var summary: String {
        let topByPhase = criticalFindings.isEmpty
            ? model.findings
            : criticalFindings
        let sorted = topByPhase.sorted { (a, b) -> Bool in
            if a.severity != b.severity { return a.severity > b.severity }
            return (a.timestamp ?? .distantPast) < (b.timestamp ?? .distantPast)
        }
        let topThree = sorted.prefix(3).map { $0.title }
        if topThree.isEmpty { return "" }
        return "Top findings: " + topThree.joined(separator: " · ") + "."
    }
}

// MARK: - More tab

/// "More" surfaces the lower-traffic tools (filesystem browse, lateral
/// movement, IOCs) and the case lifecycle (close). Anything that needs the
/// ingest pipeline stays off iOS so this tab is intentionally minimal.
struct MoreTab: View {
    @EnvironmentObject private var model: AppModel

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 0) {
                LargeTitle(title: "More")

                SectionHeader(label: "Analysis")
                Card {
                    NavigationLink {
                        FilesystemDrillView()
                    } label: {
                        moreRow(icon: "folder", title: "Filesystem",
                                trailing: counter(model.fileCount))
                    }
                    .buttonStyle(.plain)
                    Divider().background(Theme.hair2).padding(.leading, 50)

                    NavigationLink {
                        LateralDrillView()
                    } label: {
                        moreRow(icon: "point.3.connected.trianglepath.dotted",
                                title: "Lateral movement",
                                trailing: lateralHops)
                    }
                    .buttonStyle(.plain)
                    Divider().background(Theme.hair2).padding(.leading, 50)

                    NavigationLink {
                        IOCsDrillView()
                    } label: {
                        moreRow(icon: "scope", title: "Indicators (IOCs)",
                                trailing: counter(model.iocs.count))
                    }
                    .buttonStyle(.plain)
                    Divider().background(Theme.hair2).padding(.leading, 50)

                    NavigationLink {
                        CustodyDrillView()
                    } label: {
                        moreRow(icon: "checkmark.seal", title: "Chain of custody",
                                trailing: counter(model.custodyLog.count))
                    }
                    .buttonStyle(.plain)
                }

                SectionHeader(label: "Case").padding(.top, 14)
                Card {
                    Button {
                        model.closeCase()
                    } label: {
                        moreRow(icon: "xmark.circle", title: "Close case",
                                trailing: "", titleColor: Theme.crit)
                    }
                    .buttonStyle(.plain)
                }

                Spacer(minLength: 26)
            }
        }
        .background(Theme.bg.ignoresSafeArea())
        .toolbar(.hidden, for: .navigationBar)
    }

    private var lateralHops: String {
        let count = model.lateralGraph.edges.count   // cached; no per-render rebuild
        return count == 0 ? "—" : "\(count) hop\(count == 1 ? "" : "s")"
    }

    private func counter(_ n: Int) -> String {
        let fmt = NumberFormatter()
        fmt.numberStyle = .decimal
        return fmt.string(from: NSNumber(value: n)) ?? "\(n)"
    }

    /// Row inside a More-card. macOS-style toolbar/help is unused on iOS so
    /// each row is just an HStack with leading icon + title + trailing value.
    private func moreRow(icon: String, title: String, trailing: String,
                         titleColor: Color = Theme.text) -> some View {
        HStack(spacing: 12) {
            Image(systemName: icon)
                .font(.system(size: 16))
                .frame(width: 22)
                .foregroundStyle(Theme.teal2)
            Text(title)
                .font(.system(size: 14.5, weight: .medium))
                .foregroundStyle(titleColor)
            Spacer()
            if !trailing.isEmpty {
                Text(trailing)
                    .font(.system(size: 14.5))
                    .foregroundStyle(Theme.text3)
            }
            Image(systemName: "chevron.right")
                .font(.system(size: 11, weight: .semibold))
                .foregroundStyle(Theme.text3.opacity(0.7))
        }
        .padding(.horizontal, 15)
        .padding(.vertical, 13)
        .contentShape(Rectangle())
    }
}
#endif
