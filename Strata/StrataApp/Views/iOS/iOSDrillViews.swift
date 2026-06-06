#if !os(macOS)
import SwiftUI

// MARK: - Filesystem drill view

/// Tap-through filesystem browser keyed off the same `FileEntry` set the
/// macOS view uses. The mockup's breadcrumb sits at the top; we mirror that
/// here with the navigation title doing double duty so the analyst always
/// knows where they are.
struct FilesystemDrillView: View {
    @EnvironmentObject private var model: AppModel
    /// Current path inside the evidence, in `/A/B/C` form. Empty == root.
    @State private var path: String = ""

    private var children: [FileEntry] {
        let prefix = path
        return model.files
            .filter { $0.parentPath == (prefix.isEmpty ? "/" : prefix) }
            .sorted { lhs, rhs in
                if lhs.isDirectory != rhs.isDirectory { return lhs.isDirectory }
                return lhs.name.localizedCaseInsensitiveCompare(rhs.name) == .orderedAscending
            }
    }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 0) {
                LargeTitle(title: "Filesystem")

                breadcrumb

                note

                if children.isEmpty {
                    emptyState
                } else {
                    Card { rows }.padding(.top, 10)
                }

                Spacer(minLength: 26)
            }
        }
        .background(Theme.bg.ignoresSafeArea())
        .navigationBarTitleDisplayMode(.inline)
        .toolbarBackground(Theme.bg, for: .navigationBar)
        .toolbarBackground(.visible, for: .navigationBar)
    }

    private var breadcrumb: some View {
        let crumbs = path.split(separator: "/").map(String.init)
        return HStack(spacing: 5) {
            Text("C:\\")
                .font(.system(size: 12.5, design: .monospaced))
                .foregroundStyle(Theme.text2)
            ForEach(Array(crumbs.enumerated()), id: \.offset) { idx, name in
                Text("›").foregroundStyle(Theme.text3)
                Text(name)
                    .font(.system(size: 12.5, weight: idx == crumbs.count - 1 ? .semibold : .regular,
                                  design: .monospaced))
                    .foregroundStyle(idx == crumbs.count - 1 ? Theme.text : Theme.text2)
            }
        }
        .padding(.horizontal, 22)
        .padding(.top, 4)
    }

    private var note: some View {
        let total = model.files.count
        let deleted = model.files.filter(\.isDeleted).count
        return Text("\(human(total)) objects · \(human(deleted)) deleted")
            .font(.system(size: 12))
            .foregroundStyle(Theme.text3)
            .padding(.horizontal, 22)
            .padding(.top, 10)
    }

    private var emptyState: some View {
        ContentUnavailableView(
            "No files here",
            systemImage: "folder",
            description: Text("Either this folder is empty or the case has no files indexed."))
            .padding(.top, 60)
            .frame(maxWidth: .infinity)
    }

    @ViewBuilder private var rows: some View {
        ForEach(children) { entry in
            Button {
                if entry.isDirectory {
                    let parent = path.isEmpty ? "/" : path
                    path = parent == "/" ? "/\(entry.name)" : "\(parent)/\(entry.name)"
                }
            } label: {
                HStack(spacing: 12) {
                    Image(systemName: entry.isDirectory ? "folder" : iconForFile(entry))
                        .font(.system(size: 17))
                        .frame(width: 24)
                        .foregroundStyle(iconColor(entry))
                    Text(entry.name)
                        .font(entry.isDirectory
                              ? .system(size: 14)
                              : .system(size: 12.5, design: .monospaced))
                        .foregroundStyle(entry.isDeleted ? Theme.text2 : Theme.text)
                        .lineLimit(1)
                        .truncationMode(.middle)
                    Spacer()
                    if entry.isDeleted { DeletedBadge() }
                    if !entry.isDirectory {
                        Text(ByteCountFormatter.string(fromByteCount: entry.size, countStyle: .file))
                            .font(.system(size: 11.5, design: .monospaced))
                            .foregroundStyle(Theme.text3)
                    } else {
                        Image(systemName: "chevron.right")
                            .font(.system(size: 11, weight: .semibold))
                            .foregroundStyle(Theme.text3.opacity(0.7))
                    }
                }
                .padding(.horizontal, 15)
                .padding(.vertical, 12)
                .contentShape(Rectangle())
            }
            .buttonStyle(.plain)
            .disabled(!entry.isDirectory)
            .overlay(alignment: .bottom) {
                Divider().background(Theme.hair2)
            }
        }
    }

    private func iconForFile(_ entry: FileEntry) -> String {
        if entry.isDeleted { return "trash" }
        switch entry.name.lowercased() {
        case let n where n.hasSuffix(".evtx"): return "doc.text"
        case let n where n.hasSuffix(".dat"):  return "doc"
        case let n where n.hasSuffix(".exe"):  return "doc.badge.gearshape"
        default:                                return "doc"
        }
    }

    private func iconColor(_ entry: FileEntry) -> Color {
        if entry.isDeleted { return Theme.crit }
        if entry.isDirectory { return Color(red: 0x7C/255, green: 0xB8/255, blue: 0xEC/255) }
        switch entry.name.lowercased() {
        case let n where n.hasSuffix(".docm") || n.hasSuffix(".doc"): return Theme.amber
        default: return Theme.text3
        }
    }

    private func human(_ n: Int) -> String {
        let f = NumberFormatter(); f.numberStyle = .decimal
        return f.string(from: NSNumber(value: n)) ?? "\(n)"
    }
}

// MARK: - Lateral Movement drill view

/// Read-only summary of the LateralGraph. The macOS canvas is too dense to
/// port verbatim onto a phone; instead we show node tags + a hops list,
/// which gives the same forensic information in a thumb-scrollable form.
struct LateralDrillView: View {
    @EnvironmentObject private var model: AppModel

    private var graph: LateralGraph { LateralGraph.build(from: model.events) }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 0) {
                LargeTitle(
                    title: "Lateral Movement",
                    subtitle: subtitle)

                if graph.edges.isEmpty {
                    ContentUnavailableView(
                        "No lateral logons",
                        systemImage: "point.3.connected.trianglepath.dotted",
                        description: Text("No 4624/4625 events with remote logon types were observed."))
                        .padding(.top, 60)
                        .frame(maxWidth: .infinity)
                } else {
                    legend.padding(.horizontal, 16).padding(.top, 4)
                    SectionHeader(label: "Hops").padding(.top, 14)
                    Card { hopRows }
                    SectionHeader(label: "Hosts").padding(.top, 14)
                    Card { hostRows }
                }

                Spacer(minLength: 26)
            }
        }
        .background(Theme.bg.ignoresSafeArea())
        .navigationBarTitleDisplayMode(.inline)
        .toolbarBackground(Theme.bg, for: .navigationBar)
        .toolbarBackground(.visible, for: .navigationBar)
    }

    private var subtitle: String {
        "\(graph.nodes.count) hosts · \(graph.edges.count) edges"
    }

    private var legend: some View {
        HStack(spacing: 14) {
            HStack(spacing: 5) { SeverityDot(color: Theme.amber); Text("Known host") }
            HStack(spacing: 5) { SeverityDot(color: Theme.text3); Text("External source") }
            Spacer()
        }
        .font(.system(size: 11.5))
        .foregroundStyle(Theme.text2)
    }

    @ViewBuilder private var hopRows: some View {
        ForEach(graph.edges.sorted(by: { $0.firstSeen < $1.firstSeen }), id: \.id) { edge in
            HStack(spacing: 11) {
                Text(Self.timeFmt.string(from: edge.firstSeen))
                    .font(.system(size: 11, design: .monospaced))
                    .foregroundStyle(Theme.text3)
                    .frame(width: 60, alignment: .leading)
                VStack(alignment: .leading, spacing: 1) {
                    HStack(spacing: 4) {
                        Text(edge.source).font(.system(size: 12.5, design: .monospaced))
                        Text("→").foregroundStyle(Theme.text3)
                        Text(edge.target).font(.system(size: 12.5, weight: .semibold, design: .monospaced))
                    }
                    .foregroundStyle(Theme.text)
                    Text(hopSubtitle(edge))
                        .font(.system(size: 11))
                        .foregroundStyle(Theme.text3)
                }
                Spacer()
                if edge.failureCount > 0 {
                    SeverityDot(color: Theme.high)
                } else {
                    SeverityDot(color: Theme.teal)
                }
            }
            .padding(.horizontal, 14)
            .padding(.vertical, 11)
            .overlay(alignment: .bottom) { Divider().background(Theme.hair2) }
        }
    }

    private func hopSubtitle(_ edge: LateralGraph.Edge) -> String {
        var parts: [String] = []
        if !edge.users.isEmpty {
            parts.append(edge.users.sorted().joined(separator: ", "))
        }
        if !edge.logonTypes.isEmpty {
            let types = edge.logonTypes.sorted().map(String.init).joined(separator: "/")
            parts.append("LT \(types)")
        }
        if edge.count > 0 {
            parts.append("\(edge.count) success\(edge.count == 1 ? "" : "es")")
        }
        if edge.failureCount > 0 {
            parts.append("\(edge.failureCount) fail\(edge.failureCount == 1 ? "" : "s")")
        }
        return parts.joined(separator: " · ")
    }

    @ViewBuilder private var hostRows: some View {
        ForEach(graph.nodes.sorted(by: { $0.degree > $1.degree }), id: \.id) { node in
            HStack(spacing: 12) {
                SeverityDot(color: node.kind == .knownHost ? Theme.amber : Theme.text3)
                Text(node.id)
                    .font(.system(size: 13, design: .monospaced))
                    .foregroundStyle(Theme.text)
                Spacer()
                Text("\(node.degree) edge\(node.degree == 1 ? "" : "s")")
                    .font(.system(size: 12))
                    .foregroundStyle(Theme.text3)
            }
            .padding(.horizontal, 14)
            .padding(.vertical, 11)
            .overlay(alignment: .bottom) { Divider().background(Theme.hair2) }
        }
    }

    private static let timeFmt: DateFormatter = {
        let f = DateFormatter()
        f.dateFormat = "HH:mm:ss"
        f.locale = Locale(identifier: "en_US_POSIX")
        return f
    }()
}

// MARK: - IOCs drill view

/// Read-only IOC list. iOS doesn't paste-import new IOCs yet (that happens
/// in the ingest-side workflow), so this surface is only for review and
/// quick copy.
struct IOCsDrillView: View {
    @EnvironmentObject private var model: AppModel

    private var grouped: [(IOCKind, [IOC])] {
        let dict = Dictionary(grouping: model.iocs, by: \.kind)
        return IOCKind.allCases.compactMap { kind in
            guard let list = dict[kind], !list.isEmpty else { return nil }
            return (kind, list)
        }
    }

    private var matchesByValue: [String: [IOCMatch]] {
        Dictionary(grouping: model.iocMatches, by: { $0.iocValue.lowercased() })
    }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 0) {
                LargeTitle(
                    title: "Indicators",
                    subtitle: "\(model.iocs.count) indicators · \(grouped.count) types")

                if model.iocs.isEmpty {
                    ContentUnavailableView(
                        "No IOCs",
                        systemImage: "scope",
                        description: Text("Load IOCs on the macOS app to see them surfaced here."))
                        .padding(.top, 60)
                        .frame(maxWidth: .infinity)
                } else {
                    ForEach(grouped, id: \.0) { (kind, list) in
                        SectionHeader(label: sectionLabel(kind)).padding(.top, 14)
                        Card {
                            ForEach(list) { ioc in
                                iocRow(ioc)
                            }
                        }
                    }
                }

                Spacer(minLength: 26)
            }
        }
        .background(Theme.bg.ignoresSafeArea())
        .navigationBarTitleDisplayMode(.inline)
        .toolbarBackground(Theme.bg, for: .navigationBar)
        .toolbarBackground(.visible, for: .navigationBar)
    }

    private func sectionLabel(_ kind: IOCKind) -> String {
        switch kind {
        case .ip:     return "IP addresses"
        case .domain: return "Domains"
        case .url:    return "URLs"
        case .hash:   return "Hashes"
        }
    }

    private func iocRow(_ ioc: IOC) -> some View {
        let matches = matchesByValue[ioc.value.lowercased()] ?? []
        let severity: Color = matches.isEmpty ? Theme.info : Theme.crit
        return HStack(spacing: 11) {
            SeverityDot(color: severity)
            VStack(alignment: .leading, spacing: 2) {
                Text(ioc.value)
                    .font(.system(size: 12.5, design: .monospaced))
                    .foregroundStyle(Theme.text)
                    .lineLimit(1)
                    .truncationMode(.middle)
                Text(tag(ioc, matches: matches))
                    .font(.system(size: 11))
                    .foregroundStyle(Theme.text2)
            }
            Spacer()
            Button {
                UIPasteboard.general.string = ioc.value
            } label: {
                Image(systemName: "doc.on.doc")
                    .font(.system(size: 14))
                    .foregroundStyle(Theme.text3.opacity(0.7))
            }
            .buttonStyle(.plain)
        }
        .padding(.horizontal, 14)
        .padding(.vertical, 12)
        .overlay(alignment: .bottom) { Divider().background(Theme.hair2) }
    }

    private func tag(_ ioc: IOC, matches: [IOCMatch]) -> String {
        var parts: [String] = []
        if !ioc.note.isEmpty { parts.append(ioc.note) }
        if !matches.isEmpty {
            parts.append("\(matches.count) match\(matches.count == 1 ? "" : "es")")
        } else {
            parts.append("no matches")
        }
        return parts.joined(separator: " · ")
    }
}
#endif
