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
    @State private var displayLimit = 200
    private let pageSize = 200

    /// Delegate to the shared, unit-tested normalizer. TSK parentPaths carry a
    /// trailing slash and KAPE's don't, so both sides must be normalized or
    /// image-backed cases show every subfolder as empty.
    private func normalized(_ p: String) -> String { FileEntry.normalizeDirPath(p) }

    private var children: [FileEntry] {
        let here = normalized(path)
        return model.files
            .filter { normalized($0.parentPath) == here }
            .sorted { lhs, rhs in
                if lhs.isDirectory != rhs.isDirectory { return lhs.isDirectory }
                return lhs.name.localizedCaseInsensitiveCompare(rhs.name) == .orderedAscending
            }
    }

    var body: some View {
        let kids = children
        return ScrollView {
            VStack(alignment: .leading, spacing: 0) {
                LargeTitle(title: "Filesystem")

                breadcrumb

                note

                if kids.isEmpty {
                    emptyState
                } else {
                    Card { rows(kids) }.padding(.top, 10)
                }

                Spacer(minLength: 26)
            }
        }
        .background(Theme.bg.ignoresSafeArea())
        .navigationBarTitleDisplayMode(.inline)
        .toolbarBackground(Theme.bg, for: .navigationBar)
        .toolbarBackground(.visible, for: .navigationBar)
        .onChange(of: path) { displayLimit = pageSize }   // restart paging on navigate
    }

    /// Tappable breadcrumb so the analyst can jump back up the tree (the system
    /// back button only exits the whole screen, since navigation mutates `path`
    /// rather than pushing a NavigationStack).
    private var breadcrumb: some View {
        let crumbs = path.split(separator: "/").map(String.init)
        return HStack(spacing: 5) {
            Button { path = "" } label: {
                Text("C:\\")
                    .font(.system(size: 12.5, design: .monospaced))
                    .foregroundStyle(Theme.text2)
            }
            .buttonStyle(.plain)
            ForEach(Array(crumbs.enumerated()), id: \.offset) { idx, name in
                Text("›").foregroundStyle(Theme.text3)
                Button {
                    path = "/" + crumbs[0...idx].joined(separator: "/")
                } label: {
                    Text(name)
                        .font(.system(size: 12.5, weight: idx == crumbs.count - 1 ? .semibold : .regular,
                                      design: .monospaced))
                        .foregroundStyle(idx == crumbs.count - 1 ? Theme.text : Theme.text2)
                }
                .buttonStyle(.plain)
            }
        }
        .padding(.horizontal, 22)
        .padding(.top, 4)
    }

    private var note: some View {
        let files = model.files
        let total = files.count
        let deleted = files.lazy.filter(\.isDeleted).count
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

    @ViewBuilder private func rows(_ kids: [FileEntry]) -> some View {
        // Cap rendered rows: a Windows folder (System32 / WinSxS) can hold tens
        // of thousands of entries, which would spike memory on a phone.
        ForEach(kids.prefix(displayLimit)) { entry in
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
        if kids.count > displayLimit {
            Button { displayLimit += pageSize } label: {
                Text("Show \(min(pageSize, kids.count - displayLimit)) more · \(human(kids.count - displayLimit)) hidden")
                    .font(.system(size: 12.5, weight: .semibold))
                    .foregroundStyle(Theme.teal)
                    .frame(maxWidth: .infinity)
                    .padding(.vertical, 13)
            }
            .buttonStyle(.plain)
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

    private var graph: LateralGraph { model.lateralGraph }   // cached on AppModel

    var body: some View {
        // Build + sort once per render (graph was rebuilt 4x, each re-sorting
        // the event set and recompiling regexes).
        let graph = self.graph
        let edges = graph.edges.sorted { $0.firstSeen < $1.firstSeen }
        let nodes = graph.nodes.sorted { $0.degree > $1.degree }
        return ScrollView {
            VStack(alignment: .leading, spacing: 0) {
                LargeTitle(
                    title: "Lateral Movement",
                    subtitle: "\(graph.nodes.count) hosts · \(graph.edges.count) edges")

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
                    Card { hopRows(edges) }
                    SectionHeader(label: "Hosts").padding(.top, 14)
                    Card { hostRows(nodes) }
                }

                Spacer(minLength: 26)
            }
        }
        .background(Theme.bg.ignoresSafeArea())
        .navigationBarTitleDisplayMode(.inline)
        .toolbarBackground(Theme.bg, for: .navigationBar)
        .toolbarBackground(.visible, for: .navigationBar)
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

    @ViewBuilder private func hopRows(_ edges: [LateralGraph.Edge]) -> some View {
        ForEach(edges, id: \.id) { edge in
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

    @ViewBuilder private func hostRows(_ nodes: [LateralGraph.Node]) -> some View {
        ForEach(nodes, id: \.id) { node in
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
        f.timeZone = TimeZone(identifier: "UTC")   // forensic timestamps are UTC
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
                    .frame(width: 44, height: 44)        // 44pt minimum hit target
                    .contentShape(Rectangle())
            }
            .buttonStyle(.plain)
            .accessibilityLabel("Copy \(ioc.value)")
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

// MARK: - Registry drill view

/// Tap-through registry browser over the same `RegistryValue` set the macOS
/// explorer uses. Navigation mutates a `path` component stack (hive first),
/// with a tappable breadcrumb to climb back up — mirroring FilesystemDrillView.
/// Each level shows the current key's subkeys (tap to descend) and its values.
struct RegistryDrillView: View {
    @EnvironmentObject private var model: AppModel
    /// Key tree, rebuilt off the render path when the data/scope changes.
    @State private var tree: [RegistryNode] = []
    /// Component stack into the tree; [] == the hive list (root).
    @State private var path: [String] = []
    @State private var displayLimit = 200
    private let pageSize = 200

    /// Resolve the current `path` to its node and the child keys at this level.
    /// A broken path (data changed under us) falls back to the deepest level
    /// still reachable so the view never goes blank.
    private func locate() -> (node: RegistryNode?, children: [RegistryNode]) {
        var level = tree
        var current: RegistryNode?
        for comp in path {
            guard let match = level.first(where: { $0.name == comp }) else {
                return (current, level)
            }
            current = match
            level = match.children ?? []
        }
        return (current, level)
    }

    var body: some View {
        let (node, children) = locate()
        let values = node?.values ?? []
        return ScrollView {
            VStack(alignment: .leading, spacing: 0) {
                LargeTitle(title: "Registry")

                breadcrumb

                note(node: node)

                if children.isEmpty && values.isEmpty {
                    emptyState
                } else {
                    if !children.isEmpty {
                        SectionHeader(label: path.isEmpty ? "Hives" : "Subkeys").padding(.top, 12)
                        Card { keyRows(children) }
                    }
                    if !values.isEmpty {
                        SectionHeader(label: "Values").padding(.top, 16)
                        Card { valueRows(values) }
                    }
                }

                Spacer(minLength: 26)
            }
        }
        .background(Theme.bg.ignoresSafeArea())
        .navigationBarTitleDisplayMode(.inline)
        .toolbarBackground(Theme.bg, for: .navigationBar)
        .toolbarBackground(.visible, for: .navigationBar)
        // Build the tree off the render path (HostProfile-style): the value set
        // can be tens of thousands of rows, so don't rebuild inside body.
        .task(id: model.dataVersion) {
            tree = RegistryNode.buildTree(from: model.registryValues)
        }
        .onChange(of: path) { displayLimit = pageSize }   // restart paging on navigate
    }

    /// Tappable breadcrumb (registry paths run long, so it scrolls horizontally).
    /// The system back button exits the whole screen since navigation mutates
    /// `path` rather than pushing a NavigationStack.
    private var breadcrumb: some View {
        ScrollView(.horizontal, showsIndicators: false) {
            HStack(spacing: 5) {
                Button { path = [] } label: {
                    Text("Registry")
                        .font(.system(size: 12.5, design: .monospaced))
                        .foregroundStyle(Theme.text2)
                }
                .buttonStyle(.plain)
                ForEach(Array(path.enumerated()), id: \.offset) { idx, name in
                    Text("›").foregroundStyle(Theme.text3)
                    Button {
                        path = Array(path[0...idx])
                    } label: {
                        Text(name)
                            .font(.system(size: 12.5, weight: idx == path.count - 1 ? .semibold : .regular,
                                          design: .monospaced))
                            .foregroundStyle(idx == path.count - 1 ? Theme.text : Theme.text2)
                    }
                    .buttonStyle(.plain)
                }
            }
            .padding(.horizontal, 22)
            .padding(.top, 4)
        }
    }

    private func note(node: RegistryNode?) -> some View {
        var parts = ["\(human(model.registryValueCount)) values"]
        if let lw = node?.lastWritten {
            parts.append("written \(Self.dateFmt.string(from: lw))")
        }
        return Text(parts.joined(separator: " · "))
            .font(.system(size: 12))
            .foregroundStyle(Theme.text3)
            .padding(.horizontal, 22)
            .padding(.top, 10)
    }

    private var emptyState: some View {
        ContentUnavailableView(
            "No registry data",
            systemImage: "list.bullet.indent",
            description: Text("Parse the registry hives on the macOS app to browse them here."))
            .padding(.top, 60)
            .frame(maxWidth: .infinity)
    }

    @ViewBuilder private func keyRows(_ kids: [RegistryNode]) -> some View {
        // Cap rendered rows: SOFTWARE\Classes can hold tens of thousands of
        // subkeys, which would spike memory on a phone.
        ForEach(kids.prefix(displayLimit)) { node in
            Button { path.append(node.name) } label: {
                HStack(spacing: 12) {
                    Image(systemName: node.isHive ? "externaldrive" : "folder")
                        .font(.system(size: 17))
                        .frame(width: 24)
                        .foregroundStyle(node.isHive
                            ? Theme.teal2
                            : Color(red: 0x7C/255, green: 0xB8/255, blue: 0xEC/255))
                    Text(node.name)
                        .font(.system(size: 14))
                        .foregroundStyle(Theme.text)
                        .lineLimit(1).truncationMode(.middle)
                    Spacer()
                    if !node.values.isEmpty {
                        Text("\(node.values.count)")
                            .font(.system(size: 11.5, design: .monospaced))
                            .foregroundStyle(Theme.text3)
                    }
                    Image(systemName: "chevron.right")
                        .font(.system(size: 11, weight: .semibold))
                        .foregroundStyle(Theme.text3.opacity(0.7))
                }
                .padding(.horizontal, 15).padding(.vertical, 12)
                .contentShape(Rectangle())
            }
            .buttonStyle(.plain)
            .overlay(alignment: .bottom) { Divider().background(Theme.hair2) }
        }
        if kids.count > displayLimit {
            Button { displayLimit += pageSize } label: {
                Text("Show \(min(pageSize, kids.count - displayLimit)) more · \(human(kids.count - displayLimit)) hidden")
                    .font(.system(size: 12.5, weight: .semibold))
                    .foregroundStyle(Theme.teal)
                    .frame(maxWidth: .infinity).padding(.vertical, 13)
            }
            .buttonStyle(.plain)
        }
    }

    @ViewBuilder private func valueRows(_ values: [RegistryValue]) -> some View {
        ForEach(values) { value in
            VStack(alignment: .leading, spacing: 5) {
                HStack(spacing: 8) {
                    Text(value.name.isEmpty ? "(default)" : value.name)
                        .font(.system(size: 13.5, weight: .medium))
                        .foregroundStyle(value.name.isEmpty ? Theme.text2 : Theme.text)
                        .lineLimit(1).truncationMode(.middle)
                    Pill(text: value.typeBadge, foreground: Theme.text2)
                    Spacer(minLength: 0)
                }
                Text(value.decodedData.isEmpty ? "(empty)" : value.decodedData)
                    .font(.system(size: 12, design: .monospaced))
                    .foregroundStyle(value.decodedData.isEmpty ? Theme.text3 : Theme.text2)
                    .lineLimit(4).truncationMode(.tail)
                    .textSelection(.enabled)
                    .frame(maxWidth: .infinity, alignment: .leading)
            }
            .padding(.horizontal, 15).padding(.vertical, 11)
            .overlay(alignment: .bottom) { Divider().background(Theme.hair2) }
        }
    }

    private func human(_ n: Int) -> String {
        let f = NumberFormatter(); f.numberStyle = .decimal
        return f.string(from: NSNumber(value: n)) ?? "\(n)"
    }

    private static let dateFmt: DateFormatter = {
        let f = DateFormatter()
        f.dateFormat = "yyyy-MM-dd HH:mm:ss"
        f.locale = Locale(identifier: "en_US_POSIX")
        f.timeZone = TimeZone(identifier: "UTC")   // forensic timestamps are UTC
        return f
    }()
}

// MARK: - Prefetch drill view

/// Read-only list of parsed prefetch for the active scope - one row per
/// executable, newest run first. Mirrors the macOS PrefetchView's table in a
/// thumb-scrollable form; paged because a busy host can carry thousands of .pf.
struct PrefetchDrillView: View {
    @EnvironmentObject private var model: AppModel
    @State private var displayLimit = 200
    private let pageSize = 200

    var body: some View {
        let entries = model.prefetch
        return ScrollView {
            VStack(alignment: .leading, spacing: 0) {
                LargeTitle(title: "Prefetch",
                           subtitle: "\(human(entries.count)) executable\(entries.count == 1 ? "" : "s")")

                if entries.isEmpty {
                    ContentUnavailableView(
                        "No prefetch",
                        systemImage: "bolt.badge.clock",
                        description: Text("Parse prefetch on the macOS app to browse it here."))
                        .padding(.top, 60)
                        .frame(maxWidth: .infinity)
                } else {
                    Card { rows(entries) }.padding(.top, 10)
                }

                Spacer(minLength: 26)
            }
        }
        .background(Theme.bg.ignoresSafeArea())
        .navigationBarTitleDisplayMode(.inline)
        .toolbarBackground(Theme.bg, for: .navigationBar)
        .toolbarBackground(.visible, for: .navigationBar)
    }

    @ViewBuilder private func rows(_ entries: [PrefetchEntry]) -> some View {
        ForEach(entries.prefix(displayLimit)) { entry in
            VStack(alignment: .leading, spacing: 3) {
                HStack(spacing: 11) {
                    Image(systemName: "bolt.badge.clock")
                        .font(.system(size: 16))
                        .frame(width: 22)
                        .foregroundStyle(Theme.teal2)
                    Text(entry.executableName)
                        .font(.system(size: 13.5, weight: .medium, design: .monospaced))
                        .foregroundStyle(Theme.text)
                        .lineLimit(1).truncationMode(.middle)
                    Spacer()
                    Text("\(entry.runCount)×")
                        .font(.system(size: 12, design: .monospaced))
                        .foregroundStyle(Theme.text3)
                }
                Text(subtitle(entry))
                    .font(.system(size: 11))
                    .foregroundStyle(Theme.text3)
                    .lineLimit(1).truncationMode(.middle)
                    .padding(.leading, 33)
            }
            .padding(.horizontal, 15).padding(.vertical, 11)
            .overlay(alignment: .bottom) { Divider().background(Theme.hair2) }
        }
        if entries.count > displayLimit {
            Button { displayLimit += pageSize } label: {
                Text("Show \(min(pageSize, entries.count - displayLimit)) more · \(human(entries.count - displayLimit)) hidden")
                    .font(.system(size: 12.5, weight: .semibold))
                    .foregroundStyle(Theme.teal)
                    .frame(maxWidth: .infinity).padding(.vertical, 13)
            }
            .buttonStyle(.plain)
        }
    }

    private func subtitle(_ entry: PrefetchEntry) -> String {
        let last = entry.lastRun.map { "last run \(Self.dateFmt.string(from: $0))" } ?? "no run time"
        if let path = entry.executablePath { return "\(last) · \(path)" }
        return last
    }

    private func human(_ n: Int) -> String {
        let f = NumberFormatter(); f.numberStyle = .decimal
        return f.string(from: NSNumber(value: n)) ?? "\(n)"
    }

    private static let dateFmt: DateFormatter = {
        let f = DateFormatter()
        f.dateFormat = "yyyy-MM-dd HH:mm:ss"
        f.locale = Locale(identifier: "en_US_POSIX")
        f.timeZone = TimeZone(identifier: "UTC")   // forensic timestamps are UTC
        return f
    }()
}

// MARK: - Amcache drill view

/// Read-only Amcache program-presence list for the active scope, newest
/// registration first. Each row is a binary Amcache knows about, with its
/// recovered SHA-1. Proves presence, not execution. Paged for busy hosts.
struct AmcacheDrillView: View {
    @EnvironmentObject private var model: AppModel
    @State private var displayLimit = 200
    private let pageSize = 200

    var body: some View {
        let entries = model.amcache
        return ScrollView {
            VStack(alignment: .leading, spacing: 0) {
                LargeTitle(title: "Amcache",
                           subtitle: "\(human(entries.count)) program\(entries.count == 1 ? "" : "s")")

                if entries.isEmpty {
                    ContentUnavailableView(
                        "No Amcache",
                        systemImage: "shippingbox.and.arrow.backward",
                        description: Text("Parse the registry on the macOS app to reconstruct Amcache here."))
                        .padding(.top, 60)
                        .frame(maxWidth: .infinity)
                } else {
                    Card { rows(entries) }.padding(.top, 10)
                }

                Spacer(minLength: 26)
            }
        }
        .background(Theme.bg.ignoresSafeArea())
        .navigationBarTitleDisplayMode(.inline)
        .toolbarBackground(Theme.bg, for: .navigationBar)
        .toolbarBackground(.visible, for: .navigationBar)
    }

    @ViewBuilder private func rows(_ entries: [AmcacheEntry]) -> some View {
        ForEach(entries.prefix(displayLimit)) { entry in
            VStack(alignment: .leading, spacing: 3) {
                HStack(spacing: 11) {
                    Image(systemName: "shippingbox.and.arrow.backward")
                        .font(.system(size: 16)).frame(width: 22).foregroundStyle(Theme.teal2)
                    Text(entry.name)
                        .font(.system(size: 13.5, weight: .medium, design: .monospaced))
                        .foregroundStyle(Theme.text).lineLimit(1).truncationMode(.middle)
                    Spacer()
                    if let registered = entry.registeredAt {
                        Text(Self.dateFmt.string(from: registered))
                            .font(.system(size: 11, design: .monospaced)).foregroundStyle(Theme.text3)
                    }
                }
                Text(subtitle(entry))
                    .font(.system(size: 11, design: .monospaced))
                    .foregroundStyle(Theme.text3).lineLimit(1).truncationMode(.middle)
                    .padding(.leading, 33)
            }
            .padding(.horizontal, 15).padding(.vertical, 11)
            .overlay(alignment: .bottom) { Divider().background(Theme.hair2) }
        }
        if entries.count > displayLimit {
            Button { displayLimit += pageSize } label: {
                Text("Show \(min(pageSize, entries.count - displayLimit)) more · \(human(entries.count - displayLimit)) hidden")
                    .font(.system(size: 12.5, weight: .semibold))
                    .foregroundStyle(Theme.teal)
                    .frame(maxWidth: .infinity).padding(.vertical, 13)
            }
            .buttonStyle(.plain)
        }
    }

    private func subtitle(_ entry: AmcacheEntry) -> String {
        entry.sha1 ?? entry.fullPath ?? "no hash"
    }

    private func human(_ n: Int) -> String {
        let f = NumberFormatter(); f.numberStyle = .decimal
        return f.string(from: NSNumber(value: n)) ?? "\(n)"
    }

    private static let dateFmt: DateFormatter = {
        let f = DateFormatter()
        f.dateFormat = "yyyy-MM-dd HH:mm:ss"
        f.locale = Locale(identifier: "en_US_POSIX")
        f.timeZone = TimeZone(identifier: "UTC")   // forensic timestamps are UTC
        return f
    }()
}

// MARK: - Shimcache drill view

/// Read-only AppCompatCache list for the active scope, in cache order. Proves
/// presence, not execution. Paged for busy hosts.
struct ShimcacheDrillView: View {
    @EnvironmentObject private var model: AppModel
    @State private var displayLimit = 200
    private let pageSize = 200

    var body: some View {
        let entries = model.shimcache
        return ScrollView {
            VStack(alignment: .leading, spacing: 0) {
                LargeTitle(title: "Shimcache",
                           subtitle: "\(human(entries.count)) path\(entries.count == 1 ? "" : "s") · presence, not execution")

                if entries.isEmpty {
                    ContentUnavailableView(
                        "No Shimcache",
                        systemImage: "clock.arrow.circlepath",
                        description: Text("Parse the registry on the macOS app to decode AppCompatCache here."))
                        .padding(.top, 60)
                        .frame(maxWidth: .infinity)
                } else {
                    Card { rows(entries) }.padding(.top, 10)
                }

                Spacer(minLength: 26)
            }
        }
        .background(Theme.bg.ignoresSafeArea())
        .navigationBarTitleDisplayMode(.inline)
        .toolbarBackground(Theme.bg, for: .navigationBar)
        .toolbarBackground(.visible, for: .navigationBar)
    }

    @ViewBuilder private func rows(_ entries: [ShimcacheEntry]) -> some View {
        ForEach(entries.prefix(displayLimit)) { entry in
            VStack(alignment: .leading, spacing: 3) {
                HStack(spacing: 11) {
                    Image(systemName: "clock.arrow.circlepath")
                        .font(.system(size: 16)).frame(width: 22).foregroundStyle(Theme.teal2)
                    Text(entry.name)
                        .font(.system(size: 13.5, weight: .medium, design: .monospaced))
                        .foregroundStyle(Theme.text).lineLimit(1).truncationMode(.middle)
                    Spacer()
                    if let modified = entry.lastModified {
                        Text(Self.dateFmt.string(from: modified))
                            .font(.system(size: 11, design: .monospaced)).foregroundStyle(Theme.text3)
                    }
                }
                Text(entry.path)
                    .font(.system(size: 11, design: .monospaced))
                    .foregroundStyle(Theme.text3).lineLimit(1).truncationMode(.middle)
                    .padding(.leading, 33)
            }
            .padding(.horizontal, 15).padding(.vertical, 11)
            .overlay(alignment: .bottom) { Divider().background(Theme.hair2) }
        }
        if entries.count > displayLimit {
            Button { displayLimit += pageSize } label: {
                Text("Show \(min(pageSize, entries.count - displayLimit)) more · \(human(entries.count - displayLimit)) hidden")
                    .font(.system(size: 12.5, weight: .semibold))
                    .foregroundStyle(Theme.teal)
                    .frame(maxWidth: .infinity).padding(.vertical, 13)
            }
            .buttonStyle(.plain)
        }
    }

    private func human(_ n: Int) -> String {
        let f = NumberFormatter(); f.numberStyle = .decimal
        return f.string(from: NSNumber(value: n)) ?? "\(n)"
    }

    private static let dateFmt: DateFormatter = {
        let f = DateFormatter()
        f.dateFormat = "yyyy-MM-dd HH:mm:ss"
        f.locale = Locale(identifier: "en_US_POSIX")
        f.timeZone = TimeZone(identifier: "UTC")   // forensic timestamps are UTC
        return f
    }()
}

// MARK: - Shortcut (LNK) drill view

/// Read-only shortcut list for the active scope. Surfaces the target and any
/// embedded command-line arguments (the malicious-LNK tell). Paged.
struct LnkDrillView: View {
    @EnvironmentObject private var model: AppModel
    @State private var displayLimit = 200
    private let pageSize = 200

    var body: some View {
        let entries = model.lnk
        return ScrollView {
            VStack(alignment: .leading, spacing: 0) {
                LargeTitle(title: "Shortcuts",
                           subtitle: "\(human(entries.count)) .lnk file\(entries.count == 1 ? "" : "s")")

                if entries.isEmpty {
                    ContentUnavailableView(
                        "No shortcuts",
                        systemImage: "arrowshape.turn.up.right",
                        description: Text("Parse shortcuts on the macOS app to browse them here."))
                        .padding(.top, 60)
                        .frame(maxWidth: .infinity)
                } else {
                    Card { rows(entries) }.padding(.top, 10)
                }

                Spacer(minLength: 26)
            }
        }
        .background(Theme.bg.ignoresSafeArea())
        .navigationBarTitleDisplayMode(.inline)
        .toolbarBackground(Theme.bg, for: .navigationBar)
        .toolbarBackground(.visible, for: .navigationBar)
    }

    @ViewBuilder private func rows(_ entries: [LnkEntry]) -> some View {
        ForEach(entries.prefix(displayLimit)) { entry in
            VStack(alignment: .leading, spacing: 3) {
                HStack(spacing: 11) {
                    Image(systemName: entry.arguments == nil ? "arrowshape.turn.up.right" : "exclamationmark.triangle")
                        .font(.system(size: 16)).frame(width: 22)
                        .foregroundStyle(entry.arguments == nil ? Theme.teal2 : Theme.amber)
                    Text(entry.name)
                        .font(.system(size: 13.5, weight: .medium))
                        .foregroundStyle(Theme.text).lineLimit(1).truncationMode(.middle)
                    Spacer()
                    if let modified = entry.targetModified {
                        Text(Self.dateFmt.string(from: modified))
                            .font(.system(size: 11, design: .monospaced)).foregroundStyle(Theme.text3)
                    }
                }
                Text(subtitle(entry))
                    .font(.system(size: 11, design: .monospaced))
                    .foregroundStyle(Theme.text3).lineLimit(1).truncationMode(.middle)
                    .padding(.leading, 33)
            }
            .padding(.horizontal, 15).padding(.vertical, 11)
            .overlay(alignment: .bottom) { Divider().background(Theme.hair2) }
        }
        if entries.count > displayLimit {
            Button { displayLimit += pageSize } label: {
                Text("Show \(min(pageSize, entries.count - displayLimit)) more · \(human(entries.count - displayLimit)) hidden")
                    .font(.system(size: 12.5, weight: .semibold))
                    .foregroundStyle(Theme.teal)
                    .frame(maxWidth: .infinity).padding(.vertical, 13)
            }
            .buttonStyle(.plain)
        }
    }

    private func subtitle(_ entry: LnkEntry) -> String {
        if let args = entry.arguments { return "args: \(args)" }
        return entry.targetPath ?? "(no target)"
    }

    private func human(_ n: Int) -> String {
        let f = NumberFormatter(); f.numberStyle = .decimal
        return f.string(from: NSNumber(value: n)) ?? "\(n)"
    }

    private static let dateFmt: DateFormatter = {
        let f = DateFormatter()
        f.dateFormat = "yyyy-MM-dd HH:mm:ss"
        f.locale = Locale(identifier: "en_US_POSIX")
        f.timeZone = TimeZone(identifier: "UTC")   // forensic timestamps are UTC
        return f
    }()
}

// MARK: - JumpList drill view

/// Read-only JumpList destinations for the active scope, newest access first.
/// Each row is a recent/pinned item from an application's jumplist (target +
/// DestList last-access time). Paged.
struct JumpListDrillView: View {
    @EnvironmentObject private var model: AppModel
    @State private var displayLimit = 200
    private let pageSize = 200

    var body: some View {
        let entries = model.jumpList
        return ScrollView {
            VStack(alignment: .leading, spacing: 0) {
                LargeTitle(title: "JumpLists",
                           subtitle: "\(human(entries.count)) destination\(entries.count == 1 ? "" : "s")")

                if entries.isEmpty {
                    ContentUnavailableView(
                        "No JumpLists",
                        systemImage: "list.star",
                        description: Text("Parse JumpLists on the macOS app to browse them here."))
                        .padding(.top, 60)
                        .frame(maxWidth: .infinity)
                } else {
                    Card { rows(entries) }.padding(.top, 10)
                }

                Spacer(minLength: 26)
            }
        }
        .background(Theme.bg.ignoresSafeArea())
        .navigationBarTitleDisplayMode(.inline)
        .toolbarBackground(Theme.bg, for: .navigationBar)
        .toolbarBackground(.visible, for: .navigationBar)
    }

    @ViewBuilder private func rows(_ entries: [JumpListEntry]) -> some View {
        ForEach(entries.prefix(displayLimit)) { entry in
            VStack(alignment: .leading, spacing: 3) {
                HStack(spacing: 11) {
                    Image(systemName: entry.appID.caseInsensitiveCompare(JumpListAppID.remoteDesktop) == .orderedSame
                          ? "display" : "list.star")
                        .font(.system(size: 16)).frame(width: 22).foregroundStyle(Theme.teal2)
                    Text(entry.name)
                        .font(.system(size: 13.5, weight: .medium, design: .monospaced))
                        .foregroundStyle(Theme.text).lineLimit(1).truncationMode(.middle)
                    Spacer()
                    if let last = entry.lastAccessed {
                        Text(Self.dateFmt.string(from: last))
                            .font(.system(size: 11, design: .monospaced)).foregroundStyle(Theme.text3)
                    }
                }
                Text(subtitle(entry))
                    .font(.system(size: 11, design: .monospaced))
                    .foregroundStyle(Theme.text3).lineLimit(1).truncationMode(.middle)
                    .padding(.leading, 33)
            }
            .padding(.horizontal, 15).padding(.vertical, 11)
            .overlay(alignment: .bottom) { Divider().background(Theme.hair2) }
        }
        if entries.count > displayLimit {
            Button { displayLimit += pageSize } label: {
                Text("Show \(min(pageSize, entries.count - displayLimit)) more · \(human(entries.count - displayLimit)) hidden")
                    .font(.system(size: 12.5, weight: .semibold))
                    .foregroundStyle(Theme.teal)
                    .frame(maxWidth: .infinity).padding(.vertical, 13)
            }
            .buttonStyle(.plain)
        }
    }

    private func subtitle(_ entry: JumpListEntry) -> String {
        let app = entry.application ?? entry.appID
        return "\(app) · \(entry.targetPath ?? "—")"
    }

    private func human(_ n: Int) -> String {
        let f = NumberFormatter(); f.numberStyle = .decimal
        return f.string(from: NSNumber(value: n)) ?? "\(n)"
    }

    private static let dateFmt: DateFormatter = {
        let f = DateFormatter()
        f.dateFormat = "yyyy-MM-dd HH:mm:ss"
        f.locale = Locale(identifier: "en_US_POSIX")
        f.timeZone = TimeZone(identifier: "UTC")   // forensic timestamps are UTC
        return f
    }()
}

// MARK: - USN journal drill view

/// Read-only USN change-journal list for the active scope. Colour-codes the
/// high-signal change classes (create / delete / rename) and recovers names of
/// files the live filesystem no longer shows. Paged.
struct UsnDrillView: View {
    @EnvironmentObject private var model: AppModel
    @State private var displayLimit = 200
    private let pageSize = 200

    var body: some View {
        let records = model.usn
        return ScrollView {
            VStack(alignment: .leading, spacing: 0) {
                LargeTitle(title: "USN Journal",
                           subtitle: "\(human(records.count)) record\(records.count == 1 ? "" : "s")")

                if records.isEmpty {
                    ContentUnavailableView(
                        "No USN journal",
                        systemImage: "doc.badge.clock",
                        description: Text("Parse the USN journal on the macOS app to browse it here."))
                        .padding(.top, 60)
                        .frame(maxWidth: .infinity)
                } else {
                    Card { rows(records) }.padding(.top, 10)
                }

                Spacer(minLength: 26)
            }
        }
        .background(Theme.bg.ignoresSafeArea())
        .navigationBarTitleDisplayMode(.inline)
        .toolbarBackground(Theme.bg, for: .navigationBar)
        .toolbarBackground(.visible, for: .navigationBar)
    }

    @ViewBuilder private func rows(_ records: [UsnRecord]) -> some View {
        ForEach(records.prefix(displayLimit)) { r in
            VStack(alignment: .leading, spacing: 3) {
                HStack(spacing: 11) {
                    Image(systemName: icon(for: r))
                        .font(.system(size: 16)).frame(width: 22)
                        .foregroundStyle(tint(for: r))
                    Text(r.fileName)
                        .font(.system(size: 13.5, weight: .medium))
                        .foregroundStyle(Theme.text).lineLimit(1).truncationMode(.middle)
                    Spacer()
                    if let t = r.timestamp {
                        Text(Self.dateFmt.string(from: t))
                            .font(.system(size: 11, design: .monospaced)).foregroundStyle(Theme.text3)
                    }
                }
                Text(r.reasonSummary)
                    .font(.system(size: 11, design: .monospaced))
                    .foregroundStyle(Theme.text3).lineLimit(1).truncationMode(.tail)
                    .padding(.leading, 33)
            }
            .padding(.horizontal, 15).padding(.vertical, 11)
            .overlay(alignment: .bottom) { Divider().background(Theme.hair2) }
        }
        if records.count > displayLimit {
            Button { displayLimit += pageSize } label: {
                Text("Show \(min(pageSize, records.count - displayLimit)) more · \(human(records.count - displayLimit)) hidden")
                    .font(.system(size: 12.5, weight: .semibold))
                    .foregroundStyle(Theme.teal)
                    .frame(maxWidth: .infinity).padding(.vertical, 13)
            }
            .buttonStyle(.plain)
        }
    }

    private func icon(for r: UsnRecord) -> String {
        if r.isDelete { return "trash" }
        if r.isCreate { return "plus.circle" }
        if r.isRename { return "arrow.triangle.2.circlepath" }
        return r.isDirectory ? "folder" : "doc"
    }

    private func tint(for r: UsnRecord) -> Color {
        if r.isDelete { return Theme.crit }
        if r.isCreate { return Theme.teal2 }
        if r.isRename { return Theme.amber }
        return Theme.text3
    }

    private func human(_ n: Int) -> String {
        let f = NumberFormatter(); f.numberStyle = .decimal
        return f.string(from: NSNumber(value: n)) ?? "\(n)"
    }

    private static let dateFmt: DateFormatter = {
        let f = DateFormatter()
        f.dateFormat = "yyyy-MM-dd HH:mm:ss"
        f.locale = Locale(identifier: "en_US_POSIX")
        f.timeZone = TimeZone(identifier: "UTC")   // forensic timestamps are UTC
        return f
    }()
}

// MARK: - SRUM drill view

/// Read-only SRUM list for the active scope: per-app network byte volume and
/// execution/resource usage, resolved to application paths. Colour-codes by
/// provider table. Paged.
struct SrumDrillView: View {
    @EnvironmentObject private var model: AppModel
    @State private var displayLimit = 200
    private let pageSize = 200

    var body: some View {
        let rows = model.srum
        return ScrollView {
            VStack(alignment: .leading, spacing: 0) {
                LargeTitle(title: "SRUM",
                           subtitle: "\(human(rows.count)) record\(rows.count == 1 ? "" : "s")")

                if rows.isEmpty {
                    ContentUnavailableView(
                        "No SRUM",
                        systemImage: "chart.bar.doc.horizontal",
                        description: Text("Parse SRUM on the macOS app to browse it here."))
                        .padding(.top, 60)
                        .frame(maxWidth: .infinity)
                } else {
                    Card { rowViews(rows) }.padding(.top, 10)
                }

                Spacer(minLength: 26)
            }
        }
        .background(Theme.bg.ignoresSafeArea())
        .navigationBarTitleDisplayMode(.inline)
        .toolbarBackground(Theme.bg, for: .navigationBar)
        .toolbarBackground(.visible, for: .navigationBar)
    }

    @ViewBuilder private func rowViews(_ rows: [SrumEntry]) -> some View {
        ForEach(rows.prefix(displayLimit)) { r in
            VStack(alignment: .leading, spacing: 3) {
                HStack(spacing: 11) {
                    Image(systemName: icon(for: r.kind))
                        .font(.system(size: 16)).frame(width: 22)
                        .foregroundStyle(tint(for: r.kind))
                    Text(r.appShortName)
                        .font(.system(size: 13.5, weight: .medium))
                        .foregroundStyle(Theme.text).lineLimit(1).truncationMode(.middle)
                    Spacer()
                    if let t = r.timestamp {
                        Text(Self.dateFmt.string(from: t))
                            .font(.system(size: 11, design: .monospaced)).foregroundStyle(Theme.text3)
                    }
                }
                Text("\(r.kind.label) · \(r.detailSummary)")
                    .font(.system(size: 11, design: .monospaced))
                    .foregroundStyle(Theme.text3).lineLimit(1).truncationMode(.tail)
                    .padding(.leading, 33)
            }
            .padding(.horizontal, 15).padding(.vertical, 11)
            .overlay(alignment: .bottom) { Divider().background(Theme.hair2) }
        }
        if rows.count > displayLimit {
            Button { displayLimit += pageSize } label: {
                Text("Show \(min(pageSize, rows.count - displayLimit)) more · \(human(rows.count - displayLimit)) hidden")
                    .font(.system(size: 12.5, weight: .semibold))
                    .foregroundStyle(Theme.teal)
                    .frame(maxWidth: .infinity).padding(.vertical, 13)
            }
            .buttonStyle(.plain)
        }
    }

    private func icon(for kind: SrumEntry.Kind) -> String {
        switch kind {
        case .networkData:         return "arrow.up.arrow.down"
        case .appResourceUsage:    return "cpu"
        case .networkConnectivity: return "wifi"
        }
    }

    private func tint(for kind: SrumEntry.Kind) -> Color {
        switch kind {
        case .networkData:         return Theme.teal2
        case .appResourceUsage:    return Theme.amber
        case .networkConnectivity: return Theme.text3
        }
    }

    private func human(_ n: Int) -> String {
        let f = NumberFormatter(); f.numberStyle = .decimal
        return f.string(from: NSNumber(value: n)) ?? "\(n)"
    }

    private static let dateFmt: DateFormatter = {
        let f = DateFormatter()
        f.dateFormat = "yyyy-MM-dd HH:mm:ss"
        f.locale = Locale(identifier: "en_US_POSIX")
        f.timeZone = TimeZone(identifier: "UTC")   // forensic timestamps are UTC
        return f
    }()
}

struct BrowserHistoryDrillView: View {
    @EnvironmentObject private var model: AppModel
    @State private var displayLimit = 200
    private let pageSize = 200

    var body: some View {
        let rows = model.browserHistory
        return ScrollView {
            VStack(alignment: .leading, spacing: 0) {
                LargeTitle(title: "Browser History",
                           subtitle: "\(human(rows.count)) record\(rows.count == 1 ? "" : "s")")

                if rows.isEmpty {
                    ContentUnavailableView(
                        "No browser history",
                        systemImage: "globe",
                        description: Text("Parse browser history on the macOS app to browse it here."))
                        .padding(.top, 60)
                        .frame(maxWidth: .infinity)
                } else {
                    Card { rowViews(rows) }.padding(.top, 10)
                }

                Spacer(minLength: 26)
            }
        }
        .background(Theme.bg.ignoresSafeArea())
        .navigationBarTitleDisplayMode(.inline)
        .toolbarBackground(Theme.bg, for: .navigationBar)
        .toolbarBackground(.visible, for: .navigationBar)
    }

    @ViewBuilder private func rowViews(_ rows: [BrowserHistoryEntry]) -> some View {
        ForEach(rows.prefix(displayLimit)) { r in
            VStack(alignment: .leading, spacing: 3) {
                HStack(spacing: 11) {
                    Image(systemName: r.kind == .download ? "arrow.down.circle" : "globe")
                        .font(.system(size: 16)).frame(width: 22)
                        .foregroundStyle(r.kind == .download ? Theme.amber : Theme.teal2)
                    Text(r.displayTitle)
                        .font(.system(size: 13.5, weight: .medium))
                        .foregroundStyle(Theme.text).lineLimit(1).truncationMode(.middle)
                    Spacer()
                    if let t = r.timestamp {
                        Text(Self.dateFmt.string(from: t))
                            .font(.system(size: 11, design: .monospaced)).foregroundStyle(Theme.text3)
                    }
                }
                Text("\(r.browser.label) · \(r.detailSummary)")
                    .font(.system(size: 11, design: .monospaced))
                    .foregroundStyle(Theme.text3).lineLimit(1).truncationMode(.tail)
                    .padding(.leading, 33)
                Text(r.url)
                    .font(.system(size: 10.5))
                    .foregroundStyle(Theme.text3.opacity(0.8)).lineLimit(1).truncationMode(.middle)
                    .padding(.leading, 33)
            }
            .padding(.horizontal, 15).padding(.vertical, 11)
            .overlay(alignment: .bottom) { Divider().background(Theme.hair2) }
        }
        if rows.count > displayLimit {
            Button { displayLimit += pageSize } label: {
                Text("Show \(min(pageSize, rows.count - displayLimit)) more · \(human(rows.count - displayLimit)) hidden")
                    .font(.system(size: 12.5, weight: .semibold))
                    .foregroundStyle(Theme.teal)
                    .frame(maxWidth: .infinity).padding(.vertical, 13)
            }
            .buttonStyle(.plain)
        }
    }

    private func human(_ n: Int) -> String {
        let f = NumberFormatter(); f.numberStyle = .decimal
        return f.string(from: NSNumber(value: n)) ?? "\(n)"
    }

    private static let dateFmt: DateFormatter = {
        let f = DateFormatter()
        f.dateFormat = "yyyy-MM-dd HH:mm:ss"
        f.locale = Locale(identifier: "en_US_POSIX")
        f.timeZone = TimeZone(identifier: "UTC")   // forensic timestamps are UTC
        return f
    }()
}

struct MftDrillView: View {
    @EnvironmentObject private var model: AppModel
    @State private var displayLimit = 200
    @State private var anomaliesOnly = false
    private let pageSize = 200

    var body: some View {
        let all = model.mft
        let rows = anomaliesOnly ? all.filter { $0.siCreatedPredatesFn } : all
        let anomalyCount = all.lazy.filter { $0.siCreatedPredatesFn }.count
        return ScrollView {
            VStack(alignment: .leading, spacing: 0) {
                LargeTitle(title: "MFT",
                           subtitle: "\(human(all.count)) record\(all.count == 1 ? "" : "s")")

                if all.isEmpty {
                    ContentUnavailableView(
                        "No $MFT",
                        systemImage: "tablecells",
                        description: Text("Parse the $MFT on the macOS app to browse it here."))
                        .padding(.top, 60)
                        .frame(maxWidth: .infinity)
                } else {
                    if anomalyCount > 0 {
                        Toggle(isOn: $anomaliesOnly) {
                            Label("Timestomp anomalies only (\(anomalyCount))", systemImage: "exclamationmark.triangle")
                                .font(.system(size: 13, weight: .medium))
                        }
                        .tint(Theme.teal)
                        .padding(.horizontal, 15).padding(.top, 10)
                    }
                    Card { rowViews(rows) }.padding(.top, 10)
                }

                Spacer(minLength: 26)
            }
        }
        .background(Theme.bg.ignoresSafeArea())
        .navigationBarTitleDisplayMode(.inline)
        .toolbarBackground(Theme.bg, for: .navigationBar)
        .toolbarBackground(.visible, for: .navigationBar)
    }

    @ViewBuilder private func rowViews(_ rows: [MftEntry]) -> some View {
        ForEach(rows.prefix(displayLimit)) { r in
            VStack(alignment: .leading, spacing: 3) {
                HStack(spacing: 11) {
                    Image(systemName: r.siCreatedPredatesFn ? "exclamationmark.triangle.fill"
                                                            : (r.isDirectory ? "folder" : "doc"))
                        .font(.system(size: 15)).frame(width: 22)
                        .foregroundStyle(r.siCreatedPredatesFn ? Theme.amber : Theme.text3)
                    Text(r.fileName ?? "MFT #\(r.recordNumber)")
                        .font(.system(size: 13.5, weight: .medium))
                        .foregroundStyle(Theme.text).lineLimit(1).truncationMode(.middle)
                    Spacer()
                    if let t = r.siCreated {
                        Text(Self.dateFmt.string(from: t))
                            .font(.system(size: 11, design: .monospaced)).foregroundStyle(Theme.text3)
                    }
                }
                Text(r.fullPath ?? "—")
                    .font(.system(size: 11, design: .monospaced))
                    .foregroundStyle(Theme.text3).lineLimit(1).truncationMode(.head)
                    .padding(.leading, 33)
            }
            .padding(.horizontal, 15).padding(.vertical, 11)
            .overlay(alignment: .bottom) { Divider().background(Theme.hair2) }
        }
        if rows.count > displayLimit {
            Button { displayLimit += pageSize } label: {
                Text("Show \(min(pageSize, rows.count - displayLimit)) more · \(human(rows.count - displayLimit)) hidden")
                    .font(.system(size: 12.5, weight: .semibold))
                    .foregroundStyle(Theme.teal)
                    .frame(maxWidth: .infinity).padding(.vertical, 13)
            }
            .buttonStyle(.plain)
        }
    }

    private func human(_ n: Int) -> String {
        let f = NumberFormatter(); f.numberStyle = .decimal
        return f.string(from: NSNumber(value: n)) ?? "\(n)"
    }

    private static let dateFmt: DateFormatter = {
        let f = DateFormatter()
        f.dateFormat = "yyyy-MM-dd HH:mm:ss"
        f.locale = Locale(identifier: "en_US_POSIX")
        f.timeZone = TimeZone(identifier: "UTC")   // forensic timestamps are UTC
        return f
    }()
}

#endif
