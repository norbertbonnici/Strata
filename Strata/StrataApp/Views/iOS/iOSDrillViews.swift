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

    // Derived off `body` (CLAUDE.md: "Don't do heavy work in body"): on a disk
    // image `model.files` is millions of rows, so filtering/counting per render
    // froze navigation. Recompute only when the data or the path changes.
    @State private var kids: [FileEntry] = []
    @State private var totalCount = 0
    @State private var deletedCount = 0

    private func recompute() {
        let here = normalized(path)
        let files = model.files
        kids = files
            .filter { normalized($0.parentPath) == here }
            .sorted { lhs, rhs in
                if lhs.isDirectory != rhs.isDirectory { return lhs.isDirectory }
                return lhs.name.localizedCaseInsensitiveCompare(rhs.name) == .orderedAscending
            }
        totalCount = files.count
        deletedCount = files.lazy.filter(\.isDeleted).count
    }

    var body: some View {
        ScrollView {
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
        .task(id: model.dataVersion) { recompute() }
        .onChange(of: path) { displayLimit = pageSize; recompute() }   // restart paging + refilter on navigate
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
        Text("\(human(totalCount)) objects · \(human(deletedCount)) deleted")
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

/// iOS $MFT browser — a breadcrumb tree like FilesystemDrillView. Directories
/// navigate by mutating `path`; tapping a file pushes its record detail (full
/// 100-ns $SI/$FN times + any resident $DATA).
struct MftDrillView: View {
    @EnvironmentObject private var model: AppModel
    @State private var path = #"\"#       // current directory (backslash form); "\" = root
    @State private var displayLimit = 200
    private let pageSize = 200

    private func parentDir(of full: String) -> String {
        guard let idx = full.lastIndex(of: "\\") else { return #"\"# }
        let parent = String(full[..<idx])
        return parent.isEmpty ? #"\"# : parent
    }

    private var children: [MftEntry] {
        model.mft.filter { e in
            guard let fp = e.fullPath, e.fileName != nil, fp != #"\"# else { return false }
            return parentDir(of: fp) == path
        }
        .sorted { a, b in
            if a.isDirectory != b.isDirectory { return a.isDirectory }
            return (a.fileName ?? "").localizedCaseInsensitiveCompare(b.fileName ?? "") == .orderedAscending
        }
    }

    var body: some View {
        let all = model.mft
        let kids = children
        return ScrollView {
            VStack(alignment: .leading, spacing: 0) {
                LargeTitle(title: "MFT", subtitle: "\(human(all.count)) record\(all.count == 1 ? "" : "s")")
                if all.isEmpty {
                    ContentUnavailableView("No $MFT", systemImage: "tablecells",
                        description: Text("Parse the $MFT on the macOS app to browse it here."))
                        .padding(.top, 60).frame(maxWidth: .infinity)
                } else {
                    breadcrumb
                    if kids.isEmpty {
                        ContentUnavailableView("Empty", systemImage: "folder",
                            description: Text("No records under this path."))
                            .padding(.top, 40).frame(maxWidth: .infinity)
                    } else {
                        Card { rows(kids) }.padding(.top, 10)
                    }
                }
                Spacer(minLength: 26)
            }
        }
        .background(Theme.bg.ignoresSafeArea())
        .navigationBarTitleDisplayMode(.inline)
        .toolbarBackground(Theme.bg, for: .navigationBar)
        .toolbarBackground(.visible, for: .navigationBar)
        .onChange(of: path) { displayLimit = pageSize }
    }

    private var breadcrumb: some View {
        let crumbs = path.split(separator: "\\").map(String.init)
        return ScrollView(.horizontal, showsIndicators: false) {
            HStack(spacing: 5) {
                Button { path = #"\"# } label: {
                    Text(#"\"#).font(.system(size: 12.5, design: .monospaced)).foregroundStyle(Theme.text2)
                }.buttonStyle(.plain)
                ForEach(Array(crumbs.enumerated()), id: \.offset) { idx, name in
                    Text("›").foregroundStyle(Theme.text3)
                    Button { path = "\\" + crumbs[0...idx].joined(separator: "\\") } label: {
                        Text(name)
                            .font(.system(size: 12.5, weight: idx == crumbs.count - 1 ? .semibold : .regular,
                                          design: .monospaced))
                            .foregroundStyle(idx == crumbs.count - 1 ? Theme.text : Theme.text2)
                    }.buttonStyle(.plain)
                }
            }
            .padding(.horizontal, 22).padding(.top, 6)
        }
    }

    @ViewBuilder private func rows(_ kids: [MftEntry]) -> some View {
        ForEach(kids.prefix(displayLimit)) { e in
            row(e)
            Divider().background(Theme.hair2).padding(.leading, 48)
        }
        if kids.count > displayLimit {
            Button { displayLimit += pageSize } label: {
                Text("Show \(min(pageSize, kids.count - displayLimit)) more")
                    .font(.system(size: 12.5, weight: .semibold)).foregroundStyle(Theme.teal)
                    .frame(maxWidth: .infinity).padding(.vertical, 13)
            }.buttonStyle(.plain)
        }
    }

    @ViewBuilder private func row(_ e: MftEntry) -> some View {
        if e.isDirectory {
            Button { path = e.fullPath ?? #"\"# } label: { rowContent(e) }.buttonStyle(.plain)
        } else {
            NavigationLink { MftRecordDetail(entry: e) } label: { rowContent(e) }.buttonStyle(.plain)
        }
    }

    private func rowContent(_ e: MftEntry) -> some View {
        HStack(spacing: 12) {
            Image(systemName: e.siCreatedPredatesFn ? "exclamationmark.triangle.fill"
                              : (e.isDirectory ? "folder" : "doc"))
                .font(.system(size: 16)).frame(width: 24)
                .foregroundStyle(e.siCreatedPredatesFn ? Theme.amber : (e.isDirectory ? Theme.teal2 : Theme.text3))
            Text(e.fileName ?? "MFT #\(e.recordNumber)")
                .font(e.isDirectory ? .system(size: 14) : .system(size: 12.5, design: .monospaced))
                .foregroundStyle(e.inUse ? Theme.text : Theme.text2).lineLimit(1).truncationMode(.middle)
            if e.hasResidentData {
                Image(systemName: "doc.text.below.ecg").font(.system(size: 11)).foregroundStyle(Theme.teal)
            }
            Spacer()
            if e.isDirectory {
                Image(systemName: "chevron.right").font(.system(size: 12)).foregroundStyle(Theme.text3)
            } else if let s = e.size {
                Text(ByteCountFormatter.string(fromByteCount: s, countStyle: .file))
                    .font(.system(size: 11)).foregroundStyle(Theme.text3)
            }
        }
        .padding(.horizontal, 15).padding(.vertical, 11)
        .contentShape(Rectangle())
    }

    private func human(_ n: Int) -> String {
        let f = NumberFormatter(); f.numberStyle = .decimal
        return f.string(from: NSNumber(value: n)) ?? "\(n)"
    }
}

/// iOS record detail: full lossless 100-ns timestamps + resident $DATA.
private struct MftRecordDetail: View {
    let entry: MftEntry

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 0) {
                LargeTitle(title: entry.fileName ?? "MFT #\(entry.recordNumber)")
                if entry.siCreatedPredatesFn {
                    Label("$SI predates $FN — possible timestomping (T1070.006)",
                          systemImage: "exclamationmark.triangle.fill")
                        .font(.system(size: 12)).foregroundStyle(Theme.amber)
                        .padding(.horizontal, 18).padding(.top, 4)
                }
                Card {
                    kv("Path", entry.fullPath ?? "—")
                    kv("Record", "\(entry.recordNumber) (seq \(entry.sequence))")
                    kv("State", entry.inUse ? "Allocated" : "Deleted")
                    if let s = entry.size { kv("Size", "\(s.formatted()) bytes") }
                }.padding(.top, 10)

                SectionHeader(label: "$STANDARD_INFORMATION").padding(.top, 14)
                Card {
                    timeRow("Created", entry.siCreatedRaw, flag: entry.siCreatedPredatesFn)
                    timeRow("Modified", entry.siModifiedRaw)
                    timeRow("MFT changed", entry.siChangedRaw)
                    timeRow("Accessed", entry.siAccessedRaw)
                }

                SectionHeader(label: "$FILE_NAME").padding(.top, 14)
                Card {
                    timeRow("Created", entry.fnCreatedRaw)
                    timeRow("Modified", entry.fnModifiedRaw)
                    timeRow("MFT changed", entry.fnChangedRaw)
                    timeRow("Accessed", entry.fnAccessedRaw)
                }

                if let data = entry.residentData, !data.isEmpty {
                    SectionHeader(label: "Resident $DATA — \(data.count) bytes").padding(.top, 14)
                    Card {
                        Text(MftHexDump.dump(data, max: 512))
                            .font(.system(size: 10, design: .monospaced))
                            .foregroundStyle(Theme.text2).textSelection(.enabled)
                            .padding(12).frame(maxWidth: .infinity, alignment: .leading)
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

    private func kv(_ k: String, _ v: String) -> some View {
        HStack(alignment: .top) {
            Text(k).font(.system(size: 12.5)).foregroundStyle(Theme.text3).frame(width: 90, alignment: .leading)
            Text(v).font(.system(size: 12.5, design: .monospaced)).foregroundStyle(Theme.text)
                .frame(maxWidth: .infinity, alignment: .leading).textSelection(.enabled)
        }.padding(.horizontal, 15).padding(.vertical, 7)
    }

    private func timeRow(_ label: String, _ raw: UInt64, flag: Bool = false) -> some View {
        HStack {
            Text(label).font(.system(size: 12.5)).foregroundStyle(Theme.text3).frame(width: 110, alignment: .leading)
            Text(FileTime.precise(raw) ?? "—")
                .font(.system(size: 11.5, design: .monospaced))
                .foregroundStyle(flag ? Theme.amber : Theme.text)
                .frame(maxWidth: .infinity, alignment: .leading).textSelection(.enabled)
        }.padding(.horizontal, 15).padding(.vertical, 7)
    }
}

/// Shared compact hex+ASCII dump (used by the iOS resident-data view).
enum MftHexDump {
    static func dump(_ data: Data, max: Int) -> String {
        let slice = Array(data.prefix(max))
        var out = ""
        var i = 0
        while i < slice.count {
            let row = slice[i ..< Swift.min(i + 16, slice.count)]
            let hex = row.map { String(format: "%02x", $0) }.joined(separator: " ")
                .padding(toLength: 47, withPad: " ", startingAt: 0)
            let ascii = String(row.map { (32...126).contains($0) ? Character(UnicodeScalar($0)) : "." })
            out += String(format: "%04x  ", i) + hex + "  " + ascii + "\n"
            i += 16
        }
        if data.count > max { out += "… (\(data.count - max) more bytes)\n" }
        return out
    }
}

struct WmiDrillView: View {
    @EnvironmentObject private var model: AppModel
    @State private var hideBenign = true
    @State private var displayLimit = 200
    private let pageSize = 200

    var body: some View {
        let all = model.wmi
        let rows = hideBenign ? all.filter { !$0.isCommonBenign } : all
        let benign = all.lazy.filter(\.isCommonBenign).count
        return ScrollView {
            VStack(alignment: .leading, spacing: 0) {
                LargeTitle(title: "WMI", subtitle: "\(human(all.count)) item\(all.count == 1 ? "" : "s")")
                if all.isEmpty {
                    ContentUnavailableView("No WMI persistence", systemImage: "gearshape.2",
                        description: Text("Parse the WMI repository on the macOS app to browse it here."))
                        .padding(.top, 60).frame(maxWidth: .infinity)
                } else {
                    if benign > 0 {
                        Toggle(isOn: $hideBenign) {
                            Label("Hide built-in (\(benign))", systemImage: "checkmark.seal")
                                .font(.system(size: 13, weight: .medium))
                        }.tint(Theme.teal).padding(.horizontal, 15).padding(.top, 10)
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

    @ViewBuilder private func rowViews(_ rows: [WmiPersistenceEntry]) -> some View {
        ForEach(rows.prefix(displayLimit)) { e in
            NavigationLink { WmiRecordDetail(entry: e) } label: {
                HStack(spacing: 11) {
                    Image(systemName: e.kind == .scriptConsumer ? "curlybraces" : "arrow.triangle.branch")
                        .font(.system(size: 15)).frame(width: 22)
                        .foregroundStyle(e.isCommonBenign ? Theme.text3 : Theme.amber)
                    VStack(alignment: .leading, spacing: 2) {
                        Text(e.title).font(.system(size: 13.5, weight: .medium))
                            .foregroundStyle(Theme.text).lineLimit(1).truncationMode(.middle)
                        Text(e.detailSummary).font(.system(size: 11, design: .monospaced))
                            .foregroundStyle(Theme.text3).lineLimit(1).truncationMode(.middle)
                    }
                    Spacer()
                    Image(systemName: "chevron.right").font(.system(size: 12)).foregroundStyle(Theme.text3)
                }
                .padding(.horizontal, 15).padding(.vertical, 11).contentShape(Rectangle())
            }
            .buttonStyle(.plain)
            Divider().background(Theme.hair2).padding(.leading, 48)
        }
        if rows.count > displayLimit {
            Button { displayLimit += pageSize } label: {
                Text("Show \(min(pageSize, rows.count - displayLimit)) more")
                    .font(.system(size: 12.5, weight: .semibold)).foregroundStyle(Theme.teal)
                    .frame(maxWidth: .infinity).padding(.vertical, 13)
            }.buttonStyle(.plain)
        }
    }

    private func human(_ n: Int) -> String {
        let f = NumberFormatter(); f.numberStyle = .decimal
        return f.string(from: NSNumber(value: n)) ?? "\(n)"
    }
}

private struct WmiRecordDetail: View {
    let entry: WmiPersistenceEntry
    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 0) {
                LargeTitle(title: entry.title)
                if !entry.isCommonBenign {
                    Label("WMI persistence (T1546.003)", systemImage: "exclamationmark.triangle.fill")
                        .font(.system(size: 12)).foregroundStyle(Theme.amber)
                        .padding(.horizontal, 18).padding(.top, 4)
                }
                Card {
                    kv("Kind", entry.kind.label)
                    if let t = entry.consumerType { kv("Consumer type", t) }
                    if let f = entry.filterName { kv("Filter", f) }
                    if let e = entry.scriptEngine { kv("Engine", e) }
                    if entry.isCommonBenign { kv("Note", "Built-in (BVT/SCM)") }
                }.padding(.top, 10)
                if let q = entry.query, !q.isEmpty { section("Trigger (WQL)", q) }
                if let c = entry.command, !c.isEmpty { section("Command", c) }
                if let s = entry.scriptText, !s.isEmpty { section("Script", s) }
                Spacer(minLength: 26)
            }
        }
        .background(Theme.bg.ignoresSafeArea())
        .navigationBarTitleDisplayMode(.inline)
        .toolbarBackground(Theme.bg, for: .navigationBar)
        .toolbarBackground(.visible, for: .navigationBar)
    }
    private func kv(_ k: String, _ v: String) -> some View {
        HStack(alignment: .top) {
            Text(k).font(.system(size: 12.5)).foregroundStyle(Theme.text3).frame(width: 110, alignment: .leading)
            Text(v).font(.system(size: 12.5, design: .monospaced)).foregroundStyle(Theme.text)
                .frame(maxWidth: .infinity, alignment: .leading).textSelection(.enabled)
        }.padding(.horizontal, 15).padding(.vertical, 7)
    }
    private func section(_ title: String, _ value: String) -> some View {
        VStack(alignment: .leading, spacing: 0) {
            SectionHeader(label: title).padding(.top, 14)
            Card {
                Text(value).font(.system(size: 11, design: .monospaced)).foregroundStyle(Theme.text2)
                    .textSelection(.enabled).padding(12).frame(maxWidth: .infinity, alignment: .leading)
            }
        }
    }
}

// MARK: - Launch Items drill view (macOS)

/// Read-only launchd-job list for the active scope - the macOS auto-start /
/// persistence foothold. One row per job with its domain and executable.
struct LaunchItemsDrillView: View {
    @EnvironmentObject private var model: AppModel
    @State private var displayLimit = 200
    private let pageSize = 200

    var body: some View {
        let entries = model.launchItems
        return ScrollView {
            VStack(alignment: .leading, spacing: 0) {
                LargeTitle(title: "Launch Items",
                           subtitle: "\(human(entries.count)) job\(entries.count == 1 ? "" : "s")")

                if entries.isEmpty {
                    ContentUnavailableView(
                        "No launch items",
                        systemImage: "powerplug",
                        description: Text("Parse macOS artifacts on the macOS app to browse launchd jobs here."))
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

    @ViewBuilder private func rows(_ entries: [LaunchItemEntry]) -> some View {
        ForEach(entries.prefix(displayLimit)) { entry in
            VStack(alignment: .leading, spacing: 3) {
                HStack(spacing: 11) {
                    Image(systemName: "powerplug")
                        .font(.system(size: 16))
                        .frame(width: 22)
                        .foregroundStyle(Theme.teal2)
                    Text(entry.label)
                        .font(.system(size: 13.5, weight: .medium, design: .monospaced))
                        .foregroundStyle(Theme.text)
                        .lineLimit(1).truncationMode(.middle)
                    Spacer()
                    if entry.runAtLoad {
                        Text("RunAtLoad")
                            .font(.system(size: 11, design: .monospaced))
                            .foregroundStyle(Theme.text3)
                    }
                }
                Text("\(entry.scope.label) · \(entry.executable ?? "(no program)")")
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

    private func human(_ n: Int) -> String {
        let f = NumberFormatter(); f.numberStyle = .decimal
        return f.string(from: NSNumber(value: n)) ?? "\(n)"
    }
}

// MARK: - Quarantine drill view (macOS)

/// Read-only macOS download-provenance list for the active scope, newest first.
/// Each row is a file pulled from the network: what downloaded it and from where.
struct QuarantineDrillView: View {
    @EnvironmentObject private var model: AppModel
    @State private var displayLimit = 200
    private let pageSize = 200

    var body: some View {
        let events = model.quarantine
        return ScrollView {
            VStack(alignment: .leading, spacing: 0) {
                LargeTitle(title: "Quarantine",
                           subtitle: "\(human(events.count)) download\(events.count == 1 ? "" : "s")")

                if events.isEmpty {
                    ContentUnavailableView(
                        "No quarantine events",
                        systemImage: "shield.lefthalf.filled",
                        description: Text("Parse macOS artifacts on the macOS app to browse download provenance here."))
                        .padding(.top, 60)
                        .frame(maxWidth: .infinity)
                } else {
                    Card { rows(events) }.padding(.top, 10)
                }

                Spacer(minLength: 26)
            }
        }
        .background(Theme.bg.ignoresSafeArea())
        .navigationBarTitleDisplayMode(.inline)
        .toolbarBackground(Theme.bg, for: .navigationBar)
        .toolbarBackground(.visible, for: .navigationBar)
    }

    @ViewBuilder private func rows(_ events: [QuarantineEvent]) -> some View {
        ForEach(events.prefix(displayLimit)) { event in
            VStack(alignment: .leading, spacing: 3) {
                HStack(spacing: 11) {
                    Image(systemName: "shield.lefthalf.filled")
                        .font(.system(size: 16))
                        .frame(width: 22)
                        .foregroundStyle(Theme.teal2)
                    Text(event.displayTitle)
                        .font(.system(size: 13.5, weight: .medium, design: .monospaced))
                        .foregroundStyle(Theme.text)
                        .lineLimit(1).truncationMode(.middle)
                    Spacer()
                    Text(event.agentName ?? "—")
                        .font(.system(size: 12, design: .monospaced))
                        .foregroundStyle(Theme.text3)
                }
                Text(subtitle(event))
                    .font(.system(size: 11))
                    .foregroundStyle(Theme.text3)
                    .lineLimit(1).truncationMode(.middle)
                    .padding(.leading, 33)
            }
            .padding(.horizontal, 15).padding(.vertical, 11)
            .overlay(alignment: .bottom) { Divider().background(Theme.hair2) }
        }
        if events.count > displayLimit {
            Button { displayLimit += pageSize } label: {
                Text("Show \(min(pageSize, events.count - displayLimit)) more · \(human(events.count - displayLimit)) hidden")
                    .font(.system(size: 12.5, weight: .semibold))
                    .foregroundStyle(Theme.teal)
                    .frame(maxWidth: .infinity).padding(.vertical, 13)
            }
            .buttonStyle(.plain)
        }
    }

    private func subtitle(_ event: QuarantineEvent) -> String {
        let when = event.timestamp.map { Self.dateFmt.string(from: $0) } ?? "no time"
        if let host = event.dataHost ?? event.originHost { return "\(when) · \(host)" }
        return when
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

// MARK: - Persistence drill view (macOS)

/// Read-only macOS persistence sweep for the active scope - cron, periodic,
/// emond, login/logout hooks, rc scripts, and configuration profiles (launchd
/// jobs are the separate Launch Items drill). One row per mechanism.
struct MacPersistenceDrillView: View {
    @EnvironmentObject private var model: AppModel
    @State private var displayLimit = 200
    private let pageSize = 200

    var body: some View {
        let items = model.macPersistence
        return ScrollView {
            VStack(alignment: .leading, spacing: 0) {
                LargeTitle(title: "Persistence",
                           subtitle: "\(human(items.count)) item\(items.count == 1 ? "" : "s")")

                if items.isEmpty {
                    ContentUnavailableView(
                        "No persistence",
                        systemImage: "calendar.badge.clock",
                        description: Text("Parse macOS artifacts on the macOS app to browse the persistence sweep here."))
                        .padding(.top, 60)
                        .frame(maxWidth: .infinity)
                } else {
                    Card { rows(items) }.padding(.top, 10)
                }

                Spacer(minLength: 26)
            }
        }
        .background(Theme.bg.ignoresSafeArea())
        .navigationBarTitleDisplayMode(.inline)
        .toolbarBackground(Theme.bg, for: .navigationBar)
        .toolbarBackground(.visible, for: .navigationBar)
    }

    @ViewBuilder private func rows(_ items: [MacPersistenceItem]) -> some View {
        ForEach(items.prefix(displayLimit)) { item in
            VStack(alignment: .leading, spacing: 3) {
                HStack(spacing: 11) {
                    Image(systemName: "calendar.badge.clock")
                        .font(.system(size: 16))
                        .frame(width: 22)
                        .foregroundStyle(Theme.teal2)
                    Text(item.title)
                        .font(.system(size: 13.5, weight: .medium, design: .monospaced))
                        .foregroundStyle(Theme.text)
                        .lineLimit(1).truncationMode(.middle)
                    Spacer()
                    Text(item.kind.label)
                        .font(.system(size: 11, design: .monospaced))
                        .foregroundStyle(Theme.text3)
                }
                Text(item.command.isEmpty ? item.sourceFile : item.command)
                    .font(.system(size: 11))
                    .foregroundStyle(Theme.text3)
                    .lineLimit(1).truncationMode(.middle)
                    .padding(.leading, 33)
            }
            .padding(.horizontal, 15).padding(.vertical, 11)
            .overlay(alignment: .bottom) { Divider().background(Theme.hair2) }
        }
        if items.count > displayLimit {
            Button { displayLimit += pageSize } label: {
                Text("Show \(min(pageSize, items.count - displayLimit)) more · \(human(items.count - displayLimit)) hidden")
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
}

// MARK: - KnowledgeC drill view (macOS)

/// Read-only macOS KnowledgeC behavioural timeline for the active scope — app
/// focus/usage, screen on/off, media, Safari. Filterable by app/value.
struct KnowledgeCDrillView: View {
    @EnvironmentObject private var model: AppModel
    @State private var query = ""

    private var filtered: [KnowledgeEntry] {
        let rows = model.knowledgeC
        guard !query.isEmpty else { return rows }
        return rows.filter {
            ($0.value?.localizedCaseInsensitiveContains(query) ?? false)
                || $0.category.label.localizedCaseInsensitiveContains(query)
        }
    }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 0) {
                LargeTitle(title: "KnowledgeC",
                           subtitle: "\(model.knowledgeCCount) record\(model.knowledgeCCount == 1 ? "" : "s")")
                TextField("Filter app / value...", text: $query)
                    .textFieldStyle(.roundedBorder).padding(.top, 10)
                let rows = filtered
                if rows.isEmpty {
                    ContentUnavailableView("No KnowledgeC records", systemImage: "brain").padding(.top, 40)
                } else {
                    Card {
                        ForEach(Array(rows.prefix(800).enumerated()), id: \.element.id) { index, e in
                            VStack(alignment: .leading, spacing: 3) {
                                HStack {
                                    Text(e.category.label).font(.caption.bold()).foregroundStyle(Theme.teal)
                                    Spacer()
                                    if let t = e.startDate {
                                        Text(t.formatted(date: .numeric, time: .shortened))
                                            .font(.caption2.monospacedDigit()).foregroundStyle(Theme.text3)
                                    }
                                }
                                Text(e.summary).font(.caption.monospaced())
                                    .foregroundStyle(Theme.text).lineLimit(2)
                            }
                            .padding(.vertical, 5)
                            if index < min(rows.count, 800) - 1 { Divider().background(Theme.hair2) }
                        }
                    }
                }
                Spacer(minLength: 26)
            }
            .padding(.horizontal)
        }
        .background(Theme.bg.ignoresSafeArea())
        .navigationBarTitleDisplayMode(.inline)
        .toolbarBackground(Theme.bg, for: .navigationBar)
        .toolbarBackground(.visible, for: .navigationBar)
    }
}

// MARK: - TCC (privacy) drill view (macOS)

/// Read-only macOS TCC privacy grants for the active scope — which apps were
/// allowed Camera/Mic/Screen/Accessibility/Full Disk Access, sensitive ones
/// highlighted. Filterable by service / client.
struct TCCDrillView: View {
    @EnvironmentObject private var model: AppModel
    @State private var query = ""
    @State private var sensitiveOnly = false

    private var filtered: [TCCAccess] {
        var rows = model.tcc
        if sensitiveOnly { rows = rows.filter { $0.isSensitive } }
        guard !query.isEmpty else { return rows }
        return rows.filter {
            $0.serviceLabel.localizedCaseInsensitiveContains(query)
                || $0.client.localizedCaseInsensitiveContains(query)
        }
    }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 0) {
                LargeTitle(title: "TCC (Privacy)",
                           subtitle: "\(model.tccCount) grant\(model.tccCount == 1 ? "" : "s")")
                Toggle("Sensitive only", isOn: $sensitiveOnly)
                    .font(.subheadline).foregroundStyle(Theme.text).tint(Theme.teal).padding(.top, 10)
                TextField("Filter service / client...", text: $query)
                    .textFieldStyle(.roundedBorder).padding(.top, 8)
                let rows = filtered
                if rows.isEmpty {
                    ContentUnavailableView("No TCC grants", systemImage: "hand.raised").padding(.top, 40)
                } else {
                    Card {
                        ForEach(Array(rows.prefix(800).enumerated()), id: \.element.id) { index, g in
                            VStack(alignment: .leading, spacing: 3) {
                                HStack {
                                    Text(g.serviceLabel)
                                        .font(.caption.bold())
                                        .foregroundStyle(g.isSensitive ? Color.orange : Theme.teal)
                                    if g.authValue == .allowed {
                                        Text("Allowed").font(.caption2).foregroundStyle(Theme.high)
                                    }
                                    Spacer()
                                    if let t = g.lastModified {
                                        Text(t.formatted(date: .numeric, time: .shortened))
                                            .font(.caption2.monospacedDigit()).foregroundStyle(Theme.text3)
                                    }
                                }
                                Text(g.clientLabel).font(.caption.monospaced())
                                    .foregroundStyle(Theme.text).lineLimit(2)
                                Text(g.scope).font(.caption2).foregroundStyle(Theme.text3)
                            }
                            .padding(.vertical, 5)
                            if index < min(rows.count, 800) - 1 { Divider().background(Theme.hair2) }
                        }
                    }
                }
                Spacer(minLength: 26)
            }
            .padding(.horizontal)
        }
        .background(Theme.bg.ignoresSafeArea())
        .navigationBarTitleDisplayMode(.inline)
        .toolbarBackground(Theme.bg, for: .navigationBar)
        .toolbarBackground(.visible, for: .navigationBar)
    }
}

// MARK: - Unified Log drill view (macOS)

/// Read-only macOS unified-log entries for the active scope — timestamped,
/// level-coloured, filterable by process / message. Capped for responsiveness.
struct UnifiedLogDrillView: View {
    @EnvironmentObject private var model: AppModel
    @State private var query = ""
    @State private var errorsOnly = false

    private var filtered: [UnifiedLogEntry] {
        var rows = model.unifiedLog
        if errorsOnly { rows = rows.filter { $0.level == .error || $0.level == .fault } }
        guard !query.isEmpty else { return rows }
        return rows.filter {
            $0.message.localizedCaseInsensitiveContains(query)
                || ($0.process?.localizedCaseInsensitiveContains(query) ?? false)
        }
    }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 0) {
                LargeTitle(title: "Unified Log",
                           subtitle: "\(model.unifiedLogCount) entr\(model.unifiedLogCount == 1 ? "y" : "ies")")
                Toggle("Errors only", isOn: $errorsOnly)
                    .font(.subheadline).foregroundStyle(Theme.text).tint(Theme.teal).padding(.top, 10)
                TextField("Filter message / process...", text: $query)
                    .textFieldStyle(.roundedBorder).padding(.top, 8)
                let rows = filtered
                if rows.isEmpty {
                    ContentUnavailableView("No unified-log entries", systemImage: "list.bullet.rectangle").padding(.top, 40)
                } else {
                    if rows.count > 500 {
                        Text("Showing first 500 of \(rows.count).")
                            .font(.caption2).foregroundStyle(Theme.text3).padding(.top, 6)
                    }
                    Card {
                        ForEach(Array(rows.prefix(500).enumerated()), id: \.element.id) { index, e in
                            VStack(alignment: .leading, spacing: 3) {
                                HStack {
                                    Text(e.process ?? "unified log")
                                        .font(.caption.bold()).foregroundStyle(Theme.teal)
                                    if e.level == .error || e.level == .fault {
                                        Text(e.level.label).font(.caption2).foregroundStyle(Theme.high)
                                    }
                                    Spacer()
                                    if let t = e.timestamp {
                                        Text(t.formatted(date: .numeric, time: .shortened))
                                            .font(.caption2.monospacedDigit()).foregroundStyle(Theme.text3)
                                    }
                                }
                                Text(e.message.isEmpty ? "(message could not be resolved)" : e.message)
                                    .font(.caption.monospaced())
                                    .foregroundStyle(e.message.isEmpty ? Theme.text3 : Theme.text)
                                    .lineLimit(3)
                            }
                            .padding(.vertical, 5)
                            if index < min(rows.count, 500) - 1 {
                                Divider().background(Theme.hair2)
                            }
                        }
                    }
                }
                Spacer(minLength: 26)
            }
            .padding(.horizontal)
        }
        .background(Theme.bg.ignoresSafeArea())
        .navigationBarTitleDisplayMode(.inline)
        .toolbarBackground(Theme.bg, for: .navigationBar)
        .toolbarBackground(.visible, for: .navigationBar)
    }
}

// MARK: - FSEvents drill view (macOS)

/// Read-only macOS FSEvents change history for the active scope - the kernel's
/// coalesced filesystem-change log (no per-record timestamp; ordered by event
/// ID). One row per record with its path and coalesced change flags.
struct FSEventsDrillView: View {
    @EnvironmentObject private var model: AppModel
    @State private var displayLimit = 200
    private let pageSize = 200

    var body: some View {
        let records = model.fsEvents
        return ScrollView {
            VStack(alignment: .leading, spacing: 0) {
                LargeTitle(title: "FSEvents",
                           subtitle: "\(human(records.count)) record\(records.count == 1 ? "" : "s")")

                if records.isEmpty {
                    ContentUnavailableView(
                        "No FSEvents",
                        systemImage: "doc.on.doc",
                        description: Text("Parse macOS artifacts on the macOS app to browse the FSEvents history here."))
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

    @ViewBuilder private func rows(_ records: [FSEventRecord]) -> some View {
        ForEach(records.prefix(displayLimit)) { record in
            VStack(alignment: .leading, spacing: 3) {
                HStack(spacing: 11) {
                    Image(systemName: "doc.on.doc")
                        .font(.system(size: 16))
                        .frame(width: 22)
                        .foregroundStyle(Theme.teal2)
                    Text(record.name)
                        .font(.system(size: 13.5, weight: .medium, design: .monospaced))
                        .foregroundStyle(Theme.text)
                        .lineLimit(1).truncationMode(.middle)
                    Spacer()
                    Text(record.isFolder ? "Folder" : (record.isFile ? "File" : "—"))
                        .font(.system(size: 11, design: .monospaced))
                        .foregroundStyle(Theme.text3)
                }
                Text(record.flagSummary)
                    .font(.system(size: 11))
                    .foregroundStyle(Theme.text3)
                    .lineLimit(1).truncationMode(.tail)
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

    private func human(_ n: Int) -> String {
        let f = NumberFormatter(); f.numberStyle = .decimal
        return f.string(from: NSNumber(value: n)) ?? "\(n)"
    }
}

#endif
