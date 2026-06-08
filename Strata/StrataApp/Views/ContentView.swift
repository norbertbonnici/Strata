import SwiftUI
import UniformTypeIdentifiers

enum SidebarItem: String, CaseIterable, Identifiable {
    case overview = "Overview"
    case evidence = "Evidence"
    case timeline = "Timeline"
    case events = "Events"
    case registry = "Registry"
    case prefetch = "Prefetch"
    case amcache = "Amcache"
    case shimcache = "Shimcache"
    case lnk = "Shortcuts"
    case lateral = "Lateral"
    case killChain = "Kill Chain"
    case iocs = "IOCs"
    case custody = "Custody"

    var id: String { rawValue }
    var symbol: String {
        switch self {
        case .overview:  return "square.grid.2x2"
        case .evidence:  return "folder"
        case .timeline:  return "clock"
        case .events:    return "doc.text.magnifyingglass"
        case .registry:  return "list.bullet.indent"
        case .prefetch:  return "bolt.badge.clock"
        case .amcache:   return "shippingbox.and.arrow.backward"
        case .shimcache: return "clock.arrow.circlepath"
        case .lnk:       return "arrowshape.turn.up.right"
        case .lateral:   return "point.3.connected.trianglepath.dotted"
        case .killChain: return "link"
        case .iocs:      return "scope"
        case .custody:   return "checkmark.seal"
        }
    }
}

struct ContentView: View {
    @EnvironmentObject private var model: AppModel
    // List(_:selection:) on iOS requires an optional binding for the
    // sidebar-style selection; we keep a non-nil default so the detail pane
    // always has something to render.
    @State private var item: SidebarItem? = .overview

    var body: some View {
        Group {
            if model.currentCase == nil {
                WelcomeView()
            } else {
                #if os(macOS)
                caseBody
                #else
                // iOS uses a TabView-based layout that better fits a phone
                // and the iOS HIG. macOS keeps the sidebar/split view.
                iOSCaseView()
                #endif
            }
        }
        #if os(macOS)
        .overlay(alignment: .bottom) { statusBar }
        #endif
        // Single sheet binding (see AppModel.ActiveSheet) so two top-level
        // modals never compete - stacking .sheet(isPresented:) modifiers on
        // the same view can SIGABRT in SwiftUI.
        .sheet(item: $model.activeSheet) { sheet in
            switch sheet {
            case .newCase:
                #if os(macOS)
                NewCaseSheet().environmentObject(model)
                #else
                EmptyView()
                #endif
            case .enrichment: EnrichmentSheet().environmentObject(model)
            case .export:
                #if os(macOS)
                ExportSheet().environmentObject(model)
                #else
                EmptyView()
                #endif
            case .acquisitionEditor(let id):
                #if os(macOS)
                AcquisitionEditorSheet(evidenceID: id).environmentObject(model)
                #else
                EmptyView()
                #endif
            }
        }
    }

    #if os(macOS)
    private var caseBody: some View {
        NavigationSplitView {
            List(SidebarItem.allCases, selection: $item) { entry in
                Label(entry.rawValue, systemImage: entry.symbol).tag(entry)
            }
            // Hide the List's own scroll background so the Theme.bg2 paints
            // straight through; otherwise the sidebar reads as system-dark
            // gray and clashes with the deep blue-teal in the detail pane.
            .scrollContentBackground(.hidden)
            .background(Theme.bg2)
            .navigationTitle(model.currentCase?.name ?? "Strata")
            .navigationSplitViewColumnWidth(min: 200, ideal: 220, max: 320)
        } detail: {
            Group {
                switch item ?? .overview {
                case .overview:  OverviewView()
                case .evidence:  EvidenceTreeView()
                case .timeline:  TimelineView()
                case .events:    EventsView()
                case .registry:  RegistryView()
                case .prefetch:  PrefetchView()
                case .amcache:   AmcacheView()
                case .shimcache: ShimcacheView()
                case .lnk:       LnkView()
                case .lateral:   LateralMovementView()
                case .killChain: KillChainView()
                case .iocs:      IOCView()
                case .custody:   ChainOfCustodyView()
                }
            }
            .background(Theme.bg)
            .toolbar {
                ToolbarItem(placement: .navigation) {
                    EvidenceScopePicker()
                }
                #if os(macOS)
                ToolbarItem(placement: .primaryAction) {
                    Button { model.showAddHostPicker = true } label: {
                        Label("Add Host...", systemImage: "plus")
                    }
                    .disabled(model.isWorking)
                    .help("Ingest a new disk image or KAPE capture into this case.")
                }
                #endif
                ToolbarItem(placement: .primaryAction) {
                    Button { model.closeCase() } label: {
                        Label("Close Case", systemImage: "xmark.circle")
                    }
                    .disabled(model.isWorking)
                    .help("Close this case and return to the welcome screen.")
                }
            }
            #if os(macOS)
            // Multi-select to match the old NSOpenPanel behavior. We hand
            // ingest each URL sequentially because tsk_loaddb is single-
            // threaded and chewing on a disk image - parallel runs would
            // just thrash I/O. `.item` permits any file (E01/VHD/VHDX/raw);
            // `.folder` lets the analyst point at a loose KAPE capture.
            .fileImporter(
                isPresented: $model.showAddHostPicker,
                allowedContentTypes: [.item, .folder],
                allowsMultipleSelection: true
            ) { result in
                guard case .success(let urls) = result, !urls.isEmpty else { return }
                Task {
                    for url in urls {
                        let didStart = url.startAccessingSecurityScopedResource()
                        await model.ingest(sourceURL: url)
                        if didStart { url.stopAccessingSecurityScopedResource() }
                    }
                }
            }
            #endif
        }
    }
    #endif

    @ViewBuilder
    private var statusBar: some View {
        if model.isWorking || !model.statusMessage.isEmpty || model.errorMessage != nil {
            if let p = model.progress, model.errorMessage == nil {
                // Determinate phase (event log / registry parsing) - dedicate
                // a tall row to the label + bar + percent so it's actually
                // readable rather than crammed into a one-liner.
                VStack(alignment: .leading, spacing: 4) {
                    HStack {
                        Text(p.label)
                            .font(.caption).foregroundStyle(.secondary)
                            .lineLimit(1).truncationMode(.middle)
                        Spacer()
                        Text("\(p.current) / \(p.total)  \(p.percent)%")
                            .font(.caption.monospacedDigit())
                            .foregroundStyle(.secondary)
                    }
                    ProgressView(value: p.fraction)
                        .progressViewStyle(.linear)
                }
                .padding(.horizontal, 12).padding(.vertical, 6)
                .background(.regularMaterial)
            } else {
                // Indeterminate / status / error one-liner.
                HStack(spacing: 8) {
                    if model.isWorking { ProgressView().controlSize(.small) }
                    Text(model.errorMessage ?? model.statusMessage)
                        .font(.caption)
                        .foregroundStyle(model.errorMessage == nil ? Color.secondary : Color.red)
                        .lineLimit(1).truncationMode(.middle)
                    Spacer()
                }
                .padding(8)
                .background(.regularMaterial)
            }
        }
    }

}

/// Toolbar control that lets the user scope every screen to a single
/// evidence source or fold them all into one combined view.
private struct EvidenceScopePicker: View {
    @EnvironmentObject private var model: AppModel

    var body: some View {
        if model.evidenceList.isEmpty {
            EmptyView()
        } else {
            Picker("Scope", selection: $model.activeEvidenceID) {
                Text("All evidence (\(model.evidenceList.count))").tag(UUID?.none)
                Divider()
                ForEach(model.evidenceList) { evidence in
                    Text(evidence.displayName).tag(Optional(evidence.id))
                }
            }
            .pickerStyle(.menu)
            .frame(minWidth: 220)
            .help("Choose which evidence source the views below should show.")
        }
    }
}
