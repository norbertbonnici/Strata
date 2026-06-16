import SwiftUI
import UniformTypeIdentifiers

enum SidebarItem: String, CaseIterable, Identifiable {
    case overview = "Overview"
    case search = "Search"
    case evidence = "Evidence"
    case timeline = "Timeline"
    case events = "Events"
    case registry = "Registry"
    case prefetch = "Prefetch"
    case amcache = "Amcache"
    case shimcache = "Shimcache"
    case lnk = "Shortcuts"
    case jumpList = "JumpLists"
    case usn = "USN Journal"
    case srum = "SRUM"
    case browser = "Browser History"
    case mft = "MFT"
    case wmi = "WMI"
    case recycleBin = "Recycle Bin"
    case linuxLogs = "Auth & Logins"
    case shellHistory = "Shell History"
    case linuxPersistence = "Linux Persistence"
    case linuxAccess = "Accounts & SSH"
    case webLogs = "Web Logs"
    case packages = "Packages"
    case journald = "Journal"
    case audit = "Audit"
    case syslog = "System Log"
    case lastlog = "Last Login"
    case launchItems = "Launch Items"
    case quarantine = "Quarantine"
    case macPersistence = "Persistence"
    case fsEvents = "FSEvents"
    case unifiedLog = "Unified Log"
    case tcc = "TCC (Privacy)"
    case knowledgeC = "KnowledgeC"
    case macRecentItems = "Recent Items"
    case macSecurity = "macOS Security"
    case carvedFiles = "Carved Files"
    case kexts = "Extensions"
    case backgroundItems = "Background Items"
    case lateral = "Lateral"
    case killChain = "Kill Chain"
    case iocs = "IOCs"
    case annotations = "Annotations"
    case designUI = "Design UI"
    case activity = "Activity"
    case custody = "Custody"

    var id: String { rawValue }
    var symbol: String {
        switch self {
        case .overview:  return "square.grid.2x2"
        case .search:    return "magnifyingglass"
        case .evidence:  return "folder"
        case .timeline:  return "clock"
        case .events:    return "doc.text.magnifyingglass"
        case .registry:  return "list.bullet.indent"
        case .prefetch:  return "bolt.badge.clock"
        case .amcache:   return "shippingbox.and.arrow.backward"
        case .shimcache: return "clock.arrow.circlepath"
        case .lnk:       return "arrowshape.turn.up.right"
        case .jumpList:  return "list.star"
        case .usn:       return "doc.badge.clock"
        case .srum:      return "chart.bar.doc.horizontal"
        case .browser:   return "globe"
        case .mft:       return "tablecells"
        case .wmi:       return "gearshape.2"
        case .recycleBin: return "trash"
        case .linuxLogs: return "person.badge.key"
        case .shellHistory: return "terminal"
        case .linuxPersistence: return "calendar.badge.clock"
        case .linuxAccess: return "key.horizontal"
        case .webLogs: return "network"
        case .packages: return "shippingbox"
        case .journald: return "doc.text.below.ecg"
        case .audit:    return "checklist"
        case .syslog:   return "doc.plaintext"
        case .lastlog:  return "person.crop.square.badge.camera"
        case .launchItems: return "powerplug"
        case .quarantine:  return "shield.lefthalf.filled"
        case .macPersistence: return "calendar.badge.clock"
        case .fsEvents:  return "doc.on.doc"
        case .unifiedLog: return "list.bullet.rectangle"
        case .tcc:       return "hand.raised"
        case .knowledgeC: return "brain"
        case .macRecentItems: return "clock.arrow.circlepath"
        case .macSecurity: return "checkmark.shield"
        case .carvedFiles: return "doc.badge.arrow.up"
        case .kexts: return "puzzlepiece.extension"
        case .backgroundItems: return "person.badge.clock"
        case .lateral:   return "point.3.connected.trianglepath.dotted"
        case .killChain: return "link"
        case .iocs:      return "scope"
        case .annotations: return "bookmark"
        case .designUI:  return "rectangle.3.group"
        case .activity:  return "waveform.path.ecg"
        case .custody:   return "checkmark.seal"
        }
    }

    /// The OS whose artifacts this tab shows, or nil for cross-platform tabs
    /// (always visible). Used to hide tabs that can't apply to the evidence's
    /// OS - a registry hive can't exist on ext4, `auth.log` can't on NTFS.
    /// Browser history is cross-platform (Chrome/Firefox run on both).
    var osFamily: OSFamily? {
        switch self {
        case .events, .registry, .prefetch, .amcache, .shimcache,
             .lnk, .jumpList, .usn, .srum, .mft, .wmi, .recycleBin:
            return .windows
        case .linuxLogs, .shellHistory, .linuxPersistence, .linuxAccess, .webLogs,
             .packages, .journald, .audit, .syslog, .lastlog:
            return .linux
        case .launchItems, .quarantine, .macPersistence, .fsEvents, .unifiedLog, .tcc, .knowledgeC, .macRecentItems, .macSecurity, .carvedFiles, .kexts, .backgroundItems:
            return .macos
        case .overview, .search, .evidence, .timeline, .browser, .lateral,
             .killChain, .iocs, .annotations, .designUI, .activity, .custody:
            return nil
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
            case .annotationEditor(let draft):
                #if os(macOS)
                AnnotationEditorSheet(draft: draft).environmentObject(model)
                #else
                EmptyView()
                #endif
            case .fileVaultUnlock(let id):
                #if os(macOS)
                FileVaultUnlockSheet(evidenceID: id).environmentObject(model)
                #else
                EmptyView()
                #endif
            }
        }
    }

    #if os(macOS)
    /// Tabs visible for the current scope: cross-platform tabs plus the OS
    /// tabs that apply to the loaded evidence (all of them under "Show all").
    private var visibleSidebarItems: [SidebarItem] {
        SidebarItem.allCases.filter { isVisible($0) }
    }

    /// Single source of truth for tab visibility. Most tabs gate on their one
    /// `osFamily`; Shell History is the exception — zsh/bash history exists on
    /// **both** Linux and macOS, so it shows for either.
    private func isVisible(_ item: SidebarItem) -> Bool {
        if item == .shellHistory { return model.shows(anyOf: [.linux, .macos]) }
        return model.shows(osFamily: item.osFamily)
    }

    private var caseBody: some View {
        NavigationSplitView {
            VStack(spacing: 0) {
                List(visibleSidebarItems, selection: $item) { entry in
                    Label(entry.rawValue, systemImage: entry.symbol).tag(entry)
                }
                // Hide the List's own scroll background so the Theme.bg2 paints
                // straight through; otherwise the sidebar reads as system-dark
                // gray and clashes with the deep blue-teal in the detail pane.
                .scrollContentBackground(.hidden)
                .background(Theme.bg2)
                sidebarOSFooter
            }
            .background(Theme.bg2)
            .navigationTitle(model.currentCase?.name ?? "Strata")
            .navigationSplitViewColumnWidth(min: 200, ideal: 220, max: 320)
        } detail: {
            Group {
                switch item ?? .overview {
                case .overview:  OverviewView()
                case .search:    GlobalSearchView()
                case .evidence:  EvidenceTreeView()
                case .timeline:  TimelineView()
                case .events:    EventsView()
                case .registry:  RegistryView()
                case .prefetch:  PrefetchView()
                case .amcache:   AmcacheView()
                case .shimcache: ShimcacheView()
                case .lnk:       LnkView()
                case .jumpList:  JumpListView()
                case .usn:       UsnView()
                case .srum:      SrumView()
                case .browser:   BrowserHistoryView()
                case .mft:       MftView()
                case .wmi:       WmiView()
                case .recycleBin: RecycleBinView()
                case .linuxLogs: LinuxLogsView()
                case .shellHistory: ShellHistoryView()
                case .linuxPersistence: LinuxPersistenceView()
                case .linuxAccess: LinuxAccessView()
                case .webLogs: WebLogView()
                case .packages: PackageView()
                case .journald: JournaldView()
                case .audit:    AuditView()
                case .syslog:   SyslogView()
                case .lastlog:  LastlogView()
                case .launchItems: LaunchItemsView()
                case .quarantine:  QuarantineView()
                case .macPersistence: MacPersistenceView()
                case .fsEvents:  FSEventsView()
                case .unifiedLog: UnifiedLogView()
                case .tcc:       TCCView()
                case .knowledgeC: KnowledgeCView()
                case .macRecentItems: MacRecentItemsView()
                case .macSecurity: MacSecurityView()
                case .carvedFiles: CarvedFilesView()
                case .kexts: MacKextsView()
                case .backgroundItems: MacBackgroundItemsView()
                case .lateral:   LateralMovementView()
                case .killChain: KillChainView()
                case .iocs:      IOCView()
                case .annotations: AnnotationsView()
                case .designUI:  DesignSurfacesView()
                case .activity:  ActivityLifecycleView()
                case .custody:   ChainOfCustodyView()
                }
            }
            .background(Theme.bg)
            // A pivot request (from the Annotations list or a finding) must
            // also switch the detail pane to the Timeline tab; TimelineView
            // itself consumes the range once it appears.
            .onChange(of: model.timelinePivot) { _, pivot in
                if pivot != nil { item = .timeline }
            }
            // If the scope change hides the currently-selected tab (e.g.
            // switching from a Linux host to a Windows one with Shell History
            // selected), fall back to Overview so the detail pane isn't stuck
            // on a now-hidden, empty tab.
            .onChange(of: model.activeEvidenceID) { _, _ in clampSelection() }
            .onChange(of: model.showAllArtifactTabs) { _, _ in clampSelection() }
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

    /// Shown only when the OS filter is actually doing something - a single-OS
    /// scope (some tabs hidden) or the override already on. Lets the analyst
    /// reveal the hidden tabs without cluttering a mixed/undetermined case.
    @ViewBuilder
    private var sidebarOSFooter: some View {
        let someHidden = visibleSidebarItems.count < SidebarItem.allCases.count
        if someHidden || model.showAllArtifactTabs {
            Divider()
            Toggle(isOn: $model.showAllArtifactTabs) {
                Label("Show all tabs", systemImage: "rectangle.stack")
                    .font(.caption)
            }
            .toggleStyle(.checkbox)
            .controlSize(.small)
            .padding(.horizontal, 12)
            .padding(.vertical, 8)
            .frame(maxWidth: .infinity, alignment: .leading)
            .help("Show artifact tabs for every OS, even ones the loaded evidence doesn't use.")
        }
    }

    /// Reset the selection to Overview when the current tab is no longer
    /// visible for the scope.
    private func clampSelection() {
        if let current = item, !isVisible(current) {
            item = .overview
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
