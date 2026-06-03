import SwiftUI

enum SidebarItem: String, CaseIterable, Identifiable {
    case overview = "Overview"
    case evidence = "Evidence"
    case timeline = "Timeline"
    case events = "Events"
    case lateral = "Lateral"
    case killChain = "Kill Chain"

    var id: String { rawValue }
    var symbol: String {
        switch self {
        case .overview:  return "square.grid.2x2"
        case .evidence:  return "folder"
        case .timeline:  return "clock"
        case .events:    return "doc.text.magnifyingglass"
        case .lateral:   return "point.3.connected.trianglepath.dotted"
        case .killChain: return "link"
        }
    }
}

struct ContentView: View {
    @EnvironmentObject private var model: AppModel
    @State private var item: SidebarItem = .overview

    var body: some View {
        Group {
            if model.currentCase == nil {
                WelcomeView()
            } else {
                caseBody
            }
        }
        .overlay(alignment: .bottom) { statusBar }
        // Hosted at the top level so File > New Case from the menu can show
        // the sheet whether the welcome screen or the case UI is on screen.
        .sheet(isPresented: $model.showingNewCaseSheet) { NewCaseSheet() }
    }

    private var caseBody: some View {
        NavigationSplitView {
            List(SidebarItem.allCases, selection: $item) { entry in
                Label(entry.rawValue, systemImage: entry.symbol).tag(entry)
            }
            .navigationTitle(model.currentCase?.name ?? "Strata")
            .navigationSplitViewColumnWidth(min: 200, ideal: 220, max: 320)
        } detail: {
            Group {
                switch item {
                case .overview:  OverviewView()
                case .evidence:  EvidenceTreeView()
                case .timeline:  TimelineView()
                case .events:    EventsView()
                case .lateral:   LateralMovementView()
                case .killChain: KillChainView()
                }
            }
            .toolbar {
                ToolbarItem(placement: .navigation) {
                    EvidenceScopePicker()
                }
                ToolbarItem(placement: .primaryAction) {
                    Button { openSource() } label: {
                        Label("Add Host...", systemImage: "plus")
                    }
                    .disabled(model.isWorking)
                    .help("Ingest a new disk image or KAPE capture into this case.")
                }
                ToolbarItem(placement: .primaryAction) {
                    Button { model.closeCase() } label: {
                        Label("Close Case", systemImage: "xmark.circle")
                    }
                    .disabled(model.isWorking)
                    .help("Close this case and return to the welcome screen.")
                }
            }
        }
    }

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

    private func openSource() {
        let panel = NSOpenPanel()
        panel.allowsMultipleSelection = true
        panel.canChooseDirectories = true   // allow loose KAPE folders so we can flag them
        panel.canChooseFiles = true
        panel.message = "Select one or more E01 images, KAPE .vhd files, or raw images."
        guard panel.runModal() == .OK else { return }
        // Ingest sequentially: tsk_loaddb is single-threaded and chewing on a
        // disk image, so doing them in parallel would just thrash I/O.
        let urls = panel.urls
        Task {
            for url in urls { await model.ingest(sourceURL: url) }
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
