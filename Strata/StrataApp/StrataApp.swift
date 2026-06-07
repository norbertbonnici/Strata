import SwiftUI

@main
struct StrataApp: App {
    @StateObject private var model = AppModel()

    var body: some Scene {
        WindowGroup {
            ContentView()
                .environmentObject(model)
                #if os(macOS)
                .frame(minWidth: 1000, minHeight: 640)
                #endif
                // Force the dark palette on both platforms so system controls
                // (text fields, toolbar buttons, sheets) read correctly against
                // the Theme.bg backgrounds we paint behind them.
                .preferredColorScheme(.dark)
                .tint(Theme.teal2)
        }
        #if os(macOS)
        .windowStyle(.titleBar)
        .commands {
            CaseCommands(model: model)
            ToolsCommands(model: model)
        }
        #endif
    }
}

#if os(macOS)

/// File-menu wiring for case lifecycle. Replaces the default "New Window"
/// item so Cmd-N triggers New Case instead of opening a duplicate window.
private struct CaseCommands: Commands {
    @ObservedObject var model: AppModel

    var body: some Commands {
        CommandGroup(replacing: .newItem) {
            Button("New Case...") { model.requestNewCase() }
                .keyboardShortcut("n", modifiers: [.command])
            Button("Open Case...") { model.requestOpenCase() }
                .keyboardShortcut("o", modifiers: [.command])

            Menu("Open Recent") {
                if model.recentCases.isEmpty {
                    Text("No Recent Cases").foregroundStyle(.secondary)
                } else {
                    ForEach(model.recentCases, id: \.self) { url in
                        Button(url.deletingPathExtension().lastPathComponent) {
                            Task { await model.openCase(at: url) }
                        }
                    }
                }
            }

            Divider()

            Button("Close Case") { model.closeCase() }
                .keyboardShortcut("w", modifiers: [.command, .shift])
                .disabled(model.currentCase == nil)
        }
    }
}
/// Tools menu - hosts enrichment passes that are opt-in rather than part of
/// the standard ingest pipeline (IOC matching today; VT / GeoIP / etc. as
/// they land).
private struct ToolsCommands: Commands {
    @ObservedObject var model: AppModel

    var body: some Commands {
        CommandMenu("Tools") {
            Button("Parse Artifacts") {
                Task { await model.parseArtifacts() }
            }
            .keyboardShortcut("r", modifiers: [.command])
            .disabled(model.currentCase == nil || model.evidenceList.isEmpty || model.isWorking)
            Button("Run Enrichment...") { model.requestEnrichment() }
                .keyboardShortcut("e", modifiers: [.command])
                .disabled(model.currentCase == nil)
            Button("Run IOC Match") {
                Task { await model.runIOCMatch() }
            }
            .disabled(model.currentCase == nil || model.iocs.isEmpty || model.isWorking)

            Divider()

            Button("Export...") { model.requestExport() }
                .keyboardShortcut("e", modifiers: [.command, .shift])
                .disabled(model.currentCase == nil)
        }
    }
}

#endif
