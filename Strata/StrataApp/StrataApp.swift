import SwiftUI

@main
struct StrataApp: App {
    @StateObject private var model = AppModel()

    var body: some Scene {
        WindowGroup {
            ContentView()
                .environmentObject(model)
                .frame(minWidth: 1000, minHeight: 640)
        }
        .windowStyle(.titleBar)
        .commands { CaseCommands(model: model) }
    }
}

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
