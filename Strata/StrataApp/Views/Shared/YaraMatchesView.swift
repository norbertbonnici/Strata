import SwiftUI
import UniformTypeIdentifiers

#if os(macOS)
import AppKit
#endif

struct YaraMatchesView: View {
    @EnvironmentObject private var model: AppModel
    @State private var query = ""

    private var matches: [YaraMatch] {
        let values = model.yaraMatches
        guard !query.isEmpty else { return values.sorted { $0.rule < $1.rule } }
        return values.filter {
            $0.rule.localizedCaseInsensitiveContains(query)
                || $0.path.localizedCaseInsensitiveContains(query)
        }.sorted { $0.rule < $1.rule }
    }

    var body: some View {
        VStack(spacing: 0) {
            #if os(macOS)
            controls
            Divider()
            #endif
            if matches.isEmpty {
                ContentUnavailableView(
                    model.yaraMatches.isEmpty ? "No YARA Matches" : "No Matching Results",
                    systemImage: "shield.checkered",
                    description: Text(model.yaraMatches.isEmpty
                                      ? "Choose a rules file and scan the evidence."
                                      : "Try a different search."))
            } else {
                Table(matches) {
                    TableColumn("Rule", value: \.rule).width(min: 180, ideal: 240)
                    TableColumn("Evidence path", value: \.path)
                    TableColumn("Size") { match in
                        Text(ByteCountFormatter.string(fromByteCount: match.fileSize,
                                                       countStyle: .file))
                    }.width(90)
                }
            }
        }
        .navigationTitle("YARA Matches")
        .searchable(text: $query, prompt: "Rule or path")
    }

    #if os(macOS)
    private var controls: some View {
        HStack(spacing: 12) {
            Button(action: chooseRules) {
                Label(model.yaraRulesPath.isEmpty ? "Choose Rules" : "Change Rules",
                      systemImage: "doc.badge.gearshape")
            }
            Text(model.yaraRulesPath.isEmpty ? "No rules selected" : URL(fileURLWithPath: model.yaraRulesPath).lastPathComponent)
                .foregroundStyle(.secondary)
                .lineLimit(1)
            Spacer()
            Stepper("Max file: \(model.yaraMaximumFileMB) MB",
                    value: $model.yaraMaximumFileMB, in: 1...2048, step: 25)
                .fixedSize()
                .onChange(of: model.yaraMaximumFileMB) { _, _ in model.saveYaraConfiguration() }
            Stepper("Files: \(model.yaraMaximumFiles)",
                    value: $model.yaraMaximumFiles, in: 100...100_000, step: 1000)
                .fixedSize()
                .onChange(of: model.yaraMaximumFiles) { _, _ in model.saveYaraConfiguration() }
            Button {
                Task { await model.runYaraScan() }
            } label: {
                Label("Scan", systemImage: "play.fill")
            }
            .buttonStyle(.borderedProminent)
            .disabled(model.isWorking || model.yaraRulesPath.isEmpty)
        }
        .padding(12)
    }

    private func chooseRules() {
        let panel = NSOpenPanel()
        panel.title = "Choose YARA Rules"
        panel.allowedContentTypes = [.plainText]
        panel.allowsMultipleSelection = false
        panel.canChooseDirectories = false
        guard panel.runModal() == .OK, let url = panel.url else { return }
        model.yaraRulesPath = url.path
        model.saveYaraConfiguration()
    }
    #endif
}
