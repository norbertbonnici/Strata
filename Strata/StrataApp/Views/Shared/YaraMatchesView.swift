import SwiftUI
import UniformTypeIdentifiers

#if os(macOS)
import AppKit
#endif

struct YaraMatchesView: View {
    @EnvironmentObject private var model: AppModel
    @State private var query = ""
    /// Filtered + sorted rows and whether any match exists at all, rebuilt in
    /// `.task(id:)` when the data or the query changes — not in `body`, which
    /// used to filter and sort the full match set twice per render.
    @State private var matches: [YaraMatch] = []
    @State private var hasAnyMatch = false

    private struct Key: Equatable { let query: String; let version: Int }
    private var key: Key { Key(query: query, version: model.dataVersion) }

    var body: some View {
        VStack(spacing: 0) {
            #if os(macOS)
            controls
            Divider()
            #endif
            if matches.isEmpty {
                ContentUnavailableView(
                    hasAnyMatch ? "No Matching Results" : "No YARA Matches",
                    systemImage: "shield.checkered",
                    description: Text(hasAnyMatch
                                      ? "Try a different search."
                                      : "Choose a rules file and scan the evidence."))
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
        .task(id: key) { refresh() }
    }

    private func refresh() {
        let all = model.yaraMatches
        let filtered = query.isEmpty ? all : all.filter {
            $0.rule.localizedCaseInsensitiveContains(query)
                || $0.path.localizedCaseInsensitiveContains(query)
        }
        matches = filtered.sorted { $0.rule < $1.rule }
        hasAnyMatch = !all.isEmpty
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
        // `.yar` / `.yara` have no system UTI — they resolve to dynamic types
        // that don't conform to plain text — so list them explicitly or the
        // panel greys out every conventionally named rules file.
        panel.allowedContentTypes = [.plainText]
            + ["yar", "yara"].compactMap { UTType(filenameExtension: $0) }
        panel.allowsMultipleSelection = false
        panel.canChooseDirectories = false
        guard panel.runModal() == .OK, let url = panel.url else { return }
        model.yaraRulesPath = url.path
        model.saveYaraConfiguration()
    }
    #endif
}
