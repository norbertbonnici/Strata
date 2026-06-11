import SwiftUI

/// macOS launchd persistence — LaunchAgents / LaunchDaemons parsed from the
/// host's plists. Column-sortable + filterable; flags surface via Findings.
struct MacLaunchItemsView: View {
    @EnvironmentObject private var model: AppModel
    @State private var query = ""
    @State private var sort = [KeyPathComparator(\LaunchItemEntry.label, order: .forward)]

    private func filtered(_ rows: [LaunchItemEntry]) -> [LaunchItemEntry] {
        guard !query.isEmpty else { return rows }
        return rows.filter {
            $0.label.localizedCaseInsensitiveContains(query)
                || $0.commandLine.localizedCaseInsensitiveContains(query)
                || $0.plistPath.localizedCaseInsensitiveContains(query)
        }
    }

    var body: some View {
        let rows = model.launchItems
        let visible = filtered(rows).sorted(using: sort)
        return Group {
            if rows.isEmpty {
                emptyState(symbol: "powerplug",
                           text: "Click Parse to read launchd plists (/Library/Launch{Agents,Daemons}, ~/Library/LaunchAgents).")
            } else {
                VStack(spacing: 0) {
                    filterBar
                    Divider()
                    Table(visible, sortOrder: $sort) {
                        TableColumn("Label", value: \.label) { e in
                            Text(e.label).font(.caption.monospaced()).lineLimit(1).truncationMode(.middle)
                        }
                        TableColumn("Scope", value: \.sortScope) { e in
                            Text(e.scope.label).font(.caption).foregroundStyle(.secondary)
                        }
                        .width(min: 90, ideal: 110, max: 140)
                        TableColumn("Run@Load", value: \.sortRunAtLoad) { e in
                            Text(e.runAtLoad ? "yes" : "—")
                                .font(.caption).foregroundStyle(e.runAtLoad ? Color.orange : .secondary)
                        }
                        .width(min: 60, ideal: 70, max: 90)
                        TableColumn("Command") { e in
                            Text(e.commandLine).font(.caption.monospaced())
                                .lineLimit(1).truncationMode(.middle).help(e.commandLine)
                        }
                    }
                }
            }
        }
        .navigationTitle(rows.isEmpty ? "Launch Items" : "Launch Items - \(visible.count) of \(rows.count)")
    }

    private var filterBar: some View {
        HStack { Spacer()
            TextField("Filter label / command / path…", text: $query)
                .textFieldStyle(.roundedBorder).frame(width: 300)
        }.padding(8)
    }

    @ViewBuilder
    private func emptyState(symbol: String, text: String) -> some View {
        ContentUnavailableView {
            Label("No launch items parsed yet", systemImage: symbol)
        } description: { Text(model.files.isEmpty ? "Ingest a macOS image first." : text) } actions: {
            #if os(macOS)
            if !model.files.isEmpty {
                Button { Task { await model.parseArtifacts() } } label: { Label("Parse artifacts", systemImage: "play.fill") }
                    .disabled(model.isWorking)
            }
            #endif
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }
}

private extension LaunchItemEntry {
    var sortScope: String { scope.label }
    var sortRunAtLoad: Int { runAtLoad ? 0 : 1 }
}

/// macOS LaunchServices quarantine — where each downloaded file came from and
/// which app pulled it. Column-sortable + filterable.
struct MacQuarantineView: View {
    @EnvironmentObject private var model: AppModel
    @State private var query = ""
    @State private var sort = [KeyPathComparator(\QuarantineEvent.sortTime, order: .reverse)]

    private func filtered(_ rows: [QuarantineEvent]) -> [QuarantineEvent] {
        guard !query.isEmpty else { return rows }
        return rows.filter {
            ($0.dataURL?.localizedCaseInsensitiveContains(query) ?? false)
                || ($0.originURL?.localizedCaseInsensitiveContains(query) ?? false)
                || ($0.agentName?.localizedCaseInsensitiveContains(query) ?? false)
        }
    }

    var body: some View {
        let rows = model.quarantine
        let visible = filtered(rows).sorted(using: sort)
        return Group {
            if rows.isEmpty {
                ContentUnavailableView {
                    Label("No quarantine records parsed yet", systemImage: "shield.lefthalf.filled")
                } description: {
                    Text(model.files.isEmpty ? "Ingest a macOS image first."
                         : "Click Parse to read the LaunchServices quarantine store.")
                } actions: {
                    #if os(macOS)
                    if !model.files.isEmpty {
                        Button { Task { await model.parseArtifacts() } } label: { Label("Parse artifacts", systemImage: "play.fill") }
                            .disabled(model.isWorking)
                    }
                    #endif
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else {
                VStack(spacing: 0) {
                    HStack { Spacer()
                        TextField("Filter URL / origin / agent…", text: $query)
                            .textFieldStyle(.roundedBorder).frame(width: 300)
                    }.padding(8)
                    Divider()
                    Table(visible, sortOrder: $sort) {
                        TableColumn("When", value: \.sortTime) { e in
                            Text(e.timestamp.map { $0.formatted(date: .numeric, time: .standard) } ?? "—").monospacedDigit()
                        }
                        .width(min: 130, ideal: 150, max: 170)
                        TableColumn("Agent", value: \.sortAgent) { e in
                            Text(e.agentName ?? "—").font(.caption).foregroundStyle(.secondary).lineLimit(1)
                        }
                        .width(min: 90, ideal: 120, max: 160)
                        TableColumn("Downloaded") { e in
                            Text(e.dataURL ?? "—").font(.caption.monospaced()).lineLimit(1).truncationMode(.middle).help(e.dataURL ?? "")
                        }
                        TableColumn("From (origin)") { e in
                            Text(e.originURL ?? "—").font(.caption).foregroundStyle(.secondary)
                                .lineLimit(1).truncationMode(.middle).help(e.originURL ?? "")
                        }
                    }
                }
            }
        }
        .navigationTitle(rows.isEmpty ? "Quarantine" : "Quarantine - \(visible.count) of \(rows.count)")
    }
}

private extension QuarantineEvent {
    var sortTime: Date { timestamp ?? .distantPast }
    var sortAgent: String { agentName ?? "" }
}
