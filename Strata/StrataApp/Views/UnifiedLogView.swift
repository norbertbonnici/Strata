import SwiftUI

/// macOS **unified log** (`.tracev3`) entries — the primary macOS telemetry
/// (process execution, auth, TCC, network). Level-coloured, filterable by
/// process / message and free text, capped for table responsiveness.
struct UnifiedLogView: View {
    @EnvironmentObject private var model: AppModel
    @State private var query = ""
    @State private var errorsOnly = false   // error + fault
    @State private var selectedID: UnifiedLogEntry.ID?
    @State private var sort = [KeyPathComparator(\UnifiedLogEntry.sortTime, order: .reverse)]

    private static let maxRows = 20_000

    private func filtered(_ rows: [UnifiedLogEntry]) -> [UnifiedLogEntry] {
        var out = rows
        if errorsOnly { out = out.filter { $0.level == .error || $0.level == .fault } }
        if !query.isEmpty {
            out = out.filter {
                $0.message.localizedCaseInsensitiveContains(query)
                    || ($0.process?.localizedCaseInsensitiveContains(query) ?? false)
                    || ($0.subsystem?.localizedCaseInsensitiveContains(query) ?? false)
            }
        }
        return out
    }

    var body: some View {
        let rows = model.unifiedLog
        let all = filtered(rows).sorted(using: sort)
        let visible = Array(all.prefix(Self.maxRows))
        return Group {
            if rows.isEmpty {
                ContentUnavailableView {
                    Label("No unified log parsed yet", systemImage: "list.bullet.rectangle")
                } description: {
                    Text(model.files.isEmpty
                         ? "Ingest a macOS image first, then come back here."
                         : "Click Parse to decode the unified log (/var/db/diagnostics).")
                } actions: {
                    #if os(macOS)
                    if !model.files.isEmpty {
                        Button { Task { await model.parseArtifacts() } } label: {
                            Label("Parse artifacts", systemImage: "play.fill")
                        }
                        .disabled(model.isWorking)
                    }
                    #endif
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else {
                VStack(spacing: 0) {
                    HStack(spacing: 12) {
                        Toggle("Errors only", isOn: $errorsOnly)
                            .toggleStyle(.switch).controlSize(.small)
                        Spacer()
                        TextField("Filter message / process...", text: $query)
                            .textFieldStyle(.roundedBorder).frame(width: 300)
                    }
                    .padding(8)
                    if all.count > visible.count {
                        HStack(spacing: 6) {
                            Image(systemName: "info.circle")
                            Text("Showing first \(visible.count.formatted()) of \(all.count.formatted()) — filter to narrow.")
                                .font(.caption).foregroundStyle(.secondary)
                            Spacer()
                        }
                        .padding(.horizontal, 8).padding(.vertical, 4)
                        .background(Color.secondary.opacity(0.08))
                    }
                    Divider()
                    split(visible, detail: rows.first { $0.id == selectedID })
                }
            }
        }
        .navigationTitle(rows.isEmpty ? "Unified Log" : "Unified Log - \(all.count.formatted()) of \(rows.count.formatted())")
    }

    private func table(_ visible: [UnifiedLogEntry]) -> some View {
        Table(visible, selection: $selectedID, sortOrder: $sort) {
            TableColumn("Time", value: \.sortTime) { e in
                Text(e.timestamp.map { $0.formatted(date: .numeric, time: .standard) } ?? "—")
                    .monospacedDigit()
            }
            .width(min: 130, ideal: 150, max: 170)
            TableColumn("Level", value: \.sortLevel) { e in
                Text(e.level.label)
                    .font(.caption2.bold())
                    .foregroundStyle(levelColor(e.level))
            }
            .width(min: 50, ideal: 60, max: 72)
            TableColumn("Process", value: \.sortProcess) { e in
                Text(e.process ?? "—").font(.caption).foregroundStyle(.secondary).lineLimit(1)
            }
            .width(min: 90, ideal: 130, max: 200)
            TableColumn("Message", value: \.message) { e in
                Text(e.message).font(.caption.monospaced()).lineLimit(1).truncationMode(.tail)
            }
        }
    }

    private func levelColor(_ level: UnifiedLogEntry.Level) -> Color {
        switch level {
        case .fault:   return .red
        case .error:   return .orange
        case .debug:   return .secondary
        default:       return .primary
        }
    }

    @ViewBuilder
    private func split(_ visible: [UnifiedLogEntry], detail: UnifiedLogEntry?) -> some View {
        #if os(macOS)
        HSplitView {
            table(visible).frame(minWidth: 560, maxHeight: .infinity)
            UnifiedLogDetailView(entry: detail).frame(minWidth: 280, maxHeight: .infinity)
        }
        #else
        HStack(spacing: 0) {
            table(visible)
            Divider()
            UnifiedLogDetailView(entry: detail).frame(minWidth: 280, maxHeight: .infinity)
        }
        #endif
    }
}

/// Non-optional sort keys for the sortable `Table` columns.
private extension UnifiedLogEntry {
    var sortTime: Date { timestamp ?? .distantPast }
    var sortLevel: String { level.rawValue }
    var sortProcess: String { process ?? "" }
}

private struct UnifiedLogDetailView: View {
    let entry: UnifiedLogEntry?
    var body: some View {
        if let entry {
            ScrollView {
                VStack(alignment: .leading, spacing: 10) {
                    Text(entry.process ?? "unified log").font(.headline)
                    LabeledContent("Time", value: entry.timestamp.map {
                        $0.formatted(date: .numeric, time: .standard) } ?? "—")
                    LabeledContent("Type", value: entry.eventType.label)
                    LabeledContent("Level", value: entry.level.label)
                    if let pid = entry.pid { LabeledContent("PID", value: String(pid)) }
                    if let s = entry.subsystem { LabeledContent("Subsystem", value: s) }
                    if let c = entry.category { LabeledContent("Category", value: c) }
                    VStack(alignment: .leading, spacing: 4) {
                        Text("Message").font(.caption.bold()).foregroundStyle(.secondary)
                        Text(entry.message.isEmpty ? "(message could not be resolved)" : entry.message)
                            .font(.system(size: 11, design: .monospaced))
                            .foregroundStyle(entry.message.isEmpty ? .secondary : .primary)
                            .textSelection(.enabled)
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .padding(8)
                            .background(.quaternary.opacity(0.4), in: RoundedRectangle(cornerRadius: 6))
                    }
                    LabeledContent("Source") {
                        Text(entry.sourceFile).font(.caption.monospaced()).textSelection(.enabled)
                            .frame(maxWidth: .infinity, alignment: .trailing)
                    }
                }
                .padding()
                .frame(maxWidth: .infinity, alignment: .leading)
            }
        } else {
            ContentUnavailableView("Select an entry", systemImage: "list.bullet.rectangle")
        }
    }
}
