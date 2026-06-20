import SwiftUI

/// systemd journal (journald) entries - on a modern host this is the primary
/// log, carrying auth / service / kernel events that on older hosts would be in
/// auth.log/syslog. Priority-coloured, filterable by program/unit and free
/// text, capped for table responsiveness.
struct JournaldView: View {
    @EnvironmentObject private var model: AppModel
    @State private var query = ""
    @State private var errorsOnly = false   // priority <= 3 (err and worse)
    @State private var selectedID: JournaldEntry.ID?
    @State private var sort = [KeyPathComparator(\JournaldEntry.sortTime, order: .reverse)]

    private static let maxRows = 20_000

    private func filtered(_ rows: [JournaldEntry]) -> [JournaldEntry] {
        var out = rows
        if errorsOnly { out = out.filter { ($0.priority ?? 6) <= 3 } }
        if !query.isEmpty {
            out = out.filter {
                $0.message.localizedCaseInsensitiveContains(query)
                    || ($0.program?.localizedCaseInsensitiveContains(query) ?? false)
                    || ($0.unit?.localizedCaseInsensitiveContains(query) ?? false)
            }
        }
        return out
    }

    var body: some View {
        let rows = model.journald
        // Sort before the row cap so the visible slice honours the chosen order.
        let all = filtered(rows).sorted(using: sort)
        let visible = Array(all.prefix(Self.maxRows))
        return Group {
            if rows.isEmpty {
                ContentUnavailableView {
                    Label("No journal parsed yet", systemImage: "doc.text.below.ecg")
                } description: {
                    Text(model.files.isEmpty
                         ? "Ingest evidence first, then come back here."
                         : "Click Parse to decode the systemd journal (/var/log/journal).")
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
                        Toggle("Errors only (≤ err)", isOn: $errorsOnly)
                            .toggleStyle(.switch).controlSize(.small)
                        Spacer()
                        TextField("Filter message / program / unit...", text: $query)
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
        .navigationTitle(rows.isEmpty ? "Journal" : "Journal - \(all.count.formatted()) of \(rows.count.formatted())")
    }

    private func table(_ visible: [JournaldEntry]) -> some View {
        Table(visible, selection: $selectedID, sortOrder: $sort) {
            TableColumn("Time", value: \.sortTime) { e in
                Text(e.timestamp.map { $0.formatted(date: .numeric, time: .standard) } ?? "—")
                    .monospacedDigit()
            }
            .width(min: 130, ideal: 150, max: 170)
            TableColumn("Pri", value: \.sortPriority) { e in
                Text(e.priorityLabel ?? "—")
                    .font(.caption2.bold())
                    .foregroundStyle(priorityColor(e.priority))
            }
            .width(min: 44, ideal: 52, max: 64)
            TableColumn("Program", value: \.sortProgram) { e in
                Text(e.program ?? "—").font(.caption).foregroundStyle(.secondary).lineLimit(1)
            }
            .width(min: 80, ideal: 110, max: 160)
            TableColumn("Message", value: \.message) { e in
                Text(e.message).font(.caption.monospaced()).lineLimit(1).truncationMode(.tail)
            }
        }
    }

    private func priorityColor(_ priority: Int?) -> Color {
        switch priority ?? 6 {
        case 0...2:  return .red       // emerg/alert/crit
        case 3:      return .orange    // err
        case 4:      return .yellow    // warning
        default:     return .secondary // notice/info/debug
        }
    }

    @ViewBuilder
    private func split(_ visible: [JournaldEntry], detail: JournaldEntry?) -> some View {
        #if os(macOS)
        HSplitView {
            table(visible).frame(minWidth: 560, maxHeight: .infinity)
            JournaldDetailView(entry: detail).frame(minWidth: 280, maxHeight: .infinity)
        }
        #else
        HStack(spacing: 0) {
            table(visible)
            Divider()
            JournaldDetailView(entry: detail).frame(minWidth: 280, maxHeight: .infinity)
        }
        #endif
    }
}

/// Non-optional sort keys for the sortable `Table` columns.
private extension JournaldEntry {
    var sortTime: Date { timestamp ?? .distantPast }
    var sortPriority: Int { priority ?? 6 }   // default to "info" when absent
    var sortProgram: String { program ?? "" }
}

private struct JournaldDetailView: View {
    let entry: JournaldEntry?
    var body: some View {
        if let entry {
            ScrollView {
                VStack(alignment: .leading, spacing: 10) {
                    Text(entry.program ?? "journal").font(.headline)
                    LabeledContent("Time", value: entry.timestamp.map {
                        $0.formatted(date: .numeric, time: .standard) } ?? "—")
                    if let p = entry.priorityLabel { LabeledContent("Priority", value: p) }
                    if let u = entry.unit { LabeledContent("Unit", value: u) }
                    if let c = entry.comm { LabeledContent("Comm", value: c) }
                    if let pid = entry.pid { LabeledContent("PID", value: String(pid)) }
                    if let uid = entry.uid { LabeledContent("UID", value: String(uid)) }
                    if let h = entry.hostname { LabeledContent("Hostname", value: h) }
                    VStack(alignment: .leading, spacing: 4) {
                        Text("Message").font(.caption.bold()).foregroundStyle(.secondary)
                        Text(entry.message.isEmpty ? "(unavailable — compressed value)" : entry.message)
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
            ContentUnavailableView("Select an entry", systemImage: "doc.text.below.ecg")
        }
    }
}
