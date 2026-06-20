import SwiftUI

/// macOS Powerlog: process-execution / app-activity records recovered from the
/// powerd analytics database — process & bundle names, PIDs, app lifecycle, the
/// frontmost app, and per-process network volume, with offset-corrected times.
struct PowerlogView: View {
    @EnvironmentObject private var model: AppModel
    @State private var query = ""
    @State private var kindFilter: PowerlogEntry.Kind?
    @State private var selectedID: PowerlogEntry.ID?
    @State private var sort = [KeyPathComparator(\PowerlogEntry.sortTime, order: .reverse)]

    private func filtered(_ items: [PowerlogEntry]) -> [PowerlogEntry] {
        items.filter { e in
            (kindFilter == nil || e.kind == kindFilter)
            && (query.isEmpty
                || (e.processName?.localizedCaseInsensitiveContains(query) ?? false)
                || (e.bundleID?.localizedCaseInsensitiveContains(query) ?? false)
                || (e.event?.localizedCaseInsensitiveContains(query) ?? false))
        }
    }

    var body: some View {
        let rows = model.powerlog
        let visible = filtered(rows).sorted(using: sort)
        return Group {
            if rows.isEmpty {
                ContentUnavailableView {
                    Label("No Powerlog records parsed yet", systemImage: "bolt.batteryblock")
                } description: {
                    Text(model.files.isEmpty
                         ? "Ingest a macOS image first, then come back here."
                         : "Click Parse to read the Powerlog database.")
                } actions: {
                    #if os(macOS)
                    if !model.files.isEmpty {
                        Button { Task { await model.parseMac() } } label: {
                            Label("Parse macOS artifacts", systemImage: "play.fill")
                        }
                        .disabled(model.isWorking)
                    }
                    #endif
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else {
                VStack(spacing: 0) {
                    HStack(spacing: 12) {
                        Picker("Kind", selection: $kindFilter) {
                            Text("All").tag(PowerlogEntry.Kind?.none)
                            ForEach(PowerlogEntry.Kind.allCases, id: \.self) { k in
                                Text(k.label).tag(PowerlogEntry.Kind?.some(k))
                            }
                        }
                        .pickerStyle(.menu)
                        .frame(width: 200)
                        Spacer()
                        TextField("Filter process / bundle / event...", text: $query)
                            .textFieldStyle(.roundedBorder)
                            .frame(width: 300)
                        #if os(macOS)
                        Button { Task { await model.parseMac() } } label: {
                            Image(systemName: "arrow.clockwise")
                        }
                        .help("Re-parse macOS artifacts")
                        .disabled(model.isWorking)
                        #endif
                    }
                    .padding(8)
                    Divider()
                    split(visible, detail: rows.first { $0.id == selectedID })
                        .frame(maxWidth: .infinity, maxHeight: .infinity)
                }
            }
        }
        .navigationTitle(rows.isEmpty ? "Powerlog"
                         : "Powerlog - \(visible.count.formatted()) of \(rows.count.formatted())")
    }

    private func table(_ visible: [PowerlogEntry]) -> some View {
        Table(visible, selection: $selectedID, sortOrder: $sort) {
            TableColumn("When", value: \.sortTime) { e in
                Text(e.date?.formatted(date: .numeric, time: .standard) ?? "—")
                    .monospacedDigit().font(.caption)
            }
            .width(min: 130, ideal: 150, max: 180)
            TableColumn("Kind") { e in
                Text(e.kind.label).font(.caption).foregroundStyle(.secondary)
            }
            .width(min: 80, ideal: 90, max: 110)
            TableColumn("Process / App") { e in
                Text(e.displayName).font(.callout).lineLimit(1).truncationMode(.middle)
            }
            TableColumn("Detail") { e in
                Text(detail(e)).font(.caption).foregroundStyle(.secondary)
                    .lineLimit(1).truncationMode(.tail)
            }
        }
    }

    private func detail(_ e: PowerlogEntry) -> String {
        switch e.kind {
        case .process:      return e.pid.map { "pid \($0)" } ?? (e.bundleID ?? "")
        case .appLifecycle: return e.event ?? (e.bundleID ?? "")
        case .frontmost:    return e.bundleID ?? ""
        case .network:      return "in \(e.bytesIn ?? 0) / out \(e.bytesOut ?? 0) bytes"
        }
    }

    @ViewBuilder
    private func split(_ visible: [PowerlogEntry], detail: PowerlogEntry?) -> some View {
        #if os(macOS)
        HSplitView {
            table(visible).frame(minWidth: 580, maxHeight: .infinity)
            PowerlogDetailView(entry: detail).frame(minWidth: 280, maxHeight: .infinity)
        }
        #else
        table(visible)
        #endif
    }
}

private extension PowerlogEntry {
    var sortTime: Date { date ?? .distantPast }
}

private struct PowerlogDetailView: View {
    let entry: PowerlogEntry?

    var body: some View {
        if let e = entry {
            ScrollView {
                VStack(alignment: .leading, spacing: 10) {
                    Text(e.displayName).font(.headline).textSelection(.enabled)
                    LabeledContent("Kind", value: e.kind.label)
                    if let b = e.bundleID { LabeledContent("Bundle ID", value: b) }
                    if let p = e.pid { LabeledContent("PID", value: String(p)) }
                    if let ev = e.event, !ev.isEmpty { LabeledContent("Event", value: ev) }
                    LabeledContent("Time", value: e.date?.formatted(date: .long, time: .standard) ?? "—")
                    if let end = e.endDate {
                        LabeledContent("End", value: end.formatted(date: .long, time: .standard))
                    }
                    if e.kind == .network {
                        LabeledContent("Bytes in", value: (e.bytesIn ?? 0).formatted())
                        LabeledContent("Bytes out", value: (e.bytesOut ?? 0).formatted())
                    }
                    Divider()
                    LabeledContent("Source") {
                        Text(e.sourceFile).font(.caption.monospaced()).textSelection(.enabled)
                            .frame(maxWidth: .infinity, alignment: .trailing)
                    }
                }
                .padding()
                .frame(maxWidth: .infinity, alignment: .leading)
            }
        } else {
            ContentUnavailableView("Select a record", systemImage: "bolt.batteryblock")
        }
    }
}
