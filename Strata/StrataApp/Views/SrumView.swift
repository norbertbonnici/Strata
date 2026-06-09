import SwiftUI

/// Parsed Windows SRUM (`SRUDB.dat`) rows for the active scope: per-application
/// network byte volume and execution/resource usage, time-bucketed, with the
/// AppId/UserId foreign keys resolved to application paths and user SIDs.
struct SrumView: View {
    @EnvironmentObject private var model: AppModel
    @State private var query = ""
    @State private var kindFilter: SrumEntry.Kind?
    @State private var selectedID: SrumEntry.ID?

    private func filtered(_ rows: [SrumEntry]) -> [SrumEntry] {
        var out = rows
        if let kindFilter { out = out.filter { $0.kind == kindFilter } }
        guard !query.isEmpty else { return out }
        return out.filter { r in
            (r.application?.localizedCaseInsensitiveContains(query) ?? false)
                || (r.userSID?.localizedCaseInsensitiveContains(query) ?? false)
        }
    }

    var body: some View {
        let rows = model.srum
        let visible = filtered(rows)
        return Group {
            if rows.isEmpty {
                ContentUnavailableView {
                    Label("No SRUM parsed yet", systemImage: "chart.bar.doc.horizontal")
                } description: {
                    Text(model.files.isEmpty
                         ? "Ingest evidence first, then come back here."
                         : "Click Parse to extract and parse the SRUM database (SRUDB.dat).")
                } actions: {
                    #if os(macOS)
                    if !model.files.isEmpty {
                        Button { Task { await model.parseArtifacts() } } label: {
                            Label("Parse artifacts", systemImage: "play.fill")
                        }
                        .disabled(model.isWorking)
                        .help("Parse event logs, registry, artifacts, and SRUM, then run all analyzers.")
                    }
                    #endif
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else {
                VStack(spacing: 0) {
                    HStack(spacing: 12) {
                        Picker("Kind", selection: $kindFilter) {
                            Text("All").tag(SrumEntry.Kind?.none)
                            ForEach(SrumEntry.Kind.allCases, id: \.self) { k in
                                Text(k.label).tag(SrumEntry.Kind?.some(k))
                            }
                        }
                        .pickerStyle(.menu)
                        .frame(width: 200)
                        Spacer()
                        TextField("Filter application / user SID...", text: $query)
                            .textFieldStyle(.roundedBorder)
                            .frame(width: 300)
                        #if os(macOS)
                        Button { Task { await model.parseArtifacts() } } label: {
                            Image(systemName: "arrow.clockwise")
                        }
                        .help("Re-parse artifacts, then re-run analyzers")
                        .disabled(model.isWorking)
                        #endif
                    }
                    .padding(8)
                    Divider()
                    split(visible, detail: rows.first { $0.id == selectedID })
                        .frame(maxWidth: .infinity, maxHeight: .infinity)
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .top)
            }
        }
        .navigationTitle(rows.isEmpty ? "SRUM" : "SRUM - \(visible.count) of \(rows.count)")
    }

    private func table(_ visible: [SrumEntry]) -> some View {
        Table(visible, selection: $selectedID) {
            TableColumn("Application") { r in
                Text(r.appShortName).font(.caption).lineLimit(1).truncationMode(.middle)
            }
            TableColumn("Kind") { r in
                Text(r.kind.label).font(.caption).foregroundStyle(.secondary)
            }
            TableColumn("Detail") { r in
                Text(r.detailSummary).font(.caption).monospacedDigit().lineLimit(1)
            }
            TableColumn("When") { r in
                Text(r.timestamp?.formatted(date: .numeric, time: .standard) ?? "—")
                    .font(.caption).monospacedDigit()
            }
        }
        .frame(minWidth: 600, maxHeight: .infinity)
    }

    @ViewBuilder
    private func split(_ visible: [SrumEntry], detail: SrumEntry?) -> some View {
        #if os(macOS)
        HSplitView {
            table(visible)
            SrumDetailView(entry: detail).frame(minWidth: 300, maxHeight: .infinity)
        }
        #else
        HStack(spacing: 0) {
            table(visible)
            Divider()
            SrumDetailView(entry: detail).frame(minWidth: 300, maxHeight: .infinity)
        }
        #endif
    }
}

private struct SrumDetailView: View {
    let entry: SrumEntry?
    var body: some View {
        if let entry {
            ScrollView {
                VStack(alignment: .leading, spacing: 10) {
                    Text(entry.appShortName).font(.headline)
                    LabeledContent("Kind", value: entry.kind.label)
                    if let app = entry.application {
                        LabeledContent("Application") {
                            Text(app).font(.caption.monospaced()).textSelection(.enabled)
                                .frame(maxWidth: .infinity, alignment: .trailing)
                        }
                    }
                    if let sid = entry.userSID {
                        LabeledContent("User SID") {
                            Text(sid).font(.caption.monospaced()).textSelection(.enabled)
                                .frame(maxWidth: .infinity, alignment: .trailing)
                        }
                    }
                    if let t = entry.timestamp {
                        LabeledContent("Timestamp", value: t.formatted(date: .abbreviated, time: .standard))
                    }
                    if let s = entry.bytesSent { LabeledContent("Bytes sent", value: SrumEntry.humanBytes(s)) }
                    if let r = entry.bytesReceived { LabeledContent("Bytes received", value: SrumEntry.humanBytes(r)) }
                    if let r = entry.bytesRead { LabeledContent("Bytes read", value: SrumEntry.humanBytes(r)) }
                    if let w = entry.bytesWritten { LabeledContent("Bytes written", value: SrumEntry.humanBytes(w)) }
                    if let cs = entry.connectStart { LabeledContent("Connection start", value: cs.formatted(date: .abbreviated, time: .standard)) }
                    if let cd = entry.connectedSeconds { LabeledContent("Connected", value: SrumEntry.humanDuration(cd)) }
                    if let luid = entry.interfaceLuid { LabeledContent("Interface LUID", value: "\(luid)") }
                    LabeledContent("Source") {
                        Text(entry.sourceFile).font(.caption.monospaced()).textSelection(.enabled)
                            .frame(maxWidth: .infinity, alignment: .trailing)
                    }
                }
                .padding()
                .frame(maxWidth: .infinity, alignment: .leading)
            }
        } else {
            ContentUnavailableView("Select a row", systemImage: "chart.bar.doc.horizontal")
        }
    }
}
