import SwiftUI

/// Parsed NTFS `$MFT` records for the active scope: every file/dir with its
/// `$STANDARD_INFORMATION` and `$FILE_NAME` MACB sets side by side. The "Anomalies
/// only" toggle narrows to records whose `$SI` creation predates their `$FN`
/// creation — the timestomping tell.
struct MftView: View {
    @EnvironmentObject private var model: AppModel
    @State private var query = ""
    @State private var anomaliesOnly = false
    @State private var selectedID: MftEntry.ID?

    private func filtered(_ rows: [MftEntry]) -> [MftEntry] {
        var out = rows
        if anomaliesOnly { out = out.filter { $0.siCreatedPredatesFn } }
        guard !query.isEmpty else { return out }
        return out.filter { e in
            (e.fullPath?.localizedCaseInsensitiveContains(query) ?? false)
                || (e.fileName?.localizedCaseInsensitiveContains(query) ?? false)
        }
    }

    var body: some View {
        let rows = model.mft
        let visible = filtered(rows)
        let anomalyCount = rows.lazy.filter { $0.siCreatedPredatesFn }.count
        return Group {
            if rows.isEmpty {
                ContentUnavailableView {
                    Label("No $MFT parsed yet", systemImage: "tablecells")
                } description: {
                    Text(model.files.isEmpty
                         ? "Ingest evidence first, then come back here."
                         : "Click Parse to extract and parse the NTFS $MFT (true MACB + timestomp detection).")
                } actions: {
                    #if os(macOS)
                    if !model.files.isEmpty {
                        Button { Task { await model.parseArtifacts() } } label: {
                            Label("Parse artifacts", systemImage: "play.fill")
                        }
                        .disabled(model.isWorking)
                        .help("Parse event logs, registry, artifacts, and the $MFT, then run all analyzers.")
                    }
                    #endif
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else {
                VStack(spacing: 0) {
                    HStack(spacing: 12) {
                        Toggle(isOn: $anomaliesOnly) {
                            Label("Anomalies only (\(anomalyCount))", systemImage: "exclamationmark.triangle")
                        }
                        .toggleStyle(.switch)
                        Spacer()
                        TextField("Filter path / name...", text: $query)
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
        .navigationTitle(rows.isEmpty ? "MFT" : "MFT - \(visible.count) of \(rows.count)")
    }

    private func table(_ visible: [MftEntry]) -> some View {
        Table(visible, selection: $selectedID) {
            TableColumn("Name") { e in
                HStack(spacing: 5) {
                    if e.siCreatedPredatesFn {
                        Image(systemName: "exclamationmark.triangle.fill")
                            .foregroundStyle(.orange).font(.caption2)
                    }
                    Text(e.fileName ?? "—").font(.caption).lineLimit(1).truncationMode(.middle)
                }
            }
            TableColumn("Path") { e in
                Text(e.fullPath ?? "—").font(.caption2).foregroundStyle(.secondary)
                    .lineLimit(1).truncationMode(.head)
            }
            TableColumn("$SI Created") { e in
                Text(Self.fmt(e.siCreated)).font(.caption).monospacedDigit()
                    .foregroundStyle(e.siCreatedPredatesFn ? .orange : .primary)
            }
            TableColumn("$FN Created") { e in
                Text(Self.fmt(e.fnCreated)).font(.caption).monospacedDigit().foregroundStyle(.secondary)
            }
        }
        .frame(minWidth: 600, maxHeight: .infinity)
    }

    @ViewBuilder
    private func split(_ visible: [MftEntry], detail: MftEntry?) -> some View {
        #if os(macOS)
        HSplitView {
            table(visible)
            MftDetailView(entry: detail).frame(minWidth: 320, maxHeight: .infinity)
        }
        #else
        HStack(spacing: 0) {
            table(visible)
            Divider()
            MftDetailView(entry: detail).frame(minWidth: 320, maxHeight: .infinity)
        }
        #endif
    }

    static func fmt(_ d: Date?) -> String {
        d?.formatted(date: .numeric, time: .standard) ?? "—"
    }
}

private struct MftDetailView: View {
    let entry: MftEntry?
    var body: some View {
        if let entry {
            ScrollView {
                VStack(alignment: .leading, spacing: 10) {
                    Text(entry.fileName ?? "MFT #\(entry.recordNumber)").font(.headline).lineLimit(2)
                    if entry.siCreatedPredatesFn {
                        Label("$SI creation predates $FN creation — possible timestomping (T1070.006)",
                              systemImage: "exclamationmark.triangle.fill")
                            .font(.caption).foregroundStyle(.orange)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                    if let path = entry.fullPath {
                        LabeledContent("Path") {
                            Text(path).font(.caption.monospaced()).textSelection(.enabled)
                                .frame(maxWidth: .infinity, alignment: .trailing)
                        }
                    }
                    LabeledContent("Record", value: "\(entry.recordNumber) (seq \(entry.sequence))")
                    LabeledContent("Type", value: entry.isDirectory ? "Directory" : "File")
                    LabeledContent("State", value: entry.inUse ? "Allocated" : "Deleted")
                    if let size = entry.size { LabeledContent("Size", value: "\(size) bytes") }

                    Divider()
                    Text("$STANDARD_INFORMATION").font(.caption.bold()).foregroundStyle(.secondary)
                    timeRow("Created", entry.siCreated, flag: entry.siCreatedPredatesFn)
                    timeRow("Modified", entry.siModified)
                    timeRow("MFT changed", entry.siChanged)
                    timeRow("Accessed", entry.siAccessed)

                    Divider()
                    Text("$FILE_NAME (not timestomp-settable)").font(.caption.bold()).foregroundStyle(.secondary)
                    timeRow("Created", entry.fnCreated)
                    timeRow("Modified", entry.fnModified)
                    timeRow("MFT changed", entry.fnChanged)
                    timeRow("Accessed", entry.fnAccessed)

                    LabeledContent("Source") {
                        Text(entry.sourceFile).font(.caption.monospaced()).textSelection(.enabled)
                            .frame(maxWidth: .infinity, alignment: .trailing)
                    }
                }
                .padding()
                .frame(maxWidth: .infinity, alignment: .leading)
            }
        } else {
            ContentUnavailableView("Select a record", systemImage: "tablecells")
        }
    }

    private func timeRow(_ label: String, _ date: Date?, flag: Bool = false) -> some View {
        LabeledContent(label) {
            Text(date?.formatted(date: .abbreviated, time: .standard) ?? "—")
                .font(.caption.monospaced())
                .foregroundStyle(flag ? .orange : .primary)
        }
    }
}
