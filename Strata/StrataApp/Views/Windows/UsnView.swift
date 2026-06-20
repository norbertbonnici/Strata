import SwiftUI

/// Parsed NTFS USN change-journal records (`$Extend\$UsnJrnl:$J`) for the active
/// scope: per-file create / delete / rename evidence with NTFS-generated
/// timestamps that recovers names of files the live filesystem no longer shows.
struct UsnView: View {
    @EnvironmentObject private var model: AppModel
    @State private var query = ""
    @State private var onlyKeyChanges = false
    @State private var selectedID: UsnRecord.ID?

    private func filtered(_ records: [UsnRecord]) -> [UsnRecord] {
        var rows = records
        if onlyKeyChanges {
            rows = rows.filter { $0.isCreate || $0.isDelete || $0.isRename }
        }
        guard !query.isEmpty else { return rows }
        return rows.filter { r in
            r.fileName.localizedCaseInsensitiveContains(query)
                || r.reasonSummary.localizedCaseInsensitiveContains(query)
        }
    }

    var body: some View {
        let records = model.usn
        let visible = filtered(records)
        return Group {
            if records.isEmpty {
                ContentUnavailableView {
                    Label("No USN journal parsed yet", systemImage: "doc.badge.clock")
                } description: {
                    Text(model.files.isEmpty
                         ? "Ingest evidence first, then come back here."
                         : "Click Parse to extract and parse the NTFS change journal ($UsnJrnl:$J).")
                } actions: {
                    #if os(macOS)
                    if !model.files.isEmpty {
                        Button { Task { await model.parseArtifacts() } } label: {
                            Label("Parse artifacts", systemImage: "play.fill")
                        }
                        .disabled(model.isWorking)
                        .help("Parse event logs, registry, shortcuts, and the USN journal, then run all analyzers.")
                    }
                    #endif
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else {
                VStack(spacing: 0) {
                    HStack(spacing: 12) {
                        Toggle("Key changes only", isOn: $onlyKeyChanges)
                            #if os(macOS)
                            .toggleStyle(.checkbox)
                            #endif
                            .help("Show only create / delete / rename records.")
                        Spacer()
                        TextField("Filter name / reason...", text: $query)
                            .textFieldStyle(.roundedBorder)
                            .frame(width: 320)
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
                    split(visible, detail: records.first { $0.id == selectedID })
                        .frame(maxWidth: .infinity, maxHeight: .infinity)
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .top)
            }
        }
        .navigationTitle(records.isEmpty ? "USN Journal" : "USN Journal - \(visible.count) of \(records.count)")
    }

    private func table(_ visible: [UsnRecord]) -> some View {
        Table(visible, selection: $selectedID) {
            TableColumn("Name") { r in
                HStack(spacing: 4) {
                    Image(systemName: r.isDirectory ? "folder" : "doc")
                        .foregroundStyle(.secondary).font(.caption2)
                    Text(r.fileName).font(.caption).lineLimit(1).truncationMode(.middle)
                }
            }
            TableColumn("Reasons") { r in
                Text(r.reasonSummary).font(.caption).lineLimit(1).truncationMode(.tail)
                    .foregroundStyle(color(for: r))
            }
            TableColumn("When") { r in
                Text(r.timestamp?.formatted(date: .numeric, time: .standard) ?? "—")
                    .font(.caption).monospacedDigit()
            }
            TableColumn("MFT") { r in
                Text("\(r.mftEntry)").font(.caption).monospacedDigit().foregroundStyle(.secondary)
            }
        }
        .frame(minWidth: 600, maxHeight: .infinity)
    }

    private func color(for r: UsnRecord) -> Color {
        if r.isDelete { return .red }
        if r.isCreate { return .green }
        if r.isRename { return .orange }
        return .primary
    }

    @ViewBuilder
    private func split(_ visible: [UsnRecord], detail: UsnRecord?) -> some View {
        #if os(macOS)
        HSplitView {
            table(visible)
            UsnDetailView(record: detail).frame(minWidth: 300, maxHeight: .infinity)
        }
        #else
        HStack(spacing: 0) {
            table(visible)
            Divider()
            UsnDetailView(record: detail).frame(minWidth: 300, maxHeight: .infinity)
        }
        #endif
    }
}

private struct UsnDetailView: View {
    let record: UsnRecord?
    var body: some View {
        if let record {
            ScrollView {
                VStack(alignment: .leading, spacing: 10) {
                    Text(record.fileName).font(.headline)
                    LabeledContent("Type", value: record.isDirectory ? "Directory" : "File")
                    LabeledContent("Reasons") {
                        Text(record.reasonSummary).font(.caption).textSelection(.enabled)
                            .frame(maxWidth: .infinity, alignment: .trailing)
                    }
                    if let t = record.timestamp {
                        LabeledContent("When", value: t.formatted(date: .abbreviated, time: .standard))
                    }
                    LabeledContent("USN", value: "\(record.usn)")
                    LabeledContent("MFT entry", value: "\(record.mftEntry)")
                    LabeledContent("MFT sequence", value: "\(record.mftSequence)")
                    LabeledContent("Parent MFT", value: "\(record.parentMftEntry)")
                    LabeledContent("File attributes",
                                   value: String(format: "0x%08X", record.fileAttributes))
                    LabeledContent("Source") {
                        Text(record.sourceFile).font(.caption.monospaced()).textSelection(.enabled)
                            .frame(maxWidth: .infinity, alignment: .trailing)
                    }
                }
                .padding()
                .frame(maxWidth: .infinity, alignment: .leading)
            }
        } else {
            ContentUnavailableView("Select a record", systemImage: "doc.badge.clock")
        }
    }
}
