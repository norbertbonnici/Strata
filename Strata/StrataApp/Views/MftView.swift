import SwiftUI
#if os(macOS)
import AppKit
#endif

/// NTFS `$MFT` records as a **per-volume tree** (like the Evidence tab), with a
/// detail pane that shows the full lossless 100-ns `$SI`/`$FN` timestamps and any
/// resident `$DATA` (small files recoverable straight from the MFT). The
/// "Anomalies only" filter narrows the tree to suspected timestomping.
struct MftView: View {
    @EnvironmentObject private var model: AppModel
    @State private var query = ""
    @State private var anomaliesOnly = false
    @State private var selection: MftEntry?
    @State private var tree: [MftNode] = []
    @State private var debounce: Task<Void, Never>?

    private func keep(_ e: MftEntry) -> Bool {
        if anomaliesOnly && !e.siCreatedPredatesFn { return false }
        guard !query.isEmpty else { return true }
        return (e.fullPath?.localizedCaseInsensitiveContains(query) ?? false)
            || (e.fileName?.localizedCaseInsensitiveContains(query) ?? false)
    }

    var body: some View {
        let rows = model.mft
        let anomalyCount = rows.lazy.filter { $0.siCreatedPredatesFn }.count
        return Group {
            if rows.isEmpty {
                ContentUnavailableView {
                    Label("No $MFT parsed yet", systemImage: "tablecells")
                } description: {
                    Text(model.files.isEmpty
                         ? "Ingest evidence first, then come back here."
                         : "Click Parse to extract and parse the NTFS $MFT (true MACB, timestomp detection, resident-file recovery).")
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
                        if anomalyCount > 0 {
                            Toggle(isOn: $anomaliesOnly) {
                                Label("Anomalies only (\(anomalyCount))", systemImage: "exclamationmark.triangle")
                            }
                            .toggleStyle(.switch).controlSize(.small)
                        }
                        Spacer()
                        TextField("Filter path / name...", text: $query)
                            .textFieldStyle(.roundedBorder).frame(width: 280)
                        Text("\(rows.count.formatted()) records").font(.caption).foregroundStyle(.secondary)
                    }
                    .padding(.horizontal, 12).padding(.vertical, 6)
                    Divider()
                    split.frame(maxWidth: .infinity, maxHeight: .infinity)
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .top)
            }
        }
        .navigationTitle("MFT")
        .onAppear { rebuild() }
        .onChange(of: model.dataVersion) {
            rebuild()
            if let sel = selection { selection = model.mft.first { $0.id == sel.id } }
        }
        // Debounce the free-text filter: a full O(n log n) tree rebuild on every
        // keystroke would stutter on a million-record $MFT.
        .onChange(of: query) {
            debounce?.cancel()
            debounce = Task {
                try? await Task.sleep(for: .milliseconds(250))
                guard !Task.isCancelled else { return }
                rebuild()
            }
        }
        .onChange(of: anomaliesOnly) { rebuild() }
    }

    private func rebuild() {
        tree = MftNode.buildTree(from: model.mft.filter(keep))
    }

    private var mftTree: some View {
        List {
            OutlineGroup(tree, children: \.children) { node in
                HStack(spacing: 6) {
                    Image(systemName: icon(node))
                        .foregroundStyle(node.isVolume ? Color.accentColor
                                         : (node.entry?.siCreatedPredatesFn == true ? .orange : .secondary))
                    Text(node.name).fontWeight(node.isVolume ? .semibold : .regular)
                        .lineLimit(1).truncationMode(.middle)
                    if node.entry?.hasResidentData == true {
                        Image(systemName: "doc.text.below.ecg").font(.caption2).foregroundStyle(.teal)
                            .help("Has resident $DATA — recoverable from the MFT")
                    }
                    if node.entry?.inUse == false {
                        Text("deleted").font(.caption2).padding(.horizontal, 5).padding(.vertical, 1)
                            .background(.red.opacity(0.2), in: Capsule()).foregroundStyle(.red)
                    }
                    Spacer()
                    if let e = node.entry, !e.isDirectory, let s = e.size {
                        Text(ByteCountFormatter.string(fromByteCount: s, countStyle: .file))
                            .font(.caption).foregroundStyle(.secondary)
                    }
                }
                .contentShape(Rectangle())
                .onTapGesture { if let e = node.entry { selection = e } }
            }
        }
        .frame(minWidth: 360, maxHeight: .infinity)
    }

    private func icon(_ node: MftNode) -> String {
        if node.isVolume { return "internaldrive" }
        if node.entry?.siCreatedPredatesFn == true { return "exclamationmark.triangle.fill" }
        return (node.entry?.isDirectory ?? true) ? "folder" : "doc"
    }

    @ViewBuilder private var split: some View {
        #if os(macOS)
        HSplitView { mftTree; MftDetailView(entry: selection).frame(minWidth: 320, maxHeight: .infinity) }
        #else
        HStack(spacing: 0) {
            mftTree; Divider(); MftDetailView(entry: selection).frame(minWidth: 320, maxHeight: .infinity)
        }
        #endif
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
                        labeled("Path", path, mono: true)
                    }
                    LabeledContent("Volume", value: entry.volume)
                    LabeledContent("Record", value: "\(entry.recordNumber) (seq \(entry.sequence))")
                    LabeledContent("Type", value: entry.isDirectory ? "Directory" : "File")
                    LabeledContent("State", value: entry.inUse ? "Allocated" : "Deleted")
                    if let size = entry.size { LabeledContent("Size", value: "\(size.formatted()) bytes") }

                    timeBlock("$STANDARD_INFORMATION",
                              [("Created", entry.siCreatedRaw, entry.siCreatedPredatesFn),
                               ("Modified", entry.siModifiedRaw, false),
                               ("MFT changed", entry.siChangedRaw, false),
                               ("Accessed", entry.siAccessedRaw, false)])
                    timeBlock("$FILE_NAME (not timestomp-settable)",
                              [("Created", entry.fnCreatedRaw, false),
                               ("Modified", entry.fnModifiedRaw, false),
                               ("MFT changed", entry.fnChangedRaw, false),
                               ("Accessed", entry.fnAccessedRaw, false)])

                    if let data = entry.residentData, !data.isEmpty {
                        residentSection(data, name: entry.fileName)
                    }
                    labeled("Source", entry.sourceFile, mono: true)
                }
                .padding()
                .frame(maxWidth: .infinity, alignment: .leading)
            }
        } else {
            ContentUnavailableView("Select a record", systemImage: "tablecells")
        }
    }

    private func timeBlock(_ title: String, _ rows: [(String, UInt64, Bool)]) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            Divider()
            Text(title).font(.caption.bold()).foregroundStyle(.secondary)
            ForEach(rows, id: \.0) { (label, raw, flag) in
                LabeledContent(label) {
                    Text(FileTime.precise(raw) ?? "—")   // full 100-ns precision
                        .font(.caption.monospaced()).textSelection(.enabled)
                        .foregroundStyle(flag ? .orange : .primary)
                        .frame(maxWidth: .infinity, alignment: .trailing)
                }
            }
        }
    }

    @ViewBuilder private func residentSection(_ data: Data, name: String?) -> some View {
        Divider()
        HStack {
            Text("Resident $DATA — \(data.count) bytes").font(.caption.bold()).foregroundStyle(.teal)
            Spacer()
            #if os(macOS)
            Button("Save…") { saveResident(data, name: name) }.controlSize(.small)
            #endif
        }
        Text(Self.hexDump(data, max: 512))
            .font(.system(size: 10.5, design: .monospaced))
            .textSelection(.enabled)
            .padding(8)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(.quaternary.opacity(0.4), in: RoundedRectangle(cornerRadius: 6))
    }

    private func labeled(_ title: String, _ value: String, mono: Bool) -> some View {
        LabeledContent(title) {
            Text(value).font(mono ? .caption.monospaced() : .caption).textSelection(.enabled)
                .frame(maxWidth: .infinity, alignment: .trailing)
        }
    }

    /// Compact hex+ASCII dump of the first `max` bytes.
    static func hexDump(_ data: Data, max: Int) -> String {
        let slice = Array(data.prefix(max))
        var out = ""
        var i = 0
        while i < slice.count {
            let row = slice[i ..< Swift.min(i + 16, slice.count)]
            let hex = row.map { String(format: "%02x", $0) }.joined(separator: " ")
                .padding(toLength: 47, withPad: " ", startingAt: 0)
            let ascii = String(row.map { (32...126).contains($0) ? Character(UnicodeScalar($0)) : "." })
            out += String(format: "%04x  ", i) + hex + "  " + ascii + "\n"
            i += 16
        }
        if data.count > max { out += "… (\(data.count - max) more bytes)\n" }
        return out
    }

    #if os(macOS)
    private func saveResident(_ data: Data, name: String?) {
        let panel = NSSavePanel()
        panel.nameFieldStringValue = name ?? "resident.bin"
        panel.canCreateDirectories = true
        if panel.runModal() == .OK, let url = panel.url { try? data.write(to: url) }
    }
    #endif
}
