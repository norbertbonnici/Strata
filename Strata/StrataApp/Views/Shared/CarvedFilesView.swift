import SwiftUI

/// Files recovered by raw-image **signature carving** (`FileCarver`) — content
/// found by magic header independent of the filesystem, reaching deleted files
/// in unallocated space and bytes libfsapfs won't surface (sealed System
/// snapshot, locked FileVault). Carved entries carry no timestamps, so there's
/// no timeline projection.
struct CarvedFilesView: View {
    @EnvironmentObject private var model: AppModel
    @State private var query = ""
    @State private var kind: CarvedFile.Kind?
    @State private var selectedID: CarvedFile.ID?
    @State private var sort = [KeyPathComparator(\CarvedFile.offset, order: .forward)]

    private func filtered(_ items: [CarvedFile]) -> [CarvedFile] {
        var out = items
        if let kind { out = out.filter { $0.kind == kind } }
        if !query.isEmpty {
            out = out.filter { f in
                f.kind.label.localizedCaseInsensitiveContains(query)
                    || f.source.localizedCaseInsensitiveContains(query)
                    || String(f.offset, radix: 16).localizedCaseInsensitiveContains(query)
            }
        }
        return out
    }

    var body: some View {
        let rows = model.carvedFiles
        let visible = filtered(rows).sorted(using: sort)
        let kinds = Array(Set(rows.map(\.kind))).sorted { $0.label < $1.label }
        return Group {
            if rows.isEmpty {
                ContentUnavailableView {
                    Label("No carved files yet", systemImage: "doc.badge.arrow.up")
                } description: {
                    Text(model.hasApfsHost
                         ? "Carve the APFS image to recover deleted / sealed / encrypted-volume files by signature."
                         : "Carving runs on the macOS APFS ingest path. Ingest an APFS image first.")
                } actions: {
                    #if os(macOS)
                    if model.hasApfsHost {
                        Button { Task { await model.carveArtifacts() } } label: {
                            Label("Carve deleted files", systemImage: "play.fill")
                        }
                        .disabled(model.isWorking)
                    }
                    #endif
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else {
                VStack(spacing: 0) {
                    HStack(spacing: 12) {
                        Picker("Type", selection: $kind) {
                            Text("All").tag(CarvedFile.Kind?.none)
                            ForEach(kinds, id: \.self) { k in
                                Text(k.label).tag(CarvedFile.Kind?.some(k))
                            }
                        }
                        .pickerStyle(.menu)
                        .frame(width: 200)

                        Spacer()

                        TextField("Filter type / offset / source...", text: $query)
                            .textFieldStyle(.roundedBorder)
                            .frame(width: 280)

                        #if os(macOS)
                        Button { Task { await model.carveArtifacts() } } label: {
                            Image(systemName: "arrow.clockwise")
                        }
                        .help("Re-carve the APFS image")
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
        .navigationTitle(rows.isEmpty ? "Carved Files"
                         : "Carved Files - \(visible.count.formatted()) of \(rows.count.formatted())")
    }

    private func table(_ visible: [CarvedFile]) -> some View {
        Table(visible, selection: $selectedID, sortOrder: $sort) {
            TableColumn("Offset", value: \.offset) { f in
                Text("0x" + String(f.offset, radix: 16))
                    .font(.caption.monospaced())
            }
            .width(min: 110, ideal: 140, max: 180)

            TableColumn("Type", value: \.sortKind) { f in
                Text(f.kind.label).font(.caption).foregroundStyle(.secondary)
            }
            .width(min: 120, ideal: 150, max: 200)

            TableColumn("Size", value: \.size) { f in
                Text((f.sizeExact ? "" : "~") + Self.sizeText(f.size))
                    .font(.caption.monospaced())
                    .foregroundStyle(f.sizeExact ? .primary : .secondary)
            }
            .width(min: 90, ideal: 110, max: 140)

            TableColumn("Source", value: \.source) { f in
                Text(f.source).font(.caption).foregroundStyle(.secondary)
                    .lineLimit(1).truncationMode(.middle)
            }
        }
    }

    @ViewBuilder
    private func split(_ visible: [CarvedFile], detail: CarvedFile?) -> some View {
        #if os(macOS)
        HSplitView {
            table(visible).frame(minWidth: 560, maxHeight: .infinity)
            CarvedFileDetailView(file: detail).frame(minWidth: 300, maxHeight: .infinity)
                .environmentObject(model)
        }
        #else
        table(visible)
        #endif
    }

    static func sizeText(_ bytes: Int64) -> String {
        ByteCountFormatter.string(fromByteCount: bytes, countStyle: .file)
    }
}

private extension CarvedFile {
    var sortKind: String { kind.label }
}

private struct CarvedFileDetailView: View {
    @EnvironmentObject private var model: AppModel
    let file: CarvedFile?

    var body: some View {
        if let file {
            ScrollView {
                VStack(alignment: .leading, spacing: 10) {
                    Text(file.kind.label).font(.headline).textSelection(.enabled)
                    LabeledContent("Offset", value: "0x" + String(file.offset, radix: 16)
                                   + " (\(file.offset.formatted()))")
                    LabeledContent("Size", value: (file.sizeExact ? "" : "~")
                                   + CarvedFilesView.sizeText(file.size)
                                   + (file.sizeExact ? "" : " (capped — no recoverable length)"))
                    LabeledContent("Source image", value: file.source)
                    Text("Recovered by signature carving from the raw image — independent of the "
                         + "filesystem. An inexact size is a cap; the real file may be shorter.")
                        .font(.caption).foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                    #if os(macOS)
                    Divider()
                    Button {
                        save(file)
                    } label: {
                        Label("Save recovered bytes...", systemImage: "square.and.arrow.down")
                    }
                    .disabled(model.isWorking)
                    #endif
                }
                .padding()
                .frame(maxWidth: .infinity, alignment: .leading)
            }
        } else {
            ContentUnavailableView("Select a carved file", systemImage: "doc.badge.arrow.up")
        }
    }

    #if os(macOS)
    private func save(_ file: CarvedFile) {
        guard let data = model.carvedFileData(file) else {
            model.errorMessage = "Couldn't read the carved bytes from the source image."
            return
        }
        let panel = NSSavePanel()
        panel.nameFieldStringValue = file.suggestedName
        guard panel.runModal() == .OK, let url = panel.url else { return }
        do { try data.write(to: url) }
        catch { model.errorMessage = error.localizedDescription }
    }
    #endif
}
