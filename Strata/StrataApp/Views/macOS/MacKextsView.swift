import SwiftUI

/// macOS kernel-extension + System-Extension inventory. Apple-shipped extensions
/// are expected; the analyst's interest is the third-party ones (kernel code or
/// privileged user-space extensions) — a persistence / rootkit vector.
struct MacKextsView: View {
    @EnvironmentObject private var model: AppModel
    @State private var query = ""
    @State private var kind: MacKextEntry.Kind?
    @State private var thirdPartyOnly = false
    @State private var selectedID: MacKextEntry.ID?
    @State private var sort = [KeyPathComparator(\MacKextEntry.title, order: .forward)]

    private func filtered(_ items: [MacKextEntry]) -> [MacKextEntry] {
        var out = items
        if let kind { out = out.filter { $0.kind == kind } }
        if thirdPartyOnly { out = out.filter { !$0.isApple } }
        if !query.isEmpty {
            out = out.filter { e in
                e.bundleID.localizedCaseInsensitiveContains(query)
                    || e.name.localizedCaseInsensitiveContains(query)
                    || (e.teamID?.localizedCaseInsensitiveContains(query) ?? false)
                    || (e.path?.localizedCaseInsensitiveContains(query) ?? false)
            }
        }
        return out
    }

    var body: some View {
        let rows = model.kexts
        let visible = filtered(rows).sorted(using: sort)
        let kinds = Array(Set(rows.map(\.kind))).sorted { $0.label < $1.label }
        return Group {
            if rows.isEmpty {
                ContentUnavailableView {
                    Label("No extensions parsed yet", systemImage: "puzzlepiece.extension")
                } description: {
                    Text(model.files.isEmpty
                         ? "Ingest a macOS image first, then come back here."
                         : "Click Parse to inventory kernel + System extensions.")
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
                        Picker("Type", selection: $kind) {
                            Text("All").tag(MacKextEntry.Kind?.none)
                            ForEach(kinds, id: \.self) { k in
                                Text(k.label).tag(MacKextEntry.Kind?.some(k))
                            }
                        }
                        .pickerStyle(.menu)
                        .frame(width: 190)

                        Toggle("Third-party only", isOn: $thirdPartyOnly)
                            #if os(macOS)
                            .toggleStyle(.checkbox)
                            #endif

                        Spacer()

                        TextField("Filter id / team / path...", text: $query)
                            .textFieldStyle(.roundedBorder)
                            .frame(width: 260)

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
        .navigationTitle(rows.isEmpty ? "Extensions"
                         : "Extensions - \(visible.count.formatted()) of \(rows.count.formatted())")
    }

    private func table(_ visible: [MacKextEntry]) -> some View {
        Table(visible, selection: $selectedID, sortOrder: $sort) {
            TableColumn("Name", value: \.title) { e in
                HStack(spacing: 6) {
                    if !e.isApple {
                        Image(systemName: "exclamationmark.triangle.fill")
                            .foregroundStyle(e.kind == .kext ? .red : .orange)
                            .font(.caption)
                    }
                    Text(e.title).font(.callout).lineLimit(1).truncationMode(.middle)
                }
            }
            TableColumn("Bundle ID", value: \.bundleID) { e in
                Text(e.bundleID).font(.caption.monospaced()).foregroundStyle(.secondary)
                    .lineLimit(1).truncationMode(.middle)
            }
            TableColumn("Type", value: \.sortKind) { e in
                Text(e.kind.label).font(.caption).foregroundStyle(.secondary)
            }
            .width(min: 110, ideal: 130, max: 160)
            TableColumn("Source") { e in
                Text(e.isApple ? "Apple" : (e.teamID.map { "Team \($0)" } ?? "third-party"))
                    .font(.caption).foregroundStyle(e.isApple ? .secondary : .primary)
            }
            .width(min: 90, ideal: 120, max: 160)
        }
    }

    @ViewBuilder
    private func split(_ visible: [MacKextEntry], detail: MacKextEntry?) -> some View {
        #if os(macOS)
        HSplitView {
            table(visible).frame(minWidth: 560, maxHeight: .infinity)
            MacKextDetailView(kext: detail).frame(minWidth: 300, maxHeight: .infinity)
        }
        #else
        table(visible)
        #endif
    }
}

private extension MacKextEntry {
    var sortKind: String { kind.label }
}

private struct MacKextDetailView: View {
    let kext: MacKextEntry?

    var body: some View {
        if let kext {
            ScrollView {
                VStack(alignment: .leading, spacing: 10) {
                    HStack(spacing: 6) {
                        Text(kext.title).font(.headline).textSelection(.enabled)
                        if !kext.isApple {
                            Text(kext.kind == .kext ? "third-party kernel code" : "third-party")
                                .font(.caption2).padding(.horizontal, 6).padding(.vertical, 2)
                                .background(kext.kind == .kext ? Color.red.opacity(0.2) : Color.orange.opacity(0.2))
                                .clipShape(Capsule())
                        }
                    }
                    LabeledContent("Type", value: kext.kind.label)
                    LabeledContent("Bundle ID", value: kext.bundleID)
                    if let v = kext.version { LabeledContent("Version", value: v) }
                    if let t = kext.teamID, !t.isEmpty { LabeledContent("Team ID", value: t) }
                    LabeledContent("Signed by", value: kext.isApple ? "Apple" : "third-party")
                    if let enabled = kext.enabled {
                        LabeledContent("State", value: enabled ? "Enabled / activated" : "Disabled / not activated")
                    }
                    if let p = kext.path {
                        LabeledContent("Path") {
                            Text(p).font(.caption.monospaced()).textSelection(.enabled)
                                .frame(maxWidth: .infinity, alignment: .trailing)
                        }
                    }
                    Divider()
                    LabeledContent("Source") {
                        Text(kext.sourceFile).font(.caption.monospaced()).textSelection(.enabled)
                            .frame(maxWidth: .infinity, alignment: .trailing)
                    }
                }
                .padding()
                .frame(maxWidth: .infinity, alignment: .leading)
            }
        } else {
            ContentUnavailableView("Select an extension", systemImage: "puzzlepiece.extension")
        }
    }
}
