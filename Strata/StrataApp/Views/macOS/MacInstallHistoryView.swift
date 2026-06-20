import SwiftUI

/// macOS Installs: the software-install history (InstallHistory.plist + PackageKit
/// receipts) — what software/OS/profile was installed, when, and by which process.
struct MacInstallHistoryView: View {
    @EnvironmentObject private var model: AppModel
    @State private var query = ""
    @State private var selectedID: MacInstallEntry.ID?
    @State private var sort = [KeyPathComparator(\MacInstallEntry.sortTime, order: .reverse)]

    private func filtered(_ items: [MacInstallEntry]) -> [MacInstallEntry] {
        guard !query.isEmpty else { return items }
        return items.filter { e in
            e.displayTitle.localizedCaseInsensitiveContains(query)
            || (e.processName?.localizedCaseInsensitiveContains(query) ?? false)
            || e.packageIdentifiers.contains { $0.localizedCaseInsensitiveContains(query) }
        }
    }

    var body: some View {
        let rows = model.installHistory
        let visible = filtered(rows).sorted(using: sort)
        return Group {
            if rows.isEmpty {
                ContentUnavailableView {
                    Label("No install history parsed yet", systemImage: "app.badge.checkmark")
                } description: {
                    Text(model.files.isEmpty
                         ? "Ingest a macOS image first, then come back here."
                         : "Click Parse to read the install history and receipts.")
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
                        Spacer()
                        TextField("Filter name / process / package id...", text: $query)
                            .textFieldStyle(.roundedBorder)
                            .frame(width: 320)
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
        .navigationTitle(rows.isEmpty ? "Installs"
                         : "Installs - \(visible.count.formatted()) of \(rows.count.formatted())")
    }

    private func table(_ visible: [MacInstallEntry]) -> some View {
        Table(visible, selection: $selectedID, sortOrder: $sort) {
            TableColumn("When", value: \.sortTime) { e in
                Text(e.date?.formatted(date: .numeric, time: .standard) ?? "—")
                    .monospacedDigit().font(.caption)
            }
            .width(min: 130, ideal: 150, max: 180)
            TableColumn("Software") { e in
                Text(e.displayTitle).font(.callout).lineLimit(1).truncationMode(.middle)
            }
            TableColumn("Version") { e in
                Text(e.version ?? "—").font(.caption).foregroundStyle(.secondary).lineLimit(1)
            }
            .width(min: 70, ideal: 90, max: 130)
            TableColumn("Installed by") { e in
                Text(e.processName ?? "—").font(.caption).foregroundStyle(.secondary).lineLimit(1)
            }
            .width(min: 100, ideal: 130, max: 180)
        }
    }

    @ViewBuilder
    private func split(_ visible: [MacInstallEntry], detail: MacInstallEntry?) -> some View {
        #if os(macOS)
        HSplitView {
            table(visible).frame(minWidth: 560, maxHeight: .infinity)
            MacInstallDetailView(entry: detail).frame(minWidth: 300, maxHeight: .infinity)
        }
        #else
        table(visible)
        #endif
    }
}

private extension MacInstallEntry {
    var sortTime: Date { date ?? .distantPast }
}

private struct MacInstallDetailView: View {
    let entry: MacInstallEntry?

    var body: some View {
        if let e = entry {
            ScrollView {
                VStack(alignment: .leading, spacing: 10) {
                    Text(e.displayTitle).font(.headline).textSelection(.enabled)
                    if let v = e.version { LabeledContent("Version", value: v) }
                    LabeledContent("Installed", value: e.date?.formatted(date: .long, time: .standard) ?? "—")
                    if let p = e.processName { LabeledContent("Installed by", value: p) }
                    if let c = e.contentType { LabeledContent("Content type", value: c) }
                    LabeledContent("Source", value: e.source.label)
                    if let f = e.packageFile { LabeledContent("Package file", value: f) }
                    if let pre = e.installPrefix { LabeledContent("Install prefix", value: pre) }
                    if !e.packageIdentifiers.isEmpty {
                        Divider()
                        Text("Package identifiers").font(.caption).foregroundStyle(.secondary)
                        ForEach(e.packageIdentifiers, id: \.self) { pid in
                            Text(pid).font(.caption.monospaced()).textSelection(.enabled)
                        }
                    }
                    Divider()
                    LabeledContent("File") {
                        Text(e.sourceFile).font(.caption.monospaced()).textSelection(.enabled)
                            .frame(maxWidth: .infinity, alignment: .trailing)
                    }
                }
                .padding()
                .frame(maxWidth: .infinity, alignment: .leading)
            }
        } else {
            ContentUnavailableView("Select an install", systemImage: "app.badge.checkmark")
        }
    }
}
