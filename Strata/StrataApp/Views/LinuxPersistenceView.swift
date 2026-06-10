import SwiftUI

/// Linux persistence mechanisms: cron jobs (system + per-user) and systemd
/// service units. The analyzer flags the suspicious ones; this view lists
/// everything so the analyst can audit the full set.
struct LinuxPersistenceView: View {
    @EnvironmentObject private var model: AppModel
    @State private var query = ""
    @State private var selectedID: LinuxPersistenceEntry.ID?

    private func filtered(_ rows: [LinuxPersistenceEntry]) -> [LinuxPersistenceEntry] {
        guard !query.isEmpty else { return rows }
        return rows.filter {
            $0.command.localizedCaseInsensitiveContains(query)
                || ($0.unitName?.localizedCaseInsensitiveContains(query) ?? false)
                || ($0.user?.localizedCaseInsensitiveContains(query) ?? false)
        }
    }

    var body: some View {
        let rows = model.linuxPersistence
        let visible = filtered(rows)
        return Group {
            if rows.isEmpty {
                ContentUnavailableView {
                    Label("No Linux persistence parsed yet", systemImage: "calendar.badge.clock")
                } description: {
                    Text(model.files.isEmpty
                         ? "Ingest evidence first, then come back here."
                         : "Click Parse to read crontabs and systemd service units from the evidence.")
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
                    HStack {
                        Spacer()
                        TextField("Filter command / unit / user...", text: $query)
                            .textFieldStyle(.roundedBorder)
                            .frame(width: 280)
                    }
                    .padding(8)
                    Divider()
                    split(visible, detail: rows.first { $0.id == selectedID })
                }
            }
        }
        .navigationTitle(rows.isEmpty ? "Linux Persistence" : "Linux Persistence - \(visible.count) of \(rows.count)")
    }

    private func table(_ visible: [LinuxPersistenceEntry]) -> some View {
        Table(visible, selection: $selectedID) {
            TableColumn("Kind") { e in
                Text(e.kind.label).font(.caption).foregroundStyle(.secondary)
            }
            .width(min: 80, ideal: 110, max: 130)
            TableColumn("Schedule / Unit") { e in
                Text(e.kind == .cron ? (e.schedule ?? "—") : (e.unitName ?? "—"))
                    .font(.caption.monospaced())
                    .lineLimit(1)
            }
            .width(min: 110, ideal: 150, max: 220)
            TableColumn("User") { e in
                Text(e.user ?? "—").font(.caption)
            }
            .width(min: 50, ideal: 70, max: 100)
            TableColumn("Command") { e in
                Text(e.command)
                    .font(.caption.monospaced())
                    .lineLimit(1)
                    .truncationMode(.middle)
            }
        }
    }

    @ViewBuilder
    private func split(_ visible: [LinuxPersistenceEntry], detail: LinuxPersistenceEntry?) -> some View {
        #if os(macOS)
        HSplitView {
            table(visible).frame(minWidth: 540, maxHeight: .infinity)
            PersistenceDetailView(entry: detail).frame(minWidth: 280, maxHeight: .infinity)
        }
        #else
        HStack(spacing: 0) {
            table(visible)
            Divider()
            PersistenceDetailView(entry: detail).frame(minWidth: 280, maxHeight: .infinity)
        }
        #endif
    }
}

private struct PersistenceDetailView: View {
    let entry: LinuxPersistenceEntry?
    var body: some View {
        if let entry {
            ScrollView {
                VStack(alignment: .leading, spacing: 10) {
                    Text(entry.title).font(.headline).lineLimit(2)
                    LabeledContent("Kind", value: entry.kind.label)
                    if let schedule = entry.schedule { LabeledContent("Schedule", value: schedule) }
                    if let unit = entry.unitName { LabeledContent("Unit", value: unit) }
                    if let user = entry.user { LabeledContent("User", value: user) }
                    if let detail = entry.detail, !detail.isEmpty {
                        LabeledContent("Description", value: detail)
                    }
                    VStack(alignment: .leading, spacing: 4) {
                        Text("Command").font(.caption.bold()).foregroundStyle(.secondary)
                        Text(entry.command)
                            .font(.system(size: 11, design: .monospaced))
                            .textSelection(.enabled)
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .padding(8)
                            .background(.quaternary.opacity(0.4), in: RoundedRectangle(cornerRadius: 6))
                    }
                    LabeledContent("Source") {
                        Text(entry.sourceFile)
                            .font(.caption.monospaced())
                            .textSelection(.enabled)
                            .frame(maxWidth: .infinity, alignment: .trailing)
                    }
                }
                .padding()
                .frame(maxWidth: .infinity, alignment: .leading)
            }
        } else {
            ContentUnavailableView("Select an entry", systemImage: "calendar.badge.clock")
        }
    }
}
