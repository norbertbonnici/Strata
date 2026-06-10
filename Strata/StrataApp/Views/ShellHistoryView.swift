import SwiftUI

/// Parsed shell history across every user on the host. zsh extended / bash
/// HISTTIMEFORMAT entries carry timestamps; plain bash history shows file
/// order only (the line number column keeps the sequence honest).
struct ShellHistoryView: View {
    @EnvironmentObject private var model: AppModel
    @State private var query = ""
    @State private var selectedID: ShellHistoryEntry.ID?
    // Default to file order (user, then line) - most bash entries are undated, so
    // sorting by time would collapse them all to the bottom on first view.
    @State private var sort = [KeyPathComparator(\ShellHistoryEntry.user, order: .forward),
                               KeyPathComparator(\ShellHistoryEntry.lineNumber, order: .forward)]

    private func filtered(_ rows: [ShellHistoryEntry]) -> [ShellHistoryEntry] {
        guard !query.isEmpty else { return rows }
        return rows.filter {
            $0.command.localizedCaseInsensitiveContains(query)
                || $0.user.localizedCaseInsensitiveContains(query)
        }
    }

    var body: some View {
        let rows = model.shellHistory
        let visible = filtered(rows).sorted(using: sort)
        return Group {
            if rows.isEmpty {
                ContentUnavailableView {
                    Label("No shell history parsed yet", systemImage: "terminal")
                } description: {
                    Text(model.files.isEmpty
                         ? "Ingest evidence first, then come back here."
                         : "Click Parse to read each user's .bash_history / .zsh_history.")
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
                        TextField("Filter command / user...", text: $query)
                            .textFieldStyle(.roundedBorder)
                            .frame(width: 280)
                    }
                    .padding(8)
                    Divider()
                    split(visible, detail: rows.first { $0.id == selectedID })
                }
            }
        }
        .navigationTitle(rows.isEmpty ? "Shell History" : "Shell History - \(visible.count) of \(rows.count)")
    }

    private func table(_ visible: [ShellHistoryEntry]) -> some View {
        Table(visible, selection: $selectedID, sortOrder: $sort) {
            TableColumn("User", value: \.user) { e in
                Text(e.user).font(.caption)
            }
            .width(min: 60, ideal: 80, max: 120)
            TableColumn("Shell", value: \.sortShell) { e in
                Text(e.shell.label).font(.caption).foregroundStyle(.secondary)
            }
            .width(min: 45, ideal: 50, max: 60)
            TableColumn("#", value: \.lineNumber) { e in
                Text(String(e.lineNumber)).font(.caption.monospacedDigit())
                    .foregroundStyle(.secondary)
            }
            .width(min: 40, ideal: 50, max: 60)
            TableColumn("Time", value: \.sortTime) { e in
                Text(e.timestamp.map { $0.formatted(date: .numeric, time: .standard) } ?? "—")
                    .monospacedDigit()
            }
            .width(min: 130, ideal: 150, max: 170)
            TableColumn("Command", value: \.command) { e in
                Text(e.command)
                    .font(.caption.monospaced())
                    .lineLimit(1)
                    .truncationMode(.tail)
            }
        }
    }

    @ViewBuilder
    private func split(_ visible: [ShellHistoryEntry], detail: ShellHistoryEntry?) -> some View {
        #if os(macOS)
        HSplitView {
            table(visible).frame(minWidth: 540, maxHeight: .infinity)
            ShellDetailView(entry: detail).frame(minWidth: 280, maxHeight: .infinity)
        }
        #else
        HStack(spacing: 0) {
            table(visible)
            Divider()
            ShellDetailView(entry: detail).frame(minWidth: 280, maxHeight: .infinity)
        }
        #endif
    }
}

/// Non-optional sort keys for the sortable shell-history `Table`.
private extension ShellHistoryEntry {
    var sortTime: Date { timestamp ?? .distantPast }
    var sortShell: String { shell.label }
}

private struct ShellDetailView: View {
    let entry: ShellHistoryEntry?
    var body: some View {
        if let entry {
            ScrollView {
                VStack(alignment: .leading, spacing: 10) {
                    Text("\(entry.user) · \(entry.shell.label)").font(.headline)
                    LabeledContent("Line", value: String(entry.lineNumber))
                    LabeledContent("Time", value: entry.timestamp.map {
                        $0.formatted(date: .numeric, time: .standard) } ?? "— (no timestamp in history)")
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
            ContentUnavailableView("Select a command", systemImage: "terminal")
        }
    }
}
