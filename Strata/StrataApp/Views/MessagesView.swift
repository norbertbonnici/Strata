import SwiftUI

/// macOS Messages (`chat.db`) — iMessage / SMS conversations recovered for
/// triage (delivery vectors, exfil-over-messaging, social graph).
struct MessagesView: View {
    @EnvironmentObject private var model: AppModel
    @State private var query = ""
    @State private var receivedOnly = false
    @State private var selectedID: MessageEntry.ID?
    @State private var sort = [KeyPathComparator(\MessageEntry.sortTime, order: .reverse)]

    private func filtered(_ items: [MessageEntry]) -> [MessageEntry] {
        var out = items
        if receivedOnly { out = out.filter { !$0.isFromMe } }
        if !query.isEmpty {
            out = out.filter { m in
                (m.text?.localizedCaseInsensitiveContains(query) ?? false)
                    || (m.handle?.localizedCaseInsensitiveContains(query) ?? false)
                    || (m.chatName?.localizedCaseInsensitiveContains(query) ?? false)
                    || (m.service?.localizedCaseInsensitiveContains(query) ?? false)
            }
        }
        return out
    }

    var body: some View {
        let rows = model.messages
        let visible = filtered(rows).sorted(using: sort)
        return Group {
            if rows.isEmpty {
                ContentUnavailableView {
                    Label("No messages parsed yet", systemImage: "message")
                } description: {
                    Text(model.files.isEmpty
                         ? "Ingest a macOS image first, then come back here."
                         : "Click Parse to read the Messages database (chat.db).")
                } actions: {
                    #if os(macOS)
                    if !model.files.isEmpty {
                        Button { Task { await model.parseMessages() } } label: {
                            Label("Parse Messages", systemImage: "play.fill")
                        }
                        .disabled(model.isWorking)
                    }
                    #endif
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else {
                VStack(spacing: 0) {
                    HStack(spacing: 12) {
                        Toggle("Received only", isOn: $receivedOnly)
                            #if os(macOS)
                            .toggleStyle(.checkbox)
                            #endif
                        Spacer()
                        TextField("Filter text / handle / chat...", text: $query)
                            .textFieldStyle(.roundedBorder)
                            .frame(width: 280)
                        #if os(macOS)
                        Button { Task { await model.parseMessages() } } label: {
                            Image(systemName: "arrow.clockwise")
                        }
                        .help("Re-parse Messages")
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
        .navigationTitle(rows.isEmpty ? "Messages"
                         : "Messages - \(visible.count.formatted()) of \(rows.count.formatted())")
    }

    private func table(_ visible: [MessageEntry]) -> some View {
        Table(visible, selection: $selectedID, sortOrder: $sort) {
            TableColumn("When", value: \.sortTime) { m in
                Text(m.timestamp?.formatted(date: .numeric, time: .standard) ?? "—")
                    .monospacedDigit().font(.caption)
            }
            .width(min: 130, ideal: 150, max: 180)
            TableColumn("Dir") { m in
                Text(m.isFromMe ? "→ Sent" : "← Recv")
                    .font(.caption).foregroundStyle(m.isFromMe ? .secondary : .primary)
            }
            .width(min: 56, ideal: 64, max: 80)
            TableColumn("Counterpart") { m in
                Text(m.counterpart).font(.caption).lineLimit(1).truncationMode(.middle)
            }
            .width(min: 120, ideal: 160, max: 220)
            TableColumn("Message") { m in
                HStack(spacing: 4) {
                    if m.hasAttachment { Image(systemName: "paperclip").font(.caption2).foregroundStyle(.secondary) }
                    Text(m.preview).font(.callout).lineLimit(1).truncationMode(.tail)
                }
            }
        }
    }

    @ViewBuilder
    private func split(_ visible: [MessageEntry], detail: MessageEntry?) -> some View {
        #if os(macOS)
        HSplitView {
            table(visible).frame(minWidth: 560, maxHeight: .infinity)
            MessageDetailView(message: detail).frame(minWidth: 300, maxHeight: .infinity)
        }
        #else
        table(visible)
        #endif
    }
}

private extension MessageEntry {
    var sortTime: Date { timestamp ?? .distantPast }
}

private struct MessageDetailView: View {
    let message: MessageEntry?

    var body: some View {
        if let message {
            ScrollView {
                VStack(alignment: .leading, spacing: 10) {
                    Text("\(message.direction) — \(message.counterpart)")
                        .font(.headline).textSelection(.enabled)
                    LabeledContent("When", value: message.timestamp?.formatted(date: .long, time: .standard) ?? "—")
                    if let s = message.service { LabeledContent("Service", value: s) }
                    if let c = message.chatName, !c.isEmpty { LabeledContent("Chat", value: c) }
                    if message.hasAttachment { LabeledContent("Attachment", value: "yes") }
                    Divider()
                    Text(message.text ?? (message.hasAttachment ? "(attachment, no text)" : "(no text)"))
                        .font(.body).textSelection(.enabled)
                        .frame(maxWidth: .infinity, alignment: .leading)
                    Divider()
                    LabeledContent("Source") {
                        Text(message.sourceFile).font(.caption.monospaced()).textSelection(.enabled)
                            .frame(maxWidth: .infinity, alignment: .trailing)
                    }
                }
                .padding()
                .frame(maxWidth: .infinity, alignment: .leading)
            }
        } else {
            ContentUnavailableView("Select a message", systemImage: "message")
        }
    }
}
