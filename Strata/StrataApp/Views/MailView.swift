import SwiftUI

/// macOS Mail (`Envelope Index`) — message summaries (sender / subject / mailbox
/// / dates) recovered for triage. Bodies live in per-message `.emlx` files and
/// aren't parsed here.
struct MailView: View {
    @EnvironmentObject private var model: AppModel
    @State private var query = ""
    @State private var receivedOnly = false
    @State private var selectedID: MailMessageEntry.ID?
    @State private var sort = [KeyPathComparator(\MailMessageEntry.sortTime, order: .reverse)]

    private func filtered(_ items: [MailMessageEntry]) -> [MailMessageEntry] {
        var out = items
        if receivedOnly { out = out.filter { !$0.isSent } }
        if !query.isEmpty {
            out = out.filter { m in
                (m.subject?.localizedCaseInsensitiveContains(query) ?? false)
                    || (m.sender?.localizedCaseInsensitiveContains(query) ?? false)
                    || (m.recipients?.localizedCaseInsensitiveContains(query) ?? false)
                    || (m.mailbox?.localizedCaseInsensitiveContains(query) ?? false)
            }
        }
        return out
    }

    var body: some View {
        let rows = model.mail
        let visible = filtered(rows).sorted(using: sort)
        return Group {
            if rows.isEmpty {
                ContentUnavailableView {
                    Label("No mail parsed yet", systemImage: "envelope")
                } description: {
                    Text(model.files.isEmpty
                         ? "Ingest a macOS image first, then come back here."
                         : "Click Parse to read the Mail Envelope Index.")
                } actions: {
                    #if os(macOS)
                    if !model.files.isEmpty {
                        Button { Task { await model.parseMail() } } label: {
                            Label("Parse Mail", systemImage: "play.fill")
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
                        TextField("Filter subject / sender / mailbox...", text: $query)
                            .textFieldStyle(.roundedBorder)
                            .frame(width: 280)
                        #if os(macOS)
                        Button { Task { await model.parseMail() } } label: {
                            Image(systemName: "arrow.clockwise")
                        }
                        .help("Re-parse Mail")
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
        .navigationTitle(rows.isEmpty ? "Mail"
                         : "Mail - \(visible.count.formatted()) of \(rows.count.formatted())")
    }

    private func table(_ visible: [MailMessageEntry]) -> some View {
        Table(visible, selection: $selectedID, sortOrder: $sort) {
            TableColumn("When", value: \.sortTime) { m in
                Text(m.timestamp?.formatted(date: .numeric, time: .standard) ?? "—")
                    .monospacedDigit().font(.caption)
            }
            .width(min: 130, ideal: 150, max: 180)
            TableColumn("Dir") { m in
                Text(m.isSent ? "→ Sent" : "← Recv")
                    .font(.caption).foregroundStyle(m.isSent ? .secondary : .primary)
            }
            .width(min: 56, ideal: 64, max: 80)
            TableColumn("From / To") { m in
                Text(m.counterpart).font(.caption).lineLimit(1).truncationMode(.middle)
            }
            .width(min: 140, ideal: 200, max: 280)
            TableColumn("Subject") { m in
                Text(m.displaySubject).font(.callout).lineLimit(1).truncationMode(.tail)
            }
        }
    }

    @ViewBuilder
    private func split(_ visible: [MailMessageEntry], detail: MailMessageEntry?) -> some View {
        #if os(macOS)
        HSplitView {
            table(visible).frame(minWidth: 560, maxHeight: .infinity)
            MailDetailView(message: detail).frame(minWidth: 300, maxHeight: .infinity)
        }
        #else
        table(visible)
        #endif
    }
}

private extension MailMessageEntry {
    var sortTime: Date { timestamp ?? .distantPast }
}

private struct MailDetailView: View {
    let message: MailMessageEntry?

    var body: some View {
        if let message {
            ScrollView {
                VStack(alignment: .leading, spacing: 10) {
                    Text(message.displaySubject).font(.headline).textSelection(.enabled)
                    LabeledContent("Direction", value: message.direction)
                    LabeledContent("From", value: message.senderDisplay.map { "\($0) <\(message.sender ?? "")>" }
                                   ?? (message.sender ?? "—"))
                    if let r = message.recipients, !r.isEmpty {
                        LabeledContent("To / Cc") {
                            Text(r).font(.caption).textSelection(.enabled)
                                .frame(maxWidth: .infinity, alignment: .trailing)
                        }
                    }
                    LabeledContent("Sent", value: message.dateSent?.formatted(date: .long, time: .standard) ?? "—")
                    LabeledContent("Received", value: message.dateReceived?.formatted(date: .long, time: .standard) ?? "—")
                    if let mb = message.mailbox {
                        LabeledContent("Mailbox") {
                            Text(mb).font(.caption.monospaced()).textSelection(.enabled)
                                .frame(maxWidth: .infinity, alignment: .trailing)
                        }
                    }
                    Divider()
                    Text("The Envelope Index summarises mail; message bodies + attachments live in "
                         + "per-message .emlx files (not parsed here).")
                        .font(.caption).foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                    LabeledContent("Source") {
                        Text(message.sourceFile).font(.caption.monospaced()).textSelection(.enabled)
                            .frame(maxWidth: .infinity, alignment: .trailing)
                    }
                }
                .padding()
                .frame(maxWidth: .infinity, alignment: .leading)
            }
        } else {
            ContentUnavailableView("Select a message", systemImage: "envelope")
        }
    }
}
