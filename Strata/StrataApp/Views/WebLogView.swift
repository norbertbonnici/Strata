import SwiftUI

/// nginx/apache access-log requests. The front line for a web-facing host -
/// the analyzer flags exploitation/webshell/scanner activity; this view is the
/// raw request log with status/method filters and free-text search over
/// path/IP/user-agent.
struct WebLogView: View {
    @EnvironmentObject private var model: AppModel
    @State private var query = ""
    @State private var onlyErrors = false   // 4xx/5xx only
    @State private var selectedID: WebAccessLogEntry.ID?

    private static let maxRows = 20_000

    private func filtered(_ rows: [WebAccessLogEntry]) -> [WebAccessLogEntry] {
        var out = rows
        if onlyErrors { out = out.filter { $0.status >= 400 } }
        if !query.isEmpty {
            out = out.filter {
                $0.target.localizedCaseInsensitiveContains(query)
                    || $0.clientIP.localizedCaseInsensitiveContains(query)
                    || ($0.userAgent?.localizedCaseInsensitiveContains(query) ?? false)
                    || $0.method.localizedCaseInsensitiveContains(query)
            }
        }
        return out
    }

    var body: some View {
        let rows = model.webAccess
        let all = filtered(rows)
        let visible = Array(all.prefix(Self.maxRows))
        return Group {
            if rows.isEmpty {
                ContentUnavailableView {
                    Label("No web logs parsed yet", systemImage: "network")
                } description: {
                    Text(model.files.isEmpty
                         ? "Ingest evidence first, then come back here."
                         : "Click Parse to read nginx/apache access logs from /var/log.")
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
                        Toggle("Errors only (4xx/5xx)", isOn: $onlyErrors)
                            .toggleStyle(.switch).controlSize(.small)
                        Spacer()
                        TextField("Filter path / IP / user-agent...", text: $query)
                            .textFieldStyle(.roundedBorder).frame(width: 300)
                    }
                    .padding(8)
                    if all.count > visible.count {
                        HStack(spacing: 6) {
                            Image(systemName: "info.circle")
                            Text("Showing first \(visible.count.formatted()) of \(all.count.formatted()) — filter to narrow.")
                                .font(.caption).foregroundStyle(.secondary)
                            Spacer()
                        }
                        .padding(.horizontal, 8).padding(.vertical, 4)
                        .background(Color.secondary.opacity(0.08))
                    }
                    Divider()
                    split(visible, detail: rows.first { $0.id == selectedID })
                }
            }
        }
        .navigationTitle(rows.isEmpty ? "Web Logs" : "Web Logs - \(all.count.formatted()) of \(rows.count.formatted())")
    }

    private func table(_ visible: [WebAccessLogEntry]) -> some View {
        Table(visible, selection: $selectedID) {
            TableColumn("Time") { e in
                Text(e.timestamp.map { $0.formatted(date: .numeric, time: .standard) } ?? "—")
                    .monospacedDigit()
            }
            .width(min: 130, ideal: 150, max: 170)
            TableColumn("Client") { e in
                Text(e.clientIP).font(.caption.monospaced())
            }
            .width(min: 90, ideal: 110, max: 150)
            TableColumn("Method") { e in
                Text(e.method).font(.caption).foregroundStyle(.secondary)
            }
            .width(min: 50, ideal: 60, max: 80)
            TableColumn("Status") { e in
                Text(String(e.status))
                    .font(.caption.monospacedDigit().bold())
                    .foregroundStyle(statusColor(e.status))
            }
            .width(min: 50, ideal: 55, max: 70)
            TableColumn("Path") { e in
                Text(e.target).font(.caption.monospaced()).lineLimit(1).truncationMode(.middle)
            }
        }
    }

    private func statusColor(_ status: Int) -> Color {
        switch status {
        case 200..<300: return .green
        case 300..<400: return .blue
        case 400..<500: return .orange
        case 500...:    return .red
        default:        return .secondary
        }
    }

    @ViewBuilder
    private func split(_ visible: [WebAccessLogEntry], detail: WebAccessLogEntry?) -> some View {
        #if os(macOS)
        HSplitView {
            table(visible).frame(minWidth: 560, maxHeight: .infinity)
            WebLogDetailView(entry: detail).frame(minWidth: 280, maxHeight: .infinity)
        }
        #else
        HStack(spacing: 0) {
            table(visible)
            Divider()
            WebLogDetailView(entry: detail).frame(minWidth: 280, maxHeight: .infinity)
        }
        #endif
    }
}

private struct WebLogDetailView: View {
    let entry: WebAccessLogEntry?
    var body: some View {
        if let entry {
            ScrollView {
                VStack(alignment: .leading, spacing: 10) {
                    Text("\(entry.method) \(entry.status)").font(.headline)
                    LabeledContent("Time", value: entry.timestamp.map {
                        $0.formatted(date: .numeric, time: .standard) } ?? "—")
                    LabeledContent("Client", value: entry.clientIP)
                    LabeledContent("Server", value: entry.server.label)
                    LabeledContent("Bytes", value: entry.bytes.formatted())
                    block("Target", entry.target)
                    if let ua = entry.userAgent { block("User-agent", ua) }
                    if let ref = entry.referer { block("Referer", ref) }
                    LabeledContent("Source") {
                        Text(entry.sourceFile).font(.caption.monospaced()).textSelection(.enabled)
                            .frame(maxWidth: .infinity, alignment: .trailing)
                    }
                }
                .padding()
                .frame(maxWidth: .infinity, alignment: .leading)
            }
        } else {
            ContentUnavailableView("Select a request", systemImage: "network")
        }
    }

    private func block(_ title: String, _ value: String) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(title).font(.caption.bold()).foregroundStyle(.secondary)
            Text(value)
                .font(.system(size: 11, design: .monospaced)).textSelection(.enabled)
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(8)
                .background(.quaternary.opacity(0.4), in: RoundedRectangle(cornerRadius: 6))
        }
    }
}
