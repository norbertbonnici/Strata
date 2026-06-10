import SwiftUI

/// General system log (/var/log/syslog, /var/log/messages) - the non-auth
/// kernel/systemd/cron telemetry, classified by category. Noise categories
/// (service start/stop, other) are hidden by default.
struct SyslogView: View {
    @EnvironmentObject private var model: AppModel
    @State private var query = ""
    @State private var category: SyslogEntry.Category? = nil
    @State private var includeNoise = false
    @State private var selectedID: SyslogEntry.ID?

    private static let maxRows = 20_000

    private func filtered(_ rows: [SyslogEntry]) -> [SyslogEntry] {
        var out = rows
        if !includeNoise { out = out.filter { !$0.category.isNoise } }
        if let category { out = out.filter { $0.category == category } }
        if !query.isEmpty {
            out = out.filter {
                $0.message.localizedCaseInsensitiveContains(query)
                    || $0.process.localizedCaseInsensitiveContains(query)
            }
        }
        return out
    }

    var body: some View {
        let rows = model.syslog
        let all = filtered(rows)
        let visible = Array(all.prefix(Self.maxRows))
        return Group {
            if rows.isEmpty {
                ContentUnavailableView {
                    Label("No system log parsed yet", systemImage: "doc.plaintext")
                } description: {
                    Text(model.files.isEmpty ? "Ingest evidence first, then come back here."
                                             : "Click Parse to read /var/log/syslog and /var/log/messages.")
                } actions: {
                    #if os(macOS)
                    if !model.files.isEmpty {
                        Button { Task { await model.parseArtifacts() } } label: {
                            Label("Parse artifacts", systemImage: "play.fill")
                        }.disabled(model.isWorking)
                    }
                    #endif
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else {
                VStack(spacing: 0) {
                    HStack(spacing: 12) {
                        Picker("Category", selection: $category) {
                            Text("All").tag(SyslogEntry.Category?.none)
                            ForEach(SyslogEntry.Category.allCases.filter { !$0.isNoise }, id: \.self) { c in
                                Text(c.label).tag(SyslogEntry.Category?.some(c))
                            }
                        }
                        .pickerStyle(.menu).frame(width: 150)
                        Toggle("Show noise", isOn: $includeNoise).toggleStyle(.switch).controlSize(.small)
                        Spacer()
                        TextField("Filter message / program...", text: $query)
                            .textFieldStyle(.roundedBorder).frame(width: 280)
                    }
                    .padding(8)
                    Divider()
                    Table(visible, selection: $selectedID) {
                        TableColumn("Time") { e in
                            Text(e.timestamp.map { $0.formatted(date: .numeric, time: .standard) } ?? "—").monospacedDigit()
                        }
                        .width(min: 130, ideal: 150, max: 170)
                        TableColumn("Category") { e in
                            Text(e.category.label).font(.caption.bold()).foregroundStyle(color(e.category))
                        }
                        .width(min: 90, ideal: 110, max: 140)
                        TableColumn("Program") { e in
                            Text(e.process).font(.caption).foregroundStyle(.secondary)
                        }
                        .width(min: 70, ideal: 90, max: 130)
                        TableColumn("Message") { e in
                            Text(e.message).font(.caption.monospaced()).lineLimit(1).truncationMode(.tail)
                        }
                    }
                }
            }
        }
        .navigationTitle(rows.isEmpty ? "System Log" : "System Log - \(all.count.formatted()) of \(rows.count.formatted())")
    }

    private func color(_ c: SyslogEntry.Category) -> Color {
        switch c {
        case .segfault, .outOfMemory, .processKilled, .diskError: return .red
        case .crashLoop, .serviceFailed:                          return .orange
        case .usbDevice, .massStorage, .cronExec, .suSession:     return .blue
        default:                                                  return .secondary
        }
    }
}

/// /var/log/lastlog - last login per account. One row per account that has ever
/// logged in.
struct LastlogView: View {
    @EnvironmentObject private var model: AppModel
    @State private var query = ""

    private func filtered(_ rows: [LastlogEntry]) -> [LastlogEntry] {
        guard !query.isEmpty else { return rows }
        return rows.filter {
            $0.account.localizedCaseInsensitiveContains(query)
                || $0.host.localizedCaseInsensitiveContains(query)
                || $0.line.localizedCaseInsensitiveContains(query)
        }
    }

    var body: some View {
        let rows = model.lastlog
        let visible = filtered(rows)
        return Group {
            if rows.isEmpty {
                ContentUnavailableView {
                    Label("No lastlog parsed yet", systemImage: "person.crop.square.badge.camera")
                } description: {
                    Text(model.files.isEmpty ? "Ingest evidence first, then come back here."
                                             : "Click Parse to decode /var/log/lastlog.")
                } actions: {
                    #if os(macOS)
                    if !model.files.isEmpty {
                        Button { Task { await model.parseArtifacts() } } label: {
                            Label("Parse artifacts", systemImage: "play.fill")
                        }.disabled(model.isWorking)
                    }
                    #endif
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else {
                VStack(spacing: 0) {
                    HStack { Spacer()
                        TextField("Filter account / host / tty...", text: $query)
                            .textFieldStyle(.roundedBorder).frame(width: 280)
                    }
                    .padding(8)
                    Divider()
                    Table(visible) {
                        TableColumn("Last login") { r in
                            Text(r.timestamp.map { $0.formatted(date: .numeric, time: .standard) } ?? "—").monospacedDigit()
                        }
                        .width(min: 130, ideal: 150, max: 170)
                        TableColumn("Account") { r in Text(r.account).font(.caption) }
                            .width(min: 80, ideal: 110, max: 160)
                        TableColumn("UID") { r in
                            Text(String(r.uid)).font(.caption.monospacedDigit()).foregroundStyle(.secondary)
                        }
                        .width(min: 44, ideal: 50, max: 70)
                        TableColumn("From") { r in
                            Text(r.line + (r.host.isEmpty ? "" : "  \(r.host)")).font(.caption.monospaced())
                        }
                    }
                }
            }
        }
        .navigationTitle(rows.isEmpty ? "Last Login" : "Last Login - \(visible.count) of \(rows.count)")
    }
}
