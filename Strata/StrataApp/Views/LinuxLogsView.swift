import SwiftUI

/// Linux authentication telemetry: classified auth.log/secure events and
/// wtmp/btmp login records, behind one segmented picker (they answer the same
/// triage question - who got in, from where, and when).
struct LinuxLogsView: View {
    @EnvironmentObject private var model: AppModel

    private enum Section: String, CaseIterable, Identifiable {
        case auth = "Auth events"
        case logins = "Login records"
        var id: String { rawValue }
    }

    @State private var section: Section = .auth
    @State private var query = ""
    @State private var selectedAuthID: AuthLogEntry.ID?
    @State private var selectedLoginID: UtmpRecord.ID?

    var body: some View {
        let authRows = filteredAuth(model.authLog)
        let loginRows = filteredLogins(model.logins)
        return Group {
            if model.authLog.isEmpty && model.logins.isEmpty {
                ContentUnavailableView {
                    Label("No Linux logs parsed yet", systemImage: "person.badge.key")
                } description: {
                    Text(model.files.isEmpty
                         ? "Ingest evidence first, then come back here."
                         : "Click Parse to read auth.log/secure and wtmp/btmp from the evidence.")
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
                        Picker("", selection: $section) {
                            ForEach(Section.allCases) { section in
                                Text(section.rawValue).tag(section)
                            }
                        }
                        .pickerStyle(.segmented)
                        .frame(width: 260)
                        Spacer()
                        TextField("Filter user / IP / message...", text: $query)
                            .textFieldStyle(.roundedBorder)
                            .frame(width: 280)
                    }
                    .padding(8)
                    Divider()
                    switch section {
                    case .auth:   authSplit(authRows)
                    case .logins: loginSplit(loginRows)
                    }
                }
            }
        }
        .navigationTitle(navigationTitle(authCount: authRows.count, loginCount: loginRows.count))
    }

    private func navigationTitle(authCount: Int, loginCount: Int) -> String {
        if model.authLog.isEmpty && model.logins.isEmpty { return "Auth & Logins" }
        switch section {
        case .auth:   return "Auth Log - \(authCount) of \(model.authLog.count)"
        case .logins: return "Logins - \(loginCount) of \(model.logins.count)"
        }
    }

    private func filteredAuth(_ rows: [AuthLogEntry]) -> [AuthLogEntry] {
        guard !query.isEmpty else { return rows }
        return rows.filter {
            $0.message.localizedCaseInsensitiveContains(query)
                || ($0.user?.localizedCaseInsensitiveContains(query) ?? false)
                || ($0.sourceIP?.localizedCaseInsensitiveContains(query) ?? false)
                || $0.process.localizedCaseInsensitiveContains(query)
        }
    }

    private func filteredLogins(_ rows: [UtmpRecord]) -> [UtmpRecord] {
        guard !query.isEmpty else { return rows }
        return rows.filter {
            $0.user.localizedCaseInsensitiveContains(query)
                || $0.host.localizedCaseInsensitiveContains(query)
                || $0.line.localizedCaseInsensitiveContains(query)
        }
    }

    // MARK: - Auth events

    @ViewBuilder
    private func authSplit(_ rows: [AuthLogEntry]) -> some View {
        let detail = rows.first { $0.id == selectedAuthID } ?? model.authLog.first { $0.id == selectedAuthID }
        splitView(table: authTable(rows), detail: AuthDetailView(entry: detail))
    }

    private func authTable(_ rows: [AuthLogEntry]) -> some View {
        Table(rows, selection: $selectedAuthID) {
            TableColumn("Time") { e in
                Text(e.timestamp.map { $0.formatted(date: .numeric, time: .standard) } ?? "—")
                    .monospacedDigit()
            }
            .width(min: 130, ideal: 150, max: 170)
            TableColumn("Event") { e in
                Text(e.kind.label)
                    .font(.caption)
                    .foregroundStyle(authColor(e.kind))
            }
            .width(min: 90, ideal: 100, max: 120)
            TableColumn("User") { e in
                Text(e.user ?? "—").font(.caption)
            }
            .width(min: 70, ideal: 90, max: 140)
            TableColumn("Source") { e in
                Text(e.sourceIP ?? "—").font(.caption.monospaced())
            }
            .width(min: 90, ideal: 110, max: 150)
            TableColumn("Message") { e in
                Text("\(e.process): \(e.message)")
                    .font(.caption)
                    .lineLimit(1)
                    .truncationMode(.tail)
            }
        }
    }

    private func authColor(_ kind: AuthLogEntry.Kind) -> Color {
        switch kind {
        case .sshFailed, .sshInvalidUser: return .orange
        case .sshAccepted:                return .green
        case .userAdded, .userModified:   return .purple
        case .sudo:                       return .blue
        default:                          return .secondary
        }
    }

    // MARK: - Login records

    @ViewBuilder
    private func loginSplit(_ rows: [UtmpRecord]) -> some View {
        let detail = rows.first { $0.id == selectedLoginID } ?? model.logins.first { $0.id == selectedLoginID }
        splitView(table: loginTable(rows), detail: LoginDetailView(record: detail))
    }

    private func loginTable(_ rows: [UtmpRecord]) -> some View {
        Table(rows, selection: $selectedLoginID) {
            TableColumn("Time") { r in
                Text(r.timestamp.map { $0.formatted(date: .numeric, time: .standard) } ?? "—")
                    .monospacedDigit()
            }
            .width(min: 130, ideal: 150, max: 170)
            TableColumn("Type") { r in
                Text(r.isFailedLogin ? "Failed login" : r.type.label)
                    .font(.caption)
                    .foregroundStyle(r.isFailedLogin ? .orange : .secondary)
            }
            .width(min: 80, ideal: 95, max: 110)
            TableColumn("User") { r in
                Text(r.user.isEmpty ? "—" : r.user).font(.caption)
            }
            .width(min: 70, ideal: 90, max: 140)
            TableColumn("Line") { r in
                Text(r.line.isEmpty ? "—" : r.line).font(.caption.monospaced())
            }
            .width(min: 60, ideal: 80, max: 110)
            TableColumn("From") { r in
                Text(r.host.isEmpty ? "—" : r.host).font(.caption.monospaced())
            }
        }
    }

    @ViewBuilder
    private func splitView(table: some View, detail: some View) -> some View {
        #if os(macOS)
        HSplitView {
            table.frame(minWidth: 540, maxHeight: .infinity)
            detail.frame(minWidth: 280, maxHeight: .infinity)
        }
        #else
        HStack(spacing: 0) {
            table
            Divider()
            detail.frame(minWidth: 280, maxHeight: .infinity)
        }
        #endif
    }
}

private struct AuthDetailView: View {
    let entry: AuthLogEntry?
    var body: some View {
        if let entry {
            ScrollView {
                VStack(alignment: .leading, spacing: 10) {
                    Text(entry.kind.label).font(.headline)
                    LabeledContent("Time", value: entry.timestamp.map {
                        $0.formatted(date: .numeric, time: .standard) } ?? "—")
                    LabeledContent("Host", value: entry.host)
                    LabeledContent("Process", value: entry.pid.map { "\(entry.process)[\($0)]" } ?? entry.process)
                    if let user = entry.user { LabeledContent("User", value: user) }
                    if let ip = entry.sourceIP { LabeledContent("Source IP", value: ip) }
                    if let port = entry.port { LabeledContent("Port", value: String(port)) }
                    if let method = entry.method { LabeledContent("Method", value: method) }
                    if let command = entry.command, !command.isEmpty {
                        VStack(alignment: .leading, spacing: 4) {
                            Text("Command").font(.caption.bold()).foregroundStyle(.secondary)
                            Text(command)
                                .font(.system(size: 11, design: .monospaced))
                                .textSelection(.enabled)
                                .frame(maxWidth: .infinity, alignment: .leading)
                                .padding(8)
                                .background(.quaternary.opacity(0.4), in: RoundedRectangle(cornerRadius: 6))
                        }
                    }
                    VStack(alignment: .leading, spacing: 4) {
                        Text("Message").font(.caption.bold()).foregroundStyle(.secondary)
                        Text(entry.message)
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
            ContentUnavailableView("Select an event", systemImage: "person.badge.key")
        }
    }
}

private struct LoginDetailView: View {
    let record: UtmpRecord?
    var body: some View {
        if let record {
            ScrollView {
                VStack(alignment: .leading, spacing: 10) {
                    Text(record.isFailedLogin ? "Failed login" : record.type.label)
                        .font(.headline)
                    if record.isFailedLogin {
                        Label("From btmp - a failed login attempt", systemImage: "exclamationmark.triangle.fill")
                            .font(.caption).foregroundStyle(.orange)
                    }
                    LabeledContent("Time", value: record.timestamp.map {
                        $0.formatted(date: .numeric, time: .standard) } ?? "—")
                    LabeledContent("User", value: record.user.isEmpty ? "—" : record.user)
                    LabeledContent("Line", value: record.line.isEmpty ? "—" : record.line)
                    LabeledContent("From", value: record.host.isEmpty ? "—" : record.host)
                    LabeledContent("PID", value: String(record.pid))
                    LabeledContent("Source") {
                        Text(record.sourceFile)
                            .font(.caption.monospaced())
                            .textSelection(.enabled)
                            .frame(maxWidth: .infinity, alignment: .trailing)
                    }
                }
                .padding()
                .frame(maxWidth: .infinity, alignment: .leading)
            }
        } else {
            ContentUnavailableView("Select a record", systemImage: "person.badge.key")
        }
    }
}
