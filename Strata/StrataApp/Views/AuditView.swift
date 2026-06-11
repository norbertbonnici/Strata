import SwiftUI

/// Linux audit (auditd) events - folded SYSCALL/EXECVE/USER_* records. The
/// kernel audit trail: what executed, who (login uid), and which files were
/// touched. Filterable by record type + free text.
struct AuditView: View {
    @EnvironmentObject private var model: AppModel
    @State private var query = ""
    @State private var execOnly = false
    @State private var selectedID: AuditEvent.ID?
    @State private var sort = [KeyPathComparator(\AuditEvent.sortTime, order: .reverse)]

    private static let maxRows = 20_000

    private func filtered(_ rows: [AuditEvent]) -> [AuditEvent] {
        var out = rows
        if execOnly { out = out.filter { $0.recordType == "EXECVE" || $0.syscall == "execve" } }
        if !query.isEmpty {
            out = out.filter {
                $0.summary.localizedCaseInsensitiveContains(query)
                    || ($0.exe?.localizedCaseInsensitiveContains(query) ?? false)
                    || ($0.account?.localizedCaseInsensitiveContains(query) ?? false)
                    || $0.recordType.localizedCaseInsensitiveContains(query)
            }
        }
        return out
    }

    var body: some View {
        let rows = model.audit
        let all = filtered(rows).sorted(using: sort)
        let visible = Array(all.prefix(Self.maxRows))
        return Group {
            if rows.isEmpty {
                ContentUnavailableView {
                    Label(model.hasParsedLinuxLogs ? "No auditd records on this host"
                                                   : "No audit log parsed yet",
                          systemImage: "checklist")
                } description: {
                    if model.files.isEmpty {
                        Text("Ingest evidence first, then come back here.")
                    } else if model.hasParsedLinuxLogs {
                        Text("`/var/log/audit/` only exists when the **auditd** service is installed — many hosts don't run it, so an empty Audit tab is expected here, not a parsing gap.")
                    } else {
                        Text("Click Parse to decode /var/log/audit/audit.log.")
                    }
                } actions: {
                    #if os(macOS)
                    if !model.files.isEmpty, !model.hasParsedLinuxLogs {
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
                        Toggle("Executions only", isOn: $execOnly).toggleStyle(.switch).controlSize(.small)
                        Spacer()
                        TextField("Filter command / exe / account / type...", text: $query)
                            .textFieldStyle(.roundedBorder).frame(width: 320)
                    }
                    .padding(8)
                    Divider()
                    split(visible, detail: rows.first { $0.id == selectedID })
                }
            }
        }
        .navigationTitle(rows.isEmpty ? "Audit" : "Audit - \(all.count.formatted()) of \(rows.count.formatted())")
    }

    private func table(_ visible: [AuditEvent]) -> some View {
        Table(visible, selection: $selectedID, sortOrder: $sort) {
            TableColumn("Time", value: \.sortTime) { e in
                Text(e.timestamp.map { $0.formatted(date: .numeric, time: .standard) } ?? "—").monospacedDigit()
            }
            .width(min: 130, ideal: 150, max: 170)
            TableColumn("Type", value: \.recordType) { e in
                Text(e.recordType).font(.caption).foregroundStyle(.secondary)
            }
            .width(min: 80, ideal: 90, max: 120)
            TableColumn("Result", value: \.sortResult) { e in
                if let r = e.result {
                    Text(r).font(.caption.bold()).foregroundStyle(r == "failed" ? .orange : .green)
                } else if let s = e.success {
                    Text(s ? "ok" : "fail").font(.caption).foregroundStyle(s ? Color.secondary : Color.orange)
                } else { Text("—").foregroundStyle(.secondary) }
            }
            .width(min: 50, ideal: 60, max: 80)
            TableColumn("Summary", value: \.summary) { e in
                Text(e.summary).font(.caption.monospaced()).lineLimit(1).truncationMode(.middle)
            }
        }
    }

    @ViewBuilder
    private func split(_ visible: [AuditEvent], detail: AuditEvent?) -> some View {
        #if os(macOS)
        HSplitView {
            table(visible).frame(minWidth: 560, maxHeight: .infinity)
            AuditDetailView(event: detail).frame(minWidth: 280, maxHeight: .infinity)
        }
        #else
        HStack(spacing: 0) {
            table(visible); Divider(); AuditDetailView(event: detail).frame(minWidth: 280, maxHeight: .infinity)
        }
        #endif
    }
}

/// Non-optional sort keys for the sortable audit `Table`.
private extension AuditEvent {
    var sortTime: Date { timestamp ?? .distantPast }
    var sortResult: String { result ?? (success.map { $0 ? "ok" : "fail" } ?? "") }
}

private struct AuditDetailView: View {
    let event: AuditEvent?
    var body: some View {
        if let event {
            ScrollView {
                VStack(alignment: .leading, spacing: 8) {
                    Text(event.recordType).font(.headline)
                    LabeledContent("Time", value: event.timestamp.map { $0.formatted(date: .numeric, time: .standard) } ?? "—")
                    if let s = event.syscall { LabeledContent("Syscall", value: s) }
                    if let s = event.success { LabeledContent("Success", value: s ? "yes" : "no") }
                    if let x = event.exit { LabeledContent("Exit", value: String(x)) }
                    if let e = event.exe { LabeledContent("Exe", value: e) }
                    if let c = event.comm { LabeledContent("Comm", value: c) }
                    if let a = event.auid { LabeledContent("auid (login uid)", value: String(a)) }
                    if let u = event.uid { LabeledContent("uid", value: String(u)) }
                    if let t = event.tty { LabeledContent("tty", value: t) }
                    if let k = event.key { LabeledContent("Rule key", value: k) }
                    if let acct = event.account { LabeledContent("Account", value: acct) }
                    if let r = event.result { LabeledContent("Result", value: r) }
                    if let ip = event.sourceIP { LabeledContent("Source", value: ip) }
                    if let cmd = event.commandLine { block("Command line", cmd) }
                    if let p = event.path { block("Path", p) }
                    LabeledContent("Source") {
                        Text(event.sourceFile).font(.caption.monospaced()).textSelection(.enabled)
                            .frame(maxWidth: .infinity, alignment: .trailing)
                    }
                }
                .padding().frame(maxWidth: .infinity, alignment: .leading)
            }
        } else {
            ContentUnavailableView("Select an event", systemImage: "checklist")
        }
    }
    private func block(_ title: String, _ value: String) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(title).font(.caption.bold()).foregroundStyle(.secondary)
            Text(value).font(.system(size: 11, design: .monospaced)).textSelection(.enabled)
                .frame(maxWidth: .infinity, alignment: .leading).padding(8)
                .background(.quaternary.opacity(0.4), in: RoundedRectangle(cornerRadius: 6))
        }
    }
}
