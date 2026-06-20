import SwiftUI

/// Parsed Gatekeeper / XProtect / MRT-style macOS security events recovered from
/// durable log files.
struct MacSecurityView: View {
    @EnvironmentObject private var model: AppModel
    @State private var query = ""
    @State private var kind: MacSecurityEvent.Kind?
    @State private var severity: MacSecurityEvent.Severity?
    @State private var selectedID: MacSecurityEvent.ID?
    @State private var sort = [KeyPathComparator(\MacSecurityEvent.sortTime, order: .reverse)]

    private func filtered(_ events: [MacSecurityEvent]) -> [MacSecurityEvent] {
        var out = events
        if let kind { out = out.filter { $0.kind == kind } }
        if let severity { out = out.filter { $0.severity == severity } }
        if !query.isEmpty {
            out = out.filter { event in
                event.message.localizedCaseInsensitiveContains(query)
                    || (event.path?.localizedCaseInsensitiveContains(query) ?? false)
                    || (event.signature?.localizedCaseInsensitiveContains(query) ?? false)
                    || event.sourceFile.localizedCaseInsensitiveContains(query)
                    || event.scope.localizedCaseInsensitiveContains(query)
            }
        }
        return out
    }

    var body: some View {
        let rows = model.macSecurityEvents
        let visible = filtered(rows).sorted(using: sort)
        let kinds = Array(Set(rows.map(\.kind))).sorted { $0.label < $1.label }
        let severities = Array(Set(rows.map(\.severity))).sorted(by: >)
        return Group {
            if rows.isEmpty {
                ContentUnavailableView {
                    Label("No macOS security events parsed yet", systemImage: "checkmark.shield")
                } description: {
                    Text(model.files.isEmpty
                         ? "Ingest a macOS image first, then come back here."
                         : "Click Parse to read Gatekeeper, XProtect, XProtect Remediator, and MRT logs.")
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
                        Picker("Kind", selection: $kind) {
                            Text("All").tag(MacSecurityEvent.Kind?.none)
                            ForEach(kinds, id: \.self) { kind in
                                Text(kind.label).tag(MacSecurityEvent.Kind?.some(kind))
                            }
                        }
                        .pickerStyle(.menu)
                        .frame(width: 180)

                        Picker("Severity", selection: $severity) {
                            Text("All").tag(MacSecurityEvent.Severity?.none)
                            ForEach(severities, id: \.self) { severity in
                                Text(severity.label).tag(MacSecurityEvent.Severity?.some(severity))
                            }
                        }
                        .pickerStyle(.menu)
                        .frame(width: 140)

                        Spacer()

                        TextField("Filter message / path / signature...", text: $query)
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
        .navigationTitle(rows.isEmpty ? "macOS Security" : "macOS Security - \(visible.count.formatted()) of \(rows.count.formatted())")
    }

    private func table(_ visible: [MacSecurityEvent]) -> some View {
        Table(visible, selection: $selectedID, sortOrder: $sort) {
            TableColumn("When", value: \.sortTime) { event in
                Text(event.timestamp?.formatted(date: .numeric, time: .standard) ?? "-")
                    .monospacedDigit()
                    .font(.caption)
            }
            .width(min: 130, ideal: 150, max: 180)

            TableColumn("Severity", value: \.sortSeverity) { event in
                Text(event.severity.label)
                    .font(.caption)
                    .foregroundStyle(event.severity.tint)
            }
            .width(min: 80, ideal: 100, max: 130)

            TableColumn("Kind", value: \.sortKind) { event in
                Text(event.kind.label)
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            .width(min: 120, ideal: 150, max: 190)

            TableColumn("Message", value: \.message) { event in
                Text(event.message)
                    .font(.callout)
                    .lineLimit(1)
                    .truncationMode(.middle)
            }

            TableColumn("Scope", value: \.scope) { event in
                Text(event.scope)
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            .width(min: 70, ideal: 90, max: 120)
        }
    }

    @ViewBuilder
    private func split(_ visible: [MacSecurityEvent], detail: MacSecurityEvent?) -> some View {
        #if os(macOS)
        HSplitView {
            table(visible).frame(minWidth: 720, maxHeight: .infinity)
            MacSecurityDetailView(event: detail).frame(minWidth: 360, maxHeight: .infinity)
        }
        #else
        table(visible)
        #endif
    }
}

private extension MacSecurityEvent {
    var sortTime: Date { timestamp ?? .distantPast }
    var sortKind: String { kind.label }
    var sortSeverity: Int {
        switch severity {
        case .info: return 0
        case .allowed: return 1
        case .warning: return 2
        case .remediated: return 3
        case .blocked: return 4
        case .detected: return 5
        }
    }
}

private extension MacSecurityEvent.Severity {
    var tint: Color {
        switch self {
        case .info, .allowed: return .secondary
        case .warning: return .orange
        case .blocked, .detected: return .red
        case .remediated: return .blue
        }
    }
}

private struct MacSecurityDetailView: View {
    let event: MacSecurityEvent?

    var body: some View {
        if let event {
            ScrollView {
                VStack(alignment: .leading, spacing: 10) {
                    Text(event.title)
                        .font(.headline)
                        .textSelection(.enabled)
                    LabeledContent("Severity", value: event.severity.label)
                    LabeledContent("Kind", value: event.kind.label)
                    LabeledContent("When", value: event.timestamp?.formatted(date: .long, time: .standard) ?? "-")
                    LabeledContent("Scope", value: event.scope)
                    if let process = event.process {
                        LabeledContent("Process", value: process)
                    }
                    if let signature = event.signature {
                        LabeledContent("Signature", value: signature)
                    }
                    if let path = event.path {
                        LabeledContent("Path") {
                            Text(path)
                                .font(.caption.monospaced())
                                .textSelection(.enabled)
                                .frame(maxWidth: .infinity, alignment: .trailing)
                        }
                    }
                    Divider()
                    Text(event.message)
                        .font(.caption.monospaced())
                        .textSelection(.enabled)
                    Divider()
                    LabeledContent("Source log") {
                        Text(event.sourceFile)
                            .font(.caption.monospaced())
                            .textSelection(.enabled)
                            .frame(maxWidth: .infinity, alignment: .trailing)
                    }
                }
                .padding()
                .frame(maxWidth: .infinity, alignment: .leading)
            }
        } else {
            ContentUnavailableView("Select a security event", systemImage: "checkmark.shield")
        }
    }
}
