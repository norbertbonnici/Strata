import SwiftUI

/// macOS **TCC** (privacy & consent) grants — which apps were allowed Camera,
/// Microphone, Screen Recording, Accessibility, Full Disk Access, etc., and
/// when. Sortable/filterable; sensitive capabilities are highlighted.
struct TCCView: View {
    @EnvironmentObject private var model: AppModel
    @State private var query = ""
    @State private var sensitiveOnly = false
    @State private var selectedID: TCCAccess.ID?
    @State private var sort = [KeyPathComparator(\TCCAccess.sortTime, order: .reverse)]

    private func filtered(_ rows: [TCCAccess]) -> [TCCAccess] {
        var out = rows
        if sensitiveOnly { out = out.filter { $0.isSensitive } }
        if !query.isEmpty {
            out = out.filter {
                $0.serviceLabel.localizedCaseInsensitiveContains(query)
                    || $0.client.localizedCaseInsensitiveContains(query)
            }
        }
        return out
    }

    var body: some View {
        let rows = model.tcc
        let visible = filtered(rows).sorted(using: sort)
        return Group {
            if rows.isEmpty {
                ContentUnavailableView {
                    Label("No TCC grants parsed yet", systemImage: "hand.raised")
                } description: {
                    Text(model.files.isEmpty
                         ? "Ingest a macOS image first, then come back here."
                         : "Click Parse to read the TCC privacy database.")
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
                        Toggle("Sensitive only", isOn: $sensitiveOnly)
                            .toggleStyle(.switch).controlSize(.small)
                        Spacer()
                        TextField("Filter service / client...", text: $query)
                            .textFieldStyle(.roundedBorder).frame(width: 280)
                    }
                    .padding(8)
                    Divider()
                    split(visible, detail: rows.first { $0.id == selectedID })
                }
            }
        }
        .navigationTitle(rows.isEmpty ? "TCC" : "TCC — \(visible.count.formatted()) of \(rows.count.formatted())")
    }

    private func table(_ visible: [TCCAccess]) -> some View {
        Table(visible, selection: $selectedID, sortOrder: $sort) {
            TableColumn("Modified", value: \.sortTime) { g in
                Text(g.lastModified.map { $0.formatted(date: .numeric, time: .standard) } ?? "—")
                    .monospacedDigit()
            }
            .width(min: 130, ideal: 150, max: 170)
            TableColumn("Service", value: \.serviceLabel) { g in
                Text(g.serviceLabel)
                    .foregroundStyle(g.isSensitive ? Color.orange : .primary)
                    .fontWeight(g.isSensitive ? .semibold : .regular)
            }
            .width(min: 110, ideal: 150, max: 220)
            TableColumn("Client", value: \.client) { g in
                Text(g.clientLabel).font(.callout).lineLimit(1).truncationMode(.middle)
            }
            TableColumn("Auth", value: \.sortAuth) { g in
                Text(g.authValue.label)
                    .font(.caption.bold())
                    .foregroundStyle(g.authValue == .allowed ? .red : .secondary)
            }
            .width(min: 56, ideal: 64, max: 80)
            TableColumn("Scope", value: \.scope) { g in
                Text(g.scope).font(.caption).foregroundStyle(.secondary)
            }
            .width(min: 60, ideal: 80, max: 120)
        }
    }

    @ViewBuilder
    private func split(_ visible: [TCCAccess], detail: TCCAccess?) -> some View {
        #if os(macOS)
        HSplitView {
            table(visible).frame(minWidth: 540, maxHeight: .infinity)
            TCCDetailView(grant: detail).frame(minWidth: 260, maxHeight: .infinity)
        }
        #else
        table(visible)
        #endif
    }
}

private extension TCCAccess {
    var sortTime: Date { lastModified ?? .distantPast }
    var sortAuth: Int { authValue.rawValue }
}

private struct TCCDetailView: View {
    let grant: TCCAccess?
    var body: some View {
        if let grant {
            ScrollView {
                VStack(alignment: .leading, spacing: 10) {
                    Text(grant.serviceLabel).font(.headline)
                        .foregroundStyle(grant.isSensitive ? Color.orange : .primary)
                    LabeledContent("Authorisation", value: grant.authValue.label)
                    LabeledContent("Client", value: grant.client)
                    LabeledContent("Client type", value: grant.clientType == 1 ? "Path" : "Bundle ID")
                    LabeledContent("Service key", value: grant.service)
                    LabeledContent("Scope", value: grant.scope)
                    if let t = grant.lastModified {
                        LabeledContent("Last modified", value: t.formatted(date: .long, time: .standard))
                    }
                    if grant.isSensitive {
                        Label("High-impact capability", systemImage: "exclamationmark.triangle.fill")
                            .font(.caption).foregroundStyle(.orange)
                    }
                    LabeledContent("Source") {
                        Text(grant.sourceFile).font(.caption.monospaced()).textSelection(.enabled)
                            .frame(maxWidth: .infinity, alignment: .trailing)
                    }
                }
                .padding()
                .frame(maxWidth: .infinity, alignment: .leading)
            }
        } else {
            ContentUnavailableView("Select a grant", systemImage: "hand.raised")
        }
    }
}
