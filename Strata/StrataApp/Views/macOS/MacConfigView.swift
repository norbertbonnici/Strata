import SwiftUI

/// macOS System Configuration: the static security-posture inventory — firewall,
/// screen-lock, software-update, Gatekeeper, remote services, and login-window
/// policy — with weakened/risky settings highlighted.
struct MacConfigView: View {
    @EnvironmentObject private var model: AppModel
    @State private var query = ""
    @State private var flaggedOnly = false
    @State private var selectedID: MacConfigSetting.ID?
    @State private var sort = [KeyPathComparator(\MacConfigSetting.name)]

    private func filtered(_ items: [MacConfigSetting]) -> [MacConfigSetting] {
        items.filter { s in
            (!flaggedOnly || s.isFlagged)
            && (query.isEmpty
                || s.name.localizedCaseInsensitiveContains(query)
                || s.value.localizedCaseInsensitiveContains(query)
                || s.interpretation.localizedCaseInsensitiveContains(query)
                || (s.domain?.localizedCaseInsensitiveContains(query) ?? false))
        }
    }

    var body: some View {
        let rows = model.macConfig
        let visible = filtered(rows).sorted(using: sort)
        return Group {
            if rows.isEmpty {
                ContentUnavailableView {
                    Label("No configuration parsed yet", systemImage: "gearshape.2")
                } description: {
                    Text(model.files.isEmpty
                         ? "Ingest a macOS image first, then come back here."
                         : "Click Parse to read the system configuration plists.")
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
                        Toggle("Flagged only", isOn: $flaggedOnly)
                            #if os(macOS)
                            .toggleStyle(.checkbox)
                            #endif
                        Spacer()
                        TextField("Filter setting / value / domain...", text: $query)
                            .textFieldStyle(.roundedBorder)
                            .frame(width: 300)
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
        .navigationTitle(rows.isEmpty ? "Configuration"
                         : "Configuration - \(visible.count.formatted()) of \(rows.count.formatted())")
    }

    private func table(_ visible: [MacConfigSetting]) -> some View {
        Table(visible, selection: $selectedID, sortOrder: $sort) {
            TableColumn("") { s in
                if s.isFlagged {
                    Image(systemName: "exclamationmark.triangle.fill")
                        .foregroundStyle(s.risk == .high ? .red : (s.risk == .medium ? .orange : .yellow))
                }
            }
            .width(20)
            TableColumn("Category") { s in
                Text(s.category.label).font(.caption).foregroundStyle(.secondary)
            }
            .width(min: 90, ideal: 110, max: 130)
            TableColumn("Setting", value: \.name) { s in
                Text(s.name).font(.callout).lineLimit(1)
            }
            .width(min: 150, ideal: 200, max: 260)
            TableColumn("Value") { s in
                Text(s.value).font(.callout.monospaced()).lineLimit(1).truncationMode(.middle)
            }
            .width(min: 90, ideal: 130, max: 200)
            TableColumn("Scope") { s in
                Text(s.scope).font(.caption).foregroundStyle(.secondary).lineLimit(1)
            }
            .width(min: 60, ideal: 80, max: 120)
        }
    }

    @ViewBuilder
    private func split(_ visible: [MacConfigSetting], detail: MacConfigSetting?) -> some View {
        #if os(macOS)
        HSplitView {
            table(visible).frame(minWidth: 560, maxHeight: .infinity)
            MacConfigDetailView(setting: detail).frame(minWidth: 300, maxHeight: .infinity)
        }
        #else
        table(visible)
        #endif
    }
}

private struct MacConfigDetailView: View {
    let setting: MacConfigSetting?

    var body: some View {
        if let s = setting {
            ScrollView {
                VStack(alignment: .leading, spacing: 10) {
                    HStack {
                        Text(s.name).font(.headline).textSelection(.enabled)
                        if s.isFlagged {
                            Text(s.risk.rawValue.capitalized)
                                .font(.caption.bold())
                                .padding(.horizontal, 6).padding(.vertical, 2)
                                .background(s.risk == .high ? Color.red.opacity(0.2)
                                            : (s.risk == .medium ? Color.orange.opacity(0.2) : Color.yellow.opacity(0.2)))
                                .clipShape(Capsule())
                        }
                    }
                    LabeledContent("Category", value: s.category.label)
                    LabeledContent("Value", value: s.value)
                    if let dom = s.domain { LabeledContent("Domain", value: dom) }
                    LabeledContent("Scope", value: s.scope)
                    if let aid = s.attackID {
                        LabeledContent("ATT&CK", value: "\(aid)\(s.attackName.map { " — \($0)" } ?? "")")
                    }
                    Divider()
                    Text(s.interpretation).font(.body).textSelection(.enabled)
                        .frame(maxWidth: .infinity, alignment: .leading)
                    Divider()
                    LabeledContent("Source") {
                        Text(s.sourceFile).font(.caption.monospaced()).textSelection(.enabled)
                            .frame(maxWidth: .infinity, alignment: .trailing)
                    }
                }
                .padding()
                .frame(maxWidth: .infinity, alignment: .leading)
            }
        } else {
            ContentUnavailableView("Select a setting", systemImage: "gearshape")
        }
    }
}
