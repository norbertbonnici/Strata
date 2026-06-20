import SwiftUI

/// Package-manager history: install / remove / upgrade of software over time,
/// from dpkg/apt (Debian) or yum/dnf (RHEL) logs. A clean "what was added or
/// removed, and when" record - the analyzer flags offensive-tool installs and
/// removal bursts; this view is the full, searchable list.
struct PackageView: View {
    @EnvironmentObject private var model: AppModel
    @State private var query = ""
    @State private var action: PackageEvent.Action? = nil
    @State private var selectedID: PackageEvent.ID?
    @State private var sort = [KeyPathComparator(\PackageEvent.sortTime, order: .reverse)]

    private func filtered(_ rows: [PackageEvent]) -> [PackageEvent] {
        var out = rows
        if let action { out = out.filter { $0.action == action } }
        if !query.isEmpty {
            out = out.filter {
                $0.package.localizedCaseInsensitiveContains(query)
                    || ($0.version?.localizedCaseInsensitiveContains(query) ?? false)
            }
        }
        return out
    }

    var body: some View {
        let rows = model.packages
        let visible = filtered(rows).sorted(using: sort)
        return Group {
            if rows.isEmpty {
                ContentUnavailableView {
                    Label("No package history parsed yet", systemImage: "shippingbox")
                } description: {
                    Text(model.files.isEmpty
                         ? "Ingest evidence first, then come back here."
                         : "Click Parse to read dpkg/apt/yum/dnf logs from /var/log.")
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
                        Picker("Action", selection: $action) {
                            Text("All").tag(PackageEvent.Action?.none)
                            ForEach(PackageEvent.Action.allCases, id: \.self) { a in
                                Text(a.label).tag(PackageEvent.Action?.some(a))
                            }
                        }
                        .pickerStyle(.menu).frame(width: 140)
                        Spacer()
                        TextField("Filter package / version...", text: $query)
                            .textFieldStyle(.roundedBorder).frame(width: 280)
                    }
                    .padding(8)
                    Divider()
                    Table(visible, selection: $selectedID, sortOrder: $sort) {
                        TableColumn("Time", value: \.sortTime) { e in
                            Text(e.timestamp.map { $0.formatted(date: .numeric, time: .standard) } ?? "—")
                                .monospacedDigit()
                        }
                        .width(min: 130, ideal: 150, max: 170)
                        TableColumn("Action", value: \.sortAction) { e in
                            Text(e.action.label)
                                .font(.caption.bold())
                                .foregroundStyle(actionColor(e.action))
                        }
                        .width(min: 70, ideal: 80, max: 100)
                        TableColumn("Package", value: \.package) { e in
                            Text(e.package).font(.caption.monospaced())
                        }
                        TableColumn("Version", value: \.sortVersion) { e in
                            Text(e.version ?? "—").font(.caption).foregroundStyle(.secondary)
                                .lineLimit(1).truncationMode(.middle)
                        }
                        TableColumn("Mgr", value: \.sortManager) { e in
                            Text(e.manager.label).font(.caption).foregroundStyle(.secondary)
                        }
                        .width(min: 44, ideal: 50, max: 60)
                    }
                }
            }
        }
        .navigationTitle(rows.isEmpty ? "Packages" : "Packages - \(visible.count) of \(rows.count)")
    }

    private func actionColor(_ action: PackageEvent.Action) -> Color {
        switch action {
        case .install, .reinstall:  return .green
        case .remove, .purge:       return .red
        case .upgrade, .downgrade:  return .blue
        }
    }
}

/// Non-optional sort keys for the sortable package `Table`.
private extension PackageEvent {
    var sortTime: Date { timestamp ?? .distantPast }
    var sortAction: String { action.label }
    var sortVersion: String { version ?? "" }
    var sortManager: String { manager.label }
}
