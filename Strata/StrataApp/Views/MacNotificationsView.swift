import SwiftUI

/// macOS Notification Center: notifications the system delivered, with app,
/// title/body, and time — corroborates app activity and can preserve message /
/// alert content.
struct MacNotificationsView: View {
    @EnvironmentObject private var model: AppModel
    @State private var query = ""
    @State private var selectedID: MacNotification.ID?
    @State private var sort = [KeyPathComparator(\MacNotification.sortTime, order: .reverse)]

    private func filtered(_ items: [MacNotification]) -> [MacNotification] {
        guard !query.isEmpty else { return items }
        return items.filter { n in
            (n.appID?.localizedCaseInsensitiveContains(query) ?? false)
                || (n.title?.localizedCaseInsensitiveContains(query) ?? false)
                || (n.body?.localizedCaseInsensitiveContains(query) ?? false)
        }
    }

    var body: some View {
        let rows = model.notifications
        let visible = filtered(rows).sorted(using: sort)
        return Group {
            if rows.isEmpty {
                ContentUnavailableView {
                    Label("No notifications parsed yet", systemImage: "bell.badge")
                } description: {
                    Text(model.files.isEmpty
                         ? "Ingest a macOS image first, then come back here."
                         : "Click Parse to read the Notification Center database.")
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
                        Spacer()
                        TextField("Filter app / title / body...", text: $query)
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
        .navigationTitle(rows.isEmpty ? "Notifications"
                         : "Notifications - \(visible.count.formatted()) of \(rows.count.formatted())")
    }

    private func table(_ visible: [MacNotification]) -> some View {
        Table(visible, selection: $selectedID, sortOrder: $sort) {
            TableColumn("When", value: \.sortTime) { n in
                Text(n.deliveredDate?.formatted(date: .numeric, time: .standard) ?? "—")
                    .monospacedDigit().font(.caption)
            }
            .width(min: 130, ideal: 150, max: 180)
            TableColumn("App") { n in
                Text(n.appID ?? "—").font(.caption).foregroundStyle(.secondary)
                    .lineLimit(1).truncationMode(.middle)
            }
            .width(min: 140, ideal: 200, max: 280)
            TableColumn("Notification") { n in
                Text(n.displayTitle).font(.callout).lineLimit(1).truncationMode(.tail)
            }
        }
    }

    @ViewBuilder
    private func split(_ visible: [MacNotification], detail: MacNotification?) -> some View {
        #if os(macOS)
        HSplitView {
            table(visible).frame(minWidth: 560, maxHeight: .infinity)
            MacNotificationDetailView(notification: detail).frame(minWidth: 300, maxHeight: .infinity)
        }
        #else
        table(visible)
        #endif
    }
}

private extension MacNotification {
    var sortTime: Date { deliveredDate ?? .distantPast }
}

private struct MacNotificationDetailView: View {
    let notification: MacNotification?

    var body: some View {
        if let n = notification {
            ScrollView {
                VStack(alignment: .leading, spacing: 10) {
                    Text(n.displayTitle).font(.headline).textSelection(.enabled)
                    if let app = n.appID { LabeledContent("App", value: app) }
                    LabeledContent("Delivered", value: n.deliveredDate?.formatted(date: .long, time: .standard) ?? "—")
                    if let t = n.title, !t.isEmpty {
                        LabeledContent("Title") {
                            Text(t).font(.callout).textSelection(.enabled)
                                .frame(maxWidth: .infinity, alignment: .trailing)
                        }
                    }
                    if let b = n.body, !b.isEmpty {
                        Divider()
                        Text(b).font(.body).textSelection(.enabled)
                            .frame(maxWidth: .infinity, alignment: .leading)
                    }
                    Divider()
                    LabeledContent("Source") {
                        Text(n.sourceFile).font(.caption.monospaced()).textSelection(.enabled)
                            .frame(maxWidth: .infinity, alignment: .trailing)
                    }
                }
                .padding()
                .frame(maxWidth: .infinity, alignment: .leading)
            }
        } else {
            ContentUnavailableView("Select a notification", systemImage: "bell")
        }
    }
}
