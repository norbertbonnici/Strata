import SwiftUI

/// Parsed macOS LaunchServices quarantine events for the active scope - macOS
/// download provenance: which app pulled a file from the network, the file's
/// URL, the referring page, and when. One row per recorded download, newest
/// first. Mirrors PrefetchView (filter bar + table/detail split + empty-state
/// parse).
struct QuarantineView: View {
    @EnvironmentObject private var model: AppModel
    @State private var query = ""
    @State private var selectedID: QuarantineEvent.ID?

    private func filtered(_ events: [QuarantineEvent]) -> [QuarantineEvent] {
        guard !query.isEmpty else { return events }
        return events.filter { e in
            (e.agentName?.localizedCaseInsensitiveContains(query) ?? false)
                || (e.dataURL?.localizedCaseInsensitiveContains(query) ?? false)
                || (e.originURL?.localizedCaseInsensitiveContains(query) ?? false)
        }
    }

    var body: some View {
        let events = model.quarantine
        let visible = filtered(events)
        return Group {
            if events.isEmpty {
                ContentUnavailableView {
                    Label("No quarantine events parsed yet", systemImage: "shield.lefthalf.filled")
                } description: {
                    Text(model.files.isEmpty
                         ? "Ingest evidence first, then come back here."
                         : "Click Parse to read the LaunchServices QuarantineEventsV2 store.")
                } actions: {
                    #if os(macOS)
                    if !model.files.isEmpty {
                        Button {
                            Task { await model.parseMac() }
                        } label: {
                            Label("Parse macOS artifacts", systemImage: "play.fill")
                        }
                        .disabled(model.isWorking)
                        .help("Parse launchd jobs, the quarantine store, and the macOS host info.")
                    }
                    #endif
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else {
                VStack(spacing: 0) {
                    HStack(spacing: 12) {
                        Spacer()
                        TextField("Filter app / URL...", text: $query)
                            .textFieldStyle(.roundedBorder)
                            .frame(width: 320)
                        #if os(macOS)
                        Button {
                            Task { await model.parseMac() }
                        } label: {
                            Image(systemName: "arrow.clockwise")
                        }
                        .help("Re-parse macOS artifacts")
                        .disabled(model.isWorking)
                        #endif
                    }
                    .padding(8)
                    Divider()

                    split(visible, detail: events.first { $0.id == selectedID })
                        .frame(maxWidth: .infinity, maxHeight: .infinity)
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .top)
            }
        }
        .navigationTitle(events.isEmpty ? "Quarantine" : "Quarantine - \(visible.count) of \(events.count)")
    }

    private func table(_ visible: [QuarantineEvent]) -> some View {
        Table(visible, selection: $selectedID) {
            TableColumn("Downloaded") { e in
                Text(e.displayTitle).font(.caption).lineLimit(1).truncationMode(.middle)
            }
            TableColumn("App") { e in
                Text(e.agentName ?? "—").font(.caption).lineLimit(1).truncationMode(.middle)
            }
            TableColumn("From host") { e in
                Text(e.dataHost ?? e.originHost ?? "—").font(.caption).lineLimit(1).truncationMode(.middle)
            }
            TableColumn("When") { e in
                Text(e.timestamp?.formatted(date: .numeric, time: .standard) ?? "—")
                    .monospacedDigit().font(.caption)
            }
        }
        .frame(minWidth: 600, maxHeight: .infinity)
    }

    @ViewBuilder
    private func split(_ visible: [QuarantineEvent], detail: QuarantineEvent?) -> some View {
        #if os(macOS)
        HSplitView {
            table(visible)
            QuarantineDetailView(event: detail)
                .frame(minWidth: 320, maxHeight: .infinity)
        }
        #else
        HStack(spacing: 0) {
            table(visible)
            Divider()
            QuarantineDetailView(event: detail)
                .frame(minWidth: 320, maxHeight: .infinity)
        }
        #endif
    }
}

private struct QuarantineDetailView: View {
    let event: QuarantineEvent?
    var body: some View {
        if let event {
            ScrollView {
                VStack(alignment: .leading, spacing: 10) {
                    Text(event.displayTitle).font(.headline).textSelection(.enabled)
                    LabeledContent("Downloaded by", value: event.agentName ?? "—")
                    LabeledContent("When",
                                   value: event.timestamp?.formatted(date: .abbreviated, time: .standard) ?? "—")
                    if let dataURL = event.dataURL {
                        LabeledContent("File URL") {
                            Text(dataURL).font(.caption.monospaced()).textSelection(.enabled)
                                .frame(maxWidth: .infinity, alignment: .trailing)
                        }
                    }
                    if let originURL = event.originURL {
                        LabeledContent("Referrer") {
                            Text(originURL).font(.caption.monospaced()).textSelection(.enabled)
                                .frame(maxWidth: .infinity, alignment: .trailing)
                        }
                    }
                    if let eventID = event.eventID {
                        LabeledContent("Event ID", value: eventID)
                    }
                    Divider()
                    LabeledContent("Source store") {
                        Text(event.sourceFile).font(.caption.monospaced()).textSelection(.enabled)
                            .frame(maxWidth: .infinity, alignment: .trailing)
                    }
                }
                .padding()
                .frame(maxWidth: .infinity, alignment: .leading)
            }
        } else {
            ContentUnavailableView("Select a download", systemImage: "shield.lefthalf.filled")
        }
    }
}
