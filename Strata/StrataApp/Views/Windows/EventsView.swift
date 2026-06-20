import SwiftUI

struct EventsView: View {
    @EnvironmentObject private var model: AppModel
    @State private var query = ""
    @State private var selectedLevel: LevelFilter = .all
    @State private var selectedEventID: EventLogRecord.ID?

    enum LevelFilter: String, CaseIterable, Identifiable {
        case all = "All"
        case critical = "Critical"
        case error = "Error"
        case warning = "Warning"
        case info = "Info"
        var id: String { rawValue }

        func matches(_ level: UInt8) -> Bool {
            switch self {
            case .all:      return true
            case .critical: return level == 1
            case .error:    return level == 2
            case .warning:  return level == 3
            case .info:     return level == 4 || level == 0
            }
        }
    }

    private func filtered(_ events: [EventLogRecord]) -> [EventLogRecord] {
        events.filter { event in
            selectedLevel.matches(event.level) &&
            (query.isEmpty
                || event.channel.localizedCaseInsensitiveContains(query)
                || event.provider.localizedCaseInsensitiveContains(query)
                || String(event.eventID).contains(query)
                || event.computer.localizedCaseInsensitiveContains(query))
        }
    }

    var body: some View {
        // Snapshot the (now-cached) events once and filter once per render, then
        // thread the results through; previously events + filter were each
        // materialized several times per body and per keystroke.
        let events = model.events
        let visible = filtered(events)
        return Group {
            if events.isEmpty {
                ContentUnavailableView {
                    Label("No events parsed yet", systemImage: "doc.text.magnifyingglass")
                } description: {
                    Text(model.files.isEmpty
                         ? "Ingest evidence first, then come back here."
                         : "Click Parse to extract and parse every .evtx in the image.")
                } actions: {
                    #if os(macOS)
                    if !model.files.isEmpty {
                        Button {
                            Task { await model.parseArtifacts() }
                        } label: {
                            Label("Parse artifacts", systemImage: "play.fill")
                        }
                        .disabled(model.isWorking)
                        .help("Parse event logs and registry hives, then run all analyzers.")
                    }
                    #endif
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else {
                VStack(spacing: 0) {
                    HStack(spacing: 12) {
                        Picker("Level", selection: $selectedLevel) {
                            ForEach(LevelFilter.allCases) { Text($0.rawValue).tag($0) }
                        }
                        .pickerStyle(.segmented)
                        .frame(maxWidth: 360)
                        Spacer()
                        TextField("Filter channel / provider / EID / host...", text: $query)
                            .textFieldStyle(.roundedBorder)
                            .frame(width: 320)
                        #if os(macOS)
                        Button {
                            Task { await model.parseArtifacts() }
                        } label: {
                            Image(systemName: "arrow.clockwise")
                        }
                        .help("Re-parse event logs and registry, then re-run analyzers")
                        .disabled(model.isWorking)
                        #endif
                    }
                    .padding(8)
                    Divider()

                    eventsSplit(visible, detail: events.first { $0.id == selectedEventID })
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .top)
            }
        }
        .navigationTitle(events.isEmpty ? "Events" : "Events - \(visible.count) of \(events.count)")
    }

    private func eventsTable(_ visible: [EventLogRecord]) -> some View {
        Table(visible, selection: $selectedEventID) {
            TableColumn("Time") { e in
                Text(e.writtenAt.formatted(date: .numeric, time: .standard))
                    .monospacedDigit().font(.caption)
            }
            TableColumn("EID") { e in
                Text("\(e.eventID)").monospacedDigit().font(.caption)
            }
            TableColumn("Level") { e in LevelBadge(level: e.level) }
            TableColumn("Channel") { e in
                Text(e.channel).font(.caption).lineLimit(1).truncationMode(.middle)
            }
            TableColumn("Provider") { e in
                Text(e.provider).font(.caption).lineLimit(1).truncationMode(.middle)
            }
            TableColumn("Computer") { e in
                Text(e.computer).font(.caption).lineLimit(1).truncationMode(.middle)
            }
        }
        .frame(minWidth: 600, maxHeight: .infinity)
    }

    @ViewBuilder
    private func eventsSplit(_ visible: [EventLogRecord], detail: EventLogRecord?) -> some View {
        #if os(macOS)
        HSplitView {
            eventsTable(visible)
            EventDetailView(event: detail)
                .frame(minWidth: 320, maxHeight: .infinity)
        }
        #else
        HStack(spacing: 0) {
            eventsTable(visible)
            Divider()
            EventDetailView(event: detail)
                .frame(minWidth: 320, maxHeight: .infinity)
        }
        #endif
    }
}

private struct LevelBadge: View {
    let level: UInt8
    var body: some View {
        Text(label)
            .font(.caption2).bold()
            .padding(.horizontal, 6).padding(.vertical, 1)
            .background(color.opacity(0.2), in: Capsule())
            .foregroundStyle(color)
    }
    private var label: String {
        switch level {
        case 1: return "CRIT"
        case 2: return "ERR"
        case 3: return "WARN"
        // Level 0 (LogAlways / unset) is treated as Information, matching the
        // Info level filter — otherwise an Info-filtered list shows blank "—".
        case 0, 4: return "INFO"
        default: return "—"
        }
    }
    private var color: Color {
        switch level {
        case 1: return .pink
        case 2: return .red
        case 3: return .orange
        case 0, 4: return .blue
        default: return .gray
        }
    }
}

private struct EventDetailView: View {
    let event: EventLogRecord?
    var body: some View {
        if let event {
            ScrollView {
                VStack(alignment: .leading, spacing: 10) {
                    Text("Event \(event.eventID)").font(.headline)
                    LabeledContent("When", value: event.writtenAt.formatted())
                    LabeledContent("Channel", value: event.channel)
                    LabeledContent("Provider", value: event.provider)
                    LabeledContent("Computer", value: event.computer)
                    LabeledContent("Record #", value: "\(event.recordNumber)")
                    LabeledContent("Source", value: (event.sourceFile as NSString).lastPathComponent)
                    Divider()
                    Text("Payload").font(.headline)
                    Text(event.payloadXML.isEmpty ? "(empty)" : event.payloadXML)
                        .font(.caption.monospaced())
                        .textSelection(.enabled)
                        .frame(maxWidth: .infinity, alignment: .leading)
                }
                .padding()
                .frame(maxWidth: .infinity, alignment: .leading)
            }
        } else {
            ContentUnavailableView("Select an event", systemImage: "doc.text")
        }
    }
}

