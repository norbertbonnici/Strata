import SwiftUI

/// Sidebar tab for managing the case's IOC list and viewing match results.
/// The list lives on AppModel (one set per case); matches are per-host and
/// rolled up across the active scope.
struct IOCView: View {
    @EnvironmentObject private var model: AppModel
    @State private var showingPasteSheet = false
    @State private var selectedKindFilter: IOCKind?
    @State private var sortOrder: [KeyPathComparator<IOCMatch>] = []

    private var matches: [IOCMatch] {
        var m = model.iocMatches
        if let filter = selectedKindFilter { m = m.filter { $0.iocKind == filter } }
        if sortOrder.isEmpty {
            // Default to chronological order so the leading "When" column is
            // honest; matches with no timestamp (file/registry hits) sort last.
            m.sort { ($0.timestamp ?? .distantFuture) < ($1.timestamp ?? .distantFuture) }
        } else {
            m.sort(using: sortOrder)
        }
        return m
    }

    var body: some View {
        VStack(spacing: 0) {
            HStack(spacing: 8) {
                Button {
                    showingPasteSheet = true
                } label: {
                    Label("Paste IOCs...", systemImage: "doc.on.clipboard")
                }
                Button {
                    Task { await model.runIOCMatch() }
                } label: {
                    Label("Run Match", systemImage: "play.fill")
                }
                .disabled(model.iocs.isEmpty || model.isWorking || model.evidenceList.isEmpty)
                Text("\(model.iocs.count) IOC\(model.iocs.count == 1 ? "" : "s") loaded")
                    .font(.caption).foregroundStyle(.secondary)
                Spacer()
                Picker("Kind", selection: $selectedKindFilter) {
                    Text("All kinds").tag(IOCKind?.none)
                    ForEach(IOCKind.allCases, id: \.self) { kind in
                        Text(kind.label).tag(Optional(kind))
                    }
                }
                .pickerStyle(.menu)
                .frame(width: 140)
            }
            .padding(8)
            Divider()

            #if os(macOS)
            HSplitView {
                iocList
                    .frame(minWidth: 280, maxHeight: .infinity)
                matchList
                    .frame(minWidth: 480, maxHeight: .infinity)
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity)
            #else
            HStack(spacing: 0) {
                iocList
                    .frame(minWidth: 280, maxHeight: .infinity)
                Divider()
                matchList
                    .frame(minWidth: 480, maxHeight: .infinity)
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity)
            #endif
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .top)
        .navigationTitle("IOCs - \(model.iocs.count) loaded, \(model.iocMatchCount) matches")
        .sheet(isPresented: $showingPasteSheet) { IOCPasteSheet() }
        .overlay {
            if model.currentCase == nil {
                ContentUnavailableView("Open a case",
                    systemImage: "scope",
                    description: Text("IOC matching runs against a loaded case."))
            }
        }
    }

    @ViewBuilder
    private var iocList: some View {
        if model.iocs.isEmpty {
            ContentUnavailableView("No IOCs loaded",
                systemImage: "scope",
                description: Text("Paste IPs, domains, URLs or hashes (one per line / comma / space)."))
        } else {
            List {
                ForEach(model.iocs) { ioc in
                    HStack(spacing: 8) {
                        IOCKindBadge(kind: ioc.kind)
                        Text(ioc.value).font(.body.monospaced())
                            .lineLimit(1).truncationMode(.middle)
                        Spacer()
                        Button {
                            model.removeIOC(ioc.id)
                        } label: {
                            Image(systemName: "minus.circle.fill")
                                .foregroundStyle(.secondary)
                        }
                        .buttonStyle(.borderless)
                    }
                }
            }
            #if os(macOS)
            .listStyle(.inset(alternatesRowBackgrounds: true))
            #else
            .listStyle(.inset)
            #endif
        }
    }

    @ViewBuilder
    private var matchList: some View {
        if matches.isEmpty {
            ContentUnavailableView("No matches",
                systemImage: "magnifyingglass",
                description: Text(model.iocs.isEmpty
                                  ? "Add IOCs above and click Run Match."
                                  : "Run Match to scan events, registry, and files."))
        } else {
            // sortOrder drives click-to-sort on the text columns; "When" and
            // "Kind" stay default-ordered (Optional/enum aren't KeyPathComparator-
            // friendly), and the chronological default above keeps rows honest.
            Table(matches, sortOrder: $sortOrder) {
                TableColumn("When") { m in
                    Text(m.timestamp?.formatted(date: .numeric, time: .standard) ?? "—")
                        .font(.caption).monospacedDigit()
                }
                TableColumn("Kind") { m in IOCKindBadge(kind: m.iocKind) }
                TableColumn("IOC", value: \.iocValue) { m in
                    Text(m.iocValue).font(.caption.monospaced())
                        .lineLimit(1).truncationMode(.middle)
                }
                TableColumn("Where", value: \.summary) { m in
                    Text(m.summary).font(.caption)
                        .lineLimit(1).truncationMode(.middle)
                }
                TableColumn("Context", value: \.context) { m in
                    Text(m.context).font(.caption.monospaced())
                        .lineLimit(1).truncationMode(.middle)
                        .help(m.context)
                }
            }
        }
    }
}

/// Modal text editor for pasting raw IOC text. Splits on whitespace / comma
/// / semicolon and auto-classifies each token via IOCKind.classify.
private struct IOCPasteSheet: View {
    @EnvironmentObject private var model: AppModel
    @Environment(\.dismiss) private var dismiss
    @State private var text = ""

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("Paste IOCs").font(.title2).bold()
            Text("One per line, or separated by spaces / commas. Lines starting with # are ignored. Kinds are auto-detected.")
                .font(.caption).foregroundStyle(.secondary)
            TextEditor(text: $text)
                .font(.body.monospaced())
                .frame(minWidth: 520, minHeight: 280)
                .border(.tertiary)
            HStack {
                Spacer()
                Button("Cancel") { dismiss() }
                Button("Add") {
                    model.addIOCs(from: text)
                    dismiss()
                }
                .keyboardShortcut(.defaultAction)
                .disabled(text.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
            }
        }
        .padding(16)
        .frame(width: 560)
    }
}

struct IOCKindBadge: View {
    let kind: IOCKind
    var body: some View {
        Text(kind.label.uppercased())
            .font(.caption2).bold()
            .padding(.horizontal, 6).padding(.vertical, 1)
            .background(color.opacity(0.2), in: Capsule())
            .foregroundStyle(color)
    }
    private var color: Color {
        switch kind {
        case .ip:     return .blue
        case .domain: return .purple
        case .url:    return .pink
        case .hash:   return .orange
        }
    }
}
