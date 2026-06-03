import SwiftUI

struct TimelineView: View {
    @EnvironmentObject private var model: AppModel
    @State private var enabledKinds: Set<MACBKind> = Set(MACBKind.allCases)
    @State private var query = ""

    private var filtered: [TimelineEvent] {
        model.timeline.filter { event in
            enabledKinds.contains(event.kind) &&
            (query.isEmpty || event.path.localizedCaseInsensitiveContains(query))
        }
    }

    var body: some View {
        VStack(spacing: 0) {
            HStack {
                ForEach(MACBKind.allCases, id: \.self) { kind in
                    Toggle(kind.label, isOn: Binding(
                        get: { enabledKinds.contains(kind) },
                        set: { on in
                            if on { enabledKinds.insert(kind) } else { enabledKinds.remove(kind) }
                        }))
                        .toggleStyle(.button)
                        .controlSize(.small)
                }
                Spacer()
                TextField("Filter path...", text: $query)
                    .textFieldStyle(.roundedBorder)
                    .frame(width: 220)
            }
            .padding(8)
            Divider()

            Table(filtered) {
                TableColumn("Time") { e in
                    Text(e.date.formatted(date: .numeric, time: .standard)).monospacedDigit()
                }
                TableColumn("MACB") { e in MACBBadge(kind: e.kind) }
                TableColumn("Path") { e in
                    HStack {
                        Text(e.path).lineLimit(1).truncationMode(.middle)
                        if e.isDeleted { Image(systemName: "trash").foregroundStyle(.red) }
                    }
                }
            }
        }
        .navigationTitle("Timeline - \(filtered.count) events")
        .overlay {
            if model.timeline.isEmpty {
                ContentUnavailableView("No timeline yet", systemImage: "clock",
                    description: Text("Ingest evidence to build a MACB timeline."))
            }
        }
    }
}

private struct MACBBadge: View {
    let kind: MACBKind
    var body: some View {
        Text(kind.rawValue)
            .font(.caption.monospaced())
            .frame(width: 18, height: 18)
            .background(color.opacity(0.25), in: RoundedRectangle(cornerRadius: 4))
            .foregroundStyle(color)
    }
    private var color: Color {
        switch kind {
        case .modified: return .blue
        case .accessed: return .green
        case .changed:  return .orange
        case .born:     return .purple
        }
    }
}
