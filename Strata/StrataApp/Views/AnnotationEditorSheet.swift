import SwiftUI

#if os(macOS)
/// Creates or edits the analyst bookmark for one target (a finding or a
/// timeline event): verdict tag + free-form note. Reuses the single
/// `.sheet(item:)` host on `ContentView` (AppModel.ActiveSheet).
struct AnnotationEditorSheet: View {
    @EnvironmentObject private var model: AppModel
    @Environment(\.dismiss) private var dismiss
    let draft: AnnotationDraft

    @State private var tag: AnalystTag?
    @State private var note = ""
    @State private var loaded = false

    private var existing: Annotation? { model.annotation(forTargetKey: draft.targetKey) }

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            VStack(alignment: .leading, spacing: 4) {
                Text(existing == nil ? "Add Bookmark" : "Edit Bookmark")
                    .font(.title2).bold()
                HStack(spacing: 6) {
                    Text(draft.sourceLabel)
                        .font(.caption2.bold())
                        .padding(.horizontal, 5).padding(.vertical, 1)
                        .background(Color.secondary.opacity(0.15),
                                    in: RoundedRectangle(cornerRadius: 4))
                    if let t = draft.timestamp {
                        Text(t.formatted(date: .numeric, time: .standard))
                            .font(.caption).foregroundStyle(.secondary)
                            .monospacedDigit()
                    }
                }
                Text(draft.title)
                    .font(.callout)
                    .lineLimit(3)
                    .truncationMode(.middle)
                    .textSelection(.enabled)
            }

            VStack(alignment: .leading, spacing: 6) {
                Text("Tag").font(.headline)
                HStack(spacing: 8) {
                    ForEach(AnalystTag.allCases, id: \.self) { candidate in
                        Toggle(isOn: Binding(
                            get: { tag == candidate },
                            set: { on in tag = on ? candidate : nil })) {
                            Label(candidate.label, systemImage: candidate.symbol)
                        }
                        .toggleStyle(.button)
                        .controlSize(.small)
                        .tint(AnnotationStyle.color(for: candidate))
                    }
                }
            }

            VStack(alignment: .leading, spacing: 6) {
                Text("Note").font(.headline)
                TextEditor(text: $note)
                    .font(.body)
                    .frame(minHeight: 80, maxHeight: 140)
                    .overlay(RoundedRectangle(cornerRadius: 6)
                        .stroke(Color.secondary.opacity(0.3)))
            }

            HStack {
                if existing != nil {
                    Button("Remove Bookmark", role: .destructive) {
                        if let id = existing?.id { model.removeAnnotation(id) }
                        dismiss()
                    }
                }
                Spacer()
                Button("Cancel") { dismiss() }
                Button("Save") {
                    model.upsertAnnotation(for: draft, tag: tag,
                                           note: note.trimmingCharacters(in: .whitespacesAndNewlines))
                    dismiss()
                }
                .keyboardShortcut(.defaultAction)
            }
        }
        .padding(20)
        .frame(width: 460)
        .onAppear(perform: loadIfNeeded)
    }

    private func loadIfNeeded() {
        guard !loaded else { return }
        loaded = true
        guard let existing else { return }
        tag = existing.tag
        note = existing.note
    }
}
#endif

/// Shared tag → color mapping (used by the editor, timeline star, annotation
/// list, and the iOS drill). Lives outside the `#if` so iOS sees it too.
enum AnnotationStyle {
    static func color(for tag: AnalystTag?) -> Color {
        switch tag {
        case .malicious:  return .red
        case .suspicious: return .orange
        case .benign:     return .green
        case .followUp:   return .blue
        case nil:         return .secondary
        }
    }
}
