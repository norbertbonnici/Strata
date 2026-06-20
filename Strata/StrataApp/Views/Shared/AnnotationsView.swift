#if os(macOS)
import SwiftUI

/// The analyst's working notes for the case: the free-form case narrative on
/// top, and every bookmark (tagged/annotated finding or timeline event)
/// below, chronological by the *target's* own timestamp so the list reads as
/// the incident story. Bookmarks are created from the Timeline (row context
/// menu) and Kill Chain (finding inspector); this tab reviews, edits, and
/// pivots back into the timeline.
struct AnnotationsView: View {
    @EnvironmentObject private var model: AppModel

    @State private var narrativeDraft = ""
    @State private var narrativeLoaded = false
    @State private var tagFilter: AnalystTag? = nil
    @State private var saveTask: Task<Void, Never>?

    /// Bookmarks shown: tag-filtered, chronological (undated last).
    private var visibleAnnotations: [Annotation] {
        model.annotations
            .filter { tagFilter == nil || $0.tag == tagFilter }
            .sorted {
                ($0.timestamp ?? .distantFuture, $0.createdAt)
                    < ($1.timestamp ?? .distantFuture, $1.createdAt)
            }
    }

    var body: some View {
        VStack(spacing: 0) {
            narrativeSection
            Divider()
            bookmarkSection
        }
        .navigationTitle("Annotations - \(model.annotations.count) bookmark\(model.annotations.count == 1 ? "" : "s")")
        .onAppear(perform: loadNarrativeIfNeeded)
        .onDisappear { flushNarrative() }
    }

    // MARK: - Case narrative

    @ViewBuilder
    private var narrativeSection: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack {
                Text("Case narrative").font(.headline)
                Spacer()
                if let modified = model.caseNotes.modifiedAt {
                    Text("Saved \(modified.formatted(date: .numeric, time: .shortened))")
                        .font(.caption).foregroundStyle(.secondary)
                }
            }
            Text("The running story of the incident - free-form analyst notes, included in the examiner report.")
                .font(.caption).foregroundStyle(.secondary)
            TextEditor(text: $narrativeDraft)
                .font(.body)
                .frame(minHeight: 110, maxHeight: 180)
                .overlay(RoundedRectangle(cornerRadius: 6)
                    .stroke(Color.secondary.opacity(0.3)))
                .onChange(of: narrativeDraft) { _, text in
                    scheduleNarrativeSave(text)
                }
        }
        .padding(12)
    }

    private func loadNarrativeIfNeeded() {
        guard !narrativeLoaded else { return }
        narrativeLoaded = true
        narrativeDraft = model.caseNotes.text
    }

    /// Debounced auto-save: one write per typing pause, not per keystroke.
    private func scheduleNarrativeSave(_ text: String) {
        saveTask?.cancel()
        saveTask = Task {
            try? await Task.sleep(nanoseconds: 800_000_000)
            if Task.isCancelled { return }
            model.updateCaseNotes(text)
        }
    }

    private func flushNarrative() {
        saveTask?.cancel()
        model.updateCaseNotes(narrativeDraft)
    }

    // MARK: - Bookmarks

    @ViewBuilder
    private var bookmarkSection: some View {
        VStack(spacing: 0) {
            HStack(spacing: 8) {
                Text("Bookmarks").font(.headline)
                Divider().frame(height: 16)
                Toggle("All", isOn: Binding(
                    get: { tagFilter == nil },
                    set: { if $0 { tagFilter = nil } }))
                    .toggleStyle(.button)
                    .controlSize(.small)
                ForEach(AnalystTag.allCases, id: \.self) { tag in
                    Toggle(isOn: Binding(
                        get: { tagFilter == tag },
                        set: { on in tagFilter = on ? tag : nil })) {
                        Label(tag.label, systemImage: tag.symbol)
                    }
                    .toggleStyle(.button)
                    .controlSize(.small)
                    .tint(AnnotationStyle.color(for: tag))
                }
                Spacer()
                Text("\(visibleAnnotations.count) shown")
                    .font(.caption).foregroundStyle(.secondary)
            }
            .padding(8)
            Divider()

            if model.annotations.isEmpty {
                ContentUnavailableView("No bookmarks yet", systemImage: "bookmark",
                    description: Text("Bookmark timeline events (right-click a row) or findings (Kill Chain inspector) to build the case story."))
            } else {
                Table(visibleAnnotations) {
                    TableColumn("Tag") { a in
                        if let tag = a.tag {
                            Label(tag.label, systemImage: tag.symbol)
                                .foregroundStyle(AnnotationStyle.color(for: tag))
                                .labelStyle(.titleAndIcon)
                        } else {
                            Image(systemName: "bookmark")
                                .foregroundStyle(.secondary)
                        }
                    }
                    .width(min: 90, ideal: 110, max: 130)
                    TableColumn("Time") { a in
                        Text(a.timestamp.map { $0.formatted(date: .numeric, time: .standard) } ?? "—")
                            .monospacedDigit()
                    }
                    .width(min: 130, ideal: 150, max: 170)
                    TableColumn("Source") { a in
                        Text(a.sourceLabel).foregroundStyle(.secondary)
                    }
                    .width(min: 70, ideal: 90, max: 120)
                    TableColumn("Item") { a in
                        Text(a.title).lineLimit(1).truncationMode(.middle)
                            .help(a.title)
                    }
                    TableColumn("Note") { a in
                        Text(a.note).lineLimit(1).truncationMode(.tail)
                            .foregroundStyle(.secondary)
                            .help(a.note)
                    }
                    TableColumn("") { a in
                        HStack(spacing: 4) {
                            if let date = a.timestamp {
                                Button {
                                    model.pivotToTimeline(around: date)
                                } label: {
                                    Image(systemName: "clock.arrow.circlepath")
                                }
                                .buttonStyle(.borderless)
                                .controlSize(.small)
                                .help("Reveal in Timeline (±30 min)")
                            }
                            Button {
                                model.activeSheet = .annotationEditor(draft(for: a))
                            } label: {
                                Image(systemName: "pencil")
                            }
                            .buttonStyle(.borderless)
                            .controlSize(.small)
                            .help("Edit bookmark")
                            Button(role: .destructive) {
                                model.removeAnnotation(a.id)
                            } label: {
                                Image(systemName: "trash")
                            }
                            .buttonStyle(.borderless)
                            .controlSize(.small)
                            .help("Delete bookmark")
                        }
                    }
                    .width(min: 80, ideal: 80, max: 90)
                }
            }
        }
    }

    /// Rebuild an editor draft from a stored annotation (the live target may
    /// not be loaded; the denormalized snapshot is enough to edit tag/note).
    private func draft(for annotation: Annotation) -> AnnotationDraft {
        if annotation.targetKind == .finding,
           let uuid = UUID(uuidString: annotation.targetKey),
           let finding = model.findings.first(where: { $0.id == uuid }) {
            return AnnotationDraft(finding: finding, evidenceID: annotation.evidenceID)
        }
        return AnnotationDraft(stored: annotation)
    }
}
#endif
