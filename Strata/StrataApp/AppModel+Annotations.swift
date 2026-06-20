import Foundation
import SwiftUI

extension AppModel {
    // MARK: - Annotations (analyst bookmarks + case narrative)

    /// The annotation pinned to a target, if any. `key` is `Finding.id
    /// .uuidString` or `TimelineEvent.stableKey`.
    func annotation(forTargetKey key: String) -> Annotation? {
        annotationsByTargetKey[key]
    }

    /// Create or update the bookmark for `draft`'s target. One annotation per
    /// target: editing an existing bookmark updates its tag/note in place.
    func upsertAnnotation(for draft: AnnotationDraft, tag: AnalystTag?, note: String) {
        let author = currentCase?.examiner ?? ""
        if let index = annotations.firstIndex(where: { $0.targetKey == draft.targetKey }) {
            annotations[index].tag = tag
            annotations[index].note = note
            annotations[index].modifiedAt = Date()
            if !author.isEmpty { annotations[index].author = author }
        } else {
            annotations.append(Annotation(author: author,
                                          targetKind: draft.targetKind,
                                          targetKey: draft.targetKey,
                                          evidenceID: draft.evidenceID,
                                          tag: tag, note: note,
                                          title: draft.title,
                                          timestamp: draft.timestamp,
                                          sourceLabel: draft.sourceLabel))
        }
        saveAnnotations()
    }

    func removeAnnotation(_ id: UUID) {
        annotations.removeAll { $0.id == id }
        saveAnnotations()
    }

    private func saveAnnotations() {
        guard let bundleURL = currentCaseBundleURL else { return }
        do {
            try CaseStore.writeAnnotations(annotations, in: bundleURL)
        } catch {
            errorMessage = "Failed to save annotations: \(error.localizedDescription)"
        }
    }

    /// Replace the case narrative and persist. No-op when unchanged so the
    /// editor's debounced auto-save doesn't churn `notes.json`.
    func updateCaseNotes(_ text: String) {
        guard caseNotes.text != text else { return }
        caseNotes = CaseNotes(text: text, modifiedAt: Date(),
                              author: currentCase?.examiner ?? "")
        guard let bundleURL = currentCaseBundleURL else { return }
        do {
            try CaseStore.writeNotes(caseNotes, in: bundleURL)
        } catch {
            errorMessage = "Failed to save case notes: \(error.localizedDescription)"
        }
    }

    /// Ask the Timeline tab to reveal `date` with ±30 min of context.
    func pivotToTimeline(around date: Date) {
        let pad: TimeInterval = 30 * 60
        timelinePivot = TimelinePivot(token: UUID(),
                                      range: date.addingTimeInterval(-pad)...date.addingTimeInterval(pad))
    }

    /// Owning host for a finding. Findings are few, so the scan is cheap -
    /// unlike timeline events, whose host attribution comes from the active
    /// scope instead.
    func evidenceID(forFinding id: UUID) -> UUID? {
        states.first { $0.value.findings.contains { $0.id == id } }?.key
    }
}
