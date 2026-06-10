#if !os(macOS)
import SwiftUI

/// Read-only annotations viewer for the iOS app: the case narrative and every
/// analyst bookmark, chronological by the target's own timestamp. Creating and
/// editing annotations is macOS-only (that's where triage happens); this view
/// displays what the macOS app recorded - the denormalized snapshot on each
/// `Annotation` means nothing needs the heavyweight artifacts loaded.
struct AnnotationsDrillView: View {
    @EnvironmentObject private var model: AppModel

    private var sorted: [Annotation] {
        model.annotations.sorted {
            ($0.timestamp ?? .distantFuture, $0.createdAt)
                < ($1.timestamp ?? .distantFuture, $1.createdAt)
        }
    }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 0) {
                LargeTitle(
                    title: "Annotations",
                    subtitle: "\(model.annotations.count) bookmark\(model.annotations.count == 1 ? "" : "s")")

                if !model.caseNotes.isEmpty {
                    SectionHeader(label: "Case narrative").padding(.top, 14)
                    Card {
                        VStack(alignment: .leading, spacing: 6) {
                            Text(model.caseNotes.text)
                                .font(.subheadline)
                                .foregroundStyle(Theme.text)
                                .textSelection(.enabled)
                            if let modified = model.caseNotes.modifiedAt {
                                Text("Updated \(modified.formatted(date: .abbreviated, time: .shortened))\(model.caseNotes.author.isEmpty ? "" : " · \(model.caseNotes.author)")")
                                    .font(.caption2)
                                    .foregroundStyle(Theme.text3)
                            }
                        }
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .padding(.vertical, 4)
                    }
                }

                if model.annotations.isEmpty && model.caseNotes.isEmpty {
                    ContentUnavailableView(
                        "No annotations",
                        systemImage: "bookmark",
                        description: Text("Bookmark findings and timeline events in the macOS app to build the case story."))
                        .padding(.top, 60)
                        .frame(maxWidth: .infinity)
                } else if !model.annotations.isEmpty {
                    SectionHeader(label: "Bookmarks").padding(.top, 14)
                    Card {
                        ForEach(Array(sorted.enumerated()), id: \.element.id) { index, annotation in
                            row(annotation, showDivider: index < sorted.count - 1)
                        }
                    }
                }

                Spacer(minLength: 26)
            }
        }
        .background(Theme.bg.ignoresSafeArea())
        .navigationBarTitleDisplayMode(.inline)
        .toolbarBackground(Theme.bg, for: .navigationBar)
        .toolbarBackground(.visible, for: .navigationBar)
    }

    @ViewBuilder
    private func row(_ annotation: Annotation, showDivider: Bool) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack(spacing: 6) {
                Image(systemName: annotation.tag?.symbol ?? "bookmark.fill")
                    .font(.caption)
                    .foregroundStyle(AnnotationStyle.color(for: annotation.tag))
                Text(annotation.tag?.label ?? "Bookmarked")
                    .font(.caption.bold())
                    .foregroundStyle(AnnotationStyle.color(for: annotation.tag))
                Text(annotation.sourceLabel)
                    .font(.caption2)
                    .padding(.horizontal, 5).padding(.vertical, 1)
                    .background(Theme.hair2, in: RoundedRectangle(cornerRadius: 4))
                    .foregroundStyle(Theme.text2)
                Spacer()
                if let t = annotation.timestamp {
                    Text(t.formatted(date: .numeric, time: .shortened))
                        .font(.caption2.monospacedDigit())
                        .foregroundStyle(Theme.text3)
                }
            }
            Text(annotation.title)
                .font(.subheadline)
                .foregroundStyle(Theme.text)
                .lineLimit(2)
                .truncationMode(.middle)
            if !annotation.note.isEmpty {
                Text(annotation.note)
                    .font(.caption)
                    .foregroundStyle(Theme.text2)
            }
        }
        .padding(.vertical, 6)
        if showDivider {
            Divider().background(Theme.hair2)
        }
    }
}
#endif
