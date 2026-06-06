import SwiftUI
import UniformTypeIdentifiers

/// Shown when no case is open. Lets the user create a new .strata bundle,
/// open an existing one, or pick from recently opened cases.
struct WelcomeView: View {
    @EnvironmentObject private var model: AppModel
    @State private var showNewCasePicker = false
    @State private var pendingNewCase: (name: String, examiner: String)?

    var body: some View {
        VStack(spacing: 24) {
            VStack(spacing: 8) {
                Image(systemName: "square.stack.3d.up")
                    .font(.system(size: 56))
                    .foregroundStyle(Theme.teal2)
                Text("Strata")
                    .font(.largeTitle).bold()
                    .foregroundStyle(Theme.text)
                Text(introMessage)
                    .foregroundStyle(Theme.text2)
            }
            .padding(.top, 60)

            HStack(spacing: 12) {
                #if os(macOS)
                Button {
                    model.activeSheet = .newCase
                } label: {
                    Label("New Case...", systemImage: "plus.square")
                        .frame(minWidth: 140)
                }
                .controlSize(.large)
                .buttonStyle(.borderedProminent)
                #endif

                Button {
                    model.requestOpenCase()
                } label: {
                    Label("Open Case...", systemImage: "folder")
                        .frame(minWidth: 140)
                }
                .controlSize(.large)
                #if !os(macOS)
                .buttonStyle(.borderedProminent)
                #endif
            }

            if !model.recentCases.isEmpty {
                VStack(alignment: .leading, spacing: 6) {
                    Text("Recent")
                        .font(.headline)
                        .foregroundStyle(Theme.text2)
                    VStack(spacing: 0) {
                        ForEach(model.recentCases, id: \.self) { url in
                            recentRow(url)
                        }
                    }
                    .background(Theme.card)
                    .overlay(RoundedRectangle(cornerRadius: 12).stroke(Theme.hair, lineWidth: 1))
                    .clipShape(RoundedRectangle(cornerRadius: 12))
                }
                .padding(.horizontal, 40)
                .frame(maxWidth: 560)
            }

            Spacer()
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .background(Theme.bg)
        // A `.strata` bundle is a directory on disk - the picker accepts a
        // folder selection on both platforms. We hold a security-scoped
        // resource for the duration of the open, then release.
        .fileImporter(
            isPresented: $model.showOpenCasePicker,
            allowedContentTypes: [.folder],
            allowsMultipleSelection: false
        ) { result in
            guard case .success(let urls) = result, let url = urls.first else { return }
            let didStart = url.startAccessingSecurityScopedResource()
            Task {
                await model.openCase(at: url)
                if didStart { url.stopAccessingSecurityScopedResource() }
            }
        }
    }

    private var introMessage: String {
        #if os(macOS)
        "Open a case to begin, or create a new one."
        #else
        "Open a case from Files or iCloud Drive."
        #endif
    }

    @ViewBuilder
    private func recentRow(_ url: URL) -> some View {
        Button {
            Task { await model.openCase(at: url) }
        } label: {
            HStack {
                Image(systemName: "tray.full").foregroundStyle(Theme.teal2)
                VStack(alignment: .leading) {
                    Text(url.deletingPathExtension().lastPathComponent)
                        .font(.body)
                        .foregroundStyle(Theme.text)
                    Text(url.path)
                        .font(.caption)
                        .foregroundStyle(Theme.text3)
                        .lineLimit(1).truncationMode(.middle)
                }
                Spacer()
            }
            .padding(.horizontal, 12).padding(.vertical, 8)
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .overlay(alignment: .bottom) { Divider().background(Theme.hair2) }
    }

}

#if os(macOS)

struct NewCaseSheet: View {
    @EnvironmentObject private var model: AppModel
    @Environment(\.dismiss) private var dismiss
    @State private var name = ""
    @State private var examiner = ""
    @State private var showFolderPicker = false

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("New Case").font(.title2).bold()
            Form {
                TextField("Case name", text: $name)
                TextField("Examiner", text: $examiner)
            }
            Text("Pick a parent folder; the case bundle will be created inside as \"<name>.strata\".")
                .font(.caption)
                .foregroundStyle(.secondary)
            HStack {
                Spacer()
                Button("Cancel") { dismiss() }
                Button("Choose Folder...") { showFolderPicker = true }
                    .keyboardShortcut(.defaultAction)
                    .disabled(name.trimmingCharacters(in: .whitespaces).isEmpty)
            }
        }
        .padding(20)
        .frame(width: 420)
        // SwiftUI's folder importer replaces NSSavePanel here. We can't ask
        // for a save name inline, so we treat the picked folder as the
        // bundle's parent and create `<trimmed>.strata` inside it.
        .fileImporter(
            isPresented: $showFolderPicker,
            allowedContentTypes: [.folder],
            allowsMultipleSelection: false
        ) { result in
            guard case .success(let urls) = result, let parent = urls.first else { return }
            let trimmed = name.trimmingCharacters(in: .whitespaces)
            let bundle = parent
                .appendingPathComponent("\(trimmed).\(CaseStore.bundleExtension)",
                                        isDirectory: true)
            let examinerCopy = examiner.trimmingCharacters(in: .whitespaces)
            let didStart = parent.startAccessingSecurityScopedResource()
            Task {
                await model.createCase(name: trimmed, examiner: examinerCopy, at: bundle)
                if didStart { parent.stopAccessingSecurityScopedResource() }
                dismiss()
            }
        }
    }
}

#endif
