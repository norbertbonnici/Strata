import SwiftUI
import AppKit

/// Shown when no case is open. Lets the user create a new .strata bundle,
/// open an existing one, or pick from recently opened cases.
struct WelcomeView: View {
    @EnvironmentObject private var model: AppModel

    var body: some View {
        VStack(spacing: 24) {
            VStack(spacing: 8) {
                Image(systemName: "square.stack.3d.up")
                    .font(.system(size: 56))
                    .foregroundStyle(.tint)
                Text("Strata").font(.largeTitle).bold()
                Text("Open a case to begin, or create a new one.")
                    .foregroundStyle(.secondary)
            }
            .padding(.top, 60)

            HStack(spacing: 12) {
                Button {
                    model.showingNewCaseSheet = true
                } label: {
                    Label("New Case...", systemImage: "plus.square")
                        .frame(minWidth: 140)
                }
                .controlSize(.large)
                .buttonStyle(.borderedProminent)

                Button {
                    model.requestOpenCase()
                } label: {
                    Label("Open Case...", systemImage: "folder")
                        .frame(minWidth: 140)
                }
                .controlSize(.large)
            }

            if !model.recentCases.isEmpty {
                VStack(alignment: .leading, spacing: 6) {
                    Text("Recent").font(.headline)
                    ForEach(model.recentCases, id: \.self) { url in
                        recentRow(url)
                    }
                }
                .padding(.horizontal, 40)
                .frame(maxWidth: 560)
            }

            Spacer()
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    @ViewBuilder
    private func recentRow(_ url: URL) -> some View {
        Button {
            Task { await model.openCase(at: url) }
        } label: {
            HStack {
                Image(systemName: "tray.full").foregroundStyle(.tint)
                VStack(alignment: .leading) {
                    Text(url.deletingPathExtension().lastPathComponent).font(.body)
                    Text(url.path)
                        .font(.caption).foregroundStyle(.secondary)
                        .lineLimit(1).truncationMode(.middle)
                }
                Spacer()
            }
            .padding(.horizontal, 10).padding(.vertical, 6)
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
    }

}

struct NewCaseSheet: View {
    @EnvironmentObject private var model: AppModel
    @Environment(\.dismiss) private var dismiss
    @State private var name = ""
    @State private var examiner = ""

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("New Case").font(.title2).bold()
            Form {
                TextField("Case name", text: $name)
                TextField("Examiner", text: $examiner)
            }
            HStack {
                Spacer()
                Button("Cancel") { dismiss() }
                Button("Create...") { chooseLocation() }
                    .keyboardShortcut(.defaultAction)
                    .disabled(name.trimmingCharacters(in: .whitespaces).isEmpty)
            }
        }
        .padding(20)
        .frame(width: 380)
    }

    private func chooseLocation() {
        let panel = NSSavePanel()
        let trimmed = name.trimmingCharacters(in: .whitespaces)
        panel.nameFieldStringValue = "\(trimmed).strata"
        panel.message = "Choose where to save the case bundle."
        guard panel.runModal() == .OK, var url = panel.url else { return }
        if url.pathExtension.lowercased() != CaseStore.bundleExtension {
            url = url.appendingPathExtension(CaseStore.bundleExtension)
        }
        let nameCopy = trimmed
        let examinerCopy = examiner.trimmingCharacters(in: .whitespaces)
        Task {
            await model.createCase(name: nameCopy, examiner: examinerCopy, at: url)
            dismiss()
        }
    }
}
