#if os(macOS)
import SwiftUI

/// Edits the acquisition provenance for one evidence item and lets the examiner
/// drop a free-form note into the custody log. Reuses the single
/// `.sheet(item:)` host on `ContentView` (AppModel.ActiveSheet).
struct AcquisitionEditorSheet: View {
    @EnvironmentObject private var model: AppModel
    @Environment(\.dismiss) private var dismiss
    let evidenceID: UUID

    @State private var examiner = ""
    @State private var tool = ""
    @State private var method = ""
    @State private var caseNumber = ""
    @State private var mediaSerial = ""
    @State private var notes = ""
    @State private var hasDate = false
    @State private var acquiredAt = Date()
    @State private var noteToAdd = ""
    @State private var loaded = false

    private var evidence: Evidence? { model.evidenceList.first { $0.id == evidenceID } }

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            VStack(alignment: .leading, spacing: 4) {
                Text("Acquisition Details").font(.title2).bold()
                if let ev = evidence {
                    Text("\(ev.displayName) · \(ev.kind.label)")
                        .font(.caption).foregroundStyle(.secondary)
                }
            }

            Form {
                TextField("Examiner", text: $examiner)
                TextField("Acquisition tool", text: $tool)
                TextField("Acquisition method", text: $method)
                TextField("Case number", text: $caseNumber)
                TextField("Media serial", text: $mediaSerial)
                Toggle("Has acquisition date", isOn: $hasDate)
                if hasDate {
                    DatePicker("Acquired at", selection: $acquiredAt)
                }
                TextField("Notes", text: $notes, axis: .vertical).lineLimit(2...5)
            }
            .formStyle(.grouped)

            Divider()

            VStack(alignment: .leading, spacing: 6) {
                Text("Add custody note").font(.headline)
                Text("Recorded immediately as an examiner annotation in the ledger.")
                    .font(.caption).foregroundStyle(.secondary)
                HStack {
                    TextField("Note", text: $noteToAdd)
                    Button("Add") {
                        model.addCustodyNote(noteToAdd, evidenceID: evidenceID)
                        noteToAdd = ""
                    }
                    .disabled(noteToAdd.trimmingCharacters(in: .whitespaces).isEmpty)
                }
            }

            HStack {
                Spacer()
                Button("Cancel") { dismiss() }
                Button("Save") {
                    var info = AcquisitionInfo()
                    info.examiner = examiner.trimmingCharacters(in: .whitespaces)
                    info.acquisitionTool = tool.trimmingCharacters(in: .whitespaces)
                    info.acquisitionMethod = method.trimmingCharacters(in: .whitespaces)
                    info.caseNumber = caseNumber.trimmingCharacters(in: .whitespaces)
                    info.mediaSerial = mediaSerial.trimmingCharacters(in: .whitespaces)
                    info.notes = notes.trimmingCharacters(in: .whitespaces)
                    info.acquiredAt = hasDate ? acquiredAt : nil
                    model.recordAcquisition(info, for: evidenceID)
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
        guard let acq = evidence?.acquisition else { return }
        examiner = acq.examiner
        tool = acq.acquisitionTool
        method = acq.acquisitionMethod
        caseNumber = acq.caseNumber
        mediaSerial = acq.mediaSerial
        notes = acq.notes
        if let d = acq.acquiredAt { hasDate = true; acquiredAt = d }
    }
}
#endif
