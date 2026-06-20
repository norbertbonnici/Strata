#if os(macOS)
import SwiftUI

/// Prompts the examiner for a FileVault secret (login/volume **password** or a
/// personal **recovery key**) when an APFS image contains an encrypted Data
/// volume that came back locked at ingest. On submit, `AppModel.unlockFileVault`
/// re-ingests the host with the secret and re-runs the macOS analyzers.
///
/// The secret is held in memory only and never written to the case bundle.
/// Reuses the single `.sheet(item:)` host on `ContentView` (AppModel.ActiveSheet).
struct FileVaultUnlockSheet: View {
    @EnvironmentObject private var model: AppModel
    @Environment(\.dismiss) private var dismiss
    let evidenceID: UUID

    @State private var password = ""
    @State private var recovery = ""

    private var evidence: Evidence? { model.evidenceList.first { $0.id == evidenceID } }
    private var lockedVolumes: [ApfsLockedVolume] {
        model.lockedApfsVolumes[evidenceID] ?? []
    }
    private var canUnlock: Bool {
        !password.trimmingCharacters(in: .whitespaces).isEmpty
            || !recovery.trimmingCharacters(in: .whitespaces).isEmpty
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            VStack(alignment: .leading, spacing: 4) {
                Label("Unlock FileVault Volume", systemImage: "lock.shield")
                    .font(.title2).bold()
                if let ev = evidence {
                    Text("\(ev.displayName) · \(ev.kind.label)")
                        .font(.caption).foregroundStyle(.secondary)
                }
            }

            if !lockedVolumes.isEmpty {
                VStack(alignment: .leading, spacing: 4) {
                    Text(lockedVolumes.count == 1
                         ? "One volume appears FileVault-encrypted and couldn't be read:"
                         : "\(lockedVolumes.count) volumes appear FileVault-encrypted and couldn't be read:")
                        .font(.callout)
                    ForEach(lockedVolumes, id: \.index) { vol in
                        Text("• \(vol.name)").font(.callout).foregroundStyle(.secondary)
                    }
                }
            }

            Text("Provide the volume password or a personal recovery key to read its "
                 + "metadata and file contents. The secret is kept in memory only and is "
                 + "never written to the case.")
                .font(.caption).foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)

            Form {
                SecureField("Volume password", text: $password)
                TextField("Recovery key (optional)", text: $recovery)
            }
            .formStyle(.grouped)

            HStack {
                Spacer()
                Button("Skip") { dismiss() }
                Button("Unlock") {
                    let pw = password.trimmingCharacters(in: .whitespaces)
                    let rk = recovery.trimmingCharacters(in: .whitespaces)
                    dismiss()
                    Task { await model.unlockFileVault(evidenceID: evidenceID,
                                                       password: pw.isEmpty ? nil : pw,
                                                       recovery: rk.isEmpty ? nil : rk) }
                }
                .keyboardShortcut(.defaultAction)
                .disabled(!canUnlock)
            }
        }
        .padding(20)
        .frame(width: 460)
    }
}
#endif
