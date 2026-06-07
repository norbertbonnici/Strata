#if !os(macOS)
import SwiftUI

/// Read-only chain-of-custody viewer for the iOS app: acquisition provenance,
/// source-hash integrity, and the custody ledger. Compute / verify / export are
/// macOS-only (they need the ingest + Process pipeline), so this view only
/// displays what the macOS app recorded.
struct CustodyDrillView: View {
    @EnvironmentObject private var model: AppModel

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 0) {
                LargeTitle(
                    title: "Chain of Custody",
                    subtitle: "\(model.custodyLog.count) log entr\(model.custodyLog.count == 1 ? "y" : "ies") · \(model.evidenceList.count) evidence")

                if model.evidenceList.isEmpty {
                    ContentUnavailableView(
                        "No evidence",
                        systemImage: "checkmark.seal",
                        description: Text("Build a case on the macOS app to record a chain of custody."))
                        .padding(.top, 60)
                        .frame(maxWidth: .infinity)
                } else {
                    ForEach(model.evidenceList) { evidence in
                        evidenceSection(evidence)
                    }
                    SectionHeader(label: "Custody log").padding(.top, 14)
                    if model.custodyLog.isEmpty {
                        Card { emptyRow("No recorded events") }
                    } else {
                        Card {
                            ForEach(sortedLog) { event in
                                logRow(event)
                            }
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

    private var sortedLog: [CustodyEvent] {
        model.custodyLog.sorted { $0.timestamp < $1.timestamp }
    }

    @ViewBuilder
    private func evidenceSection(_ evidence: Evidence) -> some View {
        SectionHeader(label: evidence.displayName).padding(.top, 14)
        Card {
            KVRow(key: "Type", value: evidence.kind.label)
            if let acq = evidence.acquisition, !acq.isEmpty {
                if !acq.examiner.isEmpty { KVRow(key: "Examiner", value: acq.examiner) }
                if !acq.acquisitionTool.isEmpty { KVRow(key: "Tool", value: acq.acquisitionTool) }
                if !acq.acquisitionMethod.isEmpty { KVRow(key: "Method", value: acq.acquisitionMethod) }
                if let d = acq.acquiredAt {
                    KVRow(key: "Acquired", value: d.formatted(date: .abbreviated, time: .shortened))
                }
                if !acq.caseNumber.isEmpty { KVRow(key: "Case #", value: acq.caseNumber) }
                if !acq.mediaSerial.isEmpty { KVRow(key: "Media serial", value: acq.mediaSerial) }
            } else {
                KVRow(key: "Acquisition", value: "—")
            }

            if evidence.sourceHashes.isEmpty {
                KVRow(key: "Hashes",
                      value: evidence.kind == .kapeLooseFolder ? "N/A (folder)" : "Not recorded",
                      showDivider: false)
            } else {
                ForEach(Array(evidence.sourceHashes.enumerated()), id: \.element.id) { idx, hash in
                    hashRow(hash, showDivider: idx < evidence.sourceHashes.count - 1)
                }
            }
        }
    }

    private func hashRow(_ hash: SourceHash, showDivider: Bool) -> some View {
        VStack(spacing: 0) {
            HStack(spacing: 11) {
                SeverityDot(color: statusColor(hash.status))
                VStack(alignment: .leading, spacing: 2) {
                    Text(hash.value)
                        .font(.system(size: 12.5, design: .monospaced))
                        .foregroundStyle(Theme.text)
                        .lineLimit(1).truncationMode(.middle)
                    Text("\(hash.algorithm.label) · \(hash.origin.label) · \(hash.status.label)")
                        .font(.system(size: 11))
                        .foregroundStyle(Theme.text2)
                }
                Spacer()
            }
            .padding(.horizontal, 15)
            .padding(.vertical, 13)
            if showDivider { Divider().background(Theme.hair2) }
        }
    }

    private func logRow(_ event: CustodyEvent) -> some View {
        VStack(spacing: 0) {
            HStack(alignment: .top, spacing: 11) {
                Image(systemName: event.action.symbol)
                    .font(.system(size: 14))
                    .frame(width: 20)
                    .foregroundStyle(Theme.teal2)
                VStack(alignment: .leading, spacing: 2) {
                    HStack {
                        Text(event.action.label)
                            .font(.system(size: 14, weight: .semibold))
                            .foregroundStyle(Theme.text)
                        Spacer()
                        Text(event.timestamp.formatted(date: .abbreviated, time: .shortened))
                            .font(.system(size: 11, design: .monospaced))
                            .foregroundStyle(Theme.text3)
                    }
                    Text(event.detail)
                        .font(.system(size: 12))
                        .foregroundStyle(Theme.text2)
                        .fixedSize(horizontal: false, vertical: true)
                    if !event.actor.isEmpty {
                        Text("by \(event.actor)")
                            .font(.system(size: 11))
                            .foregroundStyle(Theme.text3)
                    }
                }
            }
            .padding(.horizontal, 15)
            .padding(.vertical, 13)
            if event.id != sortedLog.last?.id { Divider().background(Theme.hair2) }
        }
    }

    private func emptyRow(_ text: String) -> some View {
        Text(text)
            .font(.system(size: 13))
            .foregroundStyle(Theme.text3)
            .padding(.horizontal, 15).padding(.vertical, 14)
            .frame(maxWidth: .infinity, alignment: .leading)
    }

    private func statusColor(_ status: HashVerificationStatus) -> Color {
        switch status {
        case .verified:    return Theme.teal
        case .mismatch:    return Theme.crit
        case .notVerified: return Theme.amber
        case .unavailable: return Theme.info
        }
    }
}
#endif
