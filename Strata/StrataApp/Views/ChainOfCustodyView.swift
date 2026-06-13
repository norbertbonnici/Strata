#if os(macOS)
import SwiftUI

/// Chain-of-custody tab: per-evidence acquisition provenance + source-hash
/// integrity, and the case's append-only custody ledger. Scoped by the toolbar
/// evidence picker like the other tabs.
struct ChainOfCustodyView: View {
    @EnvironmentObject private var model: AppModel

    private var scopedEvidence: [Evidence] {
        if let id = model.activeEvidenceID {
            return model.evidenceList.filter { $0.id == id }
        }
        return model.evidenceList
    }

    /// When scoped to one evidence, also show case-level (nil-evidence) events.
    private var scopedLog: [CustodyEvent] {
        guard let id = model.activeEvidenceID else { return model.custodyLog }
        return model.custodyLog.filter { $0.evidenceID == id || $0.evidenceID == nil }
    }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 20) {
                header
                if model.evidenceList.isEmpty {
                    Text("No evidence loaded. Ingest an image to begin the chain of custody.")
                        .foregroundStyle(.secondary)
                } else {
                    ForEach(scopedEvidence) { evidence in
                        EvidenceIntegrityCard(evidence: evidence)
                    }
                    custodySection
                }
            }
            .padding()
            .frame(maxWidth: .infinity, alignment: .leading)
        }
        .navigationTitle("Chain of Custody")
        .toolbar {
            ToolbarItem(placement: .primaryAction) {
                Button { model.requestExport() } label: {
                    Label("Export Report…", systemImage: "square.and.arrow.up")
                }
                .disabled(model.currentCase == nil)
                .help("Export an examiner / chain-of-custody report.")
            }
        }
    }

    @ViewBuilder
    private var header: some View {
        if let c = model.currentCase {
            VStack(alignment: .leading, spacing: 6) {
                Text("Chain of Custody").font(.title2).bold()
                Grid(alignment: .leadingFirstTextBaseline,
                     horizontalSpacing: 16, verticalSpacing: 4) {
                    GridRow {
                        Text("Case").foregroundStyle(.secondary)
                        Text(c.name).textSelection(.enabled)
                    }
                    if !c.examiner.isEmpty {
                        GridRow {
                            Text("Examiner").foregroundStyle(.secondary)
                            Text(c.examiner).textSelection(.enabled)
                        }
                    }
                    GridRow {
                        Text("Created").foregroundStyle(.secondary)
                        Text(c.createdAt.formatted(date: .abbreviated, time: .shortened))
                    }
                    GridRow {
                        Text("Log entries").foregroundStyle(.secondary)
                        Text("\(model.custodyLog.count)")
                    }
                }
                .font(.callout)
            }
        }
    }

    private var custodySection: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Custody log").font(.headline)
            if scopedLog.isEmpty {
                Text("No recorded events yet.")
                    .font(.caption).foregroundStyle(.secondary)
            } else {
                VStack(spacing: 0) {
                    ForEach(scopedLog) { event in
                        CustodyRow(event: event)
                        if event.id != scopedLog.last?.id { Divider() }
                    }
                }
                .padding(.vertical, 4)
                .frame(maxWidth: .infinity, alignment: .leading)
                .background(.quaternary, in: RoundedRectangle(cornerRadius: 10))
            }
        }
    }
}

// MARK: - Evidence integrity card

private struct EvidenceIntegrityCard: View {
    @EnvironmentObject private var model: AppModel
    let evidence: Evidence

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack(alignment: .firstTextBaseline, spacing: 8) {
                Text(evidence.displayName).font(.title3).bold()
                Text(evidence.kind.label).font(.caption).foregroundStyle(.secondary)
                Spacer()
                Button { model.activeSheet = .acquisitionEditor(evidence.id) } label: {
                    Label("Edit…", systemImage: "pencil")
                }
                .controlSize(.small)
            }
            acquisitionGrid
            Divider()
            hashesSection
        }
        .padding()
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(.quaternary, in: RoundedRectangle(cornerRadius: 10))
    }

    @ViewBuilder
    private var acquisitionGrid: some View {
        let acq = evidence.acquisition
        Grid(alignment: .leadingFirstTextBaseline, horizontalSpacing: 16, verticalSpacing: 4) {
            row("Source", evidence.sourceURL.path)
            if let acq, !acq.isEmpty {
                if !acq.examiner.isEmpty { row("Examiner", acq.examiner) }
                if !acq.acquisitionTool.isEmpty { row("Tool", acq.acquisitionTool) }
                if !acq.acquisitionMethod.isEmpty { row("Method", acq.acquisitionMethod) }
                if let d = acq.acquiredAt {
                    row("Acquired", d.formatted(date: .abbreviated, time: .shortened))
                }
                if !acq.caseNumber.isEmpty { row("Case #", acq.caseNumber) }
                if !acq.mediaSerial.isEmpty { row("Media serial", acq.mediaSerial) }
                if !acq.notes.isEmpty { row("Notes", acq.notes) }
                if acq.source != .manual {
                    GridRow {
                        Text("Provenance").foregroundStyle(.secondary)
                        Text(acq.source == .ewfMetadata ? "Auto (E01 header)" : "Auto + edited")
                            .font(.caption).foregroundStyle(.secondary)
                    }
                }
            }
        }
        .font(.callout)
        if acq?.isEmpty ?? true {
            Text("No acquisition metadata recorded. Use Edit… to add it.")
                .font(.caption).foregroundStyle(.secondary)
        }
    }

    @ViewBuilder
    private var hashesSection: some View {
        HStack {
            Text("Source hashes").font(.headline)
            Spacer()
            hashActions
        }
        if evidence.kind == .kapeLooseFolder {
            Text("Loose folder — no single image to hash.")
                .font(.caption).foregroundStyle(.secondary)
        } else if evidence.sourceHashes.isEmpty {
            Text("No hashes recorded yet.")
                .font(.caption).foregroundStyle(.secondary)
        } else {
            VStack(spacing: 6) {
                ForEach(evidence.sourceHashes) { hash in
                    HStack(spacing: 8) {
                        Text(hash.algorithm.label)
                            .font(.caption.monospaced())
                            .frame(width: 64, alignment: .leading)
                        Text(hash.value)
                            .font(.caption.monospaced())
                            .textSelection(.enabled)
                            .lineLimit(1).truncationMode(.middle)
                        Spacer()
                        Text(hash.origin.label)
                            .font(.caption2).foregroundStyle(.secondary)
                        HashStatusBadge(status: hash.status)
                    }
                }
            }
        }
    }

    @ViewBuilder
    private var hashActions: some View {
        switch evidence.kind {
        case .kapeLooseFolder:
            EmptyView()
        case .e01:
            Button("Verify (ewfverify)") {
                Task { await model.verifyEWF(for: evidence.id) }
            }
            .controlSize(.small).disabled(model.isWorking)
        case .raw, .kapeVHD, .apfs:
            if evidence.sourceHashes.contains(where: { $0.origin == .computed }) {
                Button("Re-verify") {
                    Task { await model.verifyComputedHashes(for: evidence.id) }
                }
                .controlSize(.small).disabled(model.isWorking)
            } else {
                Button("Compute hashes") {
                    Task { await model.computeSourceHashes(for: evidence.id) }
                }
                .controlSize(.small).disabled(model.isWorking)
            }
        }
    }

    private func row(_ label: String, _ value: String) -> some View {
        GridRow {
            Text(label).foregroundStyle(.secondary)
            Text(value).textSelection(.enabled)
        }
    }
}

// MARK: - Components

private struct HashStatusBadge: View {
    let status: HashVerificationStatus
    var body: some View {
        Text(status.label)
            .font(.caption2.bold())
            .padding(.horizontal, 6).padding(.vertical, 2)
            .background(color.opacity(0.18), in: Capsule())
            .foregroundStyle(color)
    }
    private var color: Color {
        switch status {
        case .verified:    return .green
        case .mismatch:    return .red
        case .notVerified: return .gray
        case .unavailable: return .gray
        }
    }
}

private struct CustodyRow: View {
    @EnvironmentObject private var model: AppModel
    let event: CustodyEvent

    var body: some View {
        HStack(alignment: .top, spacing: 10) {
            Image(systemName: event.action.symbol)
                .foregroundStyle(.secondary)
                .frame(width: 20)
            VStack(alignment: .leading, spacing: 2) {
                HStack(spacing: 6) {
                    Text(event.action.label).font(.callout.bold())
                    if let evID = event.evidenceID,
                       let name = model.evidenceList.first(where: { $0.id == evID })?.displayName {
                        Text(name).font(.caption).foregroundStyle(.secondary)
                    }
                    Spacer()
                    Text(event.timestamp.formatted(date: .abbreviated, time: .standard))
                        .font(.caption.monospacedDigit()).foregroundStyle(.secondary)
                }
                Text(event.detail)
                    .font(.caption)
                    .textSelection(.enabled)
                    .fixedSize(horizontal: false, vertical: true)
                if !event.actor.isEmpty {
                    Text("by \(event.actor)").font(.caption2).foregroundStyle(.secondary)
                }
            }
        }
        .padding(.horizontal, 12).padding(.vertical, 8)
        .frame(maxWidth: .infinity, alignment: .leading)
    }
}
#endif
