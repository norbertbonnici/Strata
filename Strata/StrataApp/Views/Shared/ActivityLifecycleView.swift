#if os(macOS)
import SwiftUI

/// Case activity and lifecycle surface, ported from the design brief as native
/// SwiftUI over Strata's existing case, evidence, and custody models.
struct ActivityLifecycleView: View {
    @EnvironmentObject private var model: AppModel
    @State private var tab: ActivityLifecycleTab = .activity
    @State private var filter: ActivityFilter = .all
    @State private var lifecycleState: LifecycleState = .review
    @State private var retention: RetentionOption = .tenYears
    @State private var disposition: DispositionOption = .retainSealed
    @State private var closeConfirmation = ""

    private var rows: [ActivityRowModel] {
        ActivityRowModel.rows(from: model.custodyLog, evidence: model.evidenceList)
    }

    private var filteredRows: [ActivityRowModel] {
        rows.filter { filter == .all || $0.category == filter.category }
    }

    private var mismatchCount: Int {
        model.evidenceList.reduce(0) { total, evidence in
            total + evidence.sourceHashes.filter { $0.status == .mismatch }.count
        }
    }

    private var canClose: Bool {
        mismatchCount == 0 && lifecycleState == .review && closeConfirmation == "CLOSE"
    }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 18) {
                appHeader
                tabPicker
                Group {
                    switch tab {
                    case .activity:
                        activityPane
                    case .lifecycle:
                        lifecyclePane
                    }
                }
                .animation(.easeInOut(duration: 0.18), value: tab)
            }
            .padding(20)
            .frame(maxWidth: 760, alignment: .leading)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .top)
        .background(Theme.bg)
        .navigationTitle("Activity")
    }

    private var appHeader: some View {
        HStack(spacing: 12) {
            StrataMark()
            VStack(alignment: .leading, spacing: 2) {
                Text("Strata")
                    .font(.system(size: 22, weight: .bold))
                    .foregroundStyle(Theme.text)
                Text("activity & lifecycle")
                    .font(.system(size: 11, weight: .medium, design: .monospaced))
                    .foregroundStyle(Theme.text3)
            }
            Spacer()
            Pill(text: "2 screens", background: Theme.card, foreground: Theme.text2)
        }
        .accessibilityElement(children: .combine)
    }

    private var tabPicker: some View {
        HStack(spacing: 8) {
            ForEach(ActivityLifecycleTab.allCases) { entry in
                Button { tab = entry } label: {
                    HStack(spacing: 8) {
                        Text(entry.number)
                            .font(.system(size: 11, weight: .bold, design: .monospaced))
                            .foregroundStyle(tab == entry ? Theme.teal2 : Theme.text3)
                        Text(entry.label)
                    }
                    .font(.system(size: 13, weight: .semibold))
                    .padding(.horizontal, 14)
                    .padding(.vertical, 8)
                    .foregroundStyle(tab == entry ? Theme.text : Theme.text2)
                    .background(tab == entry ? Theme.card2 : Theme.card)
                    .clipShape(Capsule())
                    .overlay(Capsule().stroke(tab == entry ? Theme.hair : Theme.hair2, lineWidth: 1))
                }
                .buttonStyle(.plain)
            }
        }
    }

    private var activityPane: some View {
        VStack(alignment: .leading, spacing: 14) {
            ViewHeading(
                title: "Case activity",
                subtitle: "Tamper-aware journal of what was done in this case, built from Strata's custody ledger and integrity state."
            )
            activityStatus
            filterRow
            if filteredRows.isEmpty {
                EmptyActivityCard()
            } else {
                VStack(alignment: .leading, spacing: 0) {
                    ForEach(filteredRows) { row in
                        ActivityTimelineRow(row: row)
                    }
                }
                .padding(.top, 2)
            }
            IntegrityNote(text: "The custody ledger remains append-only in Strata. Hash mismatches are promoted here as blocking alerts so transfer or closure decisions are visible before case state changes.")
        }
    }

    private var activityStatus: some View {
        HStack(spacing: 10) {
            Text("\(rows.count) entries")
                .font(.system(size: 15, weight: .semibold))
                .foregroundStyle(Theme.text)
            StatusPill(
                text: mismatchCount == 0 ? "integrity clear" : "\(mismatchCount) mismatch\(mismatchCount == 1 ? "" : "es")",
                color: mismatchCount == 0 ? Theme.teal2 : Theme.crit,
                symbol: mismatchCount == 0 ? "checkmark" : "exclamationmark.triangle.fill"
            )
            Spacer()
            Button {
                filter = .all
            } label: {
                Label("Verify journal", systemImage: "checkmark.seal")
            }
            .controlSize(.small)
            .help("Refresh the visible activity filters and review integrity alerts.")
        }
    }

    private var filterRow: some View {
        ScrollView(.horizontal, showsIndicators: false) {
            HStack(spacing: 7) {
                ForEach(ActivityFilter.allCases) { option in
                    Button { filter = option } label: {
                        Text(option.label)
                            .font(.system(size: 11, weight: .semibold, design: .monospaced))
                            .padding(.horizontal, 11)
                            .padding(.vertical, 6)
                            .foregroundStyle(filter == option ? Theme.text : Theme.text3)
                            .background(filter == option ? Theme.card2 : Theme.card)
                            .clipShape(Capsule())
                            .overlay(Capsule().stroke(filter == option ? Theme.hair : Theme.hair2, lineWidth: 1))
                    }
                    .buttonStyle(.plain)
                }
            }
        }
    }

    private var lifecyclePane: some View {
        VStack(alignment: .leading, spacing: 14) {
            ViewHeading(
                title: "Case lifecycle",
                subtitle: "Open to archived state tracking with retention, disposition, and integrity gates."
            )
            lifecycleCard
            retentionCard
            if mismatchCount > 0 {
                AlertBand(
                    title: "Transfer and close blocked",
                    message: "Resolve source-hash mismatches before closing or transferring this case."
                )
            }
            Button {
                lifecycleState = .closed
                model.appendCustody(.noteAdded, detail: "Case lifecycle marked closed from Activity view.")
            } label: {
                Label("Mark review complete and close case", systemImage: "lock.fill")
                    .frame(maxWidth: .infinity)
            }
            .buttonStyle(.borderedProminent)
            .disabled(!canClose)
            dangerZone
            IntegrityNote(text: "Closing freezes the working case by policy. This screen journals the lifecycle decision through the custody log; disposition remains gated by retention.")
        }
    }

    private var lifecycleCard: some View {
        VStack(alignment: .leading, spacing: 16) {
            SectionLabel("Case")
            Text(model.currentCase?.name ?? "Untitled case")
                .font(.system(size: 17, weight: .semibold))
                .foregroundStyle(Theme.text)
            LifecycleStepper(state: lifecycleState)
            KeyValueRow(label: "Status", value: lifecycleState.label, color: lifecycleState.color)
            KeyValueRow(label: "Opened", value: model.currentCase?.createdAt.formatted(date: .abbreviated, time: .shortened) ?? "Unknown")
            KeyValueRow(label: "Examiner", value: model.currentCase?.examiner.isEmpty == false ? model.currentCase?.examiner ?? "" : "Not recorded")
            KeyValueRow(label: "Exhibits", value: "\(model.evidenceList.count) in case")
            KeyValueRow(label: "Open findings", value: "\(model.findingCount)")
        }
        .activityCard()
    }

    private var retentionCard: some View {
        VStack(alignment: .leading, spacing: 12) {
            SectionLabel("Retention & disposition", accent: Theme.amber)
            Picker("Retention policy", selection: $retention) {
                ForEach(RetentionOption.allCases) { option in
                    Text(option.label).tag(option)
                }
            }
            Picker("On close, evidence disposition", selection: $disposition) {
                ForEach(DispositionOption.allCases) { option in
                    Text(option.label).tag(option)
                }
            }
            KeyValueRow(label: "Dispose after", value: disposeAfter)
        }
        .activityCard()
    }

    private var dangerZone: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text("Irreversible")
                .font(.system(size: 14, weight: .semibold))
                .foregroundStyle(Theme.crit)
            Text("Type CLOSE to enable the lifecycle close action. Closing is blocked while any evidence hash has a mismatch status.")
                .font(.system(size: 11, weight: .medium, design: .monospaced))
                .foregroundStyle(Theme.text2)
                .fixedSize(horizontal: false, vertical: true)
            TextField("CLOSE", text: $closeConfirmation)
                .textFieldStyle(.roundedBorder)
                .frame(maxWidth: 220)
            Button {
                model.appendCustody(.noteAdded, detail: "Disposition requested: \(disposition.label).")
            } label: {
                Label("Dispose evidence", systemImage: "trash")
                    .frame(maxWidth: .infinity)
            }
            .disabled(true)
            .help("Disposition is disabled until retention has elapsed.")
        }
        .padding(14)
        .background(Theme.crit.opacity(0.08))
        .overlay(RoundedRectangle(cornerRadius: 13).stroke(Theme.crit.opacity(0.35), lineWidth: 1))
        .clipShape(RoundedRectangle(cornerRadius: 13))
    }

    private var disposeAfter: String {
        guard let opened = model.currentCase?.createdAt, let years = retention.years else {
            return "Open-ended"
        }
        let date = Calendar.current.date(byAdding: .year, value: years, to: opened) ?? opened
        return date.formatted(date: .abbreviated, time: .omitted)
    }
}

private enum ActivityLifecycleTab: CaseIterable, Identifiable {
    case activity
    case lifecycle

    var id: Self { self }
    var number: String { self == .activity ? "01" : "02" }
    var label: String { self == .activity ? "Case activity" : "Lifecycle" }
}

private enum ActivityFilter: String, CaseIterable, Identifiable {
    case all, evidence, custody, analysis, exports, lifecycle

    var id: String { rawValue }
    var label: String { self == .all ? "All" : rawValue.capitalized }
    var category: ActivityRowCategory? {
        switch self {
        case .all: return nil
        case .evidence: return .evidence
        case .custody: return .custody
        case .analysis: return .analysis
        case .exports: return .exports
        case .lifecycle: return .lifecycle
        }
    }
}

private enum ActivityRowCategory: String {
    case evidence, custody, analysis, exports, lifecycle

    var label: String { rawValue.uppercased() }
    var color: Color {
        switch self {
        case .evidence: return Theme.teal2
        case .custody: return Color(red: 0x8D/255, green: 0x8C/255, blue: 0xF2/255)
        case .analysis: return Theme.amber
        case .exports: return Color(red: 0x5A/255, green: 0xD1/255, blue: 0x9A/255)
        case .lifecycle: return Theme.info
        }
    }
}

private struct ActivityRowModel: Identifiable {
    let id: String
    let timestamp: Date
    let actor: String
    let action: String
    let target: String
    let detail: String
    let category: ActivityRowCategory
    let isAlert: Bool
    let sequence: Int

    static func rows(from custody: [CustodyEvent], evidence: [Evidence]) -> [ActivityRowModel] {
        var out = custody.enumerated().map { index, event in
            ActivityRowModel(
                id: event.id.uuidString,
                timestamp: event.timestamp,
                actor: event.actor.isEmpty ? "System" : event.actor,
                action: event.action.label.lowercased(),
                target: evidence.first(where: { $0.id == event.evidenceID })?.displayName ?? "case",
                detail: event.detail,
                category: category(for: event.action),
                isAlert: event.action == .hashVerified && event.detail.localizedCaseInsensitiveContains("mismatch"),
                sequence: index + 1
            )
        }

        let mismatchRows = evidence.flatMap { item in
            item.sourceHashes.filter { $0.status == .mismatch }.map { hash in
                ActivityRowModel(
                    id: "mismatch-\(item.id)-\(hash.id)",
                    timestamp: hash.verifiedAt ?? hash.computedAt ?? Date.distantPast,
                    actor: "System",
                    action: "flagged integrity mismatch",
                    target: item.displayName,
                    detail: "\(hash.algorithm.label) mismatch blocks transfer and close.",
                    category: .evidence,
                    isAlert: true,
                    sequence: out.count + 1
                )
            }
        }
        out.append(contentsOf: mismatchRows)
        return out.sorted { $0.timestamp > $1.timestamp }
    }

    private static func category(for action: CustodyAction) -> ActivityRowCategory {
        switch action {
        case .acquired, .addedToCase, .hashRecorded, .hashVerified:
            return .evidence
        case .analysed, .enrichmentPerformed, .summarized:
            return .analysis
        case .exported:
            return .exports
        case .noteAdded:
            return .lifecycle
        }
    }
}

private enum LifecycleState: Int, CaseIterable, Identifiable {
    case open, active, review, closed, archived

    var id: Int { rawValue }
    var label: String {
        switch self {
        case .open: return "Open"
        case .active: return "Active"
        case .review: return "Review"
        case .closed: return "Closed"
        case .archived: return "Archived"
        }
    }
    var color: Color {
        switch self {
        case .open, .archived: return Theme.info
        case .active: return Theme.teal2
        case .review: return Theme.amber
        case .closed: return Color(red: 0x8D/255, green: 0x8C/255, blue: 0xF2/255)
        }
    }
}

private enum RetentionOption: CaseIterable, Identifiable {
    case tenYears, sevenYears, indefinite, courtDisposal

    var id: Self { self }
    var label: String {
        switch self {
        case .tenYears: return "10 years (financial crime)"
        case .sevenYears: return "7 years"
        case .indefinite: return "Indefinite (active prosecution)"
        case .courtDisposal: return "Until court disposal"
        }
    }
    var years: Int? {
        switch self {
        case .tenYears: return 10
        case .sevenYears: return 7
        case .indefinite, .courtDisposal: return nil
        }
    }
}

private enum DispositionOption: CaseIterable, Identifiable {
    case retainSealed, returnToOwner, transferToProsecution, secureDestruction

    var id: Self { self }
    var label: String {
        switch self {
        case .retainSealed: return "Retain sealed in evidence store"
        case .returnToOwner: return "Return to owner"
        case .transferToProsecution: return "Transfer to prosecution"
        case .secureDestruction: return "Secure destruction (after retention)"
        }
    }
}

private struct ViewHeading: View {
    let title: String
    let subtitle: String

    var body: some View {
        VStack(alignment: .leading, spacing: 5) {
            Text(title)
                .font(.system(size: 24, weight: .semibold))
                .foregroundStyle(Theme.text)
            Text(subtitle)
                .font(.system(size: 13.5, weight: .medium))
                .foregroundStyle(Theme.text2)
                .fixedSize(horizontal: false, vertical: true)
        }
    }
}

private struct ActivityTimelineRow: View {
    let row: ActivityRowModel

    var body: some View {
        HStack(alignment: .top, spacing: 12) {
            VStack(spacing: 0) {
                Circle()
                    .stroke(row.isAlert ? Theme.crit : row.category.color, lineWidth: 2)
                    .background(Circle().fill(Theme.bg))
                    .frame(width: 13, height: 13)
                    .shadow(color: row.isAlert ? Theme.crit.opacity(0.35) : .clear, radius: 5)
                Rectangle()
                    .fill(Theme.hair)
                    .frame(width: 2)
                    .frame(maxHeight: .infinity)
            }
            .frame(width: 14)
            VStack(alignment: .leading, spacing: 5) {
                Text(rowLine)
                    .font(.system(size: 13))
                    .foregroundStyle(row.isAlert ? Theme.crit : Theme.text)
                    .fixedSize(horizontal: false, vertical: true)
                HStack(spacing: 9) {
                    Text(row.timestamp.formatted(date: .numeric, time: .standard))
                    Text(row.category.label)
                    Text("seq #\(row.sequence)")
                }
                .font(.system(size: 10.5, weight: .medium, design: .monospaced))
                .foregroundStyle(Theme.text3)
            }
            .padding(11)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(row.isAlert ? Theme.crit.opacity(0.08) : Theme.card)
            .overlay(RoundedRectangle(cornerRadius: 11).stroke(row.isAlert ? Theme.crit.opacity(0.35) : Theme.hair2, lineWidth: 1))
            .clipShape(RoundedRectangle(cornerRadius: 11))
        }
        .padding(.bottom, 12)
    }

    private var rowLine: AttributedString {
        var text = AttributedString("\(row.actor) \(row.action) \(row.target)")
        if let actorRange = text.range(of: row.actor) {
            text[actorRange].font = .system(size: 13, weight: .semibold)
            text[actorRange].foregroundColor = row.isAlert ? Theme.crit : Theme.text
        }
        if let targetRange = text.range(of: row.target) {
            text[targetRange].font = .system(size: 13, weight: .semibold)
        }
        if !row.detail.isEmpty {
            var detail = AttributedString(" - \(row.detail)")
            detail.foregroundColor = row.isAlert ? Theme.crit.opacity(0.9) : Theme.text2
            text.append(detail)
        }
        return text
    }
}

private struct LifecycleStepper: View {
    let state: LifecycleState

    var body: some View {
        HStack(spacing: 0) {
            ForEach(LifecycleState.allCases) { step in
                VStack(spacing: 6) {
                    ZStack {
                        if step.rawValue > 0 {
                            Rectangle()
                                .fill(step.rawValue <= state.rawValue ? Theme.teal2.opacity(0.55) : Theme.hair)
                                .frame(height: 2)
                                .offset(x: -40)
                        }
                        Circle()
                            .fill(step == state ? Theme.teal2 : Theme.bg2)
                            .overlay(Circle().stroke(step.rawValue <= state.rawValue ? Theme.teal2 : Theme.hair, lineWidth: 1.5))
                            .frame(width: 26, height: 26)
                        Text(step.rawValue < state.rawValue ? "OK" : "\(step.rawValue + 1)")
                            .font(.system(size: 10, weight: .bold, design: .monospaced))
                            .foregroundStyle(step == state ? Theme.bg : (step.rawValue <= state.rawValue ? Theme.teal2 : Theme.text3))
                    }
                    Text(step.label)
                        .font(.system(size: 10, weight: .medium, design: .monospaced))
                        .foregroundStyle(step.rawValue <= state.rawValue ? Theme.text2 : Theme.text3)
                }
                .frame(maxWidth: .infinity)
            }
        }
        .padding(.vertical, 4)
    }
}

private struct KeyValueRow: View {
    let label: String
    let value: String
    var color: Color? = nil

    var body: some View {
        HStack(alignment: .firstTextBaseline, spacing: 10) {
            Text(label.uppercased())
                .font(.system(size: 11, weight: .medium, design: .monospaced))
                .foregroundStyle(Theme.text3)
            Spacer()
            Text(value)
                .font(.system(size: 12.5, weight: .medium, design: .monospaced))
                .foregroundStyle(color ?? Theme.text2)
                .multilineTextAlignment(.trailing)
        }
        .padding(.vertical, 8)
        .overlay(alignment: .bottom) {
            Rectangle().fill(Theme.hair2).frame(height: 1)
        }
    }
}

private struct SectionLabel: View {
    let text: String
    let accent: Color

    init(_ text: String, accent: Color = Theme.teal2) {
        self.text = text
        self.accent = accent
    }

    var body: some View {
        HStack(spacing: 9) {
            RoundedRectangle(cornerRadius: 2)
                .fill(accent)
                .frame(width: 3, height: 13)
            Text(text.uppercased())
                .font(.system(size: 11, weight: .bold, design: .monospaced))
                .tracking(0.7)
                .foregroundStyle(Theme.text3)
        }
    }
}

private struct StatusPill: View {
    let text: String
    let color: Color
    let symbol: String

    var body: some View {
        HStack(spacing: 6) {
            Image(systemName: symbol)
            Text(text)
        }
        .font(.system(size: 11, weight: .bold, design: .monospaced))
        .foregroundStyle(color)
        .padding(.horizontal, 9)
        .padding(.vertical, 4)
        .background(color.opacity(0.08))
        .clipShape(Capsule())
        .overlay(Capsule().stroke(color.opacity(0.35), lineWidth: 1))
    }
}

private struct IntegrityNote: View {
    let text: String

    var body: some View {
        HStack(alignment: .top, spacing: 8) {
            Image(systemName: "shield")
                .font(.system(size: 13))
                .foregroundStyle(Theme.text3)
            Text(text)
                .font(.system(size: 11, weight: .medium, design: .monospaced))
                .foregroundStyle(Theme.text3)
                .fixedSize(horizontal: false, vertical: true)
        }
    }
}

private struct AlertBand: View {
    let title: String
    let message: String

    var body: some View {
        HStack(alignment: .top, spacing: 10) {
            Image(systemName: "exclamationmark.triangle.fill")
                .foregroundStyle(Theme.crit)
            VStack(alignment: .leading, spacing: 3) {
                Text(title)
                    .font(.system(size: 13.5, weight: .semibold))
                    .foregroundStyle(Theme.crit)
                Text(message)
                    .font(.system(size: 12.5))
                    .foregroundStyle(Theme.text2)
            }
            Spacer()
        }
        .padding(12)
        .background(Theme.crit.opacity(0.08))
        .overlay(RoundedRectangle(cornerRadius: 12).stroke(Theme.crit.opacity(0.35), lineWidth: 1))
        .clipShape(RoundedRectangle(cornerRadius: 12))
    }
}

private struct EmptyActivityCard: View {
    var body: some View {
        Text("No activity entries match this filter.")
            .font(.system(size: 13))
            .foregroundStyle(Theme.text2)
            .frame(maxWidth: .infinity, alignment: .leading)
            .activityCard()
    }
}

private struct StrataMark: View {
    var body: some View {
        VStack(spacing: 3) {
            markBar(width: 22, color: Theme.info)
            markBar(width: 24, color: Theme.teal2)
            markBar(width: 18, color: Color(red: 0x8D/255, green: 0x8C/255, blue: 0xF2/255))
            markBar(width: 16, color: Theme.amber)
        }
        .frame(width: 29, height: 29)
    }

    private func markBar(width: CGFloat, color: Color) -> some View {
        RoundedRectangle(cornerRadius: 1.4)
            .fill(color)
            .frame(width: width, height: 4)
    }
}

private extension View {
    func activityCard() -> some View {
        self
            .padding(15)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(
                LinearGradient(colors: [Theme.bg2, Theme.card], startPoint: .top, endPoint: .bottom)
            )
            .overlay(RoundedRectangle(cornerRadius: 14).stroke(Theme.hair2, lineWidth: 1))
            .clipShape(RoundedRectangle(cornerRadius: 14))
    }
}
#endif
