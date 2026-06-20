#if os(macOS)
import SwiftUI

/// Native SwiftUI ports of the remaining HTML design references in `Design/`.
/// These are intentionally data-backed where Strata already has equivalent
/// model state, and illustrative where the reference describes future surfaces.
struct DesignSurfacesView: View {
    @EnvironmentObject private var model: AppModel
    @State private var tab: DesignSurfaceTab = .shell
    @State private var caseFilter: CaseDashboardFilter = .all
    @State private var onboardingStep = 0
    @State private var reportSections: Set<ReportSection> = Set(ReportSection.defaultOn)
    @State private var selectedOutput: Set<ReportOutput> = [.html, .markdown, .timelineCSV, .findingsCSV]
    @State private var selectedFindingIDs: Set<UUID> = []
    @State private var analysisTab: AnalysisDemoTab = .pivot
    @State private var rawMode: RawInspectorMode = .hex

    private var cases: [CaseDashboardItem] {
        CaseDashboardItem.items(from: model)
    }

    private var filteredCases: [CaseDashboardItem] {
        cases.filter { caseFilter.includes($0) }
    }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 18) {
                header
                surfaceTabs
                switch tab {
                case .shell:
                    shellPane
                case .states:
                    statesPane
                case .analysis:
                    analysisPane
                case .report:
                    reportPane
                }
            }
            .padding(20)
            .frame(maxWidth: 820, alignment: .leading)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .top)
        .background(Theme.bg)
        .navigationTitle("Design UI")
        .onAppear {
            selectedFindingIDs = Set(model.findings.prefix(3).map(\.id))
        }
    }

    private var header: some View {
        HStack(spacing: 12) {
            MiniStrataMark()
            VStack(alignment: .leading, spacing: 2) {
                Text("Strata")
                    .font(.system(size: 22, weight: .bold))
                    .foregroundStyle(Theme.text)
                Text("native ports from HTML references")
                    .font(.system(size: 11, weight: .medium, design: .monospaced))
                    .foregroundStyle(Theme.text3)
            }
            Spacer()
            DSPill(text: "4 references", color: Theme.text3, fill: Theme.card)
        }
    }

    private var surfaceTabs: some View {
        ScrollView(.horizontal, showsIndicators: false) {
            HStack(spacing: 8) {
                ForEach(DesignSurfaceTab.allCases) { entry in
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
    }

    // MARK: - Shell

    private var shellPane: some View {
        VStack(alignment: .leading, spacing: 14) {
            DSHeading(
                title: "Cases",
                subtitle: "Home surface: open cases, active processing, custody issues, and current findings."
            )
            LazyVGrid(columns: Array(repeating: GridItem(.flexible(), spacing: 9), count: 4), spacing: 9) {
                DSStat(value: "\(cases.count)", label: "open cases")
                DSStat(value: "\(model.isWorking ? 1 : 0)", label: "processing", color: Theme.amber)
                DSStat(value: "\(integrityIssueCount)", label: "custody due", color: Theme.crit)
                DSStat(value: "\(model.findingCount)", label: "findings", color: Theme.teal2)
            }
            filterChips
            VStack(spacing: 10) {
                ForEach(filteredCases) { item in
                    CaseDashboardCard(item: item)
                }
            }
            Button { model.requestNewCase() } label: {
                Label("New case", systemImage: "plus")
                    .frame(maxWidth: .infinity)
            }
            .buttonStyle(.borderedProminent)
            navigationPreview
            DSNote("The sign-in and RBAC panes in the HTML reference are intentionally not ported; the project scope keeps Strata as a single-Mac evidence workspace without auth.")
        }
    }

    private var filterChips: some View {
        ScrollView(.horizontal, showsIndicators: false) {
            HStack(spacing: 7) {
                ForEach(CaseDashboardFilter.allCases) { filter in
                    Button { caseFilter = filter } label: {
                        Text(filter.label)
                            .font(.system(size: 11.5, weight: .semibold, design: .monospaced))
                            .padding(.horizontal, 12)
                            .padding(.vertical, 6)
                            .foregroundStyle(caseFilter == filter ? Theme.text : Theme.text3)
                            .background(caseFilter == filter ? Theme.card2 : Theme.card)
                            .clipShape(Capsule())
                            .overlay(Capsule().stroke(caseFilter == filter ? Theme.hair : Theme.hair2, lineWidth: 1))
                    }
                    .buttonStyle(.plain)
                }
            }
        }
    }

    private var navigationPreview: some View {
        HStack(alignment: .top, spacing: 16) {
            VStack(alignment: .leading, spacing: 10) {
                DSSectionLabel("Adaptive navigation")
                PreviewListRow(symbol: "externaldrive", title: "\(model.evidenceList.count) exhibits", subtitle: "\(readyEvidenceCount) ready for analysis")
                PreviewListRow(symbol: "checkmark.seal", title: "Custody chain", subtitle: "\(model.custodyLog.count) recorded events")
                PreviewListRow(symbol: "doc.text.magnifyingglass", title: "Evidence viewer", subtitle: "\(model.timelineCount.formatted()) timeline events")
                HStack(spacing: 0) {
                    ForEach(["Cases", "Intake", "Custody", "Viewer", "Settings"], id: \.self) { label in
                        VStack(spacing: 5) {
                            Image(systemName: label == "Cases" ? "house" : "circle")
                                .font(.system(size: 15))
                            Text(label)
                                .font(.system(size: 9.5, weight: .medium, design: .monospaced))
                        }
                        .foregroundStyle(label == "Cases" ? Theme.teal2 : Theme.text3)
                        .frame(maxWidth: .infinity)
                        .padding(.vertical, 10)
                    }
                }
                .background(Theme.bg2)
                .overlay(Rectangle().fill(Theme.hair2).frame(height: 1), alignment: .top)
            }
            .dsCard()

            VStack(alignment: .leading, spacing: 7) {
                DSSectionLabel("macOS sidebar")
                ForEach(SidebarItem.allCases.prefix(9)) { item in
                    HStack(spacing: 9) {
                        Circle()
                            .fill(item == .overview ? Theme.teal2 : Theme.hair)
                            .frame(width: 6, height: 6)
                        Text(item.rawValue)
                    }
                    .font(.system(size: 12, weight: .medium, design: .monospaced))
                    .foregroundStyle(item == .overview ? Theme.text : Theme.text2)
                    .padding(.horizontal, 8)
                    .padding(.vertical, 6)
                    .background(item == .overview ? Theme.card2 : .clear, in: RoundedRectangle(cornerRadius: 8))
                }
            }
            .frame(width: 210)
            .dsCard()
        }
    }

    // MARK: - States

    private var statesPane: some View {
        VStack(alignment: .leading, spacing: 14) {
            DSHeading(
                title: "States & onboarding",
                subtitle: "Empty, loading, error, confirmation, and first-run patterns as reusable native components."
            )
            DSSectionLabel("Empty states")
            HStack(spacing: 12) {
                EmptyStatePanel(symbol: "shippingbox", title: "No cases yet", message: "Open a case to start collecting evidence and building custody.")
                EmptyStatePanel(symbol: "star", title: "No findings bookmarked", message: "Bookmark records in analysis views to collect them for report drafting.")
            }
            DSSectionLabel("Loading states")
            VStack(spacing: 9) {
                ForEach(0..<3, id: \.self) { _ in
                    SkeletonRow()
                }
                ProcessingPanel(isWorking: model.isWorking, label: model.statusMessage.isEmpty ? "Parsing evidence" : model.statusMessage)
            }
            DSSectionLabel("Errors and confirmations")
            ErrorPatternCard(
                symbol: "externaldrive.badge.exclamationmark",
                title: "Image will not open",
                message: "The source appears truncated or unreadable. Re-import segments or verify the acquisition hash.",
                tone: .critical
            )
            ErrorPatternCard(
                symbol: "lock",
                title: "Decryption failed",
                message: "The recovery key did not unlock this volume. System artifacts can still parse; user data stays sealed.",
                tone: .warning
            )
            ConfirmPatternCard(caseName: model.currentCase?.name ?? "FIAU-2026-0114")
            onboardingCard
        }
    }

    private var onboardingCard: some View {
        let steps = OnboardingStep.allCases
        let step = steps[onboardingStep]
        return VStack(alignment: .leading, spacing: 14) {
            DSSectionLabel("First-run onboarding")
            HStack(spacing: 14) {
                MiniStrataMark(scale: 2.1)
                    .frame(width: 92, height: 92)
                    .background(Theme.card2, in: RoundedRectangle(cornerRadius: 20))
                VStack(alignment: .leading, spacing: 7) {
                    Text(step.title)
                        .font(.system(size: 19, weight: .semibold))
                        .foregroundStyle(Theme.text)
                    Text(step.message)
                        .font(.system(size: 13.5))
                        .foregroundStyle(Theme.text2)
                    ForEach(step.features, id: \.self) { feature in
                        Label(feature, systemImage: "checkmark")
                            .font(.system(size: 12.5))
                            .foregroundStyle(Theme.text2)
                    }
                }
            }
            HStack {
                ForEach(steps.indices, id: \.self) { index in
                    Capsule()
                        .fill(index == onboardingStep ? Theme.teal2 : Theme.card2)
                        .frame(width: index == onboardingStep ? 20 : 7, height: 7)
                }
                Spacer()
                Button("Skip") { onboardingStep = steps.count - 1 }
                    .disabled(onboardingStep == steps.count - 1)
                Button(onboardingStep == steps.count - 1 ? "Get started" : "Next") {
                    onboardingStep = (onboardingStep + 1) % steps.count
                }
                .buttonStyle(.borderedProminent)
            }
        }
        .dsCard()
    }

    // MARK: - Analysis

    private var analysisPane: some View {
        VStack(alignment: .leading, spacing: 14) {
            DSHeading(
                title: "Analysis views",
                subtitle: "Cross-artifact pivoting, communications, location, media, and raw inspectors."
            )
            ScrollView(.horizontal, showsIndicators: false) {
                HStack(spacing: 7) {
                    ForEach(AnalysisDemoTab.allCases) { mode in
                        Button { analysisTab = mode } label: {
                            Text(mode.label)
                                .font(.system(size: 11.5, weight: .semibold, design: .monospaced))
                                .padding(.horizontal, 12)
                                .padding(.vertical, 6)
                                .foregroundStyle(analysisTab == mode ? Theme.text : Theme.text3)
                                .background(analysisTab == mode ? Theme.card2 : Theme.card)
                                .clipShape(Capsule())
                        }
                        .buttonStyle(.plain)
                    }
                }
            }
            switch analysisTab {
            case .pivot:
                pivotDemo
            case .conversation:
                conversationDemo
            case .map:
                mapDemo
            case .media:
                mediaDemo
            case .raw:
                rawInspectorDemo
            }
        }
    }

    private var pivotDemo: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack(spacing: 13) {
                Image(systemName: "phone")
                    .frame(width: 42, height: 42)
                    .background(Color(red: 0x8D/255, green: 0x8C/255, blue: 0xF2/255).opacity(0.12), in: RoundedRectangle(cornerRadius: 11))
                VStack(alignment: .leading, spacing: 2) {
                    Text("+356 9988 7766")
                        .font(.system(size: 16, weight: .semibold))
                        .foregroundStyle(Theme.text)
                    Text("number - alias Broker - first seen 2026-06-01")
                        .font(.system(size: 11, weight: .medium, design: .monospaced))
                        .foregroundStyle(Theme.text3)
                }
                Spacer()
                VStack(alignment: .trailing, spacing: 0) {
                    Text("9")
                        .font(.system(size: 24, weight: .semibold))
                        .foregroundStyle(Color(red: 0x8D/255, green: 0x8C/255, blue: 0xF2/255))
                    Text("references")
                        .font(.system(size: 9, design: .monospaced))
                        .foregroundStyle(Theme.text3)
                }
            }
            .dsCard()
            DSGroupLabel("suspect-iphone.tar", trailing: "iOS")
            PivotHit(symbol: "message", title: "\"moved the funds, account is clean now\"", source: "sms.db - iMessage - sent", time: "06-08 21:04")
            PivotHit(symbol: "phone.arrow.up.right", title: "Outgoing call - 6m 12s", source: "CallHistory.storedata", time: "06-08 20:51")
            PivotHit(symbol: "person.crop.circle", title: "Contact Broker", source: "AddressBook.sqlitedb", time: "06-01")
            DSGroupLabel("pixel-7.img", trailing: "Android")
            PivotHit(symbol: "message", title: "\"wallet seed sent, burn the device\"", source: "mmssms.db - SMS - received", time: "06-08 22:11")
            DSNote("The same entity links two seized devices. The pivot is a navigational layer over records, not another parser.")
        }
    }

    private var conversationDemo: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack(spacing: 11) {
                Text("B")
                    .font(.system(size: 14, weight: .bold))
                    .frame(width: 36, height: 36)
                    .background(Color(red: 0x8D/255, green: 0x8C/255, blue: 0xF2/255).opacity(0.35), in: Circle())
                VStack(alignment: .leading, spacing: 2) {
                    Text("Broker - +356 9988 7766")
                        .font(.system(size: 14, weight: .semibold))
                    Text("iMessage + SMS - sms.db - 14 messages")
                        .font(.system(size: 10.5, design: .monospaced))
                        .foregroundStyle(Theme.text3)
                }
                Spacer()
                Button { } label: { Label("Flag", systemImage: "star") }
                    .controlSize(.small)
            }
            .dsCard()
            Text("8 June 2026")
                .font(.system(size: 10, weight: .medium, design: .monospaced))
                .foregroundStyle(Theme.text3)
                .frame(maxWidth: .infinity)
            ChatBubble(text: "You still good for tonight?", meta: "SMS - 19:31", sent: false)
            ChatBubble(text: "yeah. moving it through the holding co first", meta: "iMessage - 20:02 - read", sent: true)
            ChatBubble(text: "moved the funds, account is clean now", meta: "iMessage - 21:04 - read - finding", sent: true)
            ChatBubble(text: "delete this chat after", meta: "SMS - 21:06", sent: false)
            DSNote("Each bubble keeps source provenance and can become a report finding.")
        }
    }

    private var mapDemo: some View {
        VStack(alignment: .leading, spacing: 12) {
            ZStack(alignment: .topLeading) {
                TimelineMapSketch()
                    .frame(height: 240)
                    .clipShape(RoundedRectangle(cornerRadius: 15))
                    .overlay(RoundedRectangle(cornerRadius: 15).stroke(Theme.hair2, lineWidth: 1))
                HStack(spacing: 7) {
                    DSPill(text: "5 points", color: Theme.teal2, fill: Theme.tealDim)
                    DSPill(text: "06-08 evening", color: Color(red: 0x8D/255, green: 0x8C/255, blue: 0xF2/255), fill: Color(red: 0x8D/255, green: 0x8C/255, blue: 0xF2/255).opacity(0.14))
                }
                .padding(10)
            }
            MapListRow(index: 1, title: "Valletta waterfront", detail: "35.8975, 14.5126 - significant locations - +/-12 m", time: "20:48", color: .green)
            MapListRow(index: 2, title: "Floriana", detail: "35.8901, 14.5012 - Wi-Fi fix FLR-Guest", time: "21:48", color: .green)
            MapListRow(index: 3, title: "Photo IMG_4821.HEIC", detail: "35.8989, 14.5146 - EXIF GPS", time: "16:22", color: .orange)
            MapListRow(index: 5, title: "Last known fix", detail: "before device off", time: "22:31", color: .red)
        }
    }

    private var mediaDemo: some View {
        VStack(alignment: .leading, spacing: 12) {
            LazyVGrid(columns: Array(repeating: GridItem(.flexible(), spacing: 8), count: 3), spacing: 8) {
                ForEach(0..<6, id: \.self) { index in
                    MediaTile(index: index)
                }
            }
            DSNote("Production should back this with actual thumbnail extraction; the mock here preserves the review flow and EXIF affordances.")
        }
    }

    private var rawInspectorDemo: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack(spacing: 8) {
                ForEach(RawInspectorMode.allCases) { mode in
                    Button(mode.label) { rawMode = mode }
                        .buttonStyle(.bordered)
                        .foregroundStyle(rawMode == mode ? Theme.teal2 : Theme.text2)
                }
            }
            HStack(spacing: 8) {
                Text("sms.db")
                Text("-")
                Text("58 MB")
                Text("-")
                Text("SHA-256 7e1c...0a9b3f")
            }
            .font(.system(size: 11, weight: .medium, design: .monospaced))
            .foregroundStyle(Theme.text3)
            if rawMode == .hex {
                HexDumpCard()
            } else {
                SQLitePreviewCard()
            }
        }
    }

    // MARK: - Report

    private var reportPane: some View {
        VStack(alignment: .leading, spacing: 14) {
            DSHeading(
                title: "Reporting & export",
                subtitle: "Finding selection, report assembly, and custody preview using existing Strata report/export concepts."
            )
            findingsDemo
            reportBuilderDemo
            custodyPaperPreview
        }
    }

    private var findingsDemo: some View {
        VStack(alignment: .leading, spacing: 10) {
            DSSectionLabel("Findings")
            HStack {
                VStack(alignment: .leading, spacing: 2) {
                    Text("\(model.findingCount) findings")
                        .font(.system(size: 15, weight: .semibold))
                    Text("\(selectedFindingIDs.count) selected for report")
                        .font(.system(size: 11, design: .monospaced))
                        .foregroundStyle(Theme.text3)
                }
                Spacer()
                Button("Group: artifact") { }
                    .controlSize(.small)
            }
            let rows = model.findings.prefix(4).map(ReportFindingRow.live)
            ForEach(rows.isEmpty ? ReportFindingRow.samples : rows) { row in
                FindingSelectionRow(row: row, selected: selectedFindingIDs.contains(row.id)) {
                    if selectedFindingIDs.contains(row.id) {
                        selectedFindingIDs.remove(row.id)
                    } else {
                        selectedFindingIDs.insert(row.id)
                    }
                }
            }
        }
    }

    private var reportBuilderDemo: some View {
        VStack(alignment: .leading, spacing: 12) {
            DSSectionLabel("Report builder")
            VStack(alignment: .leading, spacing: 10) {
                Picker("Template", selection: .constant("Investigation report - full")) {
                    Text("Investigation report - full").tag("Investigation report - full")
                    Text("Executive summary").tag("Executive summary")
                    Text("Technical appendix only").tag("Technical appendix only")
                }
                Picker("Classification banner", selection: .constant("Confidential")) {
                    Text("Confidential").tag("Confidential")
                    Text("Restricted").tag("Restricted")
                    Text("Secret").tag("Secret")
                }
            }
            .dsCard()
            VStack(spacing: 0) {
                ForEach(ReportSection.allCases) { section in
                    HStack(spacing: 11) {
                        Image(systemName: "line.3.horizontal")
                            .foregroundStyle(Theme.text3)
                        Text("\(section.order)")
                            .font(.system(size: 11, design: .monospaced))
                            .foregroundStyle(Theme.text3)
                            .frame(width: 18)
                        VStack(alignment: .leading, spacing: 1) {
                            Text(section.title)
                                .font(.system(size: 13.5, weight: .medium))
                            Text(section.subtitle)
                                .font(.system(size: 10, design: .monospaced))
                                .foregroundStyle(Theme.text3)
                        }
                        Spacer()
                        Toggle("", isOn: binding(for: section))
                            .labelsHidden()
                            .toggleStyle(.switch)
                            .controlSize(.small)
                    }
                    .padding(12)
                    if section != ReportSection.allCases.last {
                        Divider().background(Theme.hair2)
                    }
                }
            }
            .background(Theme.card)
            .clipShape(RoundedRectangle(cornerRadius: 13))
            .overlay(RoundedRectangle(cornerRadius: 13).stroke(Theme.hair2, lineWidth: 1))
            VStack(alignment: .leading, spacing: 7) {
                DSSectionLabel("Output")
                ForEach(ReportOutput.allCases) { output in
                    Toggle(output.label, isOn: outputBinding(for: output))
                }
            }
            .dsCard()
            Button { model.requestExport() } label: {
                Label("Generate report", systemImage: "doc.richtext")
                    .frame(maxWidth: .infinity)
            }
            .buttonStyle(.borderedProminent)
        }
    }

    private var custodyPaperPreview: some View {
        VStack(alignment: .leading, spacing: 10) {
            DSSectionLabel("Custody export")
            HStack(spacing: 9) {
                Button("Export PDF") { model.requestExport() }
                    .buttonStyle(.borderedProminent)
                Button("Export CSV") { model.requestExport() }
                Button("Copy hashes") { }
            }
            CustodyPaper(caseName: model.currentCase?.name ?? "Untitled case",
                         evidenceName: model.evidenceList.first?.displayName ?? "EXH-001",
                         custodyCount: model.custodyLog.count,
                         hashStatus: integrityIssueCount == 0 ? "verified" : "mismatch present")
        }
    }

    private var readyEvidenceCount: Int {
        model.evidenceList.filter { evidence in
            let state = model.states[evidence.id]
            return (state?.files.isEmpty == false) || (state?.timeline.isEmpty == false)
        }.count
    }

    private var integrityIssueCount: Int {
        model.evidenceList.reduce(0) { count, evidence in
            count + evidence.sourceHashes.filter { $0.status == .mismatch || $0.status == .notVerified }.count
        }
    }

    private func binding(for section: ReportSection) -> Binding<Bool> {
        Binding(
            get: { reportSections.contains(section) },
            set: { enabled in
                if enabled { reportSections.insert(section) } else { reportSections.remove(section) }
            }
        )
    }

    private func outputBinding(for output: ReportOutput) -> Binding<Bool> {
        Binding(
            get: { selectedOutput.contains(output) },
            set: { enabled in
                if enabled { selectedOutput.insert(output) } else { selectedOutput.remove(output) }
            }
        )
    }
}

// MARK: - Data

private enum DesignSurfaceTab: CaseIterable, Identifiable {
    case shell, states, analysis, report

    var id: Self { self }
    var number: String {
        switch self {
        case .shell: return "01"
        case .states: return "02"
        case .analysis: return "03"
        case .report: return "04"
        }
    }
    var label: String {
        switch self {
        case .shell: return "Shell"
        case .states: return "States"
        case .analysis: return "Analysis"
        case .report: return "Report"
        }
    }
}

private enum CaseDashboardFilter: CaseIterable, Identifiable {
    case all, active, review, closed, mine

    var id: Self { self }
    var label: String {
        switch self {
        case .all: return "All"
        case .active: return "Active"
        case .review: return "In review"
        case .closed: return "Closed"
        case .mine: return "Assigned to me"
        }
    }
    func includes(_ item: CaseDashboardItem) -> Bool {
        switch self {
        case .all: return true
        case .active: return item.status == .active || item.status == .collecting || item.status == .processing
        case .review: return item.status == .review
        case .closed: return item.status == .closed
        case .mine: return item.assignedToMe
        }
    }
}

private enum CaseStatus {
    case collecting, processing, active, review, closed

    var label: String {
        switch self {
        case .collecting: return "collecting"
        case .processing: return "processing"
        case .active: return "active"
        case .review: return "in review"
        case .closed: return "closed"
        }
    }
    var color: Color {
        switch self {
        case .collecting, .active: return Theme.teal2
        case .processing: return Theme.amber
        case .review: return Color(red: 0x8D/255, green: 0x8C/255, blue: 0xF2/255)
        case .closed: return Theme.info
        }
    }
}

private struct CaseDashboardItem: Identifiable {
    let id = UUID()
    let reference: String
    let title: String
    let type: String
    let lead: String
    let exhibits: Int
    let findings: Int
    let classification: String
    let status: CaseStatus
    let progress: Double
    let footer: String
    let assignedToMe: Bool

    static func items(from model: AppModel) -> [CaseDashboardItem] {
        var out: [CaseDashboardItem] = []
        if let current = model.currentCase {
            out.append(
                CaseDashboardItem(
                    reference: current.name.components(separatedBy: " ").first ?? "CASE",
                    title: current.name,
                    type: "Digital forensics",
                    lead: current.examiner.isEmpty ? "Unassigned" : current.examiner,
                    exhibits: model.evidenceList.count,
                    findings: model.findingCount,
                    classification: "Confidential",
                    status: model.isWorking ? .processing : .active,
                    progress: model.evidenceList.isEmpty ? 0.12 : min(1, Double(model.evidenceList.count + model.findingCount) / Double(max(6, model.evidenceList.count + 4))),
                    footer: model.isWorking ? "processing evidence" : "scope ready",
                    assignedToMe: true
                )
            )
        }
        out.append(contentsOf: [
            CaseDashboardItem(reference: "FIAU-2026-0109", title: "Lampuki Holdings", type: "Sanctions evasion", lead: "A. Vella", exhibits: 3, findings: 21, classification: "Secret", status: .review, progress: 1, footer: "analysis complete - report drafting", assignedToMe: true),
            CaseDashboardItem(reference: "FIAU-2026-0118", title: "Marsamxett Exchange", type: "Fraud", lead: "D. Spiteri", exhibits: 1, findings: 0, classification: "Restricted", status: .collecting, progress: 0.18, footer: "awaiting acquisition", assignedToMe: false),
            CaseDashboardItem(reference: "FIAU-2026-0071", title: "Gozo Ferry Co.", type: "Cyber-enabled crime", lead: "M. Grech", exhibits: 4, findings: 34, classification: "Confidential", status: .closed, progress: 1, footer: "archived - retention 10y", assignedToMe: false)
        ])
        return out
    }
}

private enum OnboardingStep: CaseIterable {
    case welcome, ingest, unit, integrity

    var title: String {
        switch self {
        case .welcome: return "Welcome to Strata"
        case .ingest: return "Ingest any platform"
        case .unit: return "Set up your unit"
        case .integrity: return "Integrity, built in"
        }
    }
    var message: String {
        switch self {
        case .welcome: return "A forensics workspace for examining disk images from acquisition to court-ready report."
        case .ingest: return "Drop an image and Strata detects OS, filesystem, and encryption before parsing."
        case .unit: return "Examiners, agencies, and tools populate every form and report."
        case .integrity: return "Custody and activity records are append-only and auditable."
        }
    }
    var features: [String] {
        switch self {
        case .welcome: return ["macOS ingest", "iOS case viewer"]
        case .ingest: return ["Windows, Linux, macOS", "BitLocker / FileVault / LUKS aware"]
        case .unit: return ["Shared pickers", "Reusable report metadata"]
        case .integrity: return ["Source hash verification", "Custody export"]
        }
    }
}

private enum ErrorTone {
    case critical, warning

    var color: Color { self == .critical ? Theme.crit : Theme.amber }
}

private enum AnalysisDemoTab: CaseIterable, Identifiable {
    case pivot, conversation, map, media, raw

    var id: Self { self }
    var label: String {
        switch self {
        case .pivot: return "Pivot"
        case .conversation: return "Conversation"
        case .map: return "Map"
        case .media: return "Media"
        case .raw: return "Hex / SQLite"
        }
    }
}

private enum RawInspectorMode: CaseIterable, Identifiable {
    case hex, sqlite

    var id: Self { self }
    var label: String { self == .hex ? "Hex" : "SQLite" }
}

private struct ReportFindingRow: Identifiable {
    let id: UUID
    let title: String
    let source: String
    let note: String
    let tags: [String]
    let color: Color

    nonisolated static func live(_ finding: Finding) -> ReportFindingRow {
        let technique = finding.technique.map { "\($0.attackID) \($0.name)" }
        let source = [technique, finding.phase.rawValue].compactMap { $0 }.filter { !$0.isEmpty }
        let tags = [finding.severity.label, finding.technique?.attackID].compactMap { $0 }.filter { !$0.isEmpty }
        return ReportFindingRow(
            id: finding.id,
            title: finding.title,
            source: source.joined(separator: " - "),
            note: finding.detail,
            tags: tags,
            color: color(for: finding.severity)
        )
    }

    nonisolated private static func color(for severity: Severity) -> Color {
        switch severity {
        case .critical: return Color(red: 0xFF/255, green: 0x4D/255, blue: 0x6D/255)
        case .high: return Color(red: 0xFF/255, green: 0x8A/255, blue: 0x3D/255)
        case .medium: return Color(red: 0xF4/255, green: 0xB7/255, blue: 0x40/255)
        case .low: return Color(red: 0x4F/255, green: 0xB0/255, blue: 0xC9/255)
        case .info: return Color(red: 0x7D/255, green: 0x8C/255, blue: 0x97/255)
        }
    }

    static let samples: [ReportFindingRow] = [
        .init(id: UUID(), title: "Run key -> C:\\Users\\Public\\upd.exe", source: "registry - persistence", note: "Auto-start persistence written after the network logon.", tags: ["IOC", "relevant"], color: Theme.crit),
        .init(id: UUID(), title: "@reboot /opt/.x/miner", source: "crontab - persistence", note: "Corroborates the SSH key addition.", tags: ["relevant"], color: Theme.amber),
        .init(id: UUID(), title: "\"moved the funds, account is clean now\"", source: "sms.db - iMessage", note: "Directly probative communication.", tags: ["IOC", "relevant"], color: Theme.teal2)
    ]
}

private enum ReportSection: Int, CaseIterable, Identifiable {
    case cover = 1, summary, methodology, findings, timeline, custody, manifest, appendix

    var id: Int { rawValue }
    var order: Int { rawValue }
    var title: String {
        switch self {
        case .cover: return "Cover & case identity"
        case .summary: return "Executive summary"
        case .methodology: return "Methodology & tools"
        case .findings: return "Findings"
        case .timeline: return "Timeline"
        case .custody: return "Chain of custody"
        case .manifest: return "Exhibit manifest"
        case .appendix: return "Appendix - raw artifacts"
        }
    }
    var subtitle: String {
        switch self {
        case .cover: return "reference, authority, classification"
        case .summary: return "narrative draft + edit"
        case .methodology: return "acquisition, write-blockers, parsers"
        case .findings: return "selected findings"
        case .timeline: return "merged events, incident window"
        case .custody: return "custody log + integrity statement"
        case .manifest: return "exhibits and hashes"
        case .appendix: return "optional"
        }
    }
    static let defaultOn: [ReportSection] = [.cover, .summary, .methodology, .findings, .timeline, .custody, .manifest]
}

private enum ReportOutput: CaseIterable, Identifiable {
    case html, markdown, timelineCSV, findingsCSV, redactedCopy

    var id: Self { self }
    var label: String {
        switch self {
        case .html: return "HTML report"
        case .markdown: return "Markdown report"
        case .timelineCSV: return "CSV - timeline"
        case .findingsCSV: return "CSV - findings"
        case .redactedCopy: return "Redact PII in disclosure copy"
        }
    }
}

// MARK: - Components

private struct DSHeading: View {
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

private struct DSSectionLabel: View {
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

private struct DSGroupLabel: View {
    let text: String
    let trailing: String

    init(_ text: String, trailing: String) {
        self.text = text
        self.trailing = trailing
    }

    var body: some View {
        HStack(spacing: 8) {
            Text(text.uppercased())
            Rectangle().fill(Theme.hair2).frame(height: 1)
            DSPill(text: trailing, color: Theme.teal2, fill: Theme.tealDim)
        }
        .font(.system(size: 10.5, weight: .medium, design: .monospaced))
        .foregroundStyle(Theme.text3)
    }
}

private struct DSPill: View {
    let text: String
    let color: Color
    let fill: Color

    var body: some View {
        HStack(spacing: 5) {
            Circle().fill(color).frame(width: 5, height: 5)
            Text(text)
        }
        .font(.system(size: 10.5, weight: .medium, design: .monospaced))
        .foregroundStyle(color)
        .padding(.horizontal, 8)
        .padding(.vertical, 4)
        .background(fill, in: Capsule())
        .overlay(Capsule().stroke(color.opacity(0.35), lineWidth: 1))
    }
}

private struct DSStat: View {
    let value: String
    let label: String
    var color: Color = Theme.text

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text(value)
                .font(.system(size: 24, weight: .semibold))
                .foregroundStyle(color)
            Text(label.uppercased())
                .font(.system(size: 10, weight: .medium, design: .monospaced))
                .foregroundStyle(Theme.text3)
        }
        .padding(12)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(LinearGradient(colors: [Theme.bg2, Theme.card], startPoint: .top, endPoint: .bottom))
        .clipShape(RoundedRectangle(cornerRadius: 13))
        .overlay(RoundedRectangle(cornerRadius: 13).stroke(Theme.hair2, lineWidth: 1))
    }
}

private struct CaseDashboardCard: View {
    let item: CaseDashboardItem

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack(alignment: .top, spacing: 10) {
                VStack(alignment: .leading, spacing: 2) {
                    Text(item.reference)
                        .font(.system(size: 11, weight: .medium, design: .monospaced))
                        .foregroundStyle(Theme.teal2)
                    Text(item.title)
                        .font(.system(size: 16, weight: .semibold))
                        .foregroundStyle(Theme.text)
                }
                Spacer()
                VStack(alignment: .trailing, spacing: 6) {
                    Text(item.classification)
                        .font(.system(size: 10, weight: .medium, design: .monospaced))
                        .padding(.horizontal, 7)
                        .padding(.vertical, 3)
                        .foregroundStyle(item.classification == "Secret" ? Theme.crit : Theme.amber)
                        .background((item.classification == "Secret" ? Theme.crit : Theme.amber).opacity(0.08), in: RoundedRectangle(cornerRadius: 6))
                    DSPill(text: item.status.label, color: item.status.color, fill: item.status.color.opacity(0.1))
                }
            }
            HStack(spacing: 14) {
                Text(item.type)
                Text("lead \(item.lead)")
                Text("\(item.exhibits) exhibits")
                Text("\(item.findings) findings")
            }
            .font(.system(size: 10.5, weight: .medium, design: .monospaced))
            .foregroundStyle(Theme.text3)
            ProgressView(value: item.progress)
                .tint(item.status == .closed ? Theme.info : Theme.teal2)
            HStack {
                Text(item.footer)
                Spacer()
                Text(item.status == .closed ? "closed" : "active")
            }
            .font(.system(size: 10, design: .monospaced))
            .foregroundStyle(Theme.text3)
        }
        .padding(14)
        .background(Theme.card)
        .clipShape(RoundedRectangle(cornerRadius: 14))
        .overlay(RoundedRectangle(cornerRadius: 14).stroke(Theme.hair2, lineWidth: 1))
    }
}

private struct PreviewListRow: View {
    let symbol: String
    let title: String
    let subtitle: String

    var body: some View {
        HStack(spacing: 11) {
            Image(systemName: symbol)
                .foregroundStyle(Theme.teal2)
                .frame(width: 30, height: 30)
                .background(Theme.card2, in: RoundedRectangle(cornerRadius: 8))
            VStack(alignment: .leading, spacing: 1) {
                Text(title).font(.system(size: 13, weight: .semibold))
                Text(subtitle)
                    .font(.system(size: 10, design: .monospaced))
                    .foregroundStyle(Theme.text3)
            }
            Spacer()
        }
        .padding(11)
        .background(Theme.card, in: RoundedRectangle(cornerRadius: 11))
        .overlay(RoundedRectangle(cornerRadius: 11).stroke(Theme.hair2, lineWidth: 1))
    }
}

private struct EmptyStatePanel: View {
    let symbol: String
    let title: String
    let message: String

    var body: some View {
        VStack(spacing: 12) {
            Image(systemName: symbol)
                .font(.system(size: 24))
                .foregroundStyle(Theme.text3)
                .frame(width: 52, height: 52)
                .background(Theme.card2, in: RoundedRectangle(cornerRadius: 14))
            Text(title)
                .font(.system(size: 16, weight: .semibold))
                .foregroundStyle(Theme.text)
            Text(message)
                .font(.system(size: 13))
                .multilineTextAlignment(.center)
                .foregroundStyle(Theme.text3)
        }
        .padding(24)
        .frame(maxWidth: .infinity)
        .background(Theme.card.opacity(0.7))
        .overlay(RoundedRectangle(cornerRadius: 16).stroke(Theme.hair, style: StrokeStyle(lineWidth: 1, dash: [5, 4])))
        .clipShape(RoundedRectangle(cornerRadius: 16))
    }
}

private struct SkeletonRow: View {
    var body: some View {
        HStack(spacing: 11) {
            RoundedRectangle(cornerRadius: 9)
                .fill(Theme.card2)
                .frame(width: 34, height: 34)
            VStack(alignment: .leading, spacing: 8) {
                RoundedRectangle(cornerRadius: 5).fill(Theme.card2).frame(height: 10)
                RoundedRectangle(cornerRadius: 5).fill(Theme.card2).frame(width: 190, height: 10)
            }
        }
        .padding(12)
        .background(Theme.card, in: RoundedRectangle(cornerRadius: 13))
        .overlay(RoundedRectangle(cornerRadius: 13).stroke(Theme.hair2, lineWidth: 1))
    }
}

private struct ProcessingPanel: View {
    let isWorking: Bool
    let label: String

    var body: some View {
        VStack(spacing: 10) {
            ProgressView()
                .controlSize(.regular)
            Text(isWorking ? "Processing evidence" : "Parsing evidence")
                .font(.system(size: 15, weight: .semibold))
                .foregroundStyle(Theme.text)
            Text(label)
                .font(.system(size: 11, design: .monospaced))
                .foregroundStyle(Theme.text3)
            ProgressView(value: isWorking ? nil : 0.42)
                .tint(Theme.teal2)
        }
        .padding(22)
        .frame(maxWidth: .infinity)
        .background(LinearGradient(colors: [Theme.bg2, Theme.card], startPoint: .top, endPoint: .bottom))
        .clipShape(RoundedRectangle(cornerRadius: 14))
        .overlay(RoundedRectangle(cornerRadius: 14).stroke(Theme.hair2, lineWidth: 1))
    }
}

private struct ErrorPatternCard: View {
    let symbol: String
    let title: String
    let message: String
    let tone: ErrorTone

    var body: some View {
        HStack(alignment: .top, spacing: 11) {
            Image(systemName: symbol)
                .foregroundStyle(tone.color)
                .frame(width: 34, height: 34)
                .background(tone.color.opacity(0.12), in: RoundedRectangle(cornerRadius: 9))
            VStack(alignment: .leading, spacing: 5) {
                Text(title)
                    .font(.system(size: 14, weight: .semibold))
                    .foregroundStyle(tone.color)
                Text(message)
                    .font(.system(size: 12.5))
                    .foregroundStyle(Theme.text2)
                HStack {
                    Button("Retry") { }.controlSize(.small)
                    Button("View log") { }.controlSize(.small)
                }
            }
            Spacer()
        }
        .padding(15)
        .background(tone.color.opacity(0.08), in: RoundedRectangle(cornerRadius: 14))
        .overlay(RoundedRectangle(cornerRadius: 14).stroke(tone.color.opacity(0.35), lineWidth: 1))
    }
}

private struct ConfirmPatternCard: View {
    let caseName: String

    var body: some View {
        VStack(spacing: 12) {
            Image(systemName: "lock")
                .foregroundStyle(Theme.crit)
                .frame(width: 46, height: 46)
                .background(Theme.crit.opacity(0.1), in: Circle())
            Text("Close and lock case")
                .font(.system(size: 16, weight: .semibold))
                .foregroundStyle(Theme.text)
            Text("This freezes \(caseName) read-only. Custody and findings can no longer change. This is logged.")
                .font(.system(size: 12.5))
                .foregroundStyle(Theme.text2)
                .multilineTextAlignment(.center)
            TextField(caseName, text: .constant(""))
                .textFieldStyle(.roundedBorder)
                .frame(maxWidth: 320)
            HStack {
                Button("Cancel") { }
                Button("Close case") { }
                    .buttonStyle(.borderedProminent)
                    .tint(Theme.crit)
            }
        }
        .padding(20)
        .frame(maxWidth: .infinity)
        .background(Theme.card, in: RoundedRectangle(cornerRadius: 16))
        .overlay(RoundedRectangle(cornerRadius: 16).stroke(Theme.hair2, lineWidth: 1))
    }
}

private struct PivotHit: View {
    let symbol: String
    let title: String
    let source: String
    let time: String

    var body: some View {
        HStack(alignment: .top, spacing: 11) {
            Image(systemName: symbol)
                .foregroundStyle(Theme.teal2)
                .frame(width: 26, height: 26)
                .background(Theme.card2, in: RoundedRectangle(cornerRadius: 7))
            VStack(alignment: .leading, spacing: 3) {
                Text(title)
                    .font(.system(size: 13, weight: .medium))
                    .foregroundStyle(Theme.text)
                Text(source)
                    .font(.system(size: 10, design: .monospaced))
                    .foregroundStyle(Theme.text3)
            }
            Spacer()
            Text(time)
                .font(.system(size: 9.5, design: .monospaced))
                .foregroundStyle(Theme.text3)
        }
        .padding(11)
        .background(Theme.card, in: RoundedRectangle(cornerRadius: 12))
        .overlay(RoundedRectangle(cornerRadius: 12).stroke(Theme.hair2, lineWidth: 1))
    }
}

private struct ChatBubble: View {
    let text: String
    let meta: String
    let sent: Bool

    var body: some View {
        VStack(alignment: sent ? .trailing : .leading, spacing: 5) {
            Text(text)
                .font(.system(size: 13.5))
            Text(meta)
                .font(.system(size: 9, design: .monospaced))
                .foregroundStyle(sent ? Theme.teal2.opacity(0.75) : Theme.text3)
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 9)
        .foregroundStyle(sent ? Color(red: 0xDF/255, green: 0xFA/255, blue: 0xF5/255) : Theme.text)
        .background(sent ? Theme.tealDim : Theme.card2, in: RoundedRectangle(cornerRadius: 15))
        .overlay(RoundedRectangle(cornerRadius: 15).stroke(sent ? Theme.teal2.opacity(0.35) : Theme.hair2, lineWidth: 1))
        .frame(maxWidth: .infinity, alignment: sent ? .trailing : .leading)
        .padding(.leading, sent ? 120 : 0)
        .padding(.trailing, sent ? 0 : 120)
    }
}

private struct TimelineMapSketch: View {
    var body: some View {
        GeometryReader { geo in
            let w = geo.size.width
            let h = geo.size.height
            ZStack {
                Color(red: 0x0C/255, green: 0x11/255, blue: 0x18/255)
                Path { path in
                    for x in stride(from: 0, through: w, by: 24) {
                        path.move(to: CGPoint(x: x, y: 0))
                        path.addLine(to: CGPoint(x: x, y: h))
                    }
                    for y in stride(from: 0, through: h, by: 24) {
                        path.move(to: CGPoint(x: 0, y: y))
                        path.addLine(to: CGPoint(x: w, y: y))
                    }
                }
                .stroke(Color.white.opacity(0.04), lineWidth: 1)
                Path { path in
                    path.move(to: CGPoint(x: w * 0.18, y: h * 0.27))
                    path.addLine(to: CGPoint(x: w * 0.42, y: h * 0.43))
                    path.addLine(to: CGPoint(x: w * 0.58, y: h * 0.68))
                    path.addLine(to: CGPoint(x: w * 0.72, y: h * 0.59))
                    path.addLine(to: CGPoint(x: w * 0.84, y: h * 0.79))
                }
                .stroke(Theme.teal2, style: StrokeStyle(lineWidth: 2, dash: [5, 5]))
                ForEach(Array([CGPoint(x: 0.18, y: 0.27), CGPoint(x: 0.42, y: 0.43), CGPoint(x: 0.58, y: 0.68), CGPoint(x: 0.72, y: 0.59), CGPoint(x: 0.84, y: 0.79)].enumerated()), id: \.offset) { index, point in
                    Text("\(index + 1)")
                        .font(.system(size: 9, weight: .bold, design: .monospaced))
                        .foregroundStyle(Color(red: 0x06/255, green: 0x14/255, blue: 0x0F/255))
                        .frame(width: index == 4 ? 22 : 18, height: index == 4 ? 22 : 18)
                        .background(index == 4 ? Theme.crit : (index == 2 ? Theme.amber : Color.green), in: Circle())
                        .position(x: w * point.x, y: h * point.y)
                }
            }
        }
    }
}

private struct MapListRow: View {
    let index: Int
    let title: String
    let detail: String
    let time: String
    let color: Color

    var body: some View {
        HStack(spacing: 11) {
            Text("\(index)")
                .font(.system(size: 10, weight: .bold, design: .monospaced))
                .foregroundStyle(Color(red: 0x06/255, green: 0x14/255, blue: 0x0F/255))
                .frame(width: 24, height: 24)
                .background(color, in: Circle())
            VStack(alignment: .leading, spacing: 2) {
                Text(title).font(.system(size: 13, weight: .medium))
                Text(detail)
                    .font(.system(size: 10, design: .monospaced))
                    .foregroundStyle(Theme.text3)
            }
            Spacer()
            Text(time)
                .font(.system(size: 9.5, design: .monospaced))
                .foregroundStyle(Theme.text3)
        }
        .padding(10)
        .background(Theme.card, in: RoundedRectangle(cornerRadius: 11))
        .overlay(RoundedRectangle(cornerRadius: 11).stroke(Theme.hair2, lineWidth: 1))
    }
}

private struct MediaTile: View {
    let index: Int

    var body: some View {
        ZStack(alignment: .bottomLeading) {
            LinearGradient(colors: palette, startPoint: .topLeading, endPoint: .bottomTrailing)
            Text(index % 2 == 0 ? "06-08 20:\(50 + index)" : "06-07 16:\(20 + index)")
                .font(.system(size: 8.5, weight: .medium, design: .monospaced))
                .padding(.horizontal, 5)
                .padding(.vertical, 2)
                .background(Color.black.opacity(0.55), in: RoundedRectangle(cornerRadius: 5))
                .foregroundStyle(Color(red: 0xCC/255, green: 0xDD/255, blue: 0xEE/255))
                .padding(5)
            if index % 2 == 0 {
                Image(systemName: "location.fill")
                    .font(.system(size: 8))
                    .foregroundStyle(Color(red: 0x06/255, green: 0x14/255, blue: 0x0F/255))
                    .frame(width: 17, height: 17)
                    .background(Color.green.opacity(0.85), in: Circle())
                    .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topTrailing)
                    .padding(5)
            }
        }
        .aspectRatio(1, contentMode: .fit)
        .clipShape(RoundedRectangle(cornerRadius: 11))
        .overlay(RoundedRectangle(cornerRadius: 11).stroke(Theme.hair2, lineWidth: 1))
    }

    private var palette: [Color] {
        let sets: [[Color]] = [
            [.blue.opacity(0.35), .teal.opacity(0.35)],
            [.red.opacity(0.35), .orange.opacity(0.35)],
            [.indigo.opacity(0.35), .cyan.opacity(0.35)],
            [.green.opacity(0.35), .mint.opacity(0.35)],
            [.purple.opacity(0.35), .blue.opacity(0.35)],
            [.yellow.opacity(0.35), .gray.opacity(0.35)]
        ]
        return sets[index % sets.count]
    }
}

private struct HexDumpCard: View {
    var body: some View {
        Text("""
00000000  53 51 4c 69 74 65 20 66  6f 72 6d 61 74 20 33 00  SQLite format 3.
00000010  10 00 01 01 00 40 20 20  00 00 0e 21 00 00 00 48  .....@  ...!...H
00000050  0d 0f 38 00 0a 01 7b 01  6d 6f 76 65 64 20 74 68  ..8...{.moved th
00000060  65 20 66 75 6e 64 73 2c  20 61 63 63 6f 75 6e 74  e funds, account
00000070  20 69 73 20 63 6c 65 61  6e 20 6e 6f 77 00 00 00   is clean now...
""")
        .font(.system(size: 11, design: .monospaced))
        .foregroundStyle(Color(red: 0x9F/255, green: 0xB3/255, blue: 0xA6/255))
        .padding(12)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Color(red: 0x0A/255, green: 0x0D/255, blue: 0x0C/255), in: RoundedRectangle(cornerRadius: 12))
        .overlay(RoundedRectangle(cornerRadius: 12).stroke(Color.green.opacity(0.12), lineWidth: 1))
    }
}

private struct SQLitePreviewCard: View {
    var body: some View {
        Grid(alignment: .leadingFirstTextBaseline, horizontalSpacing: 16, verticalSpacing: 8) {
            GridRow {
                header("ROWID"); header("text"); header("date"); header("service")
            }
            row("4471", "You still good for tonight?", "2026-06-08 19:31", "SMS")
            row("4472", "moved the funds, account is clean now", "2026-06-08 21:04", "iMessage", highlight: true)
            row("4473", "delete this chat after", "2026-06-08 21:06", "SMS")
        }
        .font(.system(size: 11, design: .monospaced))
        .padding(12)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Theme.card, in: RoundedRectangle(cornerRadius: 12))
        .overlay(RoundedRectangle(cornerRadius: 12).stroke(Theme.hair2, lineWidth: 1))
    }

    private func header(_ text: String) -> some View {
        Text(text).foregroundStyle(Theme.text2)
    }

    private func row(_ a: String, _ b: String, _ c: String, _ d: String, highlight: Bool = false) -> some View {
        GridRow {
            Text(a)
            Text(b).foregroundStyle(highlight ? Theme.teal2 : Theme.text2)
            Text(c)
            Text(d)
        }
        .foregroundStyle(Theme.text2)
    }
}

private struct FindingSelectionRow: View {
    let row: ReportFindingRow
    let selected: Bool
    let toggle: () -> Void

    var body: some View {
        HStack(alignment: .top, spacing: 10) {
            Rectangle()
                .fill(row.color)
                .frame(width: 3)
            VStack(alignment: .leading, spacing: 7) {
                HStack(alignment: .top) {
                    VStack(alignment: .leading, spacing: 3) {
                        Text(row.title)
                            .font(.system(size: 13.5, weight: .semibold))
                        Text(row.source)
                            .font(.system(size: 10, design: .monospaced))
                            .foregroundStyle(Theme.text3)
                    }
                    Spacer()
                    Button(action: toggle) {
                        Image(systemName: selected ? "checkmark.square.fill" : "square")
                            .foregroundStyle(selected ? Theme.teal2 : Theme.text3)
                    }
                    .buttonStyle(.plain)
                }
                Text(row.note)
                    .font(.system(size: 12))
                    .foregroundStyle(Theme.text2)
                HStack {
                    ForEach(row.tags, id: \.self) { tag in
                        Text(tag)
                            .font(.system(size: 10, weight: .medium, design: .monospaced))
                            .padding(.horizontal, 7)
                            .padding(.vertical, 3)
                            .foregroundStyle(row.color)
                            .background(row.color.opacity(0.08), in: RoundedRectangle(cornerRadius: 7))
                    }
                }
            }
            .padding(.vertical, 10)
            .padding(.trailing, 12)
        }
        .background(Theme.card, in: RoundedRectangle(cornerRadius: 13))
        .overlay(RoundedRectangle(cornerRadius: 13).stroke(Theme.hair2, lineWidth: 1))
    }
}

private struct CustodyPaper: View {
    let caseName: String
    let evidenceName: String
    let custodyCount: Int
    let hashStatus: String

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            VStack(spacing: 5) {
                Text("FIAU Malta - Financial Intelligence Analysis Unit")
                    .font(.system(size: 11, weight: .medium))
                    .tracking(1)
                    .foregroundStyle(Color(red: 0x5A/255, green: 0x5E/255, blue: 0x66/255))
                Text("Chain of Custody Record")
                    .font(.system(size: 20, weight: .semibold, design: .serif))
                Text("\(caseName) - \(evidenceName)")
                    .font(.system(size: 10.5, design: .monospaced))
                    .foregroundStyle(Color(red: 0x6A/255, green: 0x6E/255, blue: 0x76/255))
            }
            .frame(maxWidth: .infinity)
            Divider().background(Color.black)
            PaperSection("Exhibit")
            PaperKV(label: "Description", value: evidenceName)
            PaperKV(label: "Acquisition", value: "Physical or logical evidence source recorded in hosts.json")
            PaperKV(label: "Integrity", value: hashStatus)
            PaperSection("Custody chain")
            PaperChainRow(number: 1, title: "Collection", detail: "Initial acquisition or import", hash: "entry c6dd2686...1f4a - prev GENESIS")
            PaperChainRow(number: max(2, custodyCount), title: "Latest event", detail: "\(custodyCount) recorded custody event\(custodyCount == 1 ? "" : "s")", hash: "chain exported from Strata custody log")
            HStack(alignment: .top, spacing: 9) {
                Image(systemName: hashStatus == "verified" ? "checkmark" : "exclamationmark.triangle.fill")
                    .foregroundStyle(hashStatus == "verified" ? .green : .red)
                Text("Integrity statement. The exported record reflects the current custody log and evidence hash status.")
                    .font(.system(size: 12))
            }
            .padding(10)
            .background(Color(red: 0xE7/255, green: 0xEF/255, blue: 0xE9/255), in: RoundedRectangle(cornerRadius: 6))
        }
        .padding(26)
        .foregroundStyle(Color(red: 0x1A/255, green: 0x1C/255, blue: 0x20/255))
        .background(Color(red: 0xF4/255, green: 0xF2/255, blue: 0xEC/255), in: RoundedRectangle(cornerRadius: 8))
        .shadow(color: .black.opacity(0.35), radius: 20, y: 12)
    }
}

private struct PaperSection: View {
    let title: String
    init(_ title: String) { self.title = title }
    var body: some View {
        Text(title.uppercased())
            .font(.system(size: 11, weight: .bold))
            .tracking(0.8)
            .foregroundStyle(Color(red: 0x3A/255, green: 0x3E/255, blue: 0x46/255))
            .padding(.top, 6)
    }
}

private struct PaperKV: View {
    let label: String
    let value: String
    var body: some View {
        HStack(alignment: .top, spacing: 10) {
            Text(label).foregroundStyle(Color(red: 0x5A/255, green: 0x5E/255, blue: 0x66/255)).frame(width: 130, alignment: .leading)
            Text(value)
        }
        .font(.system(size: 13, design: .serif))
    }
}

private struct PaperChainRow: View {
    let number: Int
    let title: String
    let detail: String
    let hash: String

    var body: some View {
        VStack(alignment: .leading, spacing: 3) {
            Text("\(number) - \(title)").font(.system(size: 13, weight: .semibold, design: .serif))
            Text(detail).font(.system(size: 11.5, design: .serif)).foregroundStyle(Color(red: 0x4A/255, green: 0x4E/255, blue: 0x56/255))
            Text(hash).font(.system(size: 9.5, design: .monospaced)).foregroundStyle(Color(red: 0x6A/255, green: 0x6E/255, blue: 0x76/255))
        }
        .padding(.leading, 12)
        .overlay(alignment: .leading) {
            Rectangle().fill(Color.black).frame(width: 2)
        }
    }
}

private struct DSNote: View {
    let text: String
    init(_ text: String) { self.text = text }
    var body: some View {
        HStack(alignment: .top, spacing: 8) {
            Image(systemName: "info.circle")
                .foregroundStyle(Theme.text3)
            Text(text)
                .font(.system(size: 11, weight: .medium, design: .monospaced))
                .foregroundStyle(Theme.text3)
                .fixedSize(horizontal: false, vertical: true)
        }
    }
}

private struct MiniStrataMark: View {
    var scale: CGFloat = 1

    var body: some View {
        VStack(spacing: 3 * scale) {
            bar(width: 22 * scale, color: Theme.info)
            bar(width: 24 * scale, color: Theme.teal2)
            bar(width: 18 * scale, color: Color(red: 0x8D/255, green: 0x8C/255, blue: 0xF2/255))
            bar(width: 16 * scale, color: Theme.amber)
        }
        .frame(width: 29 * scale, height: 29 * scale)
    }

    private func bar(width: CGFloat, color: Color) -> some View {
        RoundedRectangle(cornerRadius: 1.4 * scale)
            .fill(color)
            .frame(width: width, height: 4 * scale)
    }
}

private extension View {
    func dsCard() -> some View {
        self
            .padding(15)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(LinearGradient(colors: [Theme.bg2, Theme.card], startPoint: .top, endPoint: .bottom))
            .clipShape(RoundedRectangle(cornerRadius: 14))
            .overlay(RoundedRectangle(cornerRadius: 14).stroke(Theme.hair2, lineWidth: 1))
    }
}
#endif
