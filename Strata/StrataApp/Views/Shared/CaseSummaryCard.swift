import SwiftUI

/// Shared card that displays the AI executive summary of the case findings.
/// macOS shows a generate/regenerate control + a settings button to pick where
/// inference runs; iOS compiles that out and displays the persisted summary
/// read-only - the same viewer/ingest split the rest of the app follows.
///
/// Used on the Kill Chain and Overview tabs. Inference runs on the configured
/// sovereignty tier (on-device / Apple Private Cloud Compute / third-party
/// cloud); the glyph, help text, and a first-run confirmation make any
/// off-device run explicit, and no run leaves the host without it.
struct CaseSummaryCard: View {
    @EnvironmentObject private var model: AppModel

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack(alignment: .firstTextBaseline) {
                Label("AI Summary", systemImage: "sparkles")
                    .font(.subheadline.bold())
                Spacer()
                #if os(macOS)
                settingsButton
                generateButton
                #endif
            }

            if let summary = model.caseSummary {
                Text(summary.text)
                    .font(.callout)
                    .textSelection(.enabled)
                    .fixedSize(horizontal: false, vertical: true)
                    .frame(maxWidth: .infinity, alignment: .leading)
                // Calibrated-trust signal: how many model claims survived the
                // evidence-reference validation pass (hidden for legacy / prose
                // summaries that carry no validation report).
                if let v = summary.validation, !summary.claims.isEmpty || v.hadIssues {
                    validationChip(v)
                }
                if !summary.claims.isEmpty {
                    claimsList(summary.claims)
                }
                caption(for: summary)
            } else {
                Text(placeholder)
                    .font(.callout)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
        .padding(14)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(.quaternary.opacity(0.4), in: RoundedRectangle(cornerRadius: 10))
        .task {
            #if os(macOS)
            // Resolve the configured backend's status once (off the render path),
            // so the labels + availability below reflect on-device vs cloud.
            model.refreshInferenceConfig()
            // Warm the on-device model when the card appears so the first
            // Generate is faster (only meaningful for the sovereign backend).
            if model.summaryIsSovereign, model.caseSummary == nil, model.summaryAvailability.isAvailable {
                FindingsSummarizer.prewarm()
            }
            #endif
        }
    }

    /// Compact validation chip: claims kept + a subtle caveat when the pass
    /// dropped or flagged anything. The detail (incl. flagged paths) is in the
    /// tooltip to keep the row short. Cross-platform (no AppKit).
    private func validationChip(_ v: SummaryValidationReport) -> some View {
        HStack(spacing: 6) {
            Image(systemName: "checkmark.seal")
            Text("\(v.claimsKept) claim\(v.claimsKept == 1 ? "" : "s") validated against evidence")
            if v.hadIssues {
                Image(systemName: "exclamationmark.triangle.fill").foregroundStyle(.orange)
                Text(v.issuesSummary)
            }
        }
        .font(.caption2)
        .foregroundStyle(.secondary)
        .help(issuesDetail(v))
    }

    private func issuesDetail(_ v: SummaryValidationReport) -> String {
        var lines = ["Kept \(v.claimsKept) of \(v.claimsProposed) proposed claim(s)."]
        if v.claimsDroppedUnsupported > 0 { lines.append("\(v.claimsDroppedUnsupported) claim(s) dropped for citing no real finding.") }
        if v.phantomRefsDropped > 0 { lines.append("\(v.phantomRefsDropped) phantom citation ID(s) stripped.") }
        if !v.flaggedPathTokens.isEmpty { lines.append("Unverified path tokens: \(v.flaggedPathTokens.joined(separator: ", "))") }
        return lines.joined(separator: "\n")
    }

    /// The validated claims as compact rows (severity dot + statement + a
    /// citation). The card lives on the Overview tab (itself scrolling), so all
    /// claims lay out inline - no row cap.
    @ViewBuilder
    private func claimsList(_ claims: [SummaryClaim]) -> some View {
        VStack(alignment: .leading, spacing: 5) {
            ForEach(Array(claims.enumerated()), id: \.offset) { _, claim in
                HStack(alignment: .top, spacing: 6) {
                    Circle().fill(color(for: claim.severity))
                        .frame(width: 6, height: 6).padding(.top, 4)
                    VStack(alignment: .leading, spacing: 1) {
                        Text(claim.statement).font(.caption)
                            .fixedSize(horizontal: false, vertical: true)
                        if let first = claim.citations.first {
                            Text(claim.citations.count > 1 ? "\(first)  +\(claim.citations.count - 1)" : first)
                                .font(.caption2).foregroundStyle(.secondary)
                                .lineLimit(1).truncationMode(.middle)
                        }
                    }
                }
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }

    /// Severity → colour, defined locally so the shared card stays free of the
    /// platform-specific severity-colour helpers (macOS `Severity.color` /
    /// iOS `Theme.severityColor`).
    private func color(for severity: Severity) -> Color {
        switch severity {
        case .info:     return .gray
        case .low:      return .yellow
        case .medium:   return .orange
        case .high:     return .red
        case .critical: return .pink
        }
    }

    private func caption(for summary: CaseSummary) -> some View {
        // Glyph reflects the tier recorded ON the summary (not the live config or
        // a label sniff), so the provenance is accurate at a glance.
        HStack(spacing: 6) {
            Image(systemName: glyph(for: summary.sovereignty))
            Text("\(summary.modelLabel) · \(summary.generatedAt.formatted(date: .abbreviated, time: .shortened))")
        }
        .font(.caption2)
        .foregroundStyle(.secondary)
    }

    /// SF Symbol for a sovereignty tier — shared by the (cross-platform) summary
    /// caption and the macOS settings button.
    private func glyph(for tier: SovereigntyTier) -> String {
        switch tier {
        case .onDevice:          return "lock.shield"
        case .applePrivateCloud: return "lock.icloud"
        case .thirdPartyCloud:   return "cloud"
        }
    }

    private var placeholder: String {
        #if os(macOS)
        if case .unavailable(let reason) = model.summaryAvailability {
            return reason
        }
        switch model.summarySovereignty {
        case .onDevice:
            return "No summary yet. Generate an on-device executive summary of the case findings with Apple Intelligence."
        case .applePrivateCloud:
            return "No summary yet. Generate an executive summary via Apple Private Cloud Compute — finding summaries leave the device, but only to Apple's attested, non-retaining servers."
        case .thirdPartyCloud:
            return "No summary yet. Generate a cloud executive summary (\(model.summaryBackendLabel)) of the case findings — evidence-derived data will be sent off this Mac."
        }
        #else
        return "No AI summary has been generated for this case."
        #endif
    }

    #if os(macOS)
    /// Opens the on-device ↔ cloud settings. Always available (even mid-run /
    /// no findings) so the analyst can switch sovereignty before generating.
    private var settingsButton: some View {
        Button {
            model.activeSheet = .inferenceSettings
        } label: {
            Image(systemName: glyph(for: model.summarySovereignty))
        }
        .controlSize(.small)
        .help(tierHelp + " Click to change where the summary model runs.")
    }

    private var tierHelp: String {
        switch model.summarySovereignty {
        case .onDevice:         return "AI inference: on-device (sovereign)."
        case .applePrivateCloud: return "AI inference: Apple Private Cloud Compute (off-device, privacy-preserving)."
        case .thirdPartyCloud:  return "AI inference: \(model.summaryBackendLabel) (third-party cloud)."
        }
    }

    private var generateButton: some View {
        let availability = model.summaryAvailability
        let hasFindings = model.findingCount > 0
        let enabled = !model.isWorking && hasFindings && availability.isAvailable
        return Button {
            // Routes through the cloud-egress confirmation when the configured
            // backend would send data off-host for the first time.
            model.requestSummaryGeneration()
        } label: {
            Label(model.caseSummary == nil ? "Generate" : "Regenerate",
                  systemImage: "sparkles")
        }
        .controlSize(.small)
        .disabled(!enabled)
        .help(helpText(availability: availability, hasFindings: hasFindings))
    }

    private func helpText(availability: SummarizerAvailability, hasFindings: Bool) -> String {
        if case .unavailable(let reason) = availability { return reason }
        if !hasFindings { return "Run the analyzers first, then generate a summary." }
        switch model.summarySovereignty {
        case .onDevice:
            return "Summarize the case findings on-device with Apple Intelligence. No data leaves this Mac."
        case .applePrivateCloud:
            return "Summarize the case findings via Apple Private Cloud Compute. Finding summaries (titles, details, paths) are sent to Apple's attested, non-retaining servers; raw evidence never leaves this Mac."
        case .thirdPartyCloud:
            return "Summarize the case findings using \(model.summaryBackendLabel). Evidence-derived data (finding summaries — titles, details, paths) will be sent off this Mac to the configured cloud model."
        }
    }
    #endif
}
