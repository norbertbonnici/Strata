import Foundation

/// Converts persisted YARA matches into case findings. A rule match establishes
/// content similarity, not execution, so the finding deliberately carries no
/// inferred ATT&CK technique or timestamp.
public nonisolated struct YaraAnalyzer: Analyzer {
    public let name = "YARA Rule Match"

    public init() {}

    public func analyze(context: AnalysisContext) -> [Finding] {
        Dictionary(grouping: context.yaraMatches, by: \.rule).map { rule, matches in
            let paths = matches.map(\.path).sorted()
            let preview = paths.prefix(20).joined(separator: "\n")
            let omitted = max(0, paths.count - 20)
            let suffix = omitted == 0 ? "" : "\n…and \(omitted) more"
            return Finding(
                title: "YARA match: \(rule)",
                detail: "Rule \(rule) matched \(matches.count) file\(matches.count == 1 ? "" : "s"). A YARA match identifies content; corroborate execution and intent with other artifacts.\n\(preview)\(suffix)",
                severity: .high,
                phase: .delivery,
                evidencePaths: paths)
        }
    }
}
