import Foundation

/// Detection over the macOS **Powerlog** activity store. Powerlog records true
/// process-execution timing (process/bundle names + PIDs powerd observed, app
/// launch/exit, frontmost app, per-process network), surviving independently of
/// the unified log — so it catches **headless/background** offensive tooling
/// that never comes to the foreground (where KnowledgeC, which only sees GUI
/// focus, would miss it).
///
/// To stay low-noise (most app/process activity is benign), detections are gated
/// on curated offensive-tool / RMM / LOLBin name lists and **aggregated per tool**
/// (one finding per matched binary, not per launch), like `KnowledgeCAnalyzer`
/// and `SrumAnalyzer`.
public nonisolated struct PowerlogAnalyzer: Analyzer {
    public let name = "Powerlog"
    public init() {}

    /// Distinctive offensive / pentest / dual-use tool name fragments (substring
    /// match on process or bundle name). Only tokens that are *unlikely to be a
    /// substring of a benign* macOS process/bundle name belong here — generic
    /// English words and names that collide with real apps go in `offensiveExecs`
    /// (exact basename) instead. (No space-containing tokens: process/bundle
    /// names never contain spaces, so they'd be inert.)
    static let offensiveTokens = [
        "mimikatz", "cobaltstrike", "meterpreter", "metasploit", "msfvenom",
        "msfconsole", "powersploit", "bruteratel", "swiftbelt", "keylogger",
        "impacket", "bettercap", "ngrok", "frpc", "frps", "masscan", "nmap",
        "hashcat", "johntheripper", "sqlmap", "gophish", "starkiller",
    ]

    /// Short / generic-word / app-colliding tool names matched on **basename
    /// equality** — a substring match on these would false-positive (e.g. "nc"
    /// matches everything; "responder" matches the core `mDNSResponder` daemon;
    /// "chisel" matches Facebook's LLDB toolset). These are CLI binaries matched
    /// by exact process basename.
    static let offensiveExecs: Set<String> = [
        "nc", "ncat", "socat", "hydra", "medusa", "ncrack", "proxychains",
        "responder", "chisel", "empire", "sliver", "havoc",
    ]

    public func analyze(context: AnalysisContext) -> [Finding] {
        analyze(context.powerlog)
    }

    /// Pure entry point (unit-tested with fixtures).
    public func analyze(_ entries: [PowerlogEntry]) -> [Finding] {
        guard !entries.isEmpty else { return [] }

        struct Agg { var count = 0; var first: Date?; var last: Date?; var haystack = Set<String>() }
        var bySubject: [String: Agg] = [:]

        for e in entries {
            let name = e.processName?.lowercased()
            let bundle = e.bundleID?.lowercased()
            // Prefer the bundle id as the canonical key so a tool seen by name in
            // one record and by bundle in another (e.g. a .process row with a
            // ProcessName + bundle vs a .frontmost row with only the bundle) folds
            // into one finding instead of splitting.
            guard let key = (bundle?.isEmpty == false ? bundle : name), !key.isEmpty else { continue }
            var agg = bySubject[key] ?? Agg()
            agg.count += 1
            if let n = name { agg.haystack.insert(n) }
            if let b = bundle { agg.haystack.insert(b) }
            if let t = e.date {
                if agg.first == nil || t < agg.first! { agg.first = t }
                if agg.last == nil || t > agg.last! { agg.last = t }
            }
            bySubject[key] = agg
        }

        var findings: [Finding] = []
        for (key, agg) in bySubject {
            let hay = agg.haystack
            let basenames = Set(hay.map { ($0 as NSString).lastPathComponent })
            // Prefer a human-readable process name (no dots) over a bundle-id key
            // for display, deterministically.
            let subject = hay.sorted().first(where: { !$0.contains(".") }) ?? key
            let span = (agg.first != nil && agg.last != nil)
                ? " between \(Self.fmt(agg.first!)) and \(Self.fmt(agg.last!))"
                : (agg.last != nil ? " at \(Self.fmt(agg.last!))" : "")

            if Self.offensiveTokens.contains(where: { tok in hay.contains(where: { $0.contains(tok) }) })
                || !basenames.isDisjoint(with: Self.offensiveExecs) {
                findings.append(Finding(
                    title: "Offensive tool executed (Powerlog): \(subject)",
                    detail: "Powerlog observed \(subject) running \(agg.count) time(s)\(span). "
                        + "The name matches a known offensive / pentest / dual-use tool. Powerlog "
                        + "records process execution even for headless tools — correlate with "
                        + "quarantine, FSEvents, and the unified log.",
                    severity: .high, phase: .exploitation,
                    technique: AttackTechnique(attackID: "T1059", name: "Command and Scripting Interpreter"),
                    timestamp: agg.last, evidencePaths: ["CurrentPowerlog.PLSQL"]))
            } else if KnowledgeCAnalyzer.remoteAccessHints.contains(where: { hint in hay.contains(where: { $0.contains(hint) }) }) {
                findings.append(Finding(
                    title: "Remote-access app executed (Powerlog): \(subject)",
                    detail: "Powerlog observed \(subject) running \(agg.count) time(s)\(span). "
                        + "This is remote-control / RMM software; Powerlog catches its background "
                        + "helper process even when it never takes GUI focus. Confirm whether this "
                        + "remote access was expected.",
                    severity: .high, phase: .commandAndControl,
                    technique: AttackTechnique(attackID: "T1219", name: "Remote Access Software"),
                    timestamp: agg.last, evidencePaths: ["CurrentPowerlog.PLSQL"]))
            } else if basenames.contains("osascript") || hay.contains(where: { $0.contains("osascript") }) {
                findings.append(Finding(
                    title: "AppleScript/JXA execution (Powerlog): osascript",
                    detail: "Powerlog observed osascript running \(agg.count) time(s)\(span). "
                        + "osascript runs AppleScript / JavaScript-for-Automation and is a common "
                        + "macOS living-off-the-land execution vector. Benign automation also uses "
                        + "it — corroborate with the unified log and the command that ran.",
                    severity: .medium, phase: .exploitation,
                    technique: AttackTechnique(attackID: "T1059.002", name: "AppleScript"),
                    timestamp: agg.last, evidencePaths: ["CurrentPowerlog.PLSQL"]))
            }
        }
        return findings.sorted { ($0.timestamp ?? .distantPast) > ($1.timestamp ?? .distantPast) }
    }

    private static func fmt(_ d: Date) -> String {
        d.formatted(date: .abbreviated, time: .standard)
    }
}
