import Foundation

/// Detection over the macOS **LaunchServices quarantine** store
/// (`[QuarantineEvent]`) — download provenance for a macOS host.
///
/// The quarantine store records every file a quarantine-aware app pulled from
/// the network, tying a file on disk back to the application and origin URL that
/// delivered it. It is a primary **delivery** / **user-execution** source
/// (T1204 User Execution, T1105 Ingress Tool Transfer). Kept low-noise by
/// reporting only high-signal rows, aggregated so a busy store yields one
/// finding per indicator:
///  1. **Risky download from suspicious origin** — an executable / installer /
///     archive / disk-image (`.dmg`/`.pkg`/`.app`/`.zip`/`.sh`/…) downloaded
///     from a raw-IP, paste-site, anonymous-share, tunneling, or suspicious-TLD
///     origin (T1105).
///  2. **Download by a non-browser agent** — a file written by `curl`/`wget`/
///     `osascript`/`python` rather than a browser or a trusted app store, the
///     signature of scripted, hands-on-keyboard delivery (T1204).
///
/// **Integration note.** `AnalysisContext` does not yet carry quarantine
/// events, so `analyze(context:)` returns `[]`; the integrator wires the field
/// in later. The detection logic lives in `analyze(_:)`, exercised directly by
/// the unit tests against fixtures.
public nonisolated struct MacQuarantineAnalyzer: Analyzer {
    public let name = "macOS Quarantine"
    public init() {}

    /// Risky file extensions when *downloaded* to a macOS host: executables,
    /// installers, mountable images, scripts, and archives that commonly carry a
    /// second-stage payload.
    static let riskyExtensions: Set<String> = [
        // macOS-native executables / installers / images
        "dmg", "pkg", "mpkg", "app", "command",
        // scripts
        "sh", "bash", "zsh", "py", "pl", "rb", "scpt", "applescript", "jxa",
        // cross-platform / dual-use payloads also seen on macOS
        "jar", "class",
        // archives (frequent payload wrappers)
        "zip", "tar", "gz", "tgz", "bz2", "xz", "7z", "rar", "iso",
    ]

    /// Host substrings for paste sites, anonymous file-drops, tunnelers,
    /// dynamic DNS, and chat-CDN payload hosts commonly used for delivery.
    static let suspiciousHosts: [String] = [
        "pastebin.com", "hastebin", "ghostbin", "privatebin", "rentry.co", "controlc.com",
        "termbin.com", "ix.io", "sprunge.us", "dpaste", "0bin",
        "anonfiles", "bayfiles", "gofile.io", "file.io", "filebin", "transfer.sh",
        "temp.sh", "ufile.io", "dropmefiles", "bashupload.com",
        "oshi.at", "0x0.st", "x0.at", "catbox.moe", "litterbox", "mega.nz", "mega.io",
        "mediafire", "wetransfer.com", "uploadfiles",
        "ngrok.io", "ngrok-free.app", "trycloudflare.com", "serveo.net", "portmap.io",
        "duckdns.org", "no-ip", "hopto.org", "cdn.discordapp.com", "discordapp.com/attachments",
    ]

    /// Suspicious top-level domains over-represented in malware delivery.
    static let suspiciousTLDs: [String] = [
        ".xyz", ".top", ".tk", ".ml", ".ga", ".cf", ".gq", ".click", ".link",
        ".zip", ".mov", ".country", ".kim", ".work", ".rest", ".fit", ".loan",
    ]

    /// Agent names that are NOT interactive browsers / trusted clients — a
    /// download attributed to one of these means a script or operator pulled
    /// the file, not a user clicking a link.
    static let nonBrowserAgents: [String] = [
        "curl", "wget", "osascript", "python", "python3", "ruby", "perl",
        "powershell", "pwsh", "node", "java", "swift", "bash", "sh", "zsh",
        "ncat", "nc", "socat", "scp", "sftp",
    ]

    /// Agent-name substrings recognised as legitimate browsers / managed
    /// clients — used to *exclude* benign rows from the non-browser rule.
    static let knownBrowserAgents: [String] = [
        "safari", "chrome", "chromium", "firefox", "edge", "brave", "opera",
        "vivaldi", "tor browser", "mail", "messages", "slack", "thunderbird",
        "app store", "appstore", "softwareupdate", "installer", "music",
        "podcasts", "tv", "books", "finder", "telegram", "whatsapp", "discord",
    ]

    public func analyze(context: AnalysisContext) -> [Finding] {
        // AnalysisContext carries no quarantine events yet — the integrator
        // wires the field in later. Detection logic lives in `analyze(_:)`.
        []
    }

    /// The real detection entry point: pure function over parsed quarantine
    /// events. Unit-tested directly with fixtures.
    public func analyze(_ events: [QuarantineEvent]) -> [Finding] {
        guard !events.isEmpty else { return [] }
        var findings: [Finding] = []
        findings += suspiciousOriginFindings(events)
        findings += nonBrowserAgentFindings(events)
        return findings
    }

    // MARK: - Rule 1: risky download from suspicious origin

    private struct OriginAgg {
        var count = 0; var last: Date?; var sampleData = ""; var sampleOrigin = ""
        var agent = ""; var source = ""; var ext = ""
        var reasons: Set<String> = []
    }

    private func suspiciousOriginFindings(_ events: [QuarantineEvent]) -> [Finding] {
        var byHost: [String: OriginAgg] = [:]
        for e in events {
            // The "where it came from" host is the data URL's host, falling back
            // to the origin/referrer host.
            guard let host = e.dataHost ?? e.originHost else { continue }
            let ext = Self.fileExtension(of: e.dataLeaf ?? e.dataURL ?? "") ?? ""
            guard Self.riskyExtensions.contains(ext) else { continue }

            var reasons: Set<String> = []
            // Evaluate suspiciousness against both the data host and the origin
            // host (the payload may sit on a CDN while the lure page is elsewhere).
            for h in [e.dataHost, e.originHost].compactMap({ $0 }) {
                if Self.isRawIPv4(h) { reasons.insert("raw IP address") }
                if Self.isSuspiciousHost(h) { reasons.insert("paste / anonymous-sharing / tunneling host") }
                if Self.hasSuspiciousTLD(h) { reasons.insert("suspicious top-level domain") }
            }
            guard !reasons.isEmpty else { continue }

            var agg = byHost[host] ?? OriginAgg()
            agg.count += 1
            agg.reasons.formUnion(reasons)
            if agg.sampleData.isEmpty { agg.sampleData = e.dataURL ?? "" }
            if agg.sampleOrigin.isEmpty { agg.sampleOrigin = e.originURL ?? "" }
            if agg.agent.isEmpty { agg.agent = e.agentName ?? "" }
            agg.source = e.sourceFile
            agg.ext = ext
            if let t = e.timestamp, t > (agg.last ?? .distantPast) { agg.last = t }
            byHost[host] = agg
        }
        return byHost.map { (host, agg) in
            let reasonText = agg.reasons.sorted().joined(separator: ", ")
            var detail = "Downloaded a .\(agg.ext.uppercased()) file from \(host) — \(reasonText)."
            if !agg.sampleData.isEmpty { detail += "\nFile: \(agg.sampleData)" }
            if !agg.sampleOrigin.isEmpty { detail += "\nReferrer: \(agg.sampleOrigin)" }
            if !agg.agent.isEmpty { detail += "\nDownloaded by: \(agg.agent)" }
            if agg.count > 1 { detail += "\nSeen \(agg.count) times." }
            detail += "\nVerify the file's provenance and detonation."
            return Finding(
                title: "Risky quarantined download from suspicious origin: \(host)",
                detail: detail,
                severity: .high,
                phase: .delivery,
                technique: AttackTechnique(attackID: "T1105", name: "Ingress Tool Transfer"),
                timestamp: agg.last,
                evidencePaths: [agg.sampleData, agg.sampleOrigin, agg.source].filter { !$0.isEmpty })
        }
    }

    // MARK: - Rule 2: download by a non-browser agent

    private struct AgentAgg {
        var count = 0; var last: Date?; var sampleData = ""; var source = ""
        var matchedAgent = ""
    }

    private func nonBrowserAgentFindings(_ events: [QuarantineEvent]) -> [Finding] {
        var byAgent: [String: AgentAgg] = [:]
        for e in events {
            guard let agent = e.agentName, !agent.isEmpty else { continue }
            let lower = agent.lowercased()
            // Skip anything that looks like a known browser / trusted client.
            guard !Self.knownBrowserAgents.contains(where: { lower.contains($0) }) else { continue }
            guard let matched = Self.nonBrowserAgents.first(where: { Self.agentMatches(lower, $0) }) else { continue }
            var agg = byAgent[matched] ?? AgentAgg()
            agg.count += 1
            agg.matchedAgent = agent
            if agg.sampleData.isEmpty { agg.sampleData = e.dataURL ?? e.originURL ?? "" }
            agg.source = e.sourceFile
            if let t = e.timestamp, t > (agg.last ?? .distantPast) { agg.last = t }
            byAgent[matched] = agg
        }
        return byAgent.map { (_, agg) in
            var detail = "A file was downloaded by '\(agg.matchedAgent)', a command-line / scripting tool rather than an interactive browser — typical of scripted, hands-on-keyboard delivery."
            if !agg.sampleData.isEmpty { detail += "\nExample: \(agg.sampleData)" }
            if agg.count > 1 { detail += "\nSeen \(agg.count) times." }
            return Finding(
                title: "Quarantined download by non-browser agent: \(agg.matchedAgent)",
                detail: detail,
                severity: .high,
                phase: .delivery,
                technique: AttackTechnique(attackID: "T1204", name: "User Execution"),
                timestamp: agg.last,
                evidencePaths: [agg.sampleData, agg.source].filter { !$0.isEmpty })
        }
    }

    // MARK: - Helpers

    static func isSuspiciousHost(_ host: String) -> Bool {
        suspiciousHosts.contains { host.contains($0) }
    }

    static func hasSuspiciousTLD(_ host: String) -> Bool {
        suspiciousTLDs.contains { host.hasSuffix($0) }
    }

    /// True for a bare IPv4 literal host (four dotted 0–255 octets).
    static func isRawIPv4(_ host: String) -> Bool {
        let parts = host.split(separator: ".", omittingEmptySubsequences: false)
        guard parts.count == 4 else { return false }
        return parts.allSatisfy { p in
            guard !p.isEmpty, p.allSatisfy(\.isNumber), let n = Int(p) else { return false }
            return n >= 0 && n <= 255
        }
    }

    /// Match an agent name against a tool token: exact word, or the name with a
    /// version suffix / path. Guards against substring false positives (e.g.
    /// "node" inside "Anode-Browser") by requiring a word boundary.
    static func agentMatches(_ agentLower: String, _ token: String) -> Bool {
        if agentLower == token { return true }
        // "curl 8.1.2", "/usr/bin/wget", "python3.11" → leading word is the tool.
        let firstWord = agentLower.split(whereSeparator: { $0 == " " || $0 == "/" }).first.map(String.init) ?? agentLower
        if firstWord == token { return true }
        // version-suffixed leaf: "python3" already in the token list, but catch
        // "wget1" / "curl7" style names too.
        if firstWord.hasPrefix(token),
           let after = firstWord.dropFirst(token.count).first,
           after.isNumber || after == "." || after == "-" {
            return true
        }
        return false
    }

    /// Lowercased file extension of a leaf name (no dot), or nil.
    static func fileExtension(of name: String) -> String? {
        // Strip any query/fragment first, then any trailing slash.
        let stripped = name.split(separator: "?").first.map(String.init) ?? name
        let leaf = stripped.split(whereSeparator: { $0 == "/" || $0 == "\\" }).last.map(String.init) ?? stripped
        guard let dot = leaf.lastIndex(of: "."), dot != leaf.startIndex else { return nil }
        let ext = leaf[leaf.index(after: dot)...].lowercased()
        return ext.isEmpty ? nil : ext
    }
}
