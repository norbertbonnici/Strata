import Foundation

/// Detection over macOS **Messages** (`chat.db`). Message content is mostly
/// benign, so this runs one high-precision rule: a message carrying a **link to
/// suspicious infrastructure** — a raw IP, a paste / anonymous-file-share / URL-
/// shortener / tunneling host, or known offensive tooling. A link **received**
/// by the user is a delivery / spearphishing vector (T1566.002); a link **sent**
/// is treated as user-driven (T1204.001 Malicious Link). Aggregated per host so a
/// chatty thread yields one finding per destination.
public nonisolated struct MacMessagesAnalyzer: Analyzer {
    public let name = "Messages"
    public init() {}

    static let suspiciousHostTokens = [
        "pastebin", "paste.ee", "ghostbin", "hastebin", "rentry.co", "0bin",
        "anonfiles", "mega.nz", "mediafire", "transfer.sh", "file.io", "gofile",
        "send.exploit", "ufile.io", "dropmefiles", "bit.ly", "tinyurl", "is.gd",
        "t.me", "telegra.ph", "cutt.ly", "grabify", "iplogger", "ngrok.io",
        "trycloudflare.com", "discord.com/api/webhooks",
        "mimikatz", "cobaltstrike", "metasploit", "/payload", ".onion",
    ]

    public func analyze(context: AnalysisContext) -> [Finding] {
        analyze(context.messages)
    }

    /// Pure detection entry point — unit-tested directly with fixtures.
    public func analyze(_ messages: [MessageEntry]) -> [Finding] {
        guard !messages.isEmpty else { return [] }
        struct Agg { var count = 0; var last: Date?; var sample = ""; var received = false
                     var rawIP = false; var sources: Set<String> = [] }
        var byHost: [String: Agg] = [:]

        for m in messages {
            guard let text = m.text, !text.isEmpty else { continue }
            for url in Self.urls(in: text) {
                guard let host = BrowserHistoryEntry.host(ofURL: url) else { continue }
                let rawIP = Self.isRawIPv4(host)
                guard rawIP || Self.isSuspicious(url: url, host: host) else { continue }
                var agg = byHost[host] ?? Agg()
                agg.count += 1
                agg.rawIP = agg.rawIP || rawIP
                if !m.isFromMe { agg.received = true }
                if agg.sample.isEmpty { agg.sample = "\(m.direction) — \(m.counterpart): \(m.preview)" }
                agg.sources.insert(m.sourceFile)
                if let t = m.timestamp, t > (agg.last ?? .distantPast) { agg.last = t }
                byHost[host] = agg
            }
        }

        return byHost.map { (host, agg) in
            let technique = agg.received
                ? AttackTechnique(attackID: "T1566.002", name: "Phishing: Spearphishing Link")
                : AttackTechnique(attackID: "T1204.001", name: "User Execution: Malicious Link")
            var detail = "A Messages conversation \(agg.received ? "received" : "sent") "
                + "\(agg.count) link(s) to \(host)"
            detail += agg.rawIP ? " (a raw IP address)." : "."
            detail += "\n\nExample: \(agg.sample)"
            detail += agg.received
                ? "\n\nA link delivered over Messages is a common phishing / second-stage delivery vector."
                : "\n\nConfirm what was shared and whether the destination is expected."
            return Finding(
                title: "Suspicious link in Messages: \(host)",
                detail: detail,
                severity: (agg.rawIP || agg.received) ? .high : .medium,
                phase: .delivery,
                technique: technique,
                timestamp: agg.last,
                evidencePaths: agg.sources.sorted())
        }
    }

    // MARK: - Helpers

    static func urls(in text: String) -> [String] {
        text.split(whereSeparator: { " \n\t\r<>\"'".contains($0) })
            .map { $0.trimmingCharacters(in: CharacterSet(charactersIn: "()[]{}.,;!")) }
            .filter { $0.lowercased().hasPrefix("http://") || $0.lowercased().hasPrefix("https://") }
    }

    static func isSuspicious(url: String, host: String) -> Bool {
        let lower = url.lowercased()
        return suspiciousHostTokens.contains { lower.contains($0) }
    }

    /// Dotted-quad IPv4 literal check (shared shape with the other analyzers).
    static func isRawIPv4(_ host: String) -> Bool {
        let parts = host.split(separator: ".")
        guard parts.count == 4 else { return false }
        return parts.allSatisfy { Int($0).map { (0...255).contains($0) } ?? false }
    }
}
