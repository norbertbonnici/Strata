import Foundation

/// Detection over the macOS **Mail** `Envelope Index`. The index carries no
/// message body, so this stays deliberately high-precision over what it *does*
/// have — sender, subject, mailbox — and flags **inbound** mail that looks like a
/// delivery vector: a **raw-IP sender domain** (anomalous for legitimate mail) or
/// a **suspicious link in the subject line** (paste / shortener / raw-IP / known
/// tooling). Aggregated per sender domain. Mapped to T1566.002 (Phishing:
/// Spearphishing Link). Reuses the Messages analyzer's URL/host helpers.
public nonisolated struct MacMailAnalyzer: Analyzer {
    public let name = "Mail"
    public init() {}

    public func analyze(context: AnalysisContext) -> [Finding] {
        analyze(context.mail)
    }

    /// Pure detection entry point — unit-tested directly with fixtures.
    public func analyze(_ mail: [MailMessageEntry]) -> [Finding] {
        guard !mail.isEmpty else { return [] }
        struct Agg { var count = 0; var last: Date?; var sample = ""; var reasons: Set<String> = []
                     var rawIP = false; var sources: Set<String> = [] }
        var byKey: [String: Agg] = [:]

        func note(_ key: String, reason: String, rawIP: Bool, _ m: MailMessageEntry) {
            var agg = byKey[key] ?? Agg()
            agg.count += 1
            agg.rawIP = agg.rawIP || rawIP
            agg.reasons.insert(reason)
            if agg.sample.isEmpty {
                agg.sample = "from \(m.sender ?? "?"): \(m.displaySubject)"
            }
            agg.sources.insert(m.sourceFile)
            if let t = m.timestamp, t > (agg.last ?? .distantPast) { agg.last = t }
            byKey[key] = agg
        }

        for m in mail {
            guard !m.isSent else { continue }   // inbound delivery is the signal
            // 1. Suspicious link in the subject line.
            if let subject = m.subject {
                for url in MacMessagesAnalyzer.urls(in: subject) {
                    guard let host = BrowserHistoryEntry.host(ofURL: url) else { continue }
                    let rawIP = MacMessagesAnalyzer.isRawIPv4(host)
                    guard rawIP || MacMessagesAnalyzer.isSuspicious(url: url, host: host) else { continue }
                    note(host, reason: "suspicious link in subject", rawIP: rawIP, m)
                }
            }
            // 2. Raw-IP sender domain.
            if let domain = Self.senderDomain(m.sender), MacMessagesAnalyzer.isRawIPv4(domain) {
                note(domain, reason: "raw-IP sender domain", rawIP: true, m)
            }
        }

        return byKey.map { (key, agg) in
            var detail = "Inbound mail involving \(key) — "
                + agg.reasons.sorted().joined(separator: ", ") + " (\(agg.count) message(s))."
            detail += "\n\nExample: \(agg.sample)"
            detail += "\n\nMail is a common phishing / second-stage delivery vector; "
                + "confirm the sender and any linked destination."
            return Finding(
                title: "Suspicious inbound mail: \(key)",
                detail: detail,
                severity: agg.rawIP ? .high : .medium,
                phase: .delivery,
                technique: AttackTechnique(attackID: "T1566.002", name: "Phishing: Spearphishing Link"),
                timestamp: agg.last,
                evidencePaths: agg.sources.sorted())
        }
    }

    /// The domain part of an email address (`user@domain` → `domain`), stripping
    /// an optional `[…]` literal wrapper.
    static func senderDomain(_ address: String?) -> String? {
        guard let address, let at = address.lastIndex(of: "@") else { return nil }
        var domain = String(address[address.index(after: at)...])
            .trimmingCharacters(in: .whitespaces).lowercased()
        if domain.hasPrefix("["), domain.hasSuffix("]") { domain = String(domain.dropFirst().dropLast()) }
        return domain.isEmpty ? nil : domain
    }
}
