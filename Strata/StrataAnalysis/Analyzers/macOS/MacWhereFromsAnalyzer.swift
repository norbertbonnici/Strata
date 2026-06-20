import Foundation

/// Detection over the **download provenance** recovered from
/// `kMDItemWhereFroms` xattrs. Most downloads are benign, so this flags only
/// high-signal origins: a file downloaded **directly from a raw IP** (no domain
/// — typical of attacker infrastructure / tool transfer, T1105) or from a
/// **paste / anonymous-file-share / tunneling** service often used to stage
/// payloads (T1102).
public nonisolated struct MacWhereFromsAnalyzer: Analyzer {
    public let name = "Download Origins"
    public init() {}

    /// Hosts for paste / anon-share / tunnel services, matched on host
    /// boundaries (exact or a subdomain) — never as raw substrings.
    static let suspiciousHosts = [
        "pastebin.com", "paste.ee", "hastebin.com", "ghostbin.com", "rentry.co",
        "transfer.sh", "anonfiles.com", "gofile.io", "file.io", "tmpfiles.org",
        "ngrok.io", "ngrok-free.app", "trycloudflare.com", "cdn.discordapp.com",
        "t.me", "telegram.org", "0x0.st", "bashupload.com",
    ]

    public func analyze(context: AnalysisContext) -> [Finding] {
        analyze(context.whereFroms)
    }

    /// Pure entry point (unit-tested with fixtures).
    public func analyze(_ entries: [MacWhereFrom]) -> [Finding] {
        guard !entries.isEmpty else { return [] }
        var findings: [Finding] = []
        var seen = Set<String>()

        for e in entries {
            guard let url = e.downloadURL, let host = e.downloadHost else { continue }

            if Self.isRawIPHost(host) {
                guard seen.insert("ip|\(e.path)|\(host)").inserted else { continue }
                // A public raw IP is the strong signal; an internal/private IP is
                // commonly a corporate mirror, so downgrade it.
                let priv = Self.isPrivateOrLocalIPv4(host)
                findings.append(Finding(
                    title: "File downloaded from a raw IP address: \(e.fileName)",
                    detail: "'\(e.fileName)' was downloaded from \(url) — a bare IP host with no domain"
                        + (priv ? " (an internal/private address — likely a mirror or file server, but "
                                  + "confirm against the quarantine store and execution artifacts)."
                                : ", characteristic of attacker infrastructure / direct tool transfer. "
                                  + "Correlate with the quarantine store and execution artifacts."),
                    severity: priv ? .medium : .high, phase: .delivery,
                    technique: AttackTechnique(attackID: "T1105", name: "Ingress Tool Transfer"),
                    timestamp: nil, evidencePaths: [e.path]))
            } else if let hit = Self.suspiciousHosts.first(where: { Self.hostMatches(host, $0) }) {
                guard seen.insert("host|\(e.path)|\(hit)").inserted else { continue }
                findings.append(Finding(
                    title: "File downloaded from a paste/anon-share service: \(e.fileName)",
                    detail: "'\(e.fileName)' was downloaded from \(url) (\(hit)) — a service commonly used "
                        + "to stage payloads. Confirm the file's legitimacy.",
                    severity: .medium, phase: .delivery,
                    technique: AttackTechnique(attackID: "T1102", name: "Web Service"),
                    timestamp: nil, evidencePaths: [e.path]))
            }
        }
        return findings
    }

    /// True when `host` is a bare IPv4 literal (four dotted octets 0–255).
    static func isRawIPHost(_ host: String) -> Bool {
        let parts = host.split(separator: ".", omittingEmptySubsequences: false)
        guard parts.count == 4 else { return false }
        return parts.allSatisfy { p in
            guard !p.isEmpty, p.allSatisfy(\.isNumber), let n = Int(p) else { return false }
            return n >= 0 && n <= 255
        }
    }

    /// RFC1918 (10/8, 172.16/12, 192.168/16), loopback (127/8), or link-local
    /// (169.254/16) IPv4 — an internal address, not external infrastructure.
    static func isPrivateOrLocalIPv4(_ host: String) -> Bool {
        let parts = host.split(separator: ".")
        guard parts.count == 4, let a = Int(parts[0]), let b = Int(parts[1]) else { return false }
        if a == 10 || a == 127 { return true }
        if a == 169 && b == 254 { return true }
        if a == 172 && (16...31).contains(b) { return true }
        if a == 192 && b == 168 { return true }
        return false
    }

    /// True when `host` is exactly `token` or a subdomain of it — a boundary
    /// match, so `profile.io` doesn't match the `file.io` token.
    static func hostMatches(_ host: String, _ token: String) -> Bool {
        host == token || host.hasSuffix("." + token)
    }
}
