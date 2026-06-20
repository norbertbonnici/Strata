import Foundation

/// Detection over parsed web-browser history (Chromium `History` + Firefox
/// `places.sqlite`).
///
/// Browser history is a primary **delivery**-stage source: it shows what was
/// navigated to and pulled down. Kept low-noise by reporting only high-signal
/// activity, aggregated so a busy history yields one finding per indicator:
///  1. **Suspicious download** — a saved file with an executable/script/archive
///     extension, or any file pulled from a paste / anonymous-sharing / tunnel
///     host or a raw IP (T1105 Ingress Tool Transfer).
///  2. **Activity to suspicious infrastructure** — visits or downloads whose host
///     is a known paste / file-drop / tunneling service, dynamic DNS, or a raw
///     IP address (T1102 Web Service).
///  3. **Offensive-tooling indicator** — a URL or download target naming a known
///     attack tool (mimikatz, Cobalt Strike, PsExec, Rubeus, …)
///     (T1588.002 Obtain Capabilities: Tool).
public nonisolated struct BrowserHistoryAnalyzer: Analyzer {
    public let name = "Browser History"
    public init() {}

    /// Extensions that should raise an eyebrow when *downloaded* via a browser.
    private static let execExtensions: Set<String> = [
        "exe", "dll", "scr", "ps1", "bat", "cmd", "vbs", "vbe", "js", "jse",
        "wsf", "wsh", "hta", "msi", "msp", "cpl", "jar", "lnk", "pif", "com",
    ]
    private static let archiveExtensions: Set<String> = [
        "zip", "rar", "7z", "cab", "gz", "tar", "iso", "img", "vhd", "vhdx", "ace", "arj",
    ]

    /// Host substrings for paste sites, anonymous file-drops, tunnelers, dynamic
    /// DNS, and chat-CDN payload hosts commonly used for second-stage delivery
    /// and exfiltration.
    private static let suspiciousHosts: [String] = [
        "pastebin.com", "hastebin", "ghostbin", "privatebin", "rentry.co", "controlc.com",
        "termbin.com", "ix.io", "sprunge.us", "dpaste", "0bin",
        "anonfiles", "bayfiles", "gofile.io", "file.io", "filebin", "transfer.sh",
        "temp.sh", "ufile.io", "dropmefiles", "send.exploit.in", "bashupload.com",
        "oshi.at", "0x0.st", "x0.at", "catbox.moe", "litterbox", "mega.nz", "mega.io",
        "mediafire", "wetransfer.com", "uploadfiles",
        "ngrok.io", "ngrok-free.app", "trycloudflare.com", "serveo.net", "portmap.io",
        "duckdns.org", "no-ip", "hopto.org", "cdn.discordapp.com", "discordapp.com/attachments",
    ]

    /// Tool-name substrings that, in a URL or download target, indicate
    /// offensive-tooling acquisition.
    private static let offensiveTools: [String] = [
        "mimikatz", "cobaltstrike", "cobalt-strike", "psexec", "procdump", "lazagne",
        "rubeus", "sharphound", "bloodhound", "winpeas", "linpeas", "seatbelt",
        "powersploit", "powerview", "nishang", "htran", "chisel", "frpc", "frps",
        "rclone", "megasync", "advanced_port_scanner", "advanced_ip_scanner",
    ]

    public func analyze(context: AnalysisContext) -> [Finding] {
        let entries = context.browserHistory
        guard !entries.isEmpty else { return [] }
        var findings: [Finding] = []
        findings += downloadFindings(entries)
        findings += suspiciousHostFindings(entries)
        findings += toolFindings(entries)
        return findings
    }

    // MARK: - Rule 1: suspicious download

    private struct DLAgg {
        var count = 0; var last: Date?; var url = ""; var target = ""
        var source = ""; var ext = ""; var suspiciousHost = false
    }

    private func downloadFindings(_ entries: [BrowserHistoryEntry]) -> [Finding] {
        var byTarget: [String: DLAgg] = [:]
        for e in entries where e.kind == .download {
            let ext = Self.fileExtension(of: e.targetLeaf ?? e.url) ?? ""
            let badExt = Self.execExtensions.contains(ext) || Self.archiveExtensions.contains(ext)
            let badHost = e.host.map(Self.isSuspiciousHost) ?? false
            guard badExt || badHost else { continue }
            let key = (e.targetPath ?? e.url).lowercased()
            var agg = byTarget[key] ?? DLAgg()
            agg.count += 1
            agg.url = e.url
            agg.target = e.targetPath ?? ""
            agg.source = e.sourceFile
            agg.ext = ext
            agg.suspiciousHost = agg.suspiciousHost || badHost
            if let t = e.timestamp, t > (agg.last ?? .distantPast) { agg.last = t }
            byTarget[key] = agg
        }
        return byTarget.values.map { agg in
            let severity: Severity = (Self.execExtensions.contains(agg.ext) || agg.suspiciousHost)
                ? .high : .medium
            let leaf = Self.leaf(agg.target.isEmpty ? agg.url : agg.target)
            var detail = "Downloaded \(leaf) from \(agg.url)."
            if !agg.target.isEmpty { detail += "\nSaved to \(agg.target)." }
            if agg.suspiciousHost {
                detail += "\nSource host is a known paste / anonymous-sharing / tunneling service or a raw IP — a common second-stage delivery channel."
            } else {
                detail += "\nA browser-delivered \(agg.ext.uppercased()) file — verify provenance and detonation."
            }
            if agg.count > 1 { detail += "\nSeen \(agg.count) times." }
            return Finding(
                title: "Suspicious browser download: \(leaf)",
                detail: detail,
                severity: severity,
                phase: .delivery,
                technique: AttackTechnique(attackID: "T1105", name: "Ingress Tool Transfer"),
                timestamp: agg.last,
                evidencePaths: [agg.url, agg.target, agg.source].filter { !$0.isEmpty })
        }
    }

    // MARK: - Rule 2: activity to suspicious infrastructure

    private struct HostAgg {
        var visits = 0; var downloads = 0; var last: Date?
        var sampleURL = ""; var source = ""; var rawIP = false
    }

    private func suspiciousHostFindings(_ entries: [BrowserHistoryEntry]) -> [Finding] {
        var byHost: [String: HostAgg] = [:]
        for e in entries {
            guard let host = e.host else { continue }
            let rawIP = Self.isRawIPv4(host)
            guard rawIP || Self.isSuspiciousHost(host) else { continue }
            var agg = byHost[host] ?? HostAgg()
            if e.kind == .download { agg.downloads += 1 } else { agg.visits += 1 }
            agg.rawIP = rawIP
            if agg.sampleURL.isEmpty { agg.sampleURL = e.url }
            agg.source = e.sourceFile
            if let t = e.timestamp, t > (agg.last ?? .distantPast) { agg.last = t }
            byHost[host] = agg
        }
        return byHost.map { (host, agg) in
            let severity: Severity = agg.downloads > 0 ? .high : .medium
            let kindNote = agg.rawIP
                ? "a raw IP address (no domain name) — typical of hands-on-keyboard C2 / staging"
                : "a known paste / anonymous file-sharing / tunneling host — common for second-stage delivery and exfiltration"
            var counts: [String] = []
            if agg.visits > 0 { counts.append("\(agg.visits) visit\(agg.visits == 1 ? "" : "s")") }
            if agg.downloads > 0 { counts.append("\(agg.downloads) download\(agg.downloads == 1 ? "" : "s")") }
            let detail = "\(counts.joined(separator: ", ")) to \(host) — \(kindNote)."
                + "\nExample: \(agg.sampleURL)"
                + (agg.last.map { "\nLast \($0.ISO8601Format())." } ?? "")
            return Finding(
                title: "Browser activity to suspicious host: \(host)",
                detail: detail,
                severity: severity,
                phase: .commandAndControl,
                technique: AttackTechnique(attackID: "T1102", name: "Web Service"),
                timestamp: agg.last,
                evidencePaths: [agg.sampleURL, agg.source].filter { !$0.isEmpty })
        }
    }

    // MARK: - Rule 3: offensive-tooling indicator

    private struct ToolAgg { var count = 0; var last: Date?; var sample = ""; var source = "" }

    private func toolFindings(_ entries: [BrowserHistoryEntry]) -> [Finding] {
        var byTool: [String: ToolAgg] = [:]
        for e in entries {
            let haystack = (e.url + " " + (e.targetLeaf ?? "")).lowercased()
            guard let tool = Self.offensiveTools.first(where: { haystack.contains($0) }) else { continue }
            var agg = byTool[tool] ?? ToolAgg()
            agg.count += 1
            if agg.sample.isEmpty { agg.sample = e.targetPath ?? e.url }
            agg.source = e.sourceFile
            if let t = e.timestamp, t > (agg.last ?? .distantPast) { agg.last = t }
            byTool[tool] = agg
        }
        return byTool.map { (tool, agg) in
            Finding(
                title: "Offensive tool referenced in browser history: \(tool)",
                detail: "A browser URL or download target references \(tool), a known offensive-security tool."
                    + "\nExample: \(agg.sample)"
                    + (agg.count > 1 ? "\nSeen \(agg.count) times." : "")
                    + (agg.last.map { "\nLast \($0.ISO8601Format())." } ?? ""),
                severity: .high,
                phase: .weaponization,
                technique: AttackTechnique(attackID: "T1588.002", name: "Obtain Capabilities: Tool"),
                timestamp: agg.last,
                evidencePaths: [agg.sample, agg.source].filter { !$0.isEmpty })
        }
    }

    // MARK: - Helpers

    private static func isSuspiciousHost(_ host: String) -> Bool {
        suspiciousHosts.contains { host.contains($0) }
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

    /// Lowercased file extension of a leaf name (no dot), or nil.
    static func fileExtension(of name: String) -> String? {
        guard let dot = name.lastIndex(of: "."), dot != name.startIndex else { return nil }
        let ext = name[name.index(after: dot)...].lowercased()
        return ext.isEmpty ? nil : ext
    }

    private static func leaf(_ path: String) -> String {
        let parts = path.split(whereSeparator: { $0 == "\\" || $0 == "/" })
        return parts.last.map(String.init) ?? path
    }
}
