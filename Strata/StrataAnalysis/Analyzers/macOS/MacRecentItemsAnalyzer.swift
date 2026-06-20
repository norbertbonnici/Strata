import Foundation

/// Detection over macOS **recent-item** stores (`LSSharedFileList` `.sfl2`,
/// Finder sidebar/favorites, recent servers/documents). These are user-behaviour
/// evidence; most entries are benign, so this runs two **high-precision** rules
/// rather than flagging every recent item:
///
///  1. **Recent remote-server connections** — a recently mounted/visited network
///     share or host (`smb://`, `afp://`, `ssh://`, `vnc://`, a raw-IP server …).
///     Recent connections to remote hosts are a lateral-movement / data-staging
///     signal; a connection to a **raw IP** is treated as higher-confidence than
///     a named host (T1021 Remote Services, protocol-specific where known).
///  2. **Recent items in suspicious locations** — a recently opened document /
///     application whose path is in a staging directory (`/tmp`, `/var/folders`,
///     `/Users/Shared` …) or carries a risky script/installer extension
///     (`.sh`, `.command`, `.scpt`, `.dmg`, `.pkg` …). Recently opening a payload
///     from a drop location is execution evidence (T1204.002 User Execution).
///
/// Aggregated per subject so a chatty store yields one finding per indicator
/// (mirroring `MacQuarantineAnalyzer` / `MacSecurityAnalyzer`).
public nonisolated struct MacRecentItemsAnalyzer: Analyzer {
    public let name = "macOS Recent Items"
    public init() {}

    /// URL schemes that denote a connection to a remote host.
    static let remoteSchemes: [String: (AttackTechnique, String)] = [
        "smb":    (AttackTechnique(attackID: "T1021.002", name: "Remote Services: SMB/Windows Admin Shares"), "SMB share"),
        "cifs":   (AttackTechnique(attackID: "T1021.002", name: "Remote Services: SMB/Windows Admin Shares"), "SMB share"),
        "afp":    (AttackTechnique(attackID: "T1021", name: "Remote Services"), "AFP share"),
        "nfs":    (AttackTechnique(attackID: "T1021", name: "Remote Services"), "NFS share"),
        "ftp":    (AttackTechnique(attackID: "T1021", name: "Remote Services"), "FTP server"),
        "ftps":   (AttackTechnique(attackID: "T1021", name: "Remote Services"), "FTP server"),
        "ssh":    (AttackTechnique(attackID: "T1021.004", name: "Remote Services: SSH"), "SSH host"),
        "sftp":   (AttackTechnique(attackID: "T1021.004", name: "Remote Services: SSH"), "SSH host"),
        "vnc":    (AttackTechnique(attackID: "T1021.005", name: "Remote Services: VNC"), "VNC host"),
        "webdav": (AttackTechnique(attackID: "T1021", name: "Remote Services"), "WebDAV share"),
    ]

    /// Staging directories where a recently opened payload is suspicious.
    static let stagingTokens = [
        "/tmp/", "/private/tmp/", "/var/tmp/", "/private/var/tmp/",
        "/users/shared/", "/private/var/folders/", "/.trash/", "/library/caches/",
    ]

    /// Risky script / installer extensions for a recently opened item.
    static let riskyExtensions = [
        ".sh", ".command", ".scpt", ".py", ".pl", ".rb", ".jar",
        ".dmg", ".pkg", ".mpkg", ".term", ".workflow",
    ]

    public func analyze(context: AnalysisContext) -> [Finding] {
        analyze(context.macRecentItems)
    }

    /// Pure detection entry point — unit-tested directly with fixtures.
    public func analyze(_ items: [MacRecentItem]) -> [Finding] {
        guard !items.isEmpty else { return [] }
        return remoteServerFindings(items) + suspiciousPathFindings(items)
    }

    // MARK: - Rule 1: recent remote-server connections

    private struct HostAgg {
        var count = 0
        var last: Date?
        var rawIP = false
        var technique = AttackTechnique(attackID: "T1021", name: "Remote Services")
        var serviceLabel = "remote host"
        var sample = ""
        var sources: Set<String> = []
    }

    private func remoteServerFindings(_ items: [MacRecentItem]) -> [Finding] {
        var byHost: [String: HostAgg] = [:]
        for item in items {
            guard let parsed = Self.remoteTarget(item) else { continue }
            var agg = byHost[parsed.host.lowercased()] ?? HostAgg()
            agg.count += 1
            agg.rawIP = agg.rawIP || Self.isRawIPv4(parsed.host)
            agg.technique = parsed.technique
            agg.serviceLabel = parsed.serviceLabel
            if agg.sample.isEmpty { agg.sample = item.value }
            agg.sources.insert(item.sourceFile)
            if let t = item.timestamp, t > (agg.last ?? .distantPast) { agg.last = t }
            byHost[parsed.host.lowercased()] = agg
        }
        return byHost.map { (host, agg) in
            var detail = "macOS recorded a recent connection to the \(agg.serviceLabel) \(host)"
            if agg.count > 1 { detail += " (\(agg.count) entries)" }
            detail += ".\n"
            detail += agg.rawIP
                ? "The target is a raw IP address, which is unusual for routine file sharing and "
                    + "common in hands-on lateral movement or data staging."
                : "Recent remote-share connections can indicate lateral movement or data staging; "
                    + "confirm the host is expected."
            detail += "\nExample: \(agg.sample)"
            return Finding(
                title: "Recent connection to \(agg.serviceLabel): \(host)",
                detail: detail,
                severity: agg.rawIP ? .high : .medium,
                phase: .exploitation,
                technique: agg.technique,
                timestamp: agg.last,
                evidencePaths: agg.sources.sorted())
        }
    }

    // MARK: - Rule 2: recent items in suspicious locations

    private struct PathAgg {
        var count = 0
        var last: Date?
        var kind: MacRecentItem.ListKind = .other
        var reasons: Set<String> = []
        var sources: Set<String> = []
    }

    private func suspiciousPathFindings(_ items: [MacRecentItem]) -> [Finding] {
        var bySubject: [String: PathAgg] = [:]
        for item in items {
            guard let path = Self.localPath(item) else { continue }
            let lower = path.lowercased()
            var reasons: Set<String> = []
            if let token = Self.stagingTokens.first(where: { lower.contains($0) }) {
                reasons.insert("staging path (\(token))")
            }
            if let ext = Self.riskyExtensions.first(where: { lower.hasSuffix($0) }) {
                reasons.insert("risky extension (\(ext))")
            }
            guard !reasons.isEmpty else { continue }
            var agg = bySubject[lower] ?? PathAgg()
            agg.count += 1
            agg.kind = item.kind
            agg.reasons.formUnion(reasons)
            agg.sources.insert(item.sourceFile)
            if let t = item.timestamp, t > (agg.last ?? .distantPast) { agg.last = t }
            bySubject[lower] = agg
        }
        return bySubject.map { (path, agg) in
            let leaf = (path as NSString).lastPathComponent
            let detail = "A recent \(agg.kind.label.lowercased().dropLast()) entry points to \(path) — "
                + agg.reasons.sorted().joined(separator: ", ")
                + ".\nRecently opening an item from a drop location or a script/installer is execution "
                + "evidence; correlate with the quarantine, FSEvents, and unified-log timelines."
            return Finding(
                title: "Recent item in suspicious location: \(leaf)",
                detail: detail,
                severity: .medium,
                phase: .exploitation,
                technique: AttackTechnique(attackID: "T1204.002", name: "User Execution: Malicious File"),
                timestamp: agg.last,
                evidencePaths: [path] + agg.sources.sorted())
        }
    }

    // MARK: - Helpers

    /// Resolve a recent item to a remote (host, technique, label) when it denotes
    /// a network connection — via a URL scheme, or a `.servers`/`.hosts` entry
    /// that looks like a bare host.
    static func remoteTarget(_ item: MacRecentItem) -> (host: String, technique: AttackTechnique, serviceLabel: String)? {
        let value = item.value
        if let schemeRange = value.range(of: "://") {
            let scheme = String(value[value.startIndex..<schemeRange.lowerBound]).lowercased()
            if let entry = remoteSchemes[scheme], let host = host(from: value) {
                return (host, entry.0, entry.1)
            }
            return nil
        }
        // A bare host string filed under a servers/hosts list.
        if item.kind == .servers || item.kind == .hosts {
            let host = value.trimmingCharacters(in: .whitespaces)
            if !host.isEmpty, !host.contains(" "), host.contains(".") || isRawIPv4(host) {
                return (host, AttackTechnique(attackID: "T1021", name: "Remote Services"), "remote host")
            }
        }
        return nil
    }

    /// The local filesystem path a recent item refers to, or nil if it's a URL /
    /// remote target. Handles `file://` URLs and bare `/`/`~` paths.
    static func localPath(_ item: MacRecentItem) -> String? {
        let value = item.value
        if value.lowercased().hasPrefix("file://") {
            return URL(string: value)?.path
        }
        if value.contains("://") { return nil }            // a remote URL, not a path
        if value.hasPrefix("/") || value.hasPrefix("~/") { return value }
        return nil
    }

    private static func host(from urlString: String) -> String? {
        if let url = URL(string: urlString), let host = url.host, !host.isEmpty { return host }
        // Fall back to manual parse for schemes URLComponents rejects.
        guard let range = urlString.range(of: "://") else { return nil }
        let rest = urlString[range.upperBound...]
        let hostPart = rest.prefix { $0 != "/" && $0 != ":" && $0 != "@" }
        // Strip an optional `user@` credential prefix.
        if let at = rest.firstIndex(of: "@"), at < (rest.firstIndex(of: "/") ?? rest.endIndex) {
            let afterAt = rest[rest.index(after: at)...]
            let h = afterAt.prefix { $0 != "/" && $0 != ":" }
            return h.isEmpty ? nil : String(h)
        }
        return hostPart.isEmpty ? nil : String(hostPart)
    }

    /// Dotted-quad IPv4 literal check (shared shape with `MacQuarantineAnalyzer`).
    static func isRawIPv4(_ host: String) -> Bool {
        let parts = host.split(separator: ".")
        guard parts.count == 4 else { return false }
        return parts.allSatisfy { part in
            guard let n = Int(part), (0...255).contains(n) else { return false }
            return true
        }
    }
}
