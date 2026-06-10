import Foundation

/// Exploitation & webshell detection over nginx/apache access logs - the front
/// line for a web-facing host. Looks for the request patterns that betray an
/// attack against the application itself, aggregating so a scan doesn't produce
/// thousands of findings.
public nonisolated struct WebLogAnalyzer: Analyzer {
    public let name = "Web Access Log"
    public init() {}

    /// Lowercased substrings in the request target that indicate an exploitation
    /// attempt, grouped so one finding summarises each class per client.
    private struct AttackClass {
        let key: String
        let title: String
        let technique: AttackTechnique
        let needles: [String]
    }

    private static let attackClasses: [AttackClass] = [
        AttackClass(key: "traversal", title: "Path traversal / LFI",
                    technique: AttackTechnique(attackID: "T1190", name: "Exploit Public-Facing Application"),
                    needles: ["../", "..%2f", "..\\", "/etc/passwd", "/proc/self/environ", "php://", "file://"]),
        AttackClass(key: "sqli", title: "SQL injection",
                    technique: AttackTechnique(attackID: "T1190", name: "Exploit Public-Facing Application"),
                    needles: ["union select", "union all select", "' or '1'='1", "or 1=1", "sleep(", "benchmark(",
                              "information_schema", "' or 1=1", "\" or \"", "xp_cmdshell"]),
        AttackClass(key: "cmdi", title: "Command injection",
                    technique: AttackTechnique(attackID: "T1190", name: "Exploit Public-Facing Application"),
                    needles: [";id", "|id", "%3bid", ";whoami", "|whoami", "$(", "%24%28", "`", "wget ", "curl ",
                              ";cat ", "/bin/sh", "/bin/bash"]),
        AttackClass(key: "xss", title: "Cross-site scripting probe",
                    technique: AttackTechnique(attackID: "T1190", name: "Exploit Public-Facing Application"),
                    needles: ["<script", "%3cscript", "javascript:", "onerror=", "onload="]),
    ]

    /// Webshell filename / path tells. A request to one of these (especially a
    /// 2xx) is high-signal.
    private static let webshellNeedles = [
        "c99.php", "r57.php", "wso.php", "b374k", "shell.php", "cmd.php", "/uploads/",
        "/tmp/", "/.well-known/.", "weevely", "alfa.php", "filesman", "adminer.php",
    ]

    /// Recon/scanner user agents.
    private static let scannerAgents = [
        "sqlmap", "nikto", "nmap", "masscan", "gobuster", "dirbuster", "dirb",
        "wpscan", "nuclei", "acunetix", "nessus", "fuzz", "feroxbuster", "ffuf",
    ]

    public func analyze(context: AnalysisContext) -> [Finding] {
        guard !context.webAccess.isEmpty else { return [] }
        var findings: [Finding] = []

        // Exploitation classes, aggregated per (class, client IP).
        struct Agg { var count = 0; var sample = ""; var last: Date?; var source = ""; var hit2xx = false }
        var byClass: [String: Agg] = [:]
        var webshells: [String: Agg] = [:]
        var scanners: [String: Agg] = [:]
        var notFound: [String: Int] = [:]   // 404s per IP (dir brute force)

        for entry in context.webAccess {
            let target = entry.target.lowercased()
            let ua = (entry.userAgent ?? "").lowercased()

            for cls in Self.attackClasses where cls.needles.contains(where: target.contains) {
                let key = "\(cls.key)|\(entry.clientIP)"
                var agg = byClass[key] ?? Agg()
                agg.count += 1
                if agg.sample.isEmpty { agg.sample = entry.target }
                if let t = entry.timestamp, agg.last == nil || t > agg.last! { agg.last = t }
                agg.source = entry.sourceFile
                if (200..<400).contains(entry.status) { agg.hit2xx = true }
                byClass[key] = agg
            }

            if Self.webshellNeedles.contains(where: target.contains) {
                let key = "\(entry.path)|\(entry.clientIP)"
                var agg = webshells[key] ?? Agg()
                agg.count += 1
                agg.sample = entry.target
                if let t = entry.timestamp, agg.last == nil || t > agg.last! { agg.last = t }
                agg.source = entry.sourceFile
                if (200..<300).contains(entry.status) { agg.hit2xx = true }
                webshells[key] = agg
            }

            if let tool = Self.scannerAgents.first(where: ua.contains) {
                var agg = scanners[tool] ?? Agg()
                agg.count += 1
                agg.sample = entry.userAgent ?? tool
                if let t = entry.timestamp, agg.last == nil || t > agg.last! { agg.last = t }
                agg.source = entry.sourceFile
                scanners[tool] = agg
            }

            if entry.status == 404 { notFound[entry.clientIP, default: 0] += 1 }
        }

        for (key, agg) in byClass {
            let parts = key.split(separator: "|")
            let cls = Self.attackClasses.first { $0.key == parts.first.map(String.init) }!
            let ip = parts.count > 1 ? String(parts[1]) : "?"
            findings.append(Finding(
                title: "\(cls.title) from \(ip)\(agg.hit2xx ? " (got 2xx/3xx)" : "")",
                detail: "\(agg.count) request(s) matching \(cls.title.lowercased()) patterns from \(ip). "
                    + "Example: \(agg.sample)",
                severity: agg.hit2xx ? .high : .medium,
                phase: .exploitation,
                technique: cls.technique,
                timestamp: agg.last,
                evidencePaths: [agg.source]))
        }

        for (_, agg) in webshells {
            findings.append(Finding(
                title: "Possible webshell access\(agg.hit2xx ? " (200 OK)" : "")",
                detail: "\(agg.count) request(s) to a webshell-shaped path: \(agg.sample). "
                    + (agg.hit2xx ? "Returned success - treat as an active webshell." : "Did not return 2xx."),
                severity: agg.hit2xx ? .critical : .high,
                phase: .installation,
                technique: AttackTechnique(attackID: "T1505.003", name: "Server Software Component: Web Shell"),
                timestamp: agg.last,
                evidencePaths: [agg.source]))
        }

        for (tool, agg) in scanners {
            findings.append(Finding(
                title: "Web scanner: \(tool)",
                detail: "\(agg.count) request(s) with a \(tool) user-agent (\(agg.sample)) - automated "
                    + "vulnerability scanning / content discovery.",
                severity: .medium,
                phase: .reconnaissance,
                technique: AttackTechnique(attackID: "T1595.002", name: "Active Scanning: Vulnerability Scanning"),
                timestamp: agg.last,
                evidencePaths: [agg.source]))
        }

        for (ip, count) in notFound where count >= 100 {
            findings.append(Finding(
                title: "Directory brute-force from \(ip)",
                detail: "\(count) requests returned 404 from \(ip) - consistent with content/path "
                    + "discovery (dirbusting).",
                severity: .low,
                phase: .reconnaissance,
                technique: AttackTechnique(attackID: "T1595.003", name: "Active Scanning: Wordlist Scanning"),
                evidencePaths: [context.webAccess.first { $0.clientIP == ip }?.sourceFile ?? ""]))
        }

        return findings
    }
}
