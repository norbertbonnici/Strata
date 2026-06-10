import Foundation

/// Parses Linux access & privilege artifacts into the `LinuxAccessInfo`
/// aggregate. Pure - text in, values out. Each method handles one source file;
/// `parseLinux` routes the right file to the right method.
public nonisolated enum LinuxAccessParser {

    // MARK: - SSH

    /// `~/.ssh/authorized_keys`: one key per line, `[options] <algo> <base64> [comment]`.
    /// Options (a comma-separated list that may contain quoted commas) precede
    /// the algorithm when the first field isn't a known key type.
    public static func parseAuthorizedKeys(text: String, user: String?,
                                           sourceFile: String) -> [SSHKey] {
        var keys: [SSHKey] = []
        for rawLine in text.split(separator: "\n", omittingEmptySubsequences: true) {
            let line = rawLine.trimmingCharacters(in: .whitespaces)
            if line.isEmpty || line.hasPrefix("#") { continue }

            var rest = Substring(line)
            var options: [String] = []
            // If the line doesn't start with a key algorithm, the leading field
            // is the options list (which can contain spaces inside quotes).
            if !isAlgorithm(firstToken(rest)) {
                let (opts, remainder) = splitOptions(rest)
                options = opts
                rest = remainder
            }
            let fields = rest.split(separator: " ", maxSplits: 2, omittingEmptySubsequences: true)
            guard fields.count >= 2, isAlgorithm(String(fields[0])) else { continue }
            let algorithm = String(fields[0])
            let comment = fields.count >= 3 ? String(fields[2]) : ""
            keys.append(SSHKey(kind: .authorized, user: user, algorithm: algorithm,
                               comment: comment, options: options, sourceFile: sourceFile))
        }
        return keys
    }

    /// `~/.ssh/known_hosts`: `[marker] host[,host...] <algo> <base64> [comment]`.
    public static func parseKnownHosts(text: String, user: String?,
                                       sourceFile: String) -> [SSHKey] {
        var keys: [SSHKey] = []
        for rawLine in text.split(separator: "\n", omittingEmptySubsequences: true) {
            let line = rawLine.trimmingCharacters(in: .whitespaces)
            if line.isEmpty || line.hasPrefix("#") { continue }
            var fields = line.split(separator: " ", omittingEmptySubsequences: true).map(String.init)
            // Optional @cert-authority / @revoked marker.
            if fields.first?.hasPrefix("@") == true { fields.removeFirst() }
            guard fields.count >= 2, isAlgorithm(fields[1]) else { continue }
            keys.append(SSHKey(kind: .knownHost, user: user, algorithm: fields[1],
                               comment: fields.count >= 3 ? fields[2] : "",
                               host: fields[0], sourceFile: sourceFile))
        }
        return keys
    }

    /// `/etc/ssh/sshd_config`: `Keyword value` lines (last value wins). Keys are
    /// lowercased so the analyzer can look them up case-insensitively.
    public static func parseSSHDConfig(text: String) -> [String: String] {
        var settings: [String: String] = [:]
        for rawLine in text.split(separator: "\n", omittingEmptySubsequences: true) {
            let line = rawLine.trimmingCharacters(in: .whitespaces)
            if line.isEmpty || line.hasPrefix("#") { continue }
            // "Keyword value" (whitespace or '=' separated).
            let parts = line.split(whereSeparator: { $0 == " " || $0 == "\t" || $0 == "=" })
            guard parts.count >= 2 else { continue }
            let key = parts[0].lowercased()
            let value = parts.dropFirst().joined(separator: " ")
            settings[key] = value
        }
        return settings
    }

    // MARK: - Privilege

    /// `/etc/sudoers` and `sudoers.d/*`: `principal host=(runas) [TAG:] command`.
    /// Defaults/alias lines and `#includedir` are skipped. Tolerant of the
    /// common shapes rather than a full sudoers grammar.
    public static func parseSudoers(text: String, sourceFile: String) -> [SudoRule] {
        var rules: [SudoRule] = []
        for rawLine in text.split(separator: "\n", omittingEmptySubsequences: true) {
            let line = rawLine.trimmingCharacters(in: .whitespaces)
            if line.isEmpty || line.hasPrefix("#") { continue }
            let upper = line.uppercased()
            if upper.hasPrefix("DEFAULTS") || upper.hasPrefix("USER_ALIAS")
                || upper.hasPrefix("CMND_ALIAS") || upper.hasPrefix("HOST_ALIAS")
                || upper.hasPrefix("RUNAS_ALIAS") || line.hasPrefix("@") { continue }

            // principal  host = (runas) tags: command
            let tokens = line.split(separator: " ", maxSplits: 1, omittingEmptySubsequences: true)
            guard tokens.count == 2 else { continue }
            let principal = String(tokens[0])
            guard let eq = tokens[1].firstIndex(of: "=") else { continue }
            var spec = tokens[1][tokens[1].index(after: eq)...].trimmingCharacters(in: .whitespaces)

            var runAs: String?
            if spec.hasPrefix("(") , let close = spec.firstIndex(of: ")") {
                runAs = String(spec[spec.index(after: spec.startIndex)..<close])
                spec = spec[spec.index(after: close)...].trimmingCharacters(in: .whitespaces)
            }
            let noPasswd = spec.uppercased().contains("NOPASSWD")
            // Drop leading tag list (NOPASSWD:, NOEXEC:, …) before the command.
            if let colon = spec.range(of: ":", options: .backwards) {
                let tags = spec[..<colon.lowerBound].uppercased()
                if tags.contains("PASSWD") || tags.contains("EXEC") || tags.contains("SETENV") {
                    spec = spec[colon.upperBound...].trimmingCharacters(in: .whitespaces)
                }
            }
            rules.append(SudoRule(principal: principal, runAs: runAs, noPasswd: noPasswd,
                                  command: spec.isEmpty ? "ALL" : spec, sourceFile: sourceFile))
        }
        return rules
    }

    /// `/etc/group`: `name:passwd:gid:member,member,...`.
    public static func parseGroup(text: String) -> [LinuxGroup] {
        var groups: [LinuxGroup] = []
        for rawLine in text.split(separator: "\n", omittingEmptySubsequences: true) {
            let line = rawLine.trimmingCharacters(in: .whitespaces)
            if line.isEmpty || line.hasPrefix("#") { continue }
            let fields = line.split(separator: ":", omittingEmptySubsequences: false).map(String.init)
            guard fields.count >= 4, let gid = Int(fields[2]) else { continue }
            let members = fields[3].split(separator: ",").map(String.init).filter { !$0.isEmpty }
            groups.append(LinuxGroup(name: fields[0], gid: gid, members: members))
        }
        return groups
    }

    /// `/etc/shadow`: `name:hash:...`. We only classify the hash field.
    public static func parseShadow(text: String) -> [String: ShadowStatus] {
        var out: [String: ShadowStatus] = [:]
        for rawLine in text.split(separator: "\n", omittingEmptySubsequences: true) {
            let line = rawLine.trimmingCharacters(in: .whitespaces)
            if line.isEmpty || line.hasPrefix("#") { continue }
            let fields = line.split(separator: ":", omittingEmptySubsequences: false).map(String.init)
            guard fields.count >= 2 else { continue }
            out[fields[0]] = shadowStatus(forHash: fields[1])
        }
        return out
    }

    static func shadowStatus(forHash hash: String) -> ShadowStatus {
        if hash.isEmpty { return .empty }
        if hash == "*" || hash == "!!" { return .noLogin }
        if hash.hasPrefix("!") || hash.hasPrefix("*") { return .locked }
        return .usable
    }

    // MARK: - Helpers

    private static let algorithms: Set<String> = [
        "ssh-rsa", "ssh-dss", "ssh-ed25519", "ssh-ed25519-sk", "sk-ssh-ed25519@openssh.com",
        "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521",
        "sk-ecdsa-sha2-nistp256@openssh.com", "ssh-rsa-cert-v01@openssh.com",
    ]

    private static func isAlgorithm(_ token: String) -> Bool {
        algorithms.contains(token) || token.hasPrefix("ssh-") || token.hasPrefix("ecdsa-")
            || token.hasPrefix("sk-")
    }

    private static func firstToken(_ s: Substring) -> String {
        String(s.split(separator: " ", maxSplits: 1).first ?? "")
    }

    /// Split the leading options field from the rest, respecting quoted
    /// commas/spaces (`command="a b",from="1,2" ssh-rsa AAAA…`).
    private static func splitOptions(_ line: Substring) -> ([String], Substring) {
        var inQuote = false
        var idx = line.startIndex
        while idx < line.endIndex {
            let c = line[idx]
            if c == "\"" { inQuote.toggle() }
            else if c == " " && !inQuote { break }
            idx = line.index(after: idx)
        }
        let optionsText = String(line[line.startIndex..<idx])
        let remainder = idx < line.endIndex ? line[line.index(after: idx)...] : line[line.endIndex...]
        // Split options on commas that are outside quotes.
        var options: [String] = []
        var current = ""
        inQuote = false
        for c in optionsText {
            if c == "\"" { inQuote.toggle(); current.append(c) }
            else if c == "," && !inQuote { options.append(current); current = "" }
            else { current.append(c) }
        }
        if !current.isEmpty { options.append(current) }
        return (options, remainder)
    }
}
