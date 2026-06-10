import Foundation

/// Builds a `LinuxHostInfo` from the few small files that identify a Linux
/// host - the Linux counterpart of the Windows registry-derived host profile.
/// Each piece is optional; feed it whatever was found.
public nonisolated enum LinuxHostInfoParser {

    /// `/etc/os-release` (or `/usr/lib/os-release`): `KEY="value"` lines.
    public static func applyOSRelease(_ text: String, to info: inout LinuxHostInfo) {
        for rawLine in text.split(separator: "\n", omittingEmptySubsequences: true) {
            let line = rawLine.trimmingCharacters(in: .whitespaces)
            guard !line.hasPrefix("#"), let eq = line.firstIndex(of: "=") else { continue }
            let key = String(line[..<eq])
            let value = String(line[line.index(after: eq)...])
                .trimmingCharacters(in: CharacterSet(charactersIn: "\"'"))
            switch key {
            case "PRETTY_NAME": info.prettyName = value
            case "ID":          info.osID = value
            case "VERSION_ID":  info.versionID = value
            default: break
            }
        }
    }

    /// `/etc/hostname`: the first non-empty line.
    public static func applyHostname(_ text: String, to info: inout LinuxHostInfo) {
        let name = text.split(separator: "\n")
            .map { $0.trimmingCharacters(in: .whitespaces) }
            .first { !$0.isEmpty && !$0.hasPrefix("#") }
        if let name { info.hostname = name }
    }

    /// `/etc/timezone` (Debian-family): e.g. "Europe/Malta".
    public static func applyTimezone(_ text: String, to info: inout LinuxHostInfo) {
        let zone = text.split(separator: "\n")
            .map { $0.trimmingCharacters(in: .whitespaces) }
            .first { !$0.isEmpty && !$0.hasPrefix("#") }
        if let zone { info.timeZone = zone }
    }

    /// `/etc/passwd`: `name:x:uid:gid:gecos:home:shell`.
    public static func applyPasswd(_ text: String, to info: inout LinuxHostInfo) {
        var users: [LinuxUser] = []
        for rawLine in text.split(separator: "\n", omittingEmptySubsequences: true) {
            let line = rawLine.trimmingCharacters(in: .whitespaces)
            guard !line.isEmpty, !line.hasPrefix("#") else { continue }
            let fields = line.split(separator: ":", omittingEmptySubsequences: false)
            guard fields.count >= 7,
                  let uid = Int(fields[2]), let gid = Int(fields[3]) else { continue }
            users.append(LinuxUser(name: String(fields[0]), uid: uid, gid: gid,
                                   home: String(fields[5]), shell: String(fields[6])))
        }
        if !users.isEmpty { info.users = users }
    }
}
