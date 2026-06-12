import Foundation

/// Parses shell history files into `ShellHistoryEntry` rows. Pure.
///
/// - `.zsh_history` **extended format**: `: <epoch>:<elapsed>;<command>` -
///   carries a real timestamp per command. Plain-format zsh lines also occur.
/// - `.bash_history`: plain commands, optionally preceded by `#<epoch>`
///   comment lines when the account had `HISTTIMEFORMAT` set. Without those,
///   order (line number) is the only chronology bash gives us.
public nonisolated enum ShellHistoryParser {

    /// Plausible epoch range for a history timestamp (2000-01-01..2100-01-01);
    /// anything else is a coincidental `#123` comment, not a HISTTIMEFORMAT stamp.
    private static let epochRange: ClosedRange<TimeInterval> = 946_684_800...4_102_444_800

    public static func parse(text: String, user: String,
                             shell: ShellHistoryEntry.Shell,
                             sourceFile: String) -> [ShellHistoryEntry] {
        var entries: [ShellHistoryEntry] = []
        var pendingTimestamp: Date?
        var lineNumber = 0

        for rawLine in text.split(separator: "\n", omittingEmptySubsequences: false) {
            lineNumber += 1
            let line = String(rawLine)
            if line.isEmpty { continue }

            // zsh extended history: ": 1700000000:0;command"
            if shell == .zsh, line.hasPrefix(": "),
               let semicolon = line.firstIndex(of: ";") {
                let header = line[line.index(line.startIndex, offsetBy: 2)..<semicolon]
                let epochText = header.split(separator: ":").first ?? ""
                let command = String(line[line.index(after: semicolon)...])
                guard !command.isEmpty else { continue }
                let stamp = TimeInterval(epochText).flatMap { epoch in
                    epochRange.contains(epoch) ? Date(timeIntervalSince1970: epoch) : nil
                }
                entries.append(ShellHistoryEntry(user: user, shell: shell, command: command,
                                                 timestamp: stamp, lineNumber: lineNumber,
                                                 sourceFile: sourceFile))
                continue
            }

            // bash HISTTIMEFORMAT: "#1700000000" stamps the NEXT command line.
            if shell == .bash, line.hasPrefix("#"),
               let epoch = TimeInterval(line.dropFirst()), epochRange.contains(epoch) {
                pendingTimestamp = Date(timeIntervalSince1970: epoch)
                continue
            }

            entries.append(ShellHistoryEntry(user: user, shell: shell, command: line,
                                             timestamp: pendingTimestamp,
                                             lineNumber: lineNumber,
                                             sourceFile: sourceFile))
            pendingTimestamp = nil
        }
        return entries
    }

    /// Derive the account name from the history file's path:
    /// `/home/<user>/.bash_history` -> user (Linux), `/Users/<user>/...` -> user
    /// (macOS), `/root/...` -> root.
    public static func user(fromPath path: String) -> String {
        let parts = path.split(whereSeparator: { $0 == "/" || $0 == "\\" }).map(String.init)
        if let homeIndex = parts.firstIndex(where: { $0.lowercased() == "home" || $0.lowercased() == "users" }),
           homeIndex + 1 < parts.count {
            return parts[homeIndex + 1]
        }
        if parts.contains(where: { $0.lowercased() == "root" }) { return "root" }
        return "?"
    }
}
