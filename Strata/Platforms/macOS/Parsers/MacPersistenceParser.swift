import Foundation

/// Pure, cross-platform parsers for the macOS persistence mechanisms that live
/// *outside* launchd - cron, `periodic`, `emond`, login/logout hooks, `rc`
/// scripts, and configuration profiles. The macOS analogue of
/// `LinuxPersistenceParser`. No I/O: each function takes already-read bytes/text
/// (extracted via icat for images, or read in place for a loose collection) plus
/// the on-disk path they came from, and returns `[MacPersistenceItem]`.
public enum MacPersistenceParser {

    // MARK: - Cron

    /// A crontab file. `isSystemCrontab` selects the 6-field form (`min hr dom
    /// mon dow USER command`, used by `/etc/crontab` and `/etc/cron.d/*`); the
    /// per-user spool form (`/private/var/at/tabs/<user>`, `/usr/lib/cron/tabs/
    /// <user>`) is 5-field and runs as `defaultUser` (the file's owner/name).
    /// `@reboot`/`@daily`/… nickname lines are recognised in both forms.
    public static func parseCrontab(_ text: String, sourceFile: String,
                                    defaultUser: String?, isSystemCrontab: Bool) -> [MacPersistenceItem] {
        var items: [MacPersistenceItem] = []
        for rawLine in text.split(separator: "\n", omittingEmptySubsequences: true) {
            let line = rawLine.trimmingCharacters(in: .whitespaces)
            guard !line.isEmpty, !line.hasPrefix("#") else { continue }
            // Skip environment-assignment lines (NAME=value with no schedule).
            if !line.hasPrefix("@"), let eq = line.firstIndex(of: "="),
               !line[..<eq].contains(" ") { continue }

            let (schedule, rest, user) = splitCron(line, isSystemCrontab: isSystemCrontab,
                                                   defaultUser: defaultUser)
            guard let schedule, !rest.isEmpty else { continue }
            items.append(MacPersistenceItem(kind: .cron, schedule: schedule, user: user,
                                            command: rest, sourceFile: sourceFile))
        }
        return items
    }

    /// Split a cron line into (schedule, command, user). Handles the `@nickname`
    /// shorthand and the 5/6-field numeric forms.
    private static func splitCron(_ line: String, isSystemCrontab: Bool,
                                  defaultUser: String?) -> (String?, String, String?) {
        let fields = line.split(separator: " ", omittingEmptySubsequences: true).map(String.init)
        if line.hasPrefix("@") {
            guard fields.count >= 2 else { return (nil, "", nil) }
            let schedule = fields[0]
            if isSystemCrontab, fields.count >= 3 {
                return (schedule, fields[2...].joined(separator: " "), fields[1])
            }
            return (schedule, fields[1...].joined(separator: " "), defaultUser)
        }
        let scheduleFieldCount = 5
        let minFields = isSystemCrontab ? scheduleFieldCount + 2 : scheduleFieldCount + 1
        guard fields.count >= minFields else { return (nil, "", nil) }
        let schedule = fields[0..<scheduleFieldCount].joined(separator: " ")
        if isSystemCrontab {
            return (schedule, fields[(scheduleFieldCount + 1)...].joined(separator: " "), fields[scheduleFieldCount])
        }
        return (schedule, fields[scheduleFieldCount...].joined(separator: " "), defaultUser)
    }

    // MARK: - Periodic

    /// A script dropped into `/etc/periodic/{daily,weekly,monthly}/` (or the
    /// `/private/etc/...` alias). Apple ships a stock set; a custom script here
    /// runs on the system's periodic cadence. Presence-only - the body isn't
    /// inspected. `name` is the script leaf, `schedule` the cadence directory.
    public static func periodicScript(path: String) -> MacPersistenceItem {
        let leaf = (path as NSString).lastPathComponent
        let cadence = ["daily", "weekly", "monthly"].first { path.lowercased().contains("/periodic/\($0)") }
        return MacPersistenceItem(kind: .periodic, schedule: cadence, command: path,
                                  name: leaf, sourceFile: path)
    }

    // MARK: - emond

    /// `/etc/emond.d/rules/*.plist` - an array of rule dictionaries. We surface
    /// every `RunCommand` action (the code-execution action type): the action's
    /// `command` + `arguments`, the rule `name`, and the triggering event types.
    /// emond is deprecated and almost exclusively seen in offensive tooling, so
    /// any rule carrying a command is high-signal.
    public static func parseEmondRules(_ data: Data, sourceFile: String) -> [MacPersistenceItem] {
        guard let object = try? PropertyListSerialization.propertyList(from: data, options: [], format: nil)
        else { return [] }
        // A rules file is an array of rule dicts; tolerate a single dict too.
        let rules: [[String: Any]]
        if let array = object as? [[String: Any]] { rules = array }
        else if let dict = object as? [String: Any] { rules = [dict] }
        else { return [] }

        var items: [MacPersistenceItem] = []
        for rule in rules {
            let ruleName = (rule["name"] as? String)
            let eventTypes = (rule["eventTypes"] as? [Any])?.compactMap { $0 as? String }.joined(separator: ", ")
            let actions = (rule["actions"] as? [[String: Any]]) ?? []
            for action in actions {
                let type = (action["type"] as? String) ?? ""
                guard type == "RunCommand" else { continue }
                let command = (action["command"] as? String) ?? ""
                let args = (action["arguments"] as? [Any])?.compactMap { $0 as? String } ?? []
                let user = action["user"] as? String
                let full = ([command] + args).filter { !$0.isEmpty }.joined(separator: " ")
                items.append(MacPersistenceItem(kind: .emond, user: user, command: full,
                                                name: ruleName, detail: eventTypes,
                                                sourceFile: sourceFile))
            }
        }
        return items
    }

    // MARK: - Login / logout hooks

    /// `com.apple.loginwindow.plist` - the `LoginHook` / `LogoutHook` keys each
    /// name a single script run at login/logout (as root, for the system-level
    /// plist). A legacy mechanism Apple deprecated; its presence is a strong
    /// persistence tell.
    public static func parseLoginWindow(_ data: Data, sourceFile: String) -> [MacPersistenceItem] {
        guard let dict = (try? PropertyListSerialization.propertyList(from: data, options: [], format: nil))
                as? [String: Any] else { return [] }
        var items: [MacPersistenceItem] = []
        if let hook = (dict["LoginHook"] as? String)?.trimmingCharacters(in: .whitespacesAndNewlines),
           !hook.isEmpty {
            items.append(MacPersistenceItem(kind: .loginHook, command: hook, sourceFile: sourceFile))
        }
        if let hook = (dict["LogoutHook"] as? String)?.trimmingCharacters(in: .whitespacesAndNewlines),
           !hook.isEmpty {
            items.append(MacPersistenceItem(kind: .logoutHook, command: hook, sourceFile: sourceFile))
        }
        return items
    }

    // MARK: - rc scripts

    /// `/etc/rc.local` / `/etc/rc.common`. macOS does not ship `rc.local`, so its
    /// presence is itself suspicious; `rc.common` is stock. We capture the first
    /// few non-comment command lines as the command preview.
    public static func rcScript(path: String, contents: String) -> MacPersistenceItem {
        let commands = contents.split(separator: "\n", omittingEmptySubsequences: true)
            .map { $0.trimmingCharacters(in: .whitespaces) }
            .filter { !$0.isEmpty && !$0.hasPrefix("#") }
        let preview = commands.prefix(3).joined(separator: " ; ")
        return MacPersistenceItem(kind: .rcScript, command: preview,
                                  name: (path as NSString).lastPathComponent, sourceFile: path)
    }

    // MARK: - Configuration profiles

    /// A `.mobileconfig` configuration profile (XML plist) or a Managed
    /// Preferences domain file. We pull the `PayloadDisplayName` /
    /// `PayloadIdentifier` for identity; profiles are an MDM control + persistence
    /// vector. Returns nil if the bytes aren't a profile-shaped plist.
    public static func configProfile(_ data: Data, sourceFile: String) -> MacPersistenceItem? {
        guard let dict = (try? PropertyListSerialization.propertyList(from: data, options: [], format: nil))
                as? [String: Any] else { return nil }
        let displayName = dict["PayloadDisplayName"] as? String
        let identifier = dict["PayloadIdentifier"] as? String
        // A Managed Preferences domain file may carry neither key; fall back to
        // the filename so it still surfaces as a managed-config item.
        let name = displayName ?? identifier ?? (sourceFile as NSString).lastPathComponent
        return MacPersistenceItem(kind: .configProfile, name: name, detail: identifier,
                                  sourceFile: sourceFile)
    }
}
