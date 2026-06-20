import Foundation

/// One macOS persistence mechanism *other than launchd* (launchd jobs are their
/// own `LaunchItemEntry`). The macOS analogue of `LinuxPersistenceEntry` -
/// covering the auto-run / event-triggered locations attackers favour on macOS:
/// cron, the `periodic` system, the (deprecated, abuse-prone) `emond` event
/// monitor, login/logout hooks, `rc` boot scripts, and configuration profiles.
///
/// Produced by `MacPersistenceParser`; surfaced in the **Persistence** tab and
/// scored by `MacPersistenceSweepAnalyzer`.
public nonisolated struct MacPersistenceItem: Identifiable, Hashable, Sendable, Codable {
    public enum Kind: String, Sendable, Codable, CaseIterable {
        case cron            // /private/var/at/tabs/<user>, /etc/crontab, cron/tabs
        case periodic        // /etc/periodic/{daily,weekly,monthly}/* scripts
        case emond           // /etc/emond.d/rules/*.plist RunCommand actions
        case loginHook       // com.apple.loginwindow LoginHook
        case logoutHook      // com.apple.loginwindow LogoutHook
        case rcScript        // /etc/rc.local, /etc/rc.common
        case configProfile   // .mobileconfig / Managed Preferences (MDM)

        public var label: String {
            switch self {
            case .cron:          return "Cron"
            case .periodic:      return "Periodic"
            case .emond:         return "emond rule"
            case .loginHook:     return "Login hook"
            case .logoutHook:    return "Logout hook"
            case .rcScript:      return "rc script"
            case .configProfile: return "Config profile"
            }
        }
    }

    public let id: UUID
    public let kind: Kind
    /// Cron: the schedule expression ("* * * * *", "@reboot"). nil elsewhere.
    public let schedule: String?
    /// The account the mechanism runs as, where recorded (system crontab column
    /// 6, the cron spool file owner, an emond action's `user`). nil if unknown.
    public let user: String?
    /// The command / script the mechanism runs (cron command, emond action
    /// command, hook script path). Empty for presence-only items (a config
    /// profile, a periodic script with no inspected body).
    public let command: String
    /// A short identity for the item: emond rule name, config-profile display
    /// name / payload id, periodic script leaf. nil for cron.
    public let name: String?
    /// Free-form extra context (emond event types, profile identifier).
    public let detail: String?
    public let sourceFile: String

    public init(id: UUID = UUID(), kind: Kind, schedule: String? = nil,
                user: String? = nil, command: String = "", name: String? = nil,
                detail: String? = nil, sourceFile: String) {
        self.id = id
        self.kind = kind
        self.schedule = schedule
        self.user = user
        self.command = command
        self.name = name
        self.detail = detail
        self.sourceFile = sourceFile
    }

    /// Display title: the item name, else the cron schedule + command head, else
    /// the command, else the source leaf.
    public var title: String {
        if let name, !name.isEmpty { return name }
        if let schedule {
            let head = command.split(separator: " ").first.map(String.init) ?? command
            return head.isEmpty ? schedule : "\(schedule)  \(head)"
        }
        if !command.isEmpty { return command }
        return (sourceFile as NSString).lastPathComponent
    }
}
