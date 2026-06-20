import Foundation

#if os(macOS)

/// Parses the curated set of macOS **security-posture / configuration** files no
/// other Strata parser covers — the firewall, screen-lock, software-update,
/// Gatekeeper master switch, remote-service enablement (SSH/Screen Sharing/
/// ARD/SMB/AFP/Apple Events), and login-window policy (auto-login, guest,
/// hidden accounts) — into `[MacConfigSetting]`.
///
/// Pure (the caller hands it already-read `Data`). Most files are property lists
/// (binary or XML — `PropertyListSerialization` decodes both); two are not
/// plists at all (`kcpassword`, `com.apple.VNCSettings.txt`), which are reported
/// by **presence only** — their stored credentials are deliberately **not
/// decoded into the case** (forensic-confidentiality: a recovered live secret
/// would otherwise be persisted to `config.json`).
public nonisolated enum MacConfigParser {

    /// Dispatch on the source path — each supported file has its own key layout.
    public static func parse(_ data: Data, sourceFile: String, scope: String) -> [MacConfigSetting] {
        let lower = sourceFile.lowercased()
        let base = (lower as NSString).lastPathComponent

        // Credential files — presence only, never decode the secret.
        if base == "kcpassword" {
            return [MacConfigSetting(
                category: .account, key: "loginwindow.kcpassword",
                name: "Auto-login password stored", value: "present",
                interpretation: "/etc/kcpassword exists — the auto-login account's password is stored "
                    + "(obfuscated, recoverable). Confirms automatic login is/was configured.",
                risk: .high, attackID: "T1078", attackName: "Valid Accounts",
                domain: "loginwindow", scope: scope, sourceFile: sourceFile)]
        }
        if base == "com.apple.vncsettings.txt" {
            return [MacConfigSetting(
                category: .remoteAccess, key: "ard.vncpassword",
                name: "VNC control password configured", value: "present",
                interpretation: "com.apple.VNCSettings.txt exists — a static VNC/Screen-Sharing control "
                    + "password is set, allowing inbound screen control.",
                risk: .high, attackID: "T1021.005", attackName: "VNC",
                domain: "com.apple.RemoteManagement", scope: scope, sourceFile: sourceFile)]
        }

        guard let dict = dictionary(data) else { return [] }

        if base == "com.apple.alf.plist" { return firewall(dict, sourceFile, scope) }
        if base.contains("com.apple.screensaver") { return screenLock(dict, sourceFile, scope) }
        if base == "com.apple.softwareupdate.plist" { return softwareUpdate(dict, sourceFile, scope) }
        if base == "com.apple.commerce.plist" { return commerce(dict, sourceFile, scope) }
        if base == "systempolicy-prefs.plist" { return gatekeeper(dict, sourceFile, scope) }
        if base == "com.apple.loginwindow.plist" { return loginWindow(dict, sourceFile, scope) }
        if base == "com.apple.remotemanagement.plist" { return remoteManagement(dict, sourceFile, scope) }
        if base.hasPrefix("disabled") || base == "overrides.plist" { return remoteServices(dict, sourceFile, scope) }
        return []
    }

    // MARK: - Domains

    private static func firewall(_ d: [String: Any], _ src: String, _ scope: String) -> [MacConfigSetting] {
        var out: [MacConfigSetting] = []
        let dom = "com.apple.alf"
        if let g = num(d, "globalstate")?.intValue {
            let on = g != 0
            out.append(MacConfigSetting(
                category: .firewall, key: "firewall.globalstate", name: "Application Firewall",
                value: g == 0 ? "off" : (g == 2 ? "on (block all)" : "on"),
                interpretation: on ? "Firewall is on (globalstate=\(g))."
                    : "Firewall is OFF — all incoming connections are allowed.",
                risk: on ? .none : .high,
                attackID: on ? nil : "T1562.004",
                attackName: on ? nil : "Disable or Modify System Firewall",
                domain: dom, scope: scope, sourceFile: src))
        }
        if let u = num(d, "firewallunload")?.boolValue, u {
            out.append(MacConfigSetting(
                category: .firewall, key: "firewall.unload", name: "Firewall unloaded",
                value: "true",
                interpretation: "The firewall service was explicitly unloaded (firewallunload=1).",
                risk: .high, attackID: "T1562.004", attackName: "Disable or Modify System Firewall",
                domain: dom, scope: scope, sourceFile: src))
        }
        if let l = num(d, "loggingenabled")?.boolValue, !l {
            out.append(MacConfigSetting(
                category: .firewall, key: "firewall.logging", name: "Firewall logging",
                value: "off",
                interpretation: "Firewall connection logging is disabled (the appfirewall.log trail is lost).",
                risk: .medium, attackID: "T1562.001", attackName: "Impair Defenses",
                domain: dom, scope: scope, sourceFile: src))
        }
        if let s = num(d, "stealthenabled")?.boolValue {
            out.append(MacConfigSetting(
                category: .firewall, key: "firewall.stealth", name: "Firewall stealth mode",
                value: s ? "on" : "off",
                interpretation: s ? "Stealth mode is on (host ignores probes)."
                    : "Stealth mode is off (host answers probes — easier to enumerate).",
                risk: s ? .none : .low,
                attackID: s ? nil : "T1562.004", attackName: s ? nil : "Disable or Modify System Firewall",
                domain: dom, scope: scope, sourceFile: src))
        }
        return out
    }

    private static func screenLock(_ d: [String: Any], _ src: String, _ scope: String) -> [MacConfigSetting] {
        // Only emit when the key is present — an absent key is "undetermined",
        // not "no password" (avoids a false "screen lock disabled" finding).
        guard let ask = num(d, "askForPassword")?.boolValue else { return [] }
        var out: [MacConfigSetting] = []
        out.append(MacConfigSetting(
            category: .screenLock, key: "screenlock.askForPassword",
            name: "Screen-lock password", value: ask ? "required" : "not required",
            interpretation: ask ? "A password is required to dismiss the screensaver/lock."
                : "No password is required to dismiss the screensaver — the lock is bypassed.",
            risk: ask ? .none : .medium,
            attackID: ask ? nil : "T1562.001", attackName: ask ? nil : "Impair Defenses",
            domain: "com.apple.screensaver", scope: scope, sourceFile: src))
        if ask, let delay = num(d, "askForPasswordDelay")?.doubleValue, delay >= 300 {
            out.append(MacConfigSetting(
                category: .screenLock, key: "screenlock.delay",
                name: "Screen-lock grace period", value: "\(Int(delay))s",
                interpretation: "A \(Int(delay))-second grace period elapses before a password is demanded, "
                    + "weakening the lock.",
                risk: .low, attackID: "T1562.001", attackName: "Impair Defenses",
                domain: "com.apple.screensaver", scope: scope, sourceFile: src))
        }
        return out
    }

    private static func softwareUpdate(_ d: [String: Any], _ src: String, _ scope: String) -> [MacConfigSetting] {
        var out: [MacConfigSetting] = []
        let dom = "com.apple.SoftwareUpdate"
        func flag(_ key: String, _ name: String, _ k: String, secureWhenTrue: Bool = true,
                  risk: MacConfigSetting.Risk) {
            guard let b = num(d, k)?.boolValue else { return }
            let secure = secureWhenTrue ? b : !b
            out.append(MacConfigSetting(
                category: .softwareUpdate, key: key, name: name,
                value: b ? "enabled" : "disabled",
                interpretation: secure ? "\(name) is enabled." : "\(name) is DISABLED.",
                risk: secure ? .none : risk,
                attackID: secure ? nil : "T1562.001", attackName: secure ? nil : "Impair Defenses",
                domain: dom, scope: scope, sourceFile: src))
        }
        flag("update.criticalInstall", "Automatic security updates", "CriticalUpdateInstall", risk: .high)
        flag("update.configDataInstall", "Security config / definition updates", "ConfigDataInstall", risk: .high)
        flag("update.autoCheck", "Automatic update check", "AutomaticCheckEnabled", risk: .medium)
        flag("update.autoDownload", "Automatic update download", "AutomaticDownload", risk: .low)
        if let date = d["LastFullSuccessfulDate"] as? Date {
            out.append(MacConfigSetting(
                category: .softwareUpdate, key: "update.lastFull", name: "Last successful update",
                value: date.formatted(date: .abbreviated, time: .omitted),
                interpretation: "Last full successful software update: \(date.formatted(date: .long, time: .omitted)).",
                risk: .none, domain: dom, scope: scope, sourceFile: src))
        }
        return out
    }

    private static func commerce(_ d: [String: Any], _ src: String, _ scope: String) -> [MacConfigSetting] {
        guard let b = num(d, "AutoUpdate")?.boolValue else { return [] }
        return [MacConfigSetting(
            category: .softwareUpdate, key: "update.appAutoUpdate", name: "Automatic app updates",
            value: b ? "enabled" : "disabled",
            interpretation: b ? "Automatic App Store app updates are enabled."
                : "Automatic App Store app updates are disabled.",
            risk: .none, domain: "com.apple.commerce", scope: scope, sourceFile: src)]
    }

    private static func gatekeeper(_ d: [String: Any], _ src: String, _ scope: String) -> [MacConfigSetting] {
        // /var/db/SystemPolicy-prefs.plist — `enabled` = "no" ⇒ `spctl --master-disable`.
        // `enabled` is canonically the string "yes"/"no" but can be written as a
        // CFBoolean/CFNumber — handle both halves symmetrically so a `false`
        // (Gatekeeper DISABLED) isn't silently dropped. Absent key ⇒ undetermined.
        let on: Bool
        if let s = d["enabled"] as? String {
            let v = s.lowercased(); on = (v == "yes" || v == "true")
        } else if let b = num(d, "enabled")?.boolValue {
            on = b
        } else {
            return []
        }
        return [MacConfigSetting(
            category: .gatekeeper, key: "gatekeeper.enabled", name: "Gatekeeper assessment",
            value: on ? "enabled" : "disabled",
            interpretation: on ? "Gatekeeper assessment is enabled."
                : "Gatekeeper is DISABLED (spctl --master-disable) — unsigned/unnotarised apps run freely.",
            risk: on ? .none : .high,
            attackID: on ? nil : "T1562.001", attackName: on ? nil : "Impair Defenses",
            domain: "com.apple.security", scope: scope, sourceFile: src)]
    }

    private static func loginWindow(_ d: [String: Any], _ src: String, _ scope: String) -> [MacConfigSetting] {
        // System copy only (the caller filters out per-user loginwindow plists).
        // Login/logout HOOKS are owned by MacPersistenceParser — not emitted here.
        var out: [MacConfigSetting] = []
        let dom = "com.apple.loginwindow"
        if let user = (d["autoLoginUser"] as? String), !user.isEmpty {
            out.append(MacConfigSetting(
                category: .loginWindow, key: "loginwindow.autoLoginUser",
                name: "Automatic login", value: user,
                interpretation: "Automatic login is enabled for '\(user)' — the console unlocks at boot "
                    + "with no password.",
                risk: .high, attackID: "T1078", attackName: "Valid Accounts",
                domain: dom, scope: scope, sourceFile: src))
        }
        if let guest = num(d, "GuestEnabled")?.boolValue, guest {
            out.append(MacConfigSetting(
                category: .loginWindow, key: "loginwindow.guest", name: "Guest account",
                value: "enabled",
                interpretation: "The Guest login account is enabled (unauthenticated local access).",
                risk: .medium, attackID: "T1078", attackName: "Valid Accounts",
                domain: dom, scope: scope, sourceFile: src))
        }
        if let hidden = d["HiddenUsersList"] as? [String], !hidden.isEmpty {
            out.append(MacConfigSetting(
                category: .account, key: "loginwindow.hiddenUsers", name: "Hidden login accounts",
                value: hidden.joined(separator: ", "),
                interpretation: "Accounts hidden from the login window: \(hidden.joined(separator: ", ")). "
                    + "A hidden account that maps to a real shell/admin user is a stealth-persistence tell — "
                    + "cross-check the user inventory.",
                risk: .high, attackID: "T1564.002", attackName: "Hidden Users",
                domain: dom, scope: scope, sourceFile: src))
        }
        if let banner = (d["LoginwindowText"] as? String), !banner.isEmpty {
            out.append(MacConfigSetting(
                category: .loginWindow, key: "loginwindow.banner", name: "Login banner",
                value: banner,
                interpretation: "Login-window banner text is set.",
                risk: .none, domain: dom, scope: scope, sourceFile: src))
        }
        return out
    }

    private static func remoteManagement(_ d: [String: Any], _ src: String, _ scope: String) -> [MacConfigSetting] {
        var out: [MacConfigSetting] = []
        let dom = "com.apple.RemoteManagement"
        if let all = num(d, "ARD_AllLocalUsers")?.boolValue, all {
            out.append(MacConfigSetting(
                category: .remoteAccess, key: "ard.allLocalUsers", name: "ARD access for all users",
                value: "enabled",
                interpretation: "Apple Remote Desktop grants access to ALL local users — broad remote-control "
                    + "exposure (typically set by `kickstart -allUsers`).",
                risk: .high, attackID: "T1021.001", attackName: "Remote Desktop Protocol",
                domain: dom, scope: scope, sourceFile: src))
        }
        return out
    }

    /// The launchd enable/disable overrides — the authoritative "is this remote
    /// service on" source. Handles both the modern flat `disabled.plist`
    /// (label → Bool, the Bool is the *disabled* flag, so `false` ⇒ ENABLED) and
    /// the pre-10.10 `overrides.plist` (label → {Disabled: Bool, …}).
    private static func remoteServices(_ d: [String: Any], _ src: String, _ scope: String) -> [MacConfigSetting] {
        var out: [MacConfigSetting] = []
        for (label, spec) in services {
            // Resolve the disabled flag across both layouts.
            var disabled: Bool?
            if let b = d[label] as? Bool { disabled = b }
            else if let n = d[label] as? NSNumber { disabled = n.boolValue }
            else if let sub = d[label] as? [String: Any] {
                if let b = sub["Disabled"] as? Bool { disabled = b }
                else if let n = sub["Disabled"] as? NSNumber { disabled = n.boolValue }
            }
            // Risky state = present and explicitly enabled (disabled == false).
            guard disabled == false else { continue }
            out.append(MacConfigSetting(
                category: spec.category, key: "service.\(label)", name: spec.name,
                value: "enabled",
                interpretation: "\(spec.name) is enabled (launchd override un-disables \(label)).",
                risk: spec.risk, attackID: spec.attackID, attackName: spec.attackName,
                domain: label, scope: scope, sourceFile: src))
        }
        return out
    }

    private struct ServiceSpec {
        let name: String; let category: MacConfigSetting.Category
        let risk: MacConfigSetting.Risk; let attackID: String; let attackName: String
    }
    private static let services: [String: ServiceSpec] = [
        "com.openssh.sshd": ServiceSpec(name: "Remote Login (SSH)", category: .remoteAccess,
            risk: .high, attackID: "T1021.004", attackName: "SSH"),
        "com.apple.screensharing": ServiceSpec(name: "Screen Sharing (VNC)", category: .remoteAccess,
            risk: .high, attackID: "T1021.001", attackName: "Remote Desktop Protocol"),
        "com.apple.RemoteDesktop.agent": ServiceSpec(name: "Apple Remote Desktop (ARD)", category: .remoteAccess,
            risk: .high, attackID: "T1021.001", attackName: "Remote Desktop Protocol"),
        "com.apple.RemoteManagement": ServiceSpec(name: "Remote Management", category: .remoteAccess,
            risk: .high, attackID: "T1021.001", attackName: "Remote Desktop Protocol"),
        "com.apple.AEServer": ServiceSpec(name: "Remote Apple Events", category: .remoteAccess,
            risk: .high, attackID: "T1021.001", attackName: "Remote Desktop Protocol"),
        "com.apple.smbd": ServiceSpec(name: "SMB File Sharing", category: .sharing,
            risk: .medium, attackID: "T1021.002", attackName: "SMB/Windows Admin Shares"),
        "com.apple.AppleFileServer": ServiceSpec(name: "AFP File Sharing", category: .sharing,
            risk: .medium, attackID: "T1021.002", attackName: "SMB/Windows Admin Shares"),
    ]

    // MARK: - Decoding helpers

    private static func dictionary(_ data: Data) -> [String: Any]? {
        (try? PropertyListSerialization.propertyList(from: data, options: [], format: nil)) as? [String: Any]
    }

    /// Read a key as a number, tolerating CFBoolean/CFNumber and numeric strings.
    private static func num(_ d: [String: Any], _ k: String) -> NSNumber? {
        if let n = d[k] as? NSNumber { return n }
        if let b = d[k] as? Bool { return NSNumber(value: b) }
        if let i = d[k] as? Int { return NSNumber(value: i) }
        if let s = d[k] as? String, let i = Int(s) { return NSNumber(value: i) }
        return nil
    }
}

#endif
