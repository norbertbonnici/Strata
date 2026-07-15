import Foundation

/// The Linux triage artifact a collected file should be parsed as — the pure
/// output of `LinuxArtifactClassifier.classify`.
public enum LinuxArtifactKind: Sendable, Equatable {
    case auth, utmp, shellHistory, cron, systemd, sysinfo
    case sshAuthorized, sshKnown, sshdConfig, sudoers, group, shadow
    case webAccess
    case systemdTimer, initScript, shellInit, xdgAutostart, ldPreload
    case packageDpkg, packageApt, packageYum, packageDnf
    case journald
    case audit, syslog, lastlog
    case lastlog2, sudoLog, appServerLog
}

/// Maps a collected file to the Linux artifact it should be parsed as, by path +
/// name. Pure and `nonisolated` so it runs off the main actor and is unit-testable
/// without an `AppModel`.
///
/// Correctness matters here beyond convenience: the parsers run over **every**
/// case regardless of the detected OS, so a loose match drags unrelated files
/// (e.g. a Windows `messagesxboxlogo.png`) into a Linux bucket and re-extracts
/// them on every open. Keep the matches path-anchored and slack-safe.
public nonisolated enum LinuxArtifactClassifier {
    public static func classify(_ entry: FileEntry) -> LinuxArtifactKind? {
        // Never classify a TSK `<name>-slack` pseudo-entry: it's the unused tail
        // of an allocated cluster, not a real file, and its name (e.g.
        // "messages.1-slack") can otherwise trip the rotation-prefix matches.
        guard !entry.isDirectory, !entry.isDeleted, entry.size > 0,
              !entry.isSlackEntry else { return nil }
        let path = entry.fullPath.lowercased()
        let name = entry.name.lowercased()
        let isGz = name.hasSuffix(".gz")
        // systemd journal: binary, under /var/log/journal/<machine-id>/.
        // (.journal~ are rotated/corrupt copies - parsed too, best effort.)
        if path.contains("/var/log/journal/"),
           name.hasSuffix(".journal") || name.hasSuffix(".journal~") {
            return .journald
        }
        // auditd log + rotations (audit.log, audit.log.1 …; not gzipped).
        if path.contains("/var/log/audit/"), name.hasPrefix("audit.log") {
            return .audit
        }
        // lastlog binary (no extension); not under a deeper dir.
        if path.hasSuffix("/var/log/lastlog") { return .lastlog }
        // Modern Ubuntu (glibc ≥ 2.40) last-login SQLite store.
        if name == "lastlog2.db" { return .lastlog2 }
        // sudo's own logfile (when `logfile` is configured), distinct from auth.log.
        if !isGz, path.hasSuffix("/var/log/sudo") || name == "sudo.log"
            || name.hasPrefix("sudo.log.") { return .sudoLog }
        // App-server request logs (reverse-proxy-less Rails/puma/Node) that the
        // nginx/apache classifier misses. Gated to well-known names to avoid noise.
        if !isGz, name == "production.log" || name == "development.log"
            || name == "staging.log"
            || (path.contains("/log/") && name.hasPrefix("puma")) {
            return .appServerLog
        }
        // General system log + rotations (syslog, syslog.1, messages,
        // messages.1, messages-YYYYMMDD, kern.log, kern.log.1). The bare files
        // match by exact /var/log/ path; the rotation-name prefixes are gated
        // on /var/log/ so a non-log file that merely *starts with* "messages" /
        // "syslog." / "kern.log" (e.g. the Windows Store asset
        // messagesxboxlogo.png) isn't misclassified as a syslog and dragged
        // through extraction on every case open.
        let inVarLog = path.contains("/var/log/")
        if path.hasSuffix("/var/log/syslog")
            || path.hasSuffix("/var/log/messages")
            || path.hasSuffix("/var/log/kern.log")
            || (inVarLog && (name.hasPrefix("syslog.")
                             || name.hasPrefix("messages.") || name.hasPrefix("messages-")
                             || name.hasPrefix("kern.log"))) {
            // skip .gz rotations (handled generally below)
            if !isGz { return .syslog }
        }
        if path.contains("/var/log/") {
            // auth.log / secure incl. rotations (auth.log.2.gz) - the gz is
            // decompressed in the handler. Other .gz logs aren't parsed here.
            if name.hasPrefix("auth.log") || name.hasPrefix("secure") {
                return .auth
            }
            if !isGz, name == "wtmp" || name == "btmp"
                || name.hasPrefix("wtmp.") || name.hasPrefix("btmp.") {
                return .utmp
            }
            // nginx/apache access logs (incl. .gz rotations + vhost-named
            // *access*.log) under their server dirs.
            if name.contains("access"), name.contains(".log"),
               path.contains("/nginx/") || path.contains("/apache2/")
                || path.contains("/httpd/") {
                return .webAccess
            }
            // Package-manager logs (incl. .gz rotations).
            if name.hasPrefix("dpkg.log") { return .packageDpkg }
            if path.contains("/apt/") && name.hasPrefix("history.log") { return .packageApt }
            if name.hasPrefix("yum.log") { return .packageYum }
            if name.hasPrefix("dnf.rpm.log") { return .packageDnf }
        }
        if isGz { return nil }   // only specific rotations are read compressed
        // Persistence: systemd timers (anywhere under systemd dirs incl. user units).
        if entry.fileExtension == "timer",
           path.contains("/systemd/system") || path.contains("/.config/systemd/") {
            return .systemdTimer
        }
        // User systemd service units (system .service handled below).
        if entry.fileExtension == "service", path.contains("/.config/systemd/") {
            return .systemd
        }
        if path.hasSuffix("/etc/ld.so.preload") { return .ldPreload }
        if path.hasSuffix("/.config/autostart") == false, name.hasSuffix(".desktop"),
           path.contains("/autostart/") {
            return .xdgAutostart
        }
        // Boot / periodic shell scripts.
        if path.hasSuffix("/etc/rc.local") || path.contains("/etc/init.d/")
            || path.contains("/etc/cron.hourly/") || path.contains("/etc/cron.daily/")
            || path.contains("/etc/cron.weekly/") || path.contains("/etc/cron.monthly/") {
            return .initScript
        }
        // Shell-init files (exec-line filtered in the handler).
        if name == ".bashrc" || name == ".bash_profile" || name == ".profile"
            || name == ".bash_login" || path.contains("/etc/profile.d/")
            || path.hasSuffix("/etc/bash.bashrc") || path.hasSuffix("/etc/profile") {
            return .shellInit
        }
        if name == ".bash_history" || name == ".zsh_history" {
            return .shellHistory
        }
        // SSH trust artifacts.
        if name == "authorized_keys" || name == "authorized_keys2" {
            return .sshAuthorized
        }
        if name == "known_hosts" || path.hasSuffix("/etc/ssh/ssh_known_hosts") {
            return .sshKnown
        }
        if path.hasSuffix("/etc/ssh/sshd_config") { return .sshdConfig }
        // Privilege.
        if path.hasSuffix("/etc/sudoers") || path.contains("/etc/sudoers.d/") {
            return .sudoers
        }
        if path.hasSuffix("/etc/group") { return .group }
        if path.hasSuffix("/etc/shadow") { return .shadow }
        if path.hasSuffix("/etc/crontab") || path.contains("/etc/cron.d/")
            || path.contains("/var/spool/cron") {
            return .cron
        }
        if entry.fileExtension == "service", path.contains("/etc/systemd/system") {
            return .systemd
        }
        if path.hasSuffix("/etc/os-release") || path.hasSuffix("/usr/lib/os-release")
            || path.hasSuffix("/etc/hostname") || path.hasSuffix("/etc/passwd")
            || path.hasSuffix("/etc/timezone") {
            return .sysinfo
        }
        // Network configuration → host IPs for the Overview.
        if path.contains("/etc/netplan/"), name.hasSuffix(".yaml") || name.hasSuffix(".yml") {
            return .sysinfo
        }
        if path.hasSuffix("/etc/network/interfaces")
            || path.contains("/etc/network/interfaces.d/") {
            return .sysinfo
        }
        return nil
    }
}
