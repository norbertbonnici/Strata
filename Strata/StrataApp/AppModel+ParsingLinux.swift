import Foundation
import SwiftUI

#if os(macOS)

extension AppModel {
    // MARK: - Linux artifact parsing

    /// Parse the Linux triage artifacts in every loaded evidence that doesn't
    /// already have them: auth logs (`auth.log`/`secure`), wtmp/btmp login
    /// records, per-user shell history, cron + systemd persistence, and the
    /// host-info files (os-release / hostname / passwd / timezone). All
    /// parsers are pure Swift (text or fixed-layout binary - no vendored
    /// tool); extraction mirrors `parsePrefetch` (icat for images, in-place
    /// for loose folders, e.g. a UAC collection). A Windows host has no
    /// candidates and is skipped silently, so this is safe in the standard
    /// `parseArtifacts` chain. Does NOT run analyzers.
    func parseLinux() async {
        guard !isWorking else { return }   // single-flight: don't overlap parse passes
        guard !evidenceList.isEmpty else {
            errorMessage = "No evidence loaded."
            return
        }
        errorMessage = nil
        isWorking = true
        defer {
            isWorking = false
            progress = nil
        }

        // The file→artifact classifier now lives in the pure, unit-tested
        // `LinuxArtifactClassifier` (extracted so its path-anchoring / slack
        // handling can be tested without an AppModel).
        typealias LinuxKind = LinuxArtifactKind

        func candidates(_ state: EvidenceState) -> [(FileEntry, LinuxKind)] {
            state.files.compactMap { entry in LinuxArtifactClassifier.classify(entry).map { (entry, $0) } }
        }

        // A host is parsed once *per artifact bucket*: each `LinuxKind` feeds one
        // bucket (the per-tab data set). We re-parse a host when its file tree
        // offers candidates for a bucket that has no data in state yet - which is
        // how cases parsed by an older build backfill newly-added artifact types
        // (journald/syslog/packages/accounts/sysinfo) instead of being skipped
        // wholesale by a coarse "any Linux artifact present" guard. The re-parse
        // is a full rebuild from the (stable) file tree, so already-filled buckets
        // are re-derived identically - no clobber.
        enum LinuxBucket: Hashable {
            case auth, logins, shellHistory, persistence, sysinfo, access
            case web, packages, journald, audit, syslog, lastlog
        }
        func bucket(for kind: LinuxKind) -> LinuxBucket {
            switch kind {
            case .auth: return .auth
            case .utmp: return .logins
            case .shellHistory: return .shellHistory
            case .cron, .systemd, .systemdTimer, .initScript, .shellInit,
                 .ldPreload, .xdgAutostart: return .persistence
            case .sysinfo: return .sysinfo
            case .sshAuthorized, .sshKnown, .sshdConfig, .sudoers, .group, .shadow:
                return .access
            case .webAccess, .appServerLog: return .web
            case .packageDpkg, .packageApt, .packageYum, .packageDnf: return .packages
            case .journald: return .journald
            case .audit: return .audit
            case .syslog: return .syslog
            case .lastlog, .lastlog2: return .lastlog
            case .sudoLog: return .auth
            }
        }
        func neededBuckets(_ state: EvidenceState) -> Set<LinuxBucket> {
            Set(candidates(state).map { bucket(for: $0.1) })
        }
        func filledBuckets(_ state: EvidenceState) -> Set<LinuxBucket> {
            var s: Set<LinuxBucket> = []
            if !state.authLog.isEmpty { s.insert(.auth) }
            if !state.logins.isEmpty { s.insert(.logins) }
            if !state.shellHistory.isEmpty { s.insert(.shellHistory) }
            if !state.linuxPersistence.isEmpty { s.insert(.persistence) }
            if state.linuxInfo != nil { s.insert(.sysinfo) }
            if state.linuxAccess != nil { s.insert(.access) }
            if !state.webAccess.isEmpty { s.insert(.web) }
            if !state.packages.isEmpty { s.insert(.packages) }
            if !state.journald.isEmpty { s.insert(.journald) }
            if !state.audit.isEmpty { s.insert(.audit) }
            if !state.syslog.isEmpty { s.insert(.syslog) }
            if !state.lastlog.isEmpty { s.insert(.lastlog) }
            return s
        }
        /// Parse this host when any bucket it has candidates for is still empty.
        func needsParse(_ state: EvidenceState) -> Bool {
            !neededBuckets(state).subtracting(filledBuckets(state)).isEmpty
        }

        let totalCandidates = evidenceList.reduce(0) { acc, evidence in
            guard let state = states[evidence.id], needsParse(state) else { return acc }
            return acc + candidates(state).count
        }
        guard totalCandidates > 0 else {
            statusMessage = "No new Linux artifacts to parse."
            return
        }
        progress = ProgressInfo(current: 0, total: totalCandidates, label: "Parsing Linux artifacts")
        var completed = 0

        do {
            let tskEnv = try TSKEnvironment.discover()

            for evidence in evidenceList {
                guard var state = states[evidence.id] else { continue }
                guard needsParse(state) else { continue }
                let found = candidates(state)
                guard !found.isEmpty else { continue }

                // Image hosts need TSK to pull each file out of the image;
                // loose folders read the file in place.
                let isLoose = evidence.kind == .kapeLooseFolder
                var database: TSKDatabase?
                var extractor: TSKFileExtractor?
                var scratch: URL?
                if !isLoose {
                    guard let dbURL = state.dbURL else { continue }
                    database = try TSKDatabase(path: dbURL)
                    extractor = TSKFileExtractor(
                        environment: tskEnv,
                        imageURL: evidence.sourceURL,
                        imageType: TSKImageIngestor.imageType(for: evidence.sourceURL))
                    guard let bundleURL = currentCaseBundleURL else { continue }
                    let dir = CaseStore.linuxScratchDirectory(forHostID: evidence.id, in: bundleURL)
                    try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
                    scratch = dir
                }

                var authLog: [AuthLogEntry] = []
                var logins: [UtmpRecord] = []
                var shellHistory: [ShellHistoryEntry] = []
                var persistence: [LinuxPersistenceEntry] = []
                var info = LinuxHostInfo()
                var access = LinuxAccessInfo()
                var web: [WebAccessLogEntry] = []
                var packages: [PackageEvent] = []
                var journald: [JournaldEntry] = []
                var audit: [AuditEvent] = []
                var syslog: [SyslogEntry] = []
                var lastlog: [LastlogEntry] = []

                for (entry, kind) in found {
                    progress = ProgressInfo(
                        current: completed,
                        total: totalCandidates,
                        label: "\(evidence.displayName): \(entry.name)")
                    defer { completed += 1 }

                    let fileURL: URL
                    if isLoose {
                        guard let disk = entry.diskURL,
                              FileManager.default.fileExists(atPath: disk.path) else { continue }
                        fileURL = disk
                    } else {
                        guard let extractInfo = try database!.fetchExtractInfo(forFileID: entry.id) else {
                            continue
                        }
                        let outURL = scratch!.appendingPathComponent("\(entry.id)-\(entry.name.scratchSafeComponent)")
                        do {
                            try await extractor!.extract(metaAddr: extractInfo.metaAddr,
                                                         imageOffsetSectors: extractInfo.imageOffsetSectors,
                                                         to: outURL)
                        } catch {
                            // One file's extraction failure must not abort the whole
                            // pass (discarding partials + skipping later hosts): record
                            // it and move on. Bytes are adversary-controlled.
                            statusMessage = "\(evidence.displayName): \(entry.name) — extraction failed (\(error.localizedDescription))"
                            continue
                        }
                        fileURL = outURL
                    }
                    // A malformed file shouldn't abort the whole run.
                    guard let rawData = try? Data(contentsOf: fileURL) else { continue }
                    // Transparently gunzip rotated auth logs (auth.log.2.gz).
                    let data: Data = entry.name.lowercased().hasSuffix(".gz")
                        ? ((try? GzipDecoder.decompress(rawData)) ?? rawData)
                        : rawData
                    func text() -> String { String(decoding: data, as: UTF8.self) }
                    let owner = ShellHistoryParser.user(fromPath: entry.fullPath)

                    switch kind {
                    case .utmp:
                        let isBtmp = entry.name.lowercased().hasPrefix("btmp")
                        logins.append(contentsOf: UtmpParser.parse(
                            data: data, sourceFile: entry.fullPath, isFailedLogin: isBtmp))
                    case .auth:
                        authLog.append(contentsOf: AuthLogParser.parse(
                            text: text(),
                            sourceFile: entry.fullPath,
                            anchor: entry.modified))
                    case .shellHistory:
                        let shell: ShellHistoryEntry.Shell =
                            entry.name.lowercased().contains("zsh") ? .zsh : .bash
                        shellHistory.append(contentsOf: ShellHistoryParser.parse(
                            text: String(decoding: data, as: UTF8.self),
                            user: ShellHistoryParser.user(fromPath: entry.fullPath),
                            shell: shell, sourceFile: entry.fullPath))
                    case .cron:
                        let isSpool = entry.fullPath.lowercased().contains("/var/spool/cron")
                        persistence.append(contentsOf: LinuxPersistenceParser.parseCrontab(
                            text: String(decoding: data, as: UTF8.self),
                            sourceFile: entry.fullPath,
                            hasUserField: !isSpool,
                            defaultUser: isSpool ? entry.name : nil))
                    case .systemdTimer:
                        if let timer = LinuxPersistenceParser.parseSystemdTimer(
                            text: text(), sourceFile: entry.fullPath) {
                            persistence.append(timer)
                        }
                    case .ldPreload:
                        persistence.append(contentsOf: LinuxPersistenceParser.parseLdPreload(
                            text: text(), sourceFile: entry.fullPath))
                    case .xdgAutostart:
                        if let auto = LinuxPersistenceParser.parseAutostart(
                            text: text(), sourceFile: entry.fullPath) {
                            persistence.append(auto)
                        }
                    case .initScript:
                        persistence.append(contentsOf: LinuxPersistenceParser.parseScript(
                            text: text(), kind: .initScript, sourceFile: entry.fullPath,
                            suspiciousOnly: false))
                    case .shellInit:
                        persistence.append(contentsOf: LinuxPersistenceParser.parseScript(
                            text: text(), kind: .shellInit, sourceFile: entry.fullPath,
                            user: owner, suspiciousOnly: true))
                    case .packageDpkg:
                        packages.append(contentsOf: PackageParser.parseDpkgLog(
                            text: text(), sourceFile: entry.fullPath))
                    case .packageApt:
                        packages.append(contentsOf: PackageParser.parseAptHistory(
                            text: text(), sourceFile: entry.fullPath))
                    case .packageYum:
                        packages.append(contentsOf: PackageParser.parseYumLog(
                            text: text(), sourceFile: entry.fullPath, anchor: entry.modified, manager: .yum))
                    case .packageDnf:
                        packages.append(contentsOf: PackageParser.parseYumLog(
                            text: text(), sourceFile: entry.fullPath, anchor: entry.modified, manager: .dnf))
                    case .journald:
                        journald.append(contentsOf: JournaldParser.parse(
                            data: data, sourceFile: entry.fullPath))
                    case .audit:
                        audit.append(contentsOf: AuditParser.parse(
                            text: text(), sourceFile: entry.fullPath))
                    case .syslog:
                        syslog.append(contentsOf: SyslogParser.parse(
                            text: text(), sourceFile: entry.fullPath, anchor: entry.modified))
                    case .lastlog:
                        lastlog.append(contentsOf: LastlogParser.parse(
                            data: data, sourceFile: entry.fullPath))
                    case .lastlog2:
                        // SQLite store → parse from the file path (not the byte
                        // buffer). UIDs are name-keyed; resolved post-loop against
                        // /etc/passwd alongside the binary-lastlog resolution.
                        lastlog.append(contentsOf: (try? Lastlog2Parser.parse(
                            fileAt: fileURL, sourceFile: entry.fullPath)) ?? [])
                    case .sudoLog:
                        authLog.append(contentsOf: SudoLogParser.parse(
                            text: text(), sourceFile: entry.fullPath, anchor: entry.modified))
                    case .appServerLog:
                        web.append(contentsOf: AppServerLogParser.parse(
                            text: text(), sourceFile: entry.fullPath))
                    case .systemd:
                        if let unit = LinuxPersistenceParser.parseSystemdUnit(
                            text: String(decoding: data, as: UTF8.self),
                            sourceFile: entry.fullPath) {
                            persistence.append(unit)
                        }
                    case .sysinfo:
                        let body = text()
                        let path = entry.fullPath.lowercased()
                        if path.hasSuffix("os-release") {
                            LinuxHostInfoParser.applyOSRelease(body, to: &info)
                        } else if path.hasSuffix("hostname") {
                            LinuxHostInfoParser.applyHostname(body, to: &info)
                        } else if path.hasSuffix("passwd") {
                            LinuxHostInfoParser.applyPasswd(body, to: &info)
                        } else if path.hasSuffix("timezone") {
                            LinuxHostInfoParser.applyTimezone(body, to: &info)
                        } else if path.contains("/netplan/") {
                            LinuxHostInfoParser.applyNetplan(body, to: &info)
                        } else if path.contains("/network/interfaces") {
                            LinuxHostInfoParser.applyInterfaces(body, to: &info)
                        }
                    case .sshAuthorized:
                        access.sshKeys.append(contentsOf: LinuxAccessParser.parseAuthorizedKeys(
                            text: text(), user: owner, sourceFile: entry.fullPath))
                    case .sshKnown:
                        access.sshKeys.append(contentsOf: LinuxAccessParser.parseKnownHosts(
                            text: text(), user: owner, sourceFile: entry.fullPath))
                    case .sshdConfig:
                        access.sshdSettings.merge(LinuxAccessParser.parseSSHDConfig(text: text())) { _, new in new }
                        access.sshdSourceFile = entry.fullPath
                    case .sudoers:
                        access.sudoRules.append(contentsOf: LinuxAccessParser.parseSudoers(
                            text: text(), sourceFile: entry.fullPath))
                    case .group:
                        access.groups = LinuxAccessParser.parseGroup(text: text())
                    case .shadow:
                        access.shadow = LinuxAccessParser.parseShadow(text: text())
                    case .webAccess:
                        let server: WebAccessLogEntry.Server =
                            entry.fullPath.lowercased().contains("/nginx/") ? .nginx
                            : (entry.fullPath.lowercased().contains("/apache2/")
                               || entry.fullPath.lowercased().contains("/httpd/")) ? .apache
                            : .unknown
                        web.append(contentsOf: WebLogParser.parseAccess(
                            text: text(), sourceFile: entry.fullPath, server: server))
                    }
                }

                // Newest-first for the list views; shell history keeps file +
                // line order (undated bash entries have no clock to sort by).
                authLog.sort { ($0.timestamp ?? .distantPast) > ($1.timestamp ?? .distantPast) }
                logins.sort { ($0.timestamp ?? .distantPast) > ($1.timestamp ?? .distantPast) }

                state.authLog = authLog
                state.logins = logins
                state.shellHistory = shellHistory
                web.sort { ($0.timestamp ?? .distantPast) > ($1.timestamp ?? .distantPast) }
                packages.sort { ($0.timestamp ?? .distantPast) > ($1.timestamp ?? .distantPast) }
                journald.sort { ($0.timestamp ?? .distantPast) > ($1.timestamp ?? .distantPast) }
                audit.sort { ($0.timestamp ?? .distantPast) > ($1.timestamp ?? .distantPast) }
                syslog.sort { ($0.timestamp ?? .distantPast) > ($1.timestamp ?? .distantPast) }
                // Resolve lastlog identities now that /etc/passwd is parsed:
                // binary lastlog is UID-keyed (fill the username); lastlog2.db is
                // name-keyed with a -1 UID sentinel (fill the UID).
                if !info.users.isEmpty {
                    let byUid = Dictionary(info.users.map { ($0.uid, $0.name) },
                                           uniquingKeysWith: { first, _ in first })
                    let byName = Dictionary(info.users.map { ($0.name, $0.uid) },
                                            uniquingKeysWith: { first, _ in first })
                    lastlog = lastlog.map { e in
                        if e.user == nil, let name = byUid[e.uid] {
                            return LastlogEntry(uid: e.uid, user: name, timestamp: e.timestamp,
                                                line: e.line, host: e.host, sourceFile: e.sourceFile)
                        }
                        if e.uid < 0, let user = e.user, let uid = byName[user] {
                            return LastlogEntry(uid: uid, user: user, timestamp: e.timestamp,
                                                line: e.line, host: e.host, sourceFile: e.sourceFile)
                        }
                        return e
                    }
                }
                lastlog.sort { ($0.timestamp ?? .distantPast) > ($1.timestamp ?? .distantPast) }
                // Recover the host's runtime IP from the journal's DHCP/avahi
                // lease lines - the only record of a DHCP-assigned address. Done
                // after journald is built so static config (netplan) lists first.
                for ip in journald.flatMap({ LinuxNetworkParser.leaseAddresses(inMessage: $0.message) }) {
                    LinuxHostInfoParser.mergeIPs([ip], into: &info)
                }
                state.linuxPersistence = persistence
                state.linuxInfo = info.isEmpty ? nil : info
                state.linuxAccess = access.isEmpty ? nil : access
                state.webAccess = web
                state.packages = packages
                state.journald = journald
                state.audit = audit
                state.syslog = syslog
                state.lastlog = lastlog
                // Splice the timestamped Linux sources onto the timeline
                // (mirrors evtx; persistence entries carry no timestamps).
                state.timeline.removeAll {
                    $0.source == .authlog || $0.source == .logins
                        || $0.source == .shellHistory || $0.source == .weblog
                        || $0.source == .package || $0.source == .journald
                        || $0.source == .auditd || $0.source == .syslog || $0.source == .lastlog
                }
                state.timeline.append(contentsOf: TimelineBuilder.build(from: authLog))
                state.timeline.append(contentsOf: TimelineBuilder.build(from: logins))
                state.timeline.append(contentsOf: TimelineBuilder.build(from: shellHistory))
                state.timeline.append(contentsOf: TimelineBuilder.build(from: web))
                state.timeline.append(contentsOf: TimelineBuilder.build(from: packages))
                state.timeline.append(contentsOf: TimelineBuilder.build(from: journald))
                state.timeline.append(contentsOf: TimelineBuilder.build(from: audit))
                state.timeline.append(contentsOf: TimelineBuilder.build(from: syslog))
                state.timeline.append(contentsOf: TimelineBuilder.build(from: lastlog))
                state.timeline.sort { $0.date < $1.date }
                states[evidence.id] = state
                if let bundleURL = currentCaseBundleURL {
                    try? CaseStore.writeAuthLog(authLog, forHostID: evidence.id, in: bundleURL)
                    try? CaseStore.writeLogins(logins, forHostID: evidence.id, in: bundleURL)
                    try? CaseStore.writeShellHistory(shellHistory, forHostID: evidence.id, in: bundleURL)
                    try? CaseStore.writeLinuxPersistence(persistence, forHostID: evidence.id, in: bundleURL)
                    if let linuxInfo = state.linuxInfo {
                        try? CaseStore.writeLinuxInfo(linuxInfo, forHostID: evidence.id, in: bundleURL)
                    }
                    if let linuxAccess = state.linuxAccess {
                        try? CaseStore.writeLinuxAccess(linuxAccess, forHostID: evidence.id, in: bundleURL)
                    }
                    try? CaseStore.writeWebAccess(web, forHostID: evidence.id, in: bundleURL)
                    try? CaseStore.writePackages(packages, forHostID: evidence.id, in: bundleURL)
                    try? CaseStore.writeJournald(journald, forHostID: evidence.id, in: bundleURL)
                    try? CaseStore.writeAudit(audit, forHostID: evidence.id, in: bundleURL)
                    try? CaseStore.writeSyslog(syslog, forHostID: evidence.id, in: bundleURL)
                    try? CaseStore.writeLastlog(lastlog, forHostID: evidence.id, in: bundleURL)
                }
            }
            progress = ProgressInfo(current: completed, total: totalCandidates,
                                    label: "Linux artifact parse complete")
        } catch {
            self.errorMessage = error.localizedDescription
            self.statusMessage = ""
        }
    }
}

#endif
