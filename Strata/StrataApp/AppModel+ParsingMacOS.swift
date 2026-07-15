import Foundation
import SwiftUI

#if os(macOS)

extension AppModel {
    // MARK: - Messages parsing

    /// Parse the macOS Messages database (`chat.db`) for every loaded evidence
    /// that doesn't already have results. `chat.db` is SQLite/WAL like browser
    /// history, so this mirrors `parseBrowserHistory`: extract the DB (+ `-wal`/
    /// `-shm` sidecars) via the loose / icat / `fsapfscat` path, parse off-main
    /// with `MessagesParser`, splice onto the timeline, and persist.
    func parseMessages() async {
        guard !evidenceList.isEmpty else { return }
        errorMessage = nil
        isWorking = true
        defer { isWorking = false; progress = nil }

        func candidates(_ state: EvidenceState) -> [FileEntry] {
            state.files.filter {
                guard !$0.isDirectory, $0.size > 0, $0.name.lowercased() == "chat.db" else { return false }
                // Gate on the canonical Messages directory so an unrelated app's
                // chat.db (caches / app bundles) isn't extracted + probed.
                return $0.fullPath.lowercased().contains("/library/messages/")
            }
        }
        func macScope(_ path: String) -> String {
            let comps = path.split(separator: "/").map(String.init)
            if let i = comps.firstIndex(where: { $0.lowercased() == "users" }), i + 1 < comps.count { return comps[i + 1] }
            return "system"
        }

        let totalCandidates = evidenceList.reduce(0) { acc, e in
            guard let s = states[e.id], s.messages.isEmpty else { return acc }
            return acc + candidates(s).count
        }
        guard totalCandidates > 0 else { statusMessage = "No new Messages database to parse."; return }
        progress = ProgressInfo(current: 0, total: totalCandidates, label: "Parsing Messages")
        var completed = 0
        // Distinguish "chat.db found but couldn't be extracted to a readable DB"
        // (source/volume unavailable) from "valid DB, 0 messages recovered".
        var realStoresSeen = 0
        var totalCollected = 0

        do {
            let tskEnv = try TSKEnvironment.discover()
            for evidence in evidenceList {
                guard var state = states[evidence.id], state.messages.isEmpty else { continue }
                let found = candidates(state)
                guard !found.isEmpty else { continue }

                let isLoose = evidence.kind == .kapeLooseFolder
                let isAPFS = evidence.kind == .apfs
                var database: TSKDatabase?
                var extractor: TSKFileExtractor?
                var apfsExtractor: FsApfsExtractor?
                var scratch: URL?
                if !isLoose {
                    guard let bundleURL = currentCaseBundleURL else { continue }
                    let dir = CaseStore.messagesScratchDirectory(forHostID: evidence.id, in: bundleURL)
                    try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
                    scratch = dir
                    if isAPFS {
                        apfsExtractor = FsApfsExtractor(environment: tskEnv,
                                                        rawURL: evidence.apfsRawURL ?? evidence.sourceURL,
                                                        credential: fileVaultCredentials[evidence.id])
                    } else {
                        guard let dbURL = state.dbURL else { continue }
                        database = try TSKDatabase(path: dbURL)
                        extractor = TSKFileExtractor(environment: tskEnv, imageURL: evidence.sourceURL,
                                                     imageType: TSKImageIngestor.imageType(for: evidence.sourceURL))
                    }
                }

                var collected: [MessageEntry] = []
                for entry in found {
                    progress = ProgressInfo(current: completed, total: totalCandidates,
                                            label: "\(evidence.displayName): \(entry.name)")
                    defer { completed += 1 }
                    let fileURL: URL
                    if isLoose {
                        guard let disk = entry.diskURL,
                              FileManager.default.fileExists(atPath: disk.path) else { continue }
                        fileURL = disk
                    } else if isAPFS {
                        let outURL = scratch!.appendingPathComponent("\(entry.id)-\(entry.name.scratchSafeComponent)")
                        let off = state.volumes.first { $0.id == entry.fsID }?.offsetBytes ?? 0
                        try? await apfsExtractor!.extract(volumePath: entry.fullPath,
                                                          volumeIndex: entry.fsID ?? 0, offsetBytes: off, to: outURL)
                        for suffix in ["-wal", "-shm"] {
                            guard let side = state.files.first(where: {
                                !$0.isDirectory && $0.parentPath == entry.parentPath
                                    && $0.name.caseInsensitiveCompare(entry.name + suffix) == .orderedSame
                            }) else { continue }
                            let soff = state.volumes.first { $0.id == side.fsID }?.offsetBytes ?? 0
                            try? await apfsExtractor!.extract(volumePath: side.fullPath,
                                                              volumeIndex: side.fsID ?? 0, offsetBytes: soff,
                                                              to: URL(fileURLWithPath: outURL.path + suffix))
                        }
                        fileURL = outURL
                    } else {
                        guard let info = try database!.fetchExtractInfo(forFileID: entry.id) else { continue }
                        let outURL = scratch!.appendingPathComponent("\(entry.id)-\(entry.name.scratchSafeComponent)")
                        do {
                            try await extractor!.extract(metaAddr: info.metaAddr,
                                                         imageOffsetSectors: info.imageOffsetSectors, to: outURL)
                        } catch {
                            // One file's extraction failure must not abort the whole
                            // pass (discarding partials + skipping later hosts): record
                            // it and move on. Bytes are adversary-controlled.
                            statusMessage = "\(evidence.displayName): \(entry.name) — extraction failed (\(error.localizedDescription))"
                            continue
                        }
                        for suffix in ["-wal", "-shm"] {
                            guard let side = state.files.first(where: {
                                !$0.isDirectory && $0.parentPath == entry.parentPath
                                    && $0.name.caseInsensitiveCompare(entry.name + suffix) == .orderedSame
                            }), let sInfo = try? database!.fetchExtractInfo(forFileID: side.id) else { continue }
                            try? await extractor!.extract(metaAddr: sInfo.metaAddr,
                                                          imageOffsetSectors: sInfo.imageOffsetSectors,
                                                          to: URL(fileURLWithPath: outURL.path + suffix))
                        }
                        fileURL = outURL
                    }
                    // A valid SQLite header means extraction produced a real DB;
                    // its absence means the bytes never came across (missing source
                    // image / sealed or locked APFS volume), not "no messages".
                    if BrowserHistoryParser.isSQLiteDatabase(at: fileURL) { realStoresSeen += 1 }
                    let source = entry.fullPath
                    let scope = macScope(source)
                    do {
                        let parsed = try await Task.detached(priority: .userInitiated) {
                            try MessagesParser.parse(fileAt: fileURL, sourceFile: source, scope: scope)
                        }.value
                        collected.append(contentsOf: parsed)
                    } catch {
                        statusMessage = "\(evidence.displayName): \(entry.name) failed (\(error.localizedDescription))"
                    }
                }

                collected.sort { ($0.timestamp ?? .distantPast) > ($1.timestamp ?? .distantPast) }
                totalCollected += collected.count
                state.messages = collected
                state.timeline.removeAll { $0.source == .messages }
                state.timeline.append(contentsOf: TimelineBuilder.build(from: collected))
                state.timeline.sort { $0.date < $1.date }
                states[evidence.id] = state
                if let bundleURL = currentCaseBundleURL {
                    try? CaseStore.writeMessages(collected, forHostID: evidence.id, in: bundleURL)
                }
            }
            progress = ProgressInfo(current: completed, total: totalCandidates, label: "Messages parse complete")
            if totalCollected > 0 {
                statusMessage = "Parsed \(totalCollected) message\(totalCollected == 1 ? "" : "s")."
            } else if realStoresSeen == 0 {
                errorMessage = "Found chat.db but couldn't read it as a database — confirm the source "
                    + "image / APFS volume is available (a sealed System or locked FileVault volume "
                    + "returns no bytes)."
            } else {
                statusMessage = "chat.db parsed but no messages recovered — the database is empty, or its "
                    + "messages are in an uncheckpointed -wal that wasn't captured in the image."
            }
        } catch {
            self.errorMessage = error.localizedDescription
            self.statusMessage = ""
        }
    }


    // MARK: - Mail parsing

    /// Parse the macOS Mail `Envelope Index` for every loaded evidence that
    /// doesn't already have results. The Envelope Index is SQLite/WAL like
    /// Messages, so this mirrors `parseMessages`: extract the DB (+ `-wal`/`-shm`
    /// sidecars) via the loose / icat / `fsapfscat` path, parse off-main with
    /// `MailParser`, splice onto the timeline, and persist.
    func parseMail() async {
        guard !evidenceList.isEmpty else { return }
        errorMessage = nil
        isWorking = true
        defer { isWorking = false; progress = nil }

        func candidates(_ state: EvidenceState) -> [FileEntry] {
            state.files.filter {
                guard !$0.isDirectory, $0.size > 0 else { return false }
                // Mail's Envelope Index: ~/Library/Mail/V*/MailData/Envelope Index.
                return $0.name.lowercased() == "envelope index"
                    && $0.fullPath.lowercased().contains("/library/mail/")
            }
        }
        func macScope(_ path: String) -> String {
            let comps = path.split(separator: "/").map(String.init)
            if let i = comps.firstIndex(where: { $0.lowercased() == "users" }), i + 1 < comps.count { return comps[i + 1] }
            return "system"
        }

        let totalCandidates = evidenceList.reduce(0) { acc, e in
            guard let s = states[e.id], s.mail.isEmpty else { return acc }
            return acc + candidates(s).count
        }
        guard totalCandidates > 0 else { statusMessage = "No new Mail to parse."; return }
        progress = ProgressInfo(current: 0, total: totalCandidates, label: "Parsing Mail")
        var completed = 0
        var realStoresSeen = 0
        var totalCollected = 0

        do {
            let tskEnv = try TSKEnvironment.discover()
            for evidence in evidenceList {
                guard var state = states[evidence.id], state.mail.isEmpty else { continue }
                let found = candidates(state)
                guard !found.isEmpty else { continue }

                let isLoose = evidence.kind == .kapeLooseFolder
                let isAPFS = evidence.kind == .apfs
                var database: TSKDatabase?
                var extractor: TSKFileExtractor?
                var apfsExtractor: FsApfsExtractor?
                var scratch: URL?
                if !isLoose {
                    guard let bundleURL = currentCaseBundleURL else { continue }
                    let dir = CaseStore.mailScratchDirectory(forHostID: evidence.id, in: bundleURL)
                    try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
                    scratch = dir
                    if isAPFS {
                        apfsExtractor = FsApfsExtractor(environment: tskEnv,
                                                        rawURL: evidence.apfsRawURL ?? evidence.sourceURL,
                                                        credential: fileVaultCredentials[evidence.id])
                    } else {
                        guard let dbURL = state.dbURL else { continue }
                        database = try TSKDatabase(path: dbURL)
                        extractor = TSKFileExtractor(environment: tskEnv, imageURL: evidence.sourceURL,
                                                     imageType: TSKImageIngestor.imageType(for: evidence.sourceURL))
                    }
                }

                var collected: [MailMessageEntry] = []
                for entry in found {
                    progress = ProgressInfo(current: completed, total: totalCandidates,
                                            label: "\(evidence.displayName): \(entry.name)")
                    defer { completed += 1 }
                    let fileURL: URL
                    if isLoose {
                        guard let disk = entry.diskURL,
                              FileManager.default.fileExists(atPath: disk.path) else { continue }
                        fileURL = disk
                    } else if isAPFS {
                        let outURL = scratch!.appendingPathComponent("\(entry.id)-EnvelopeIndex")
                        let off = state.volumes.first { $0.id == entry.fsID }?.offsetBytes ?? 0
                        try? await apfsExtractor!.extract(volumePath: entry.fullPath,
                                                          volumeIndex: entry.fsID ?? 0, offsetBytes: off, to: outURL)
                        for suffix in ["-wal", "-shm"] {
                            guard let side = state.files.first(where: {
                                !$0.isDirectory && $0.parentPath == entry.parentPath
                                    && $0.name.caseInsensitiveCompare(entry.name + suffix) == .orderedSame
                            }) else { continue }
                            let soff = state.volumes.first { $0.id == side.fsID }?.offsetBytes ?? 0
                            try? await apfsExtractor!.extract(volumePath: side.fullPath,
                                                              volumeIndex: side.fsID ?? 0, offsetBytes: soff,
                                                              to: URL(fileURLWithPath: outURL.path + suffix))
                        }
                        fileURL = outURL
                    } else {
                        guard let info = try database!.fetchExtractInfo(forFileID: entry.id) else { continue }
                        let outURL = scratch!.appendingPathComponent("\(entry.id)-EnvelopeIndex")
                        do {
                            try await extractor!.extract(metaAddr: info.metaAddr,
                                                         imageOffsetSectors: info.imageOffsetSectors, to: outURL)
                        } catch {
                            // One file's extraction failure must not abort the whole
                            // pass (discarding partials + skipping later hosts): record
                            // it and move on. Bytes are adversary-controlled.
                            statusMessage = "\(evidence.displayName): \(entry.name) — extraction failed (\(error.localizedDescription))"
                            continue
                        }
                        for suffix in ["-wal", "-shm"] {
                            guard let side = state.files.first(where: {
                                !$0.isDirectory && $0.parentPath == entry.parentPath
                                    && $0.name.caseInsensitiveCompare(entry.name + suffix) == .orderedSame
                            }), let sInfo = try? database!.fetchExtractInfo(forFileID: side.id) else { continue }
                            try? await extractor!.extract(metaAddr: sInfo.metaAddr,
                                                          imageOffsetSectors: sInfo.imageOffsetSectors,
                                                          to: URL(fileURLWithPath: outURL.path + suffix))
                        }
                        fileURL = outURL
                    }
                    if BrowserHistoryParser.isSQLiteDatabase(at: fileURL) { realStoresSeen += 1 }
                    let source = entry.fullPath
                    let scope = macScope(source)
                    do {
                        let parsed = try await Task.detached(priority: .userInitiated) {
                            try MailParser.parse(fileAt: fileURL, sourceFile: source, scope: scope)
                        }.value
                        collected.append(contentsOf: parsed)
                    } catch {
                        statusMessage = "\(evidence.displayName): \(entry.name) failed (\(error.localizedDescription))"
                    }
                }

                collected.sort { ($0.timestamp ?? .distantPast) > ($1.timestamp ?? .distantPast) }
                totalCollected += collected.count
                state.mail = collected
                state.timeline.removeAll { $0.source == .mail }
                state.timeline.append(contentsOf: TimelineBuilder.build(from: collected))
                state.timeline.sort { $0.date < $1.date }
                states[evidence.id] = state
                if let bundleURL = currentCaseBundleURL {
                    try? CaseStore.writeMail(collected, forHostID: evidence.id, in: bundleURL)
                }
            }
            progress = ProgressInfo(current: completed, total: totalCandidates, label: "Mail parse complete")
            if totalCollected > 0 {
                statusMessage = "Parsed \(totalCollected) mail message\(totalCollected == 1 ? "" : "s")."
            } else if realStoresSeen == 0 {
                errorMessage = "Found the Mail Envelope Index but couldn't read it as a database — "
                    + "confirm the source image / APFS volume is available."
            } else {
                statusMessage = "Mail Envelope Index parsed but no messages recovered (empty index "
                    + "or an unrecognised schema)."
            }
        } catch {
            self.errorMessage = error.localizedDescription
            self.statusMessage = ""
        }
    }


    /// A gzip `/.fseventsd/` blob plus its source path, carried across the
    /// actor boundary into the off-main FSEvents parse.
    private struct FSEventsBlob: Sendable { let data: Data; let sourceFile: String }

    /// Parse macOS triage artifacts — launchd persistence plists
    /// (`/Library/Launch{Agents,Daemons}`, `~/Library/LaunchAgents`) and the
    /// LaunchServices quarantine store — for every host without results. Both
    /// are plain files (icat-extract for images, read-in-place for loose).
    func parseMac() async {
        guard !isWorking else { return }   // single-flight: don't overlap parse passes
        guard !evidenceList.isEmpty else { errorMessage = "No evidence loaded."; return }
        errorMessage = nil
        isWorking = true
        defer { isWorking = false; progress = nil }

        func plists(_ s: EvidenceState) -> [FileEntry] {
            s.files.filter {
                !$0.isDirectory && $0.size > 0 && $0.name.lowercased().hasSuffix(".plist")
                    && ($0.fullPath.contains("/LaunchAgents/") || $0.fullPath.contains("/LaunchDaemons/"))
            }
        }
        func quarantines(_ s: EvidenceState) -> [FileEntry] {
            s.files.filter {
                !$0.isDirectory && $0.size > 0
                    && $0.name == "com.apple.LaunchServices.QuarantineEventsV2"
            }
        }
        // The small files that identify the macOS host (SystemVersion.plist, the
        // SystemConfiguration preferences, and the dslocal user plists) - parsed
        // into one MacHostInfo for the Overview host card.
        func hostInfoFiles(_ s: EvidenceState) -> [FileEntry] {
            s.files.filter { entry in
                guard !entry.isDirectory, entry.size > 0 else { return false }
                let lower = entry.fullPath.lowercased()
                return lower.hasSuffix("/system/library/coreservices/systemversion.plist")
                    || lower.hasSuffix("/library/preferences/systemconfiguration/preferences.plist")
                    || lower.hasSuffix("/library/preferences/systemconfiguration/networkinterfaces.plist")
                    || (lower.contains("/dslocal/nodes/default/users/") && lower.hasSuffix(".plist"))
            }
        }
        // The non-launchd persistence sweep: cron, site-local periodic scripts,
        // emond rules, login/logout hooks, rc scripts, configuration profiles.
        // (Apple-stock /etc/periodic is intentionally NOT swept - it would be
        // all-noise; only /usr/local/etc/periodic, the documented site-local
        // location, is collected.)
        func persistenceFiles(_ s: EvidenceState) -> [FileEntry] {
            s.files.filter { entry in
                guard !entry.isDirectory, entry.size > 0 else { return false }
                let lower = entry.fullPath.lowercased()
                let name = entry.name.lowercased()
                if lower.hasSuffix("/etc/crontab") || lower.contains("/cron.d/")
                    || lower.contains("/cron/tabs/") || lower.contains("/var/at/tabs/") { return true }
                if lower.contains("/usr/local/etc/periodic/") { return true }
                if lower.contains("/emond.d/rules/") && name.hasSuffix(".plist") { return true }
                if name == "com.apple.loginwindow.plist" { return true }
                if lower.hasSuffix("/etc/rc.local") || lower.hasSuffix("/etc/rc.common") { return true }
                if name.hasSuffix(".mobileconfig") { return true }
                if lower.contains("/managed preferences/") && name.hasSuffix(".plist") { return true }
                return false
            }
        }
        // FSEvents change-history logs: gzip-compressed, hex-named files under
        // /.fseventsd/ (excluding the uuid + no_log marker files).
        func fseventsFiles(_ s: EvidenceState) -> [FileEntry] {
            s.files.filter { entry in
                guard !entry.isDirectory, entry.size > 0 else { return false }
                let lower = entry.fullPath.lowercased()
                let name = entry.name.lowercased()
                return lower.contains("/.fseventsd/")
                    && name != "fseventsd-uuid" && name != "no_log"
            }
        }
        // Per-user zsh/bash history under /Users/ (macOS home dirs). The Linux
        // parser already handles /home/ + /root/ history; this picks up the Mac
        // side so the (now cross-OS) Shell History tab is populated.
        func shellHistoryFiles(_ s: EvidenceState) -> [FileEntry] {
            s.files.filter { entry in
                guard !entry.isDirectory, entry.size > 0 else { return false }
                let name = entry.name.lowercased()
                return entry.fullPath.lowercased().contains("/users/")
                    && (name == ".zsh_history" || name == ".bash_history" || name == ".sh_history")
            }
        }
        // TCC privacy-permission databases: the system one under
        // /Library/Application Support/com.apple.TCC/ and per-user copies under
        // ~/Library/Application Support/com.apple.TCC/.
        func tccFiles(_ s: EvidenceState) -> [FileEntry] {
            s.files.filter { entry in
                guard !entry.isDirectory, entry.size > 0 else { return false }
                let lower = entry.fullPath.lowercased()
                return entry.name.lowercased() == "tcc.db" && lower.contains("/com.apple.tcc/")
            }
        }
        // KnowledgeC behavioural databases — the system store under
        // /private/var/db/CoreDuet/Knowledge/ and per-user ones under
        // ~/Library/Application Support/Knowledge/.
        func knowledgeFiles(_ s: EvidenceState) -> [FileEntry] {
            s.files.filter { entry in
                guard !entry.isDirectory, entry.size > 0 else { return false }
                let lower = entry.fullPath.lowercased()
                return entry.name.lowercased() == "knowledgec.db"
                    && (lower.contains("/coreduet/knowledge/") || lower.contains("/application support/knowledge/"))
            }
        }
        // Recent Items / LSSharedFileList stores: recent apps, documents,
        // servers, favorites, and Finder sidebar lists.
        func recentItemFiles(_ s: EvidenceState) -> [FileEntry] {
            s.files.filter { entry in
                guard !entry.isDirectory, entry.size > 0 else { return false }
                let lower = entry.fullPath.lowercased()
                let name = entry.name.lowercased()
                let isRecentList = lower.contains("/com.apple.sharedfilelist/")
                    && (name.hasSuffix(".sfl") || name.hasSuffix(".sfl2") || name.hasSuffix(".sfl3") || name.hasSuffix(".plist"))
                let isSidebarList = name == "com.apple.sidebarlists.plist"
                    || lower.hasSuffix("/library/preferences/com.apple.finder.plist")
                return isRecentList || isSidebarList
            }
        }
        // Gatekeeper, XProtect, XProtect Remediator, MRT, and syspolicyd logs.
        // install.log is included because Apple security-data updates and some
        // XProtect/MRT activity are commonly recorded there.
        func securityEventFiles(_ s: EvidenceState) -> [FileEntry] {
            s.files.filter { entry in
                guard !entry.isDirectory, entry.size > 0 else { return false }
                let lower = entry.fullPath.lowercased()
                let name = entry.name.lowercased()
                let isLog = name.hasSuffix(".log") || name.hasSuffix(".log.0") || name == "install.log"
                guard isLog else { return false }
                if name == "install.log", lower.contains("/var/log/") { return true }
                if lower.contains("/library/logs/") || lower.contains("/var/log/") {
                    return name.contains("xprotect")
                        || name.contains("xprotectremediator")
                        || name.contains("mrt")
                        || name.contains("gatekeeper")
                        || name.contains("syspolicyd")
                }
                if lower.contains("/diagnosticreports/") {
                    return name.contains("xprotect") || name.contains("mrt") || name.contains("syspolicyd")
                }
                return false
            }
        }
        // Kernel extensions (Foo.kext/Contents/Info.plist under an Extensions
        // dir) + the System Extensions database (/Library/SystemExtensions/db.plist).
        func kextFiles(_ s: EvidenceState) -> [FileEntry] {
            s.files.filter { entry in
                guard !entry.isDirectory, entry.size > 0 else { return false }
                let lower = entry.fullPath.lowercased()
                if entry.name.lowercased() == "db.plist", lower.contains("/library/systemextensions/") { return true }
                return lower.hasSuffix(".kext/contents/info.plist")
                    && (lower.contains("/library/extensions/") || lower.contains("/system/library/extensions/"))
            }
        }
        // Background Task Management store (login items / agents / daemons).
        func btmFiles(_ s: EvidenceState) -> [FileEntry] {
            s.files.filter { entry in
                guard !entry.isDirectory, entry.size > 0 else { return false }
                return entry.name.lowercased().hasSuffix(".btm")
            }
        }
        // Network / device context plists: Wi-Fi known networks, DHCP leases,
        // Bluetooth, Time Machine, and lockdown (iOS) pairing records.
        func networkFiles(_ s: EvidenceState) -> [FileEntry] {
            s.files.filter { entry in
                guard !entry.isDirectory, entry.size > 0 else { return false }
                let lower = entry.fullPath.lowercased()
                let name = entry.name.lowercased()
                if name == "com.apple.airport.preferences.plist" || name == "com.apple.wifi.known-networks.plist"
                    || name == "com.apple.bluetooth.plist" || name == "com.apple.timemachine.plist" { return true }
                if lower.contains("/dhcpclient/leases/") { return true }
                if lower.contains("/var/db/lockdown/") && name.hasSuffix(".plist") { return true }
                return false
            }
        }
        // QuickLook thumbnail index (files previewed) + Trash (deletion intent).
        func quickLookFiles(_ s: EvidenceState) -> [FileEntry] {
            s.files.filter { entry in
                guard !entry.isDirectory, entry.size > 0, entry.name.lowercased() == "index.sqlite" else { return false }
                let lower = entry.fullPath.lowercased()
                return lower.contains("/quicklook/") || lower.contains("thumbnailcache")
            }
        }
        func trashEntries(_ s: EvidenceState) -> [FileEntry] {
            s.files.filter { entry in
                guard !entry.isDirectory, entry.size > 0 else { return false }
                let lower = entry.fullPath.lowercased()
                return lower.contains("/.trash/") || lower.contains("/.trashes/")
            }
        }
        // Document Versions store (`/.DocumentRevisions-V100/db-V1/db.sqlite`).
        func docRevisionFiles(_ s: EvidenceState) -> [FileEntry] {
            s.files.filter { entry in
                guard !entry.isDirectory, entry.size > 0, entry.name.lowercased() == "db.sqlite" else { return false }
                return entry.fullPath.lowercased().contains("/.documentrevisions-v100/")
            }
        }
        // Notification Center store (`…/group.com.apple.usernoted/db2/db` or the
        // legacy `…/com.apple.notificationcenter/db2/db`).
        func notificationFiles(_ s: EvidenceState) -> [FileEntry] {
            s.files.filter { entry in
                guard !entry.isDirectory, entry.size > 0, entry.name.lowercased() == "db" else { return false }
                let lower = entry.fullPath.lowercased()
                return (lower.contains("usernoted") || lower.contains("notificationcenter")) && lower.contains("/db2/")
            }
        }
        // Powerlog store (`/private/var/db/powerlog/Library/BatteryLife/CurrentPowerlog.PLSQL`).
        func powerlogFiles(_ s: EvidenceState) -> [FileEntry] {
            s.files.filter { entry in
                guard !entry.isDirectory, entry.size > 0 else { return false }
                let name = entry.name.lowercased()
                return name == "currentpowerlog.plsql"
                    || (name.hasSuffix(".plsql") && entry.fullPath.lowercased().contains("/powerlog/"))
            }
        }
        // System-configuration / security-posture files (curated set; the
        // MacConfigParser dispatches on the path). System-scoped loginwindow only
        // (per-user copies hold UI prefs, not the security keys).
        func configFiles(_ s: EvidenceState) -> [FileEntry] {
            s.files.filter { entry in
                guard !entry.isDirectory else { return false }
                let lower = entry.fullPath.lowercased()
                let name = entry.name.lowercased()
                if name == "kcpassword" { return true }
                if name == "com.apple.vncsettings.txt" { return true }
                if name == "systempolicy-prefs.plist" { return true }
                if lower.contains("com.apple.xpc.launchd/disabled") && name.hasSuffix(".plist") { return true }
                if name == "overrides.plist" && lower.contains("launchd") { return true }   // pre-10.10 legacy
                guard lower.contains("/library/preferences/") else { return false }
                switch name {
                case "com.apple.alf.plist", "com.apple.softwareupdate.plist",
                     "com.apple.commerce.plist", "com.apple.remotemanagement.plist":
                    return true
                case "com.apple.loginwindow.plist":
                    return !lower.contains("/users/")   // system copy only
                default:
                    return name.hasPrefix("com.apple.screensaver")   // per-user (plain + ByHost)
                }
            }
        }
        // Software install history — InstallHistory.plist + PackageKit receipts.
        func installFiles(_ s: EvidenceState) -> [FileEntry] {
            s.files.filter { entry in
                guard !entry.isDirectory, entry.size > 0 else { return false }
                let lower = entry.fullPath.lowercased()
                let name = entry.name.lowercased()
                if name == "installhistory.plist" { return true }
                return name.hasSuffix(".plist") && lower.contains("/db/receipts/")
            }
        }
        // WhereFroms candidates — files whose kMDItemWhereFroms xattr is worth
        // fetching. The xattr lands on files the *user* downloaded, so target the
        // download landing zones (Downloads/Desktop/Documents, any file) plus
        // disk-image/installer files (dmg/pkg/iso — rare, high-value) elsewhere
        // under /Users. Crucially, EXCLUDE `/Library/` (caches, app-support,
        // containers) and **bundle internals** (`.app/`, `.framework/`, `.bundle/`),
        // which hold tens of thousands of .bin/.gz/.jar files that are never
        // user downloads — that over-match ballooned the candidate set. Capped to
        // bound the per-file xattr reads; landing-zone files kept first.
        let whereFromCap = 2000
        let installerExts: Set<String> = ["dmg", "pkg", "iso"]
        func isLandingZone(_ lower: String) -> Bool {
            lower.contains("/downloads/") || lower.contains("/desktop/") || lower.contains("/documents/")
        }
        func whereFromCandidates(_ s: EvidenceState) -> [FileEntry] {
            let matched = s.files.filter { entry in
                // TSK emits a `<name>-slack` pseudo-entry per allocated file; it's
                // the unused tail of a cluster, not a real file. Unlike the other
                // parseMac candidate filters (which match exact names/suffixes and
                // so never match "-slack"), this one matches by location, so it
                // must exclude slack explicitly — otherwise a download-zone slack
                // entry triggers a pointless `fsapfscat -x` xattr read on every load.
                guard !entry.isSlackEntry else { return false }
                let lower = entry.fullPath.lowercased()
                guard lower.contains("/users/"), !lower.contains("/library/") else { return false }
                if lower.contains(".app/") || lower.contains(".framework/") || lower.contains(".bundle/") {
                    return false
                }
                let ext = (entry.name as NSString).pathExtension.lowercased()
                let isBundle = entry.isDirectory && (ext == "app" || ext == "appex")
                guard isBundle || (!entry.isDirectory && entry.size > 0) else { return false }
                if isLandingZone(lower) { return true }
                return !entry.isDirectory && installerExts.contains(ext)
            }
            // Keep landing-zone candidates first so truncation drops the least-likely.
            return matched.sorted { isLandingZone($0.fullPath.lowercased())
                                    && !isLandingZone($1.fullPath.lowercased()) }
        }
        // The owning scope for a macOS db path: "system" unless it lives under a
        // user home, in which case the user's name.
        func macScope(_ path: String) -> String {
            let comps = path.split(separator: "/").map(String.init)
            if let i = comps.firstIndex(where: { $0.lowercased() == "users" }), i + 1 < comps.count {
                return comps[i + 1]
            }
            return "system"
        }
        let total = evidenceList.reduce(0) { acc, e in
            guard let s = states[e.id] else { return acc }
            return acc
                + (s.launchItems.isEmpty ? plists(s).count : 0)
                + (s.quarantine.isEmpty ? quarantines(s).count : 0)
                + (s.macInfo == nil ? hostInfoFiles(s).count : 0)
                + (s.macPersistence.isEmpty ? persistenceFiles(s).count : 0)
                + (s.fsEvents.isEmpty ? fseventsFiles(s).count : 0)
                + (s.shellHistory.isEmpty ? shellHistoryFiles(s).count : 0)
                + (s.tcc.isEmpty ? tccFiles(s).count : 0)
                + (s.knowledgeC.isEmpty ? knowledgeFiles(s).count : 0)
                + (s.macRecentItems.isEmpty ? recentItemFiles(s).count : 0)
                + (s.macSecurityEvents.isEmpty ? securityEventFiles(s).count : 0)
                + (s.kexts.isEmpty ? kextFiles(s).count : 0)
                + (s.backgroundItems.isEmpty ? btmFiles(s).count : 0)
                + (s.network.isEmpty ? networkFiles(s).count : 0)
                + (s.userActivity.isEmpty ? quickLookFiles(s).count + trashEntries(s).count : 0)
                + (s.documentVersions.isEmpty ? docRevisionFiles(s).count : 0)
                + (s.notifications.isEmpty ? notificationFiles(s).count : 0)
                + (s.powerlog.isEmpty ? powerlogFiles(s).count : 0)
                + (s.macConfig.isEmpty ? configFiles(s).count : 0)
                + (s.installHistory.isEmpty ? installFiles(s).count : 0)
                + (e.kind == .apfs && s.whereFroms.isEmpty ? min(whereFromCandidates(s).count, whereFromCap) : 0)
        }
        guard total > 0 else { statusMessage = "No new macOS artifacts to parse."; return }
        progress = ProgressInfo(current: 0, total: total, label: "Parsing macOS artifacts")
        var completed = 0
        var whereFromTruncations: [String] = []
        var whereFromExtractFailures = 0
        do {
            let tskEnv = try TSKEnvironment.discover()
            for evidence in evidenceList {
                guard var state = states[evidence.id] else { continue }
                let foundPlists = state.launchItems.isEmpty ? plists(state) : []
                let foundQuar = state.quarantine.isEmpty ? quarantines(state) : []
                let foundInfo = state.macInfo == nil ? hostInfoFiles(state) : []
                let foundPersist = state.macPersistence.isEmpty ? persistenceFiles(state) : []
                let foundFSE = state.fsEvents.isEmpty ? fseventsFiles(state) : []
                let foundShell = state.shellHistory.isEmpty ? shellHistoryFiles(state) : []
                let foundTCC = state.tcc.isEmpty ? tccFiles(state) : []
                let foundKnowledge = state.knowledgeC.isEmpty ? knowledgeFiles(state) : []
                let foundRecent = state.macRecentItems.isEmpty ? recentItemFiles(state) : []
                let foundSecurity = state.macSecurityEvents.isEmpty ? securityEventFiles(state) : []
                let foundKexts = state.kexts.isEmpty ? kextFiles(state) : []
                let foundBTM = state.backgroundItems.isEmpty ? btmFiles(state) : []
                let foundNetwork = state.network.isEmpty ? networkFiles(state) : []
                let foundQuickLook = state.userActivity.isEmpty ? quickLookFiles(state) : []
                let foundTrash = state.userActivity.isEmpty ? trashEntries(state) : []
                let foundDocRev = state.documentVersions.isEmpty ? docRevisionFiles(state) : []
                let foundNotif = state.notifications.isEmpty ? notificationFiles(state) : []
                let foundPowerlog = state.powerlog.isEmpty ? powerlogFiles(state) : []
                let foundConfig = state.macConfig.isEmpty ? configFiles(state) : []
                let foundInstall = state.installHistory.isEmpty ? installFiles(state) : []
                let allWhereFromCands = (evidence.kind == .apfs && state.whereFroms.isEmpty)
                    ? whereFromCandidates(state) : []
                let foundWhereFrom = Array(allWhereFromCands.prefix(whereFromCap))
                if allWhereFromCands.count > whereFromCap {
                    whereFromTruncations.append("\(evidence.displayName): \(whereFromCap) of \(allWhereFromCands.count)")
                }
                guard !foundPlists.isEmpty || !foundQuar.isEmpty || !foundInfo.isEmpty
                    || !foundPersist.isEmpty || !foundFSE.isEmpty || !foundShell.isEmpty
                    || !foundTCC.isEmpty || !foundKnowledge.isEmpty || !foundRecent.isEmpty
                    || !foundSecurity.isEmpty || !foundKexts.isEmpty || !foundBTM.isEmpty
                    || !foundNetwork.isEmpty || !foundQuickLook.isEmpty || !foundTrash.isEmpty
                    || !foundDocRev.isEmpty || !foundNotif.isEmpty || !foundPowerlog.isEmpty
                    || !foundConfig.isEmpty || !foundInstall.isEmpty || !foundWhereFrom.isEmpty else { continue }
                let isLoose = evidence.kind == .kapeLooseFolder
                let isAPFS = evidence.kind == .apfs
                var database: TSKDatabase?
                var extractor: TSKFileExtractor?
                var apfsExtractor: FsApfsExtractor?
                var scratch: URL?
                if !isLoose {
                    guard let bundleURL = currentCaseBundleURL else { continue }
                    let dir = CaseStore.prefetchScratchDirectory(forHostID: evidence.id, in: bundleURL)
                        .deletingLastPathComponent().appendingPathComponent("mac")
                    try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
                    scratch = dir
                    if isAPFS {
                        apfsExtractor = FsApfsExtractor(environment: tskEnv,
                                                        rawURL: evidence.apfsRawURL ?? evidence.sourceURL,
                                                        credential: fileVaultCredentials[evidence.id])
                    } else {
                        guard let dbURL = state.dbURL else { continue }
                        database = try TSKDatabase(path: dbURL)
                        extractor = TSKFileExtractor(environment: tskEnv, imageURL: evidence.sourceURL,
                                                     imageType: TSKImageIngestor.imageType(for: evidence.sourceURL))
                    }
                }
                func extract(_ entry: FileEntry) async -> URL? {
                    guard !entry.isSlackEntry else { return nil }   // never read a slack pseudo-entry's content
                    if isLoose {
                        guard let disk = entry.diskURL,
                              FileManager.default.fileExists(atPath: disk.path) else { return nil }
                        return disk
                    }
                    let outURL = scratch!.appendingPathComponent("\(entry.id)-\(entry.name.scratchSafeComponent)")
                    if isAPFS {
                        let off = state.volumes.first { $0.id == entry.fsID }?.offsetBytes ?? 0
                        try? await apfsExtractor!.extract(volumePath: entry.fullPath,
                                                          volumeIndex: entry.fsID ?? 0,
                                                          offsetBytes: off, to: outURL)
                        return outURL
                    }
                    guard let info = try? database!.fetchExtractInfo(forFileID: entry.id) else { return nil }
                    try? await extractor!.extract(metaAddr: info.metaAddr,
                                                  imageOffsetSectors: info.imageOffsetSectors, to: outURL)
                    return outURL
                }
                // Extract a named extended attribute's bytes (APFS only — loose
                // collections strip xattrs and the TSK path doesn't surface them).
                // Throws on a tool failure (rc 1, e.g. an fsapfscat without `-x`
                // support) so the caller can distinguish "extraction failed" from
                // "file has no such attribute" (rc 3, returns empty → nil here).
                func extractAttribute(_ entry: FileEntry, _ attribute: String) async throws -> Data? {
                    guard !entry.isSlackEntry else { return nil }   // never read a slack pseudo-entry's xattrs
                    guard isAPFS, let apfsExtractor else { return nil }
                    let outURL = scratch!.appendingPathComponent("xattr-\(entry.id)")
                    let off = state.volumes.first { $0.id == entry.fsID }?.offsetBytes ?? 0
                    try await apfsExtractor.extract(volumePath: entry.fullPath,
                                                    volumeIndex: entry.fsID ?? 0,
                                                    offsetBytes: off, to: outURL, attribute: attribute)
                    defer { try? FileManager.default.removeItem(at: outURL) }
                    guard let data = try? Data(contentsOf: outURL), !data.isEmpty else { return nil }
                    return data
                }
                var launch: [LaunchItemEntry] = []
                var quar: [QuarantineEvent] = []
                for entry in foundPlists {
                    progress = ProgressInfo(current: completed, total: total, label: "\(evidence.displayName): \(entry.name)")
                    defer { completed += 1 }
                    guard let url = await extract(entry), let data = try? Data(contentsOf: url) else { continue }
                    if let item = LaunchItemParser.parse(data: data, plistPath: entry.fullPath) { launch.append(item) }
                }
                for entry in foundQuar {
                    progress = ProgressInfo(current: completed, total: total, label: "\(evidence.displayName): \(entry.name)")
                    defer { completed += 1 }
                    guard let url = await extract(entry) else { continue }
                    quar.append(contentsOf: (try? QuarantineParser.parse(fileAt: url, sourceFile: entry.fullPath)) ?? [])
                }
                quar.sort { ($0.timestamp ?? .distantPast) > ($1.timestamp ?? .distantPast) }
                var info = MacHostInfo()
                for entry in foundInfo {
                    progress = ProgressInfo(current: completed, total: total, label: "\(evidence.displayName): \(entry.name)")
                    defer { completed += 1 }
                    guard let url = await extract(entry), let data = try? Data(contentsOf: url) else { continue }
                    let lower = entry.fullPath.lowercased()
                    if lower.hasSuffix("/systemversion.plist") {
                        MacHostInfoParser.applySystemVersion(data, to: &info)
                    } else if lower.hasSuffix("/preferences.plist") {
                        MacHostInfoParser.applyPreferences(data, to: &info)
                    } else if lower.hasSuffix("/networkinterfaces.plist") {
                        MacHostInfoParser.applyNetworkInterfaces(data, to: &info)
                    } else {
                        MacHostInfoParser.applyUserPlist(data, to: &info)
                    }
                }
                var persist: [MacPersistenceItem] = []
                for entry in foundPersist {
                    progress = ProgressInfo(current: completed, total: total, label: "\(evidence.displayName): \(entry.name)")
                    defer { completed += 1 }
                    guard let url = await extract(entry), let data = try? Data(contentsOf: url) else { continue }
                    let lower = entry.fullPath.lowercased()
                    let name = entry.name.lowercased()
                    if name == "com.apple.loginwindow.plist" {
                        persist += MacPersistenceParser.parseLoginWindow(data, sourceFile: entry.fullPath)
                    } else if lower.contains("/emond.d/rules/") {
                        persist += MacPersistenceParser.parseEmondRules(data, sourceFile: entry.fullPath)
                    } else if name.hasSuffix(".mobileconfig") || lower.contains("/managed preferences/") {
                        if let item = MacPersistenceParser.configProfile(data, sourceFile: entry.fullPath) {
                            persist.append(item)
                        }
                    } else if lower.contains("/periodic/") {
                        persist.append(MacPersistenceParser.periodicScript(path: entry.fullPath))
                    } else if lower.hasSuffix("/rc.local") || lower.hasSuffix("/rc.common") {
                        persist.append(MacPersistenceParser.rcScript(path: entry.fullPath,
                                                                     contents: String(decoding: data, as: UTF8.self)))
                    } else {
                        // Cron. /etc/crontab and /etc/cron.d/* are the 6-field
                        // system form (with a user column); per-user spool files
                        // are 5-field and run as the file's owner (its name).
                        let isSystem = lower.hasSuffix("/etc/crontab") || lower.contains("/cron.d/")
                        persist += MacPersistenceParser.parseCrontab(
                            String(decoding: data, as: UTF8.self),
                            sourceFile: entry.fullPath,
                            defaultUser: isSystem ? nil : entry.name,
                            isSystemCrontab: isSystem)
                    }
                }
                // FSEvents: collect the gzip blobs on-main, then gunzip + parse
                // off-main (a busy store can be many MB / hundreds of thousands
                // of records).
                var fseBlobs: [FSEventsBlob] = []
                for entry in foundFSE {
                    progress = ProgressInfo(current: completed, total: total, label: "\(evidence.displayName): \(entry.name)")
                    defer { completed += 1 }
                    guard let url = await extract(entry), let data = try? Data(contentsOf: url) else { continue }
                    fseBlobs.append(FSEventsBlob(data: data, sourceFile: entry.fullPath))
                }
                let fsEvents: [FSEventRecord] = fseBlobs.isEmpty ? [] : await Task.detached {
                    fseBlobs.flatMap { FSEventsParser.parse(gzipped: $0.data, sourceFile: $0.sourceFile) }
                }.value

                // macOS zsh/bash history → the shared shellHistory collection.
                var macShell: [ShellHistoryEntry] = []
                for entry in foundShell {
                    progress = ProgressInfo(current: completed, total: total, label: "\(evidence.displayName): \(entry.name)")
                    defer { completed += 1 }
                    guard let url = await extract(entry), let data = try? Data(contentsOf: url) else { continue }
                    let shell: ShellHistoryEntry.Shell =
                        entry.name.lowercased().contains("zsh") ? .zsh : .bash
                    macShell.append(contentsOf: ShellHistoryParser.parse(
                        text: String(decoding: data, as: UTF8.self),
                        user: ShellHistoryParser.user(fromPath: entry.fullPath),
                        shell: shell, sourceFile: entry.fullPath))
                }

                // TCC privacy-permission grants (SQLite, read via GRDB off the
                // extracted scratch copy).
                var tcc: [TCCAccess] = []
                for entry in foundTCC {
                    progress = ProgressInfo(current: completed, total: total, label: "\(evidence.displayName): \(entry.name)")
                    defer { completed += 1 }
                    guard let url = await extract(entry) else { continue }
                    tcc.append(contentsOf: (try? TCCParser.parse(
                        fileAt: url, scope: macScope(entry.fullPath), sourceFile: entry.fullPath)) ?? [])
                }
                tcc.sort { ($0.lastModified ?? .distantPast) > ($1.lastModified ?? .distantPast) }

                // KnowledgeC behavioural timeline (SQLite/Core Data via GRDB).
                var knowledge: [KnowledgeEntry] = []
                for entry in foundKnowledge {
                    progress = ProgressInfo(current: completed, total: total, label: "\(evidence.displayName): \(entry.name)")
                    defer { completed += 1 }
                    guard let url = await extract(entry) else { continue }
                    knowledge.append(contentsOf: (try? KnowledgeCParser.parse(
                        fileAt: url, scope: macScope(entry.fullPath), sourceFile: entry.fullPath)) ?? [])
                }
                knowledge.sort { ($0.startDate ?? .distantPast) > ($1.startDate ?? .distantPast) }

                // Recent Items / LSSharedFileList user-activity stores.
                var recentItems: [MacRecentItem] = []
                for entry in foundRecent {
                    progress = ProgressInfo(current: completed, total: total, label: "\(evidence.displayName): \(entry.name)")
                    defer { completed += 1 }
                    guard let url = await extract(entry), let data = try? Data(contentsOf: url) else { continue }
                    recentItems.append(contentsOf: MacRecentItemParser.parse(
                        data: data, sourceFile: entry.fullPath, scope: macScope(entry.fullPath)))
                }
                recentItems.sort { ($0.timestamp ?? .distantPast) > ($1.timestamp ?? .distantPast) }

                // Gatekeeper / XProtect / MRT durable security logs.
                var securityEvents: [MacSecurityEvent] = []
                for entry in foundSecurity {
                    progress = ProgressInfo(current: completed, total: total, label: "\(evidence.displayName): \(entry.name)")
                    defer { completed += 1 }
                    guard let url = await extract(entry), let data = try? Data(contentsOf: url) else { continue }
                    securityEvents.append(contentsOf: MacSecurityParser.parse(
                        data: data, sourceFile: entry.fullPath, scope: macScope(entry.fullPath)))
                }
                securityEvents.sort { ($0.timestamp ?? .distantPast) > ($1.timestamp ?? .distantPast) }

                // Kernel + System extensions (kext Info.plist + SystemExtensions db).
                var kexts: [MacKextEntry] = []
                for entry in foundKexts {
                    progress = ProgressInfo(current: completed, total: total, label: "\(evidence.displayName): \(entry.name)")
                    defer { completed += 1 }
                    guard let url = await extract(entry), let data = try? Data(contentsOf: url) else { continue }
                    if entry.name.lowercased() == "db.plist" {
                        kexts.append(contentsOf: MacKextParser.parseSystemExtensionsDB(
                            data: data, sourceFile: entry.fullPath, scope: macScope(entry.fullPath)))
                    } else if let k = MacKextParser.parseKextInfo(
                        data: data, sourceFile: entry.fullPath, scope: macScope(entry.fullPath)) {
                        kexts.append(k)
                    }
                }
                kexts.sort { $0.title.localizedCaseInsensitiveCompare($1.title) == .orderedAscending }

                // Background Task Management (login items / agents / daemons).
                var backgroundItems: [MacBackgroundItem] = []
                for entry in foundBTM {
                    progress = ProgressInfo(current: completed, total: total, label: "\(evidence.displayName): \(entry.name)")
                    defer { completed += 1 }
                    guard let url = await extract(entry), let data = try? Data(contentsOf: url) else { continue }
                    backgroundItems.append(contentsOf: BTMParser.parse(
                        data: data, sourceFile: entry.fullPath, scope: macScope(entry.fullPath)))
                }
                backgroundItems.sort { $0.title.localizedCaseInsensitiveCompare($1.title) == .orderedAscending }

                // Network / device context (Wi-Fi / DHCP / Bluetooth / Time Machine / pairings).
                var network: [MacNetworkItem] = []
                for entry in foundNetwork {
                    progress = ProgressInfo(current: completed, total: total, label: "\(evidence.displayName): \(entry.name)")
                    defer { completed += 1 }
                    guard let url = await extract(entry), let data = try? Data(contentsOf: url) else { continue }
                    network.append(contentsOf: MacNetworkParser.parse(
                        data: data, sourceFile: entry.fullPath, scope: macScope(entry.fullPath)))
                }

                // QuickLook previews (SQLite, extracted) + Trash (a file-tree filter,
                // no extraction — the FileEntry's own MACB is the deletion time).
                var userActivity: [MacActivityItem] = []
                for entry in foundTrash {
                    progress = ProgressInfo(current: completed, total: total, label: "\(evidence.displayName): \(entry.name)")
                    defer { completed += 1 }
                    userActivity.append(MacActivityItem(
                        kind: .trash, path: entry.fullPath,
                        timestamp: entry.changed ?? entry.modified,
                        detail: ByteCountFormatter.string(fromByteCount: entry.size, countStyle: .file),
                        scope: macScope(entry.fullPath), sourceFile: entry.fullPath))
                }
                for entry in foundQuickLook {
                    progress = ProgressInfo(current: completed, total: total, label: "\(evidence.displayName): \(entry.name)")
                    defer { completed += 1 }
                    guard let url = await extract(entry) else { continue }
                    userActivity.append(contentsOf: (try? QuickLookParser.parse(
                        fileAt: url, sourceFile: entry.fullPath, scope: macScope(entry.fullPath))) ?? [])
                }

                // Document Versions store (SQLite).
                var documentVersions: [MacDocumentVersion] = []
                for entry in foundDocRev {
                    progress = ProgressInfo(current: completed, total: total, label: "\(evidence.displayName): \(entry.name)")
                    defer { completed += 1 }
                    guard let url = await extract(entry) else { continue }
                    documentVersions.append(contentsOf: (try? DocumentRevisionsParser.parse(
                        fileAt: url, sourceFile: entry.fullPath, scope: macScope(entry.fullPath))) ?? [])
                }

                // Notification Center store (SQLite).
                var notifications: [MacNotification] = []
                for entry in foundNotif {
                    progress = ProgressInfo(current: completed, total: total, label: "\(evidence.displayName): \(entry.name)")
                    defer { completed += 1 }
                    guard let url = await extract(entry) else { continue }
                    notifications.append(contentsOf: (try? NotificationParser.parse(
                        fileAt: url, sourceFile: entry.fullPath, scope: macScope(entry.fullPath))) ?? [])
                }

                // Powerlog store (SQLite).
                var powerlog: [PowerlogEntry] = []
                for entry in foundPowerlog {
                    progress = ProgressInfo(current: completed, total: total, label: "\(evidence.displayName): \(entry.name)")
                    defer { completed += 1 }
                    guard let url = await extract(entry) else { continue }
                    powerlog.append(contentsOf: (try? PowerlogParser.parse(
                        fileAt: url, sourceFile: entry.fullPath, scope: macScope(entry.fullPath))) ?? [])
                }

                // System-configuration / security-posture plists (pure parser).
                var macConfig: [MacConfigSetting] = []
                for entry in foundConfig {
                    progress = ProgressInfo(current: completed, total: total, label: "\(evidence.displayName): \(entry.name)")
                    defer { completed += 1 }
                    guard let url = await extract(entry), let data = try? Data(contentsOf: url) else { continue }
                    macConfig.append(contentsOf: MacConfigParser.parse(
                        data, sourceFile: entry.fullPath, scope: macScope(entry.fullPath)))
                }

                // Software install history (pure parser).
                var installHistory: [MacInstallEntry] = []
                for entry in foundInstall {
                    progress = ProgressInfo(current: completed, total: total, label: "\(evidence.displayName): \(entry.name)")
                    defer { completed += 1 }
                    guard let url = await extract(entry), let data = try? Data(contentsOf: url) else { continue }
                    installHistory.append(contentsOf: MacInstallHistoryParser.parse(
                        data, sourceFile: entry.fullPath, scope: macScope(entry.fullPath)))
                }

                // Download provenance — kMDItemWhereFroms xattrs (APFS only; one
                // xattr read per candidate file, capped above).
                var whereFroms: [MacWhereFrom] = []
                var wfExtractErrors = 0
                for entry in foundWhereFrom {
                    progress = ProgressInfo(current: completed, total: total, label: "\(evidence.displayName): \(entry.name)")
                    defer { completed += 1 }
                    do {
                        guard let data = try await extractAttribute(entry, "com.apple.metadata:kMDItemWhereFroms")
                        else { continue }
                        if let wf = WhereFromsParser.parse(data, path: entry.fullPath, scope: macScope(entry.fullPath)) {
                            whereFroms.append(wf)
                        }
                    } catch {
                        wfExtractErrors += 1
                    }
                }
                if wfExtractErrors > 0 { whereFromExtractFailures += wfExtractErrors }

                if !foundPlists.isEmpty { state.launchItems = launch }
                if !foundQuar.isEmpty { state.quarantine = quar }
                if !foundPersist.isEmpty { state.macPersistence = persist }
                if !foundFSE.isEmpty { state.fsEvents = fsEvents }
                if !foundTCC.isEmpty { state.tcc = tcc }
                if !foundKnowledge.isEmpty { state.knowledgeC = knowledge }
                if !foundRecent.isEmpty { state.macRecentItems = recentItems }
                if !foundSecurity.isEmpty { state.macSecurityEvents = securityEvents }
                if !foundKexts.isEmpty { state.kexts = kexts }
                if !foundBTM.isEmpty { state.backgroundItems = backgroundItems }
                if !foundNetwork.isEmpty { state.network = network }
                if !foundQuickLook.isEmpty || !foundTrash.isEmpty { state.userActivity = userActivity }
                if !foundDocRev.isEmpty { state.documentVersions = documentVersions }
                if !foundNotif.isEmpty { state.notifications = notifications }
                if !foundPowerlog.isEmpty { state.powerlog = powerlog }
                if !foundConfig.isEmpty { state.macConfig = macConfig }
                if !foundInstall.isEmpty { state.installHistory = installHistory }
                if !foundWhereFrom.isEmpty { state.whereFroms = whereFroms }
                if !macShell.isEmpty { state.shellHistory.append(contentsOf: macShell) }
                if !foundInfo.isEmpty { state.macInfo = info.isEmpty ? nil : info }
                if !tcc.isEmpty || !knowledge.isEmpty || !recentItems.isEmpty || !securityEvents.isEmpty
                    || !network.isEmpty || !userActivity.isEmpty || !documentVersions.isEmpty
                    || !notifications.isEmpty || !powerlog.isEmpty || !installHistory.isEmpty {
                    state.timeline.append(contentsOf: TimelineBuilder.build(from: tcc))
                    state.timeline.append(contentsOf: TimelineBuilder.build(from: knowledge))
                    state.timeline.append(contentsOf: TimelineBuilder.build(from: recentItems))
                    state.timeline.append(contentsOf: TimelineBuilder.build(from: securityEvents))
                    state.timeline.append(contentsOf: TimelineBuilder.build(from: network))
                    state.timeline.append(contentsOf: TimelineBuilder.build(from: userActivity))
                    state.timeline.append(contentsOf: TimelineBuilder.build(from: documentVersions))
                    state.timeline.append(contentsOf: TimelineBuilder.build(from: notifications))
                    state.timeline.append(contentsOf: TimelineBuilder.build(from: powerlog))
                    state.timeline.append(contentsOf: TimelineBuilder.build(from: installHistory))
                    state.timeline.sort { $0.date < $1.date }
                }
                states[evidence.id] = state
                if let bundleURL = currentCaseBundleURL {
                    if !foundPlists.isEmpty {
                        try? CaseStore.writeLaunchItems(launch, forHostID: evidence.id, in: bundleURL)
                    }
                    if !foundQuar.isEmpty {
                        try? CaseStore.writeQuarantine(quar, forHostID: evidence.id, in: bundleURL)
                    }
                    if !foundPersist.isEmpty {
                        try? CaseStore.writeMacPersistence(persist, forHostID: evidence.id, in: bundleURL)
                    }
                    if !foundFSE.isEmpty {
                        try? CaseStore.writeFSEvents(fsEvents, forHostID: evidence.id, in: bundleURL)
                    }
                    if !foundTCC.isEmpty {
                        try? CaseStore.writeTCC(tcc, forHostID: evidence.id, in: bundleURL)
                    }
                    if !foundKnowledge.isEmpty {
                        try? CaseStore.writeKnowledgeC(knowledge, forHostID: evidence.id, in: bundleURL)
                    }
                    if !foundRecent.isEmpty {
                        try? CaseStore.writeMacRecentItems(recentItems, forHostID: evidence.id, in: bundleURL)
                    }
                    if !foundSecurity.isEmpty {
                        try? CaseStore.writeMacSecurityEvents(securityEvents, forHostID: evidence.id, in: bundleURL)
                    }
                    if !foundKexts.isEmpty {
                        try? CaseStore.writeKexts(kexts, forHostID: evidence.id, in: bundleURL)
                    }
                    if !foundBTM.isEmpty {
                        try? CaseStore.writeBackgroundItems(backgroundItems, forHostID: evidence.id, in: bundleURL)
                    }
                    if !foundNetwork.isEmpty {
                        try? CaseStore.writeNetwork(network, forHostID: evidence.id, in: bundleURL)
                    }
                    if !foundQuickLook.isEmpty || !foundTrash.isEmpty {
                        try? CaseStore.writeUserActivity(userActivity, forHostID: evidence.id, in: bundleURL)
                    }
                    if !foundDocRev.isEmpty {
                        try? CaseStore.writeDocumentVersions(documentVersions, forHostID: evidence.id, in: bundleURL)
                    }
                    if !foundNotif.isEmpty {
                        try? CaseStore.writeNotifications(notifications, forHostID: evidence.id, in: bundleURL)
                    }
                    if !foundPowerlog.isEmpty {
                        try? CaseStore.writePowerlog(powerlog, forHostID: evidence.id, in: bundleURL)
                    }
                    if !foundConfig.isEmpty {
                        try? CaseStore.writeMacConfig(macConfig, forHostID: evidence.id, in: bundleURL)
                    }
                    if !foundInstall.isEmpty {
                        try? CaseStore.writeInstallHistory(installHistory, forHostID: evidence.id, in: bundleURL)
                    }
                    if !foundWhereFrom.isEmpty {
                        try? CaseStore.writeWhereFroms(whereFroms, forHostID: evidence.id, in: bundleURL)
                    }
                    if !macShell.isEmpty {
                        try? CaseStore.writeShellHistory(state.shellHistory, forHostID: evidence.id, in: bundleURL)
                    }
                    if !foundInfo.isEmpty, let info = state.macInfo {
                        try? CaseStore.writeMacInfo(info, forHostID: evidence.id, in: bundleURL)
                    }
                }
            }
            progress = ProgressInfo(current: completed, total: total, label: "macOS artifact parse complete")
            if whereFromExtractFailures > 0 {
                // Almost always: the bundled fsapfscat predates the `-x` xattr mode.
                statusMessage = "WhereFroms: xattr extraction failed for \(whereFromExtractFailures) file(s) — "
                    + "rebuild fsapfscat with `-x` support (scripts/build-tsk.sh) and re-bundle it into the app."
            } else if !whereFromTruncations.isEmpty {
                statusMessage = "WhereFroms coverage truncated to \(whereFromTruncations.joined(separator: ", ")) download-likely files."
            }
        } catch {
            errorMessage = error.localizedDescription
        }
    }

    /// Decode the macOS **unified log** (`.tracev3`). Discovers the diagnostics
    /// logs + timesync + the referenced `.uuidtext`/`dsc` string catalogs, extracts
    /// them (loose / icat / `fsapfscat`), and assembles timestamped, message-bearing
    /// `UnifiedLogEntry`s off-main. Only the durable **Persist** + short-term
    /// **Special** logs are decoded; Signpost (perf) and HighVolume (I/O tracing)
    /// are skipped as low-signal + high-volume.
    func parseUnifiedLog() async {
        guard !isWorking else { return }   // single-flight: don't overlap parse passes
        guard !evidenceList.isEmpty else { return }
        errorMessage = nil
        isWorking = true
        defer { isWorking = false; progress = nil }

        // The diagnostics logs we decode (Persist + Special only).
        func tracev3Files(_ s: EvidenceState) -> [FileEntry] {
            s.files.filter { e in
                guard !e.isDirectory, e.size > 0, e.name.lowercased().hasSuffix(".tracev3") else { return false }
                let p = e.fullPath.lowercased()
                return p.contains("/diagnostics/persist/") || p.contains("/diagnostics/special/")
            }
        }
        func timesyncFiles(_ s: EvidenceState) -> [FileEntry] {
            s.files.filter { !$0.isDirectory && $0.size > 0
                && $0.fullPath.lowercased().contains("/diagnostics/timesync/")
                && $0.name.lowercased().hasSuffix(".timesync") }
        }
        // All `.uuidtext`/`dsc` files, indexed by their 32-hex UUID key. A
        // uuidtext lives at `…/uuidtext/<XX>/<30hex>` (key = XX+name); a dsc at
        // `…/uuidtext/dsc/<32hex>` (key = name).
        func stringCatalogIndex(_ s: EvidenceState) -> [String: (entry: FileEntry, isDsc: Bool)] {
            var index: [String: (FileEntry, Bool)] = [:]
            for e in s.files where !e.isDirectory && e.size > 0
                && e.fullPath.lowercased().contains("/uuidtext/") {
                let comps = e.fullPath.split(separator: "/")
                guard comps.count >= 2 else { continue }
                let parent = String(comps[comps.count - 2])
                let name = e.name.uppercased()
                if parent.lowercased() == "dsc", name.count == 32 {
                    index[name] = (e, true)
                } else if parent.count == 2, name.count == 30 {
                    index[parent.uppercased() + name] = (e, false)
                }
            }
            return index
        }

        let totalWork = evidenceList.reduce(0) { acc, e in
            guard let s = states[e.id], s.unifiedLog.isEmpty else { return acc }
            return acc + tracev3Files(s).count
        }
        guard totalWork > 0 else { statusMessage = "No unified-log files to parse."; return }
        progress = ProgressInfo(current: 0, total: totalWork, label: "Decoding unified log")
        var completed = 0

        do {
            let tskEnv = try TSKEnvironment.discover()
            for evidence in evidenceList {
                guard var state = states[evidence.id], state.unifiedLog.isEmpty else { continue }
                let tv3 = tracev3Files(state)
                guard !tv3.isEmpty else { continue }
                let tsFiles = timesyncFiles(state)
                let catalogIndex = stringCatalogIndex(state)

                let isLoose = evidence.kind == .kapeLooseFolder
                let isAPFS = evidence.kind == .apfs
                var database: TSKDatabase?
                var extractor: TSKFileExtractor?
                var apfsExtractor: FsApfsExtractor?
                var scratch: URL?
                if !isLoose {
                    guard let bundleURL = currentCaseBundleURL else { continue }
                    let dir = CaseStore.unifiedLogScratchDirectory(forHostID: evidence.id, in: bundleURL)
                    try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
                    scratch = dir
                    if isAPFS {
                        apfsExtractor = FsApfsExtractor(environment: tskEnv,
                                                        rawURL: evidence.apfsRawURL ?? evidence.sourceURL,
                                                        credential: fileVaultCredentials[evidence.id])
                    } else {
                        guard let dbURL = state.dbURL else { continue }
                        database = try TSKDatabase(path: dbURL)
                        extractor = TSKFileExtractor(environment: tskEnv, imageURL: evidence.sourceURL,
                                                     imageType: TSKImageIngestor.imageType(for: evidence.sourceURL))
                    }
                }
                func extract(_ entry: FileEntry) async -> Data? {
                    if isLoose {
                        guard let disk = entry.diskURL,
                              FileManager.default.fileExists(atPath: disk.path) else { return nil }
                        return try? Data(contentsOf: disk)
                    }
                    let outURL = scratch!.appendingPathComponent("\(entry.id)-\(entry.name.scratchSafeComponent)")
                    if isAPFS {
                        let off = state.volumes.first { $0.id == entry.fsID }?.offsetBytes ?? 0
                        try? await apfsExtractor!.extract(volumePath: entry.fullPath,
                                                          volumeIndex: entry.fsID ?? 0,
                                                          offsetBytes: off, to: outURL)
                    } else {
                        guard let info = try? database!.fetchExtractInfo(forFileID: entry.id) else { return nil }
                        try? await extractor!.extract(metaAddr: info.metaAddr,
                                                      imageOffsetSectors: info.imageOffsetSectors, to: outURL)
                    }
                    return try? Data(contentsOf: outURL)
                }

                // 1. timesync → boot anchors.
                var timesyncDatas: [Data] = []
                for entry in tsFiles { if let d = await extract(entry) { timesyncDatas.append(d) } }
                let timesyncByBoot = TimesyncParser.parseAll(timesyncDatas)

                // 2. the .tracev3 logs.
                var tracev3: [(data: Data, sourceFile: String)] = []
                for entry in tv3 {
                    progress = ProgressInfo(current: completed, total: totalWork,
                                            label: "\(evidence.displayName): \(entry.name)")
                    completed += 1
                    if let d = await extract(entry) { tracev3.append((d, entry.fullPath)) }
                }
                guard !tracev3.isEmpty else { continue }

                // 3. the referenced .uuidtext/dsc string catalogs.
                let needed = UnifiedLogAssembler.referencedUUIDs(in: tracev3.map { $0.data })
                var uuidTexts: [String: UUIDTextFile] = [:]
                var dscs: [String: DscFile] = [:]
                for uuid in needed {
                    let key = uuid.replacingOccurrences(of: "-", with: "").uppercased()
                    guard let hit = catalogIndex[key], let data = await extract(hit.entry) else { continue }
                    if hit.isDsc {
                        if let f = DscParser.parse(data, uuid: uuid) { dscs[uuid] = f }
                    } else if let f = UUIDTextParser.parse(data, uuid: uuid) {
                        uuidTexts[uuid] = f
                    }
                }
                let strings = UnifiedLogStringCatalog(uuidTexts: uuidTexts, dscs: dscs)

                // 4. assemble off-main (hundreds of thousands of tracepoints).
                progress = ProgressInfo(current: completed, total: totalWork,
                                        label: "\(evidence.displayName): rendering messages")
                var entries = await Task.detached(priority: .userInitiated) {
                    UnifiedLogAssembler.assemble(tracev3: tracev3, timesyncByBoot: timesyncByBoot, strings: strings)
                }.value
                entries.sort { ($0.timestamp ?? .distantPast) > ($1.timestamp ?? .distantPast) }

                state.unifiedLog = entries
                state.timeline.append(contentsOf: TimelineBuilder.build(from: entries))
                state.timeline.sort { $0.date < $1.date }
                states[evidence.id] = state
                if let bundleURL = currentCaseBundleURL {
                    try? CaseStore.writeUnifiedLog(entries, forHostID: evidence.id, in: bundleURL)
                }
            }
            progress = ProgressInfo(current: completed, total: totalWork, label: "Unified-log decode complete")
        } catch {
            errorMessage = error.localizedDescription
        }
    }
}

#endif
