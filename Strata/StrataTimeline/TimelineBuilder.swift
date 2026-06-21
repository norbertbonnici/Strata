import Foundation

/// Expands FileEntry timestamps into discrete timeline events - the same model
/// TSK's `mactime` uses: one event per non-empty MACB timestamp.
///
/// `nonisolated` so the (pure, value-in/value-out) build can run off the main
/// actor during case load - see `AppModel.loadEvidenceState`.
public nonisolated enum TimelineBuilder {

    /// TSK emits a `<name>-slack` pseudo-entry for every allocated cluster's
    /// trailing slack space. These carry 1980-epoch timestamps and inflate
    /// the timeline by orders of magnitude without forensic value most of
    /// the time, so callers can opt to drop them at build time. The macOS
    /// UI exposes this as a toggle; the iOS load path forces it on because
    /// the timeline simply won't fit in phone memory otherwise.
    public static func isSlackEntry(_ file: FileEntry) -> Bool {
        file.isSlackEntry
    }

    public static func build(from files: [FileEntry],
                             excludeSlack: Bool = false) -> [TimelineEvent] {
        var events: [TimelineEvent] = []
        events.reserveCapacity(files.count * 2)

        for file in files {
            if excludeSlack, isSlackEntry(file) { continue }
            func add(_ date: Date?, _ kind: MACBKind) {
                guard let date else { return }
                events.append(TimelineEvent(date: date, kind: kind, source: .filesystem,
                                            fileID: file.id,
                                            path: file.fullPath, size: file.size,
                                            isDeleted: file.isDeleted))
            }
            add(file.modified, .modified)
            add(file.accessed, .accessed)
            add(file.changed, .changed)
            add(file.created, .born)
        }
        return events.sorted { $0.date < $1.date }
    }

    /// Events within a closed date range.
    public static func build(from files: [FileEntry],
                             in range: ClosedRange<Date>,
                             excludeSlack: Bool = false) -> [TimelineEvent] {
        build(from: files, excludeSlack: excludeSlack).filter { range.contains($0.date) }
    }

    /// Project Windows event log records onto the timeline so analysts can
    /// sessionize over real host activity instead of MACB noise. We surface
    /// one event per record; `kind` is forced to `.changed` (the closest fs
    /// analogue - "something happened") and the path encodes channel + EID
    /// so the table row stays readable.
    public static func build(from records: [EventLogRecord]) -> [TimelineEvent] {
        var events: [TimelineEvent] = []
        events.reserveCapacity(records.count)
        for record in records {
            // Path is now just the channel - the EID renders in its own
            // column. We keep it in `path` too so the existing free-text
            // search ("Security", "Sysmon") still matches.
            events.append(TimelineEvent(date: record.writtenAt,
                                        kind: .changed,
                                        source: .evtx,
                                        fileID: 0,
                                        path: record.channel,
                                        size: 0,
                                        isDeleted: false,
                                        eventID: record.eventID))
        }
        return events.sorted { $0.date < $1.date }
    }

    /// Project USN journal records onto the timeline. `kind` reflects the change
    /// (.born for create, .changed otherwise); the path encodes the filename +
    /// reasons so the row reads well and free-text search matches; `isDeleted`
    /// surfaces deletes. Records without a timestamp are dropped.
    public static func build(from records: [UsnRecord]) -> [TimelineEvent] {
        var events: [TimelineEvent] = []
        events.reserveCapacity(records.count)
        for record in records {
            guard let date = record.timestamp else { continue }
            events.append(TimelineEvent(date: date,
                                        kind: record.isCreate ? .born : .changed,
                                        source: .usn,
                                        fileID: 0,
                                        path: "\(record.fileName)  [\(record.reasonSummary)]",
                                        size: 0,
                                        isDeleted: record.isDelete))
        }
        return events.sorted { $0.date < $1.date }
    }

    /// Project SRUM rows onto the timeline. `kind` is `.changed` (the closest fs
    /// analogue for "activity recorded"); the path encodes the app + a kind/detail
    /// summary so the row reads well and free-text search matches. Rows without a
    /// timestamp are dropped.
    public static func build(from records: [SrumEntry]) -> [TimelineEvent] {
        var events: [TimelineEvent] = []
        events.reserveCapacity(records.count)
        for record in records {
            guard let date = record.timestamp else { continue }
            events.append(TimelineEvent(date: date,
                                        kind: .changed,
                                        source: .srum,
                                        fileID: 0,
                                        path: "\(record.appShortName)  [\(record.kind.label): \(record.detailSummary)]",
                                        size: 0,
                                        isDeleted: false))
        }
        return events.sorted { $0.date < $1.date }
    }

    /// Project browser-history rows onto the timeline. `kind` is `.changed` (the
    /// closest fs analogue for "activity recorded"); the path encodes the browser,
    /// title/URL and a kind/detail summary so the row reads well and free-text
    /// search matches. Rows without a timestamp are dropped.
    public static func build(from records: [BrowserHistoryEntry]) -> [TimelineEvent] {
        var events: [TimelineEvent] = []
        events.reserveCapacity(records.count)
        for record in records {
            guard let date = record.timestamp else { continue }
            events.append(TimelineEvent(date: date,
                                        kind: .changed,
                                        source: .browser,
                                        fileID: 0,
                                        path: "[\(record.browser.label) \(record.kind.label)] \(record.displayTitle) — \(record.url)",
                                        size: 0,
                                        isDeleted: false))
        }
        return events.sorted { $0.date < $1.date }
    }

    /// macOS Messages (`chat.db`) rows → timeline. One event per timestamped
    /// message; the path carries direction + counterpart + a body preview.
    public static func build(from records: [MessageEntry]) -> [TimelineEvent] {
        var events: [TimelineEvent] = []
        events.reserveCapacity(records.count)
        for record in records {
            guard let date = record.timestamp else { continue }
            events.append(TimelineEvent(date: date,
                                        kind: .changed,
                                        source: .messages,
                                        fileID: 0,
                                        path: record.timelineSummary,
                                        size: 0,
                                        isDeleted: false))
        }
        return events.sorted { $0.date < $1.date }
    }

    /// macOS Mail (`Envelope Index`) rows → timeline. One event per message with
    /// a date; the path carries direction + counterpart + subject.
    public static func build(from records: [MailMessageEntry]) -> [TimelineEvent] {
        var events: [TimelineEvent] = []
        events.reserveCapacity(records.count)
        for record in records {
            guard let date = record.timestamp else { continue }
            events.append(TimelineEvent(date: date,
                                        kind: .changed,
                                        source: .mail,
                                        fileID: 0,
                                        path: record.timelineSummary,
                                        size: 0,
                                        isDeleted: false))
        }
        return events.sorted { $0.date < $1.date }
    }

    /// macOS network/device items (Wi-Fi join / DHCP lease / Bluetooth last-seen /
    /// Time Machine backup) → timeline. Only items carrying a timestamp project;
    /// config-only items (pairings) are dropped.
    public static func build(from records: [MacNetworkItem]) -> [TimelineEvent] {
        var events: [TimelineEvent] = []
        for record in records {
            guard let date = record.timestamp else { continue }
            events.append(TimelineEvent(date: date,
                                        kind: .changed,
                                        source: .network,
                                        fileID: 0,
                                        path: record.timelineSummary,
                                        size: 0,
                                        isDeleted: false))
        }
        return events.sorted { $0.date < $1.date }
    }

    /// macOS user-activity items (QuickLook preview / Trash) → timeline. A Trash
    /// row is marked deleted; QuickLook is a "viewed" activity row.
    public static func build(from records: [MacActivityItem]) -> [TimelineEvent] {
        var events: [TimelineEvent] = []
        for record in records {
            guard let date = record.timestamp else { continue }
            events.append(TimelineEvent(date: date,
                                        kind: .changed,
                                        source: .userActivity,
                                        fileID: 0,
                                        path: record.timelineSummary,
                                        size: 0,
                                        isDeleted: record.kind == .trash))
        }
        return events.sorted { $0.date < $1.date }
    }

    /// macOS document Versions → timeline. One event per saved generation (a
    /// `.modified` activity row), dropping versions with no recorded time.
    public static func build(from records: [MacDocumentVersion]) -> [TimelineEvent] {
        var events: [TimelineEvent] = []
        for record in records {
            guard let date = record.versionTime else { continue }
            events.append(TimelineEvent(date: date,
                                        kind: .modified,
                                        source: .docRevisions,
                                        fileID: 0,
                                        path: record.timelineSummary,
                                        size: record.size ?? 0,
                                        isDeleted: false))
        }
        return events.sorted { $0.date < $1.date }
    }

    /// macOS Notification Center records → timeline (one event per delivered
    /// notification with a date).
    public static func build(from records: [MacNotification]) -> [TimelineEvent] {
        var events: [TimelineEvent] = []
        for record in records {
            guard let date = record.deliveredDate else { continue }
            events.append(TimelineEvent(date: date,
                                        kind: .changed,
                                        source: .notifications,
                                        fileID: 0,
                                        path: record.timelineSummary,
                                        size: 0,
                                        isDeleted: false))
        }
        return events.sorted { $0.date < $1.date }
    }

    public static func build(from records: [PowerlogEntry]) -> [TimelineEvent] {
        var events: [TimelineEvent] = []
        for record in records {
            guard let date = record.date else { continue }
            events.append(TimelineEvent(date: date,
                                        kind: .changed,
                                        source: .powerlog,
                                        fileID: 0,
                                        path: record.timelineSummary,
                                        size: 0,
                                        isDeleted: false))
        }
        return events.sorted { $0.date < $1.date }
    }

    public static func build(from records: [MacInstallEntry]) -> [TimelineEvent] {
        var events: [TimelineEvent] = []
        for record in records {
            guard let date = record.date else { continue }
            events.append(TimelineEvent(date: date,
                                        kind: .born,
                                        source: .install,
                                        fileID: 0,
                                        path: record.timelineSummary,
                                        size: 0,
                                        isDeleted: false))
        }
        return events.sorted { $0.date < $1.date }
    }

    /// Project registry keys onto the timeline as key last-written events. The
    /// parse output is per-*value*, but the timestamp libregf surfaces is the
    /// *key's*, so values are deduped to one event per key write (keyed on
    /// source hive file + key path + timestamp, so two users' NTUSER hives -
    /// same logical label - never merge). Keys without a timestamp are dropped.
    public static func build(from values: [RegistryValue]) -> [TimelineEvent] {
        var events: [TimelineEvent] = []
        var seen = Set<String>()
        for value in values {
            guard let date = value.lastWritten else { continue }
            let key = "\(value.sourceFile)|\(value.hive)|\(value.path)|\(date.timeIntervalSinceReferenceDate.bitPattern)"
            guard seen.insert(key).inserted else { continue }
            events.append(TimelineEvent(date: date,
                                        kind: .modified,
                                        source: .registry,
                                        fileID: 0,
                                        path: "\(value.fullPath)  [key written]",
                                        size: 0,
                                        isDeleted: false))
        }
        return events.sorted { $0.date < $1.date }
    }

    /// Project prefetch entries onto the timeline - one event per *recorded*
    /// run timestamp (up to 8 on Win8+). Execution evidence is the single
    /// highest-signal artifact on the timeline, so each run is its own row.
    public static func build(from entries: [PrefetchEntry]) -> [TimelineEvent] {
        var events: [TimelineEvent] = []
        events.reserveCapacity(entries.count * 2)
        for entry in entries {
            for run in entry.lastRunTimes {
                events.append(TimelineEvent(date: run,
                                            kind: .changed,
                                            source: .prefetch,
                                            fileID: 0,
                                            path: "\(entry.executableName)  [executed; \(entry.runCount) runs total]",
                                            size: 0,
                                            isDeleted: false))
            }
        }
        return events.sorted { $0.date < $1.date }
    }

    /// Project Shimcache entries onto the timeline. The timestamp is the
    /// target's `$SI` last-modified *as captured by AppCompat* - presence
    /// evidence, not execution - so the row says so.
    public static func build(from entries: [ShimcacheEntry]) -> [TimelineEvent] {
        var events: [TimelineEvent] = []
        events.reserveCapacity(entries.count)
        for entry in entries {
            guard let date = entry.lastModified else { continue }
            events.append(TimelineEvent(date: date,
                                        kind: .modified,
                                        source: .shimcache,
                                        fileID: 0,
                                        path: "\(entry.path)  [shimcache presence]",
                                        size: 0,
                                        isDeleted: false))
        }
        return events.sorted { $0.date < $1.date }
    }

    /// Project Amcache entries onto the timeline at their registry-key write
    /// time (~ when Windows inventoried the binary - first-seen, not run time).
    public static func build(from entries: [AmcacheEntry]) -> [TimelineEvent] {
        var events: [TimelineEvent] = []
        events.reserveCapacity(entries.count)
        for entry in entries {
            guard let date = entry.registeredAt else { continue }
            events.append(TimelineEvent(date: date,
                                        kind: .changed,
                                        source: .amcache,
                                        fileID: 0,
                                        path: "\(entry.fullPath ?? entry.name)  [amcache registered]",
                                        size: 0,
                                        isDeleted: false))
        }
        return events.sorted { $0.date < $1.date }
    }

    /// Project LNK shortcuts onto the timeline as the *target's* MAC times as
    /// of the access that wrote the shortcut - file-access evidence that
    /// survives the target's deletion. One event per non-nil timestamp.
    public static func build(from entries: [LnkEntry]) -> [TimelineEvent] {
        var events: [TimelineEvent] = []
        events.reserveCapacity(entries.count * 2)
        for entry in entries {
            let target = entry.targetPath ?? entry.name
            let macb: [(Date?, MACBKind)] = [
                (entry.targetModified, .modified),
                (entry.targetAccessed, .accessed),
                (entry.targetCreated, .born),
            ]
            for (date, kind) in macb {
                guard let date else { continue }
                events.append(TimelineEvent(date: date,
                                            kind: kind,
                                            source: .lnk,
                                            fileID: 0,
                                            path: "\(target)  [lnk: \(entry.name)]",
                                            size: entry.targetSize ?? 0,
                                            isDeleted: false))
            }
        }
        return events.sorted { $0.date < $1.date }
    }

    /// Project JumpList destinations onto the timeline at their DestList
    /// last-access time - a true per-target user-activity timestamp. Custom
    /// destinations (no DestList) carry no time and are dropped.
    public static func build(from entries: [JumpListEntry]) -> [TimelineEvent] {
        var events: [TimelineEvent] = []
        events.reserveCapacity(entries.count)
        for entry in entries {
            guard let date = entry.lastAccessed else { continue }
            events.append(TimelineEvent(date: date,
                                        kind: .accessed,
                                        source: .jumplist,
                                        fileID: 0,
                                        path: "\(entry.targetPath ?? entry.name)  [jumplist: \(entry.application ?? entry.appID)]",
                                        size: 0,
                                        isDeleted: false))
        }
        return events.sorted { $0.date < $1.date }
    }

    /// Project auth-log events onto the timeline. `kind` is `.changed` (the
    /// fs analogue for "activity recorded"); the path encodes the classified
    /// kind + message so rows read well and free-text search matches
    /// usernames/IPs. Entries whose (year-inferred) timestamp is missing are
    /// dropped.
    public static func build(from entries: [AuthLogEntry]) -> [TimelineEvent] {
        var events: [TimelineEvent] = []
        events.reserveCapacity(entries.count)
        for entry in entries {
            guard let date = entry.timestamp else { continue }
            events.append(TimelineEvent(date: date,
                                        kind: .changed,
                                        source: .authlog,
                                        fileID: 0,
                                        path: "\(entry.process): \(entry.message)",
                                        size: 0,
                                        isDeleted: false))
        }
        return events.sorted { $0.date < $1.date }
    }

    /// Project wtmp/btmp login records onto the timeline. btmp rows (failed
    /// logins) are labelled as such - they're brute-force evidence.
    public static func build(from records: [UtmpRecord]) -> [TimelineEvent] {
        var events: [TimelineEvent] = []
        events.reserveCapacity(records.count)
        for record in records {
            guard let date = record.timestamp else { continue }
            let what = record.isFailedLogin ? "Failed login" : record.type.label
            let from = record.host.isEmpty ? "" : " from \(record.host)"
            events.append(TimelineEvent(date: date,
                                        kind: .changed,
                                        source: .logins,
                                        fileID: 0,
                                        path: "\(what): \(record.user) on \(record.line)\(from)",
                                        size: 0,
                                        isDeleted: false))
        }
        return events.sorted { $0.date < $1.date }
    }

    /// Project shell-history commands onto the timeline. Only entries that
    /// carry a real timestamp (zsh extended / bash HISTTIMEFORMAT) appear -
    /// undated bash history has order but no clock, and inventing one would
    /// poison the timeline.
    public static func build(from entries: [ShellHistoryEntry]) -> [TimelineEvent] {
        var events: [TimelineEvent] = []
        events.reserveCapacity(entries.count)
        for entry in entries {
            guard let date = entry.timestamp else { continue }
            events.append(TimelineEvent(date: date,
                                        kind: .changed,
                                        source: .shellHistory,
                                        fileID: 0,
                                        path: "\(entry.user)$ \(entry.command)",
                                        size: 0,
                                        isDeleted: false))
        }
        return events.sorted { $0.date < $1.date }
    }

    /// Project web access-log requests onto the timeline. `kind` is `.changed`;
    /// the path encodes method + status + target + client IP so rows read well
    /// and free-text search matches IPs/paths. Requests without a (timezone-
    /// explicit) timestamp are dropped.
    public static func build(from entries: [WebAccessLogEntry]) -> [TimelineEvent] {
        var events: [TimelineEvent] = []
        events.reserveCapacity(entries.count)
        for entry in entries {
            guard let date = entry.timestamp else { continue }
            events.append(TimelineEvent(date: date,
                                        kind: .changed,
                                        source: .weblog,
                                        fileID: 0,
                                        path: "\(entry.method) \(entry.status) \(entry.target)  [\(entry.clientIP)]",
                                        size: entry.bytes,
                                        isDeleted: false))
        }
        return events.sorted { $0.date < $1.date }
    }

    /// Project package-manager events onto the timeline - install/remove/upgrade
    /// of software, one event each. `kind` is `.born` for installs, `.changed`
    /// otherwise. Events without a timestamp are dropped.
    public static func build(from events: [PackageEvent]) -> [TimelineEvent] {
        var out: [TimelineEvent] = []
        out.reserveCapacity(events.count)
        for event in events {
            guard let date = event.timestamp else { continue }
            let version = event.version.map { " \($0)" } ?? ""
            out.append(TimelineEvent(date: date,
                                     kind: event.action == .install ? .born : .changed,
                                     source: .package,
                                     fileID: 0,
                                     path: "\(event.manager.label) \(event.action.label): \(event.package)\(version)",
                                     size: 0,
                                     isDeleted: event.action.isRemoval))
        }
        return out.sorted { $0.date < $1.date }
    }

    /// Project journald entries onto the timeline. `kind` is `.changed`; the
    /// path encodes the program + message so rows read well and free-text
    /// search matches. Entries without a timestamp are dropped.
    public static func build(from entries: [JournaldEntry]) -> [TimelineEvent] {
        var out: [TimelineEvent] = []
        out.reserveCapacity(entries.count)
        for entry in entries {
            guard let date = entry.timestamp else { continue }
            let prog = entry.program.map { "\($0): " } ?? ""
            out.append(TimelineEvent(date: date, kind: .changed, source: .journald,
                                     fileID: 0, path: "\(prog)\(entry.message)",
                                     size: 0, isDeleted: false))
        }
        return out.sorted { $0.date < $1.date }
    }

    /// Project macOS unified-log entries onto the timeline. `kind` is `.changed`;
    /// the path encodes `process: message` (with subsystem when present) so rows
    /// read well and free-text search matches. Entries without a timestamp are
    /// dropped.
    public static func build(from entries: [UnifiedLogEntry]) -> [TimelineEvent] {
        var out: [TimelineEvent] = []
        out.reserveCapacity(entries.count)
        for entry in entries {
            guard let date = entry.timestamp else { continue }
            let proc = entry.process.map { "\($0): " } ?? ""
            let sub = entry.subsystem.map { "[\($0)] " } ?? ""
            out.append(TimelineEvent(date: date, kind: .changed, source: .unifiedLog,
                                     fileID: 0, path: "\(proc)\(sub)\(entry.message)",
                                     size: 0, isDeleted: false))
        }
        return out.sorted { $0.date < $1.date }
    }

    /// Project TCC privacy grants onto the timeline. `kind` is `.changed`; the
    /// path encodes `service → client (authValue)` so rows read well and search
    /// matches. Grants without a `last_modified` time are dropped.
    public static func build(from grants: [TCCAccess]) -> [TimelineEvent] {
        var out: [TimelineEvent] = []
        out.reserveCapacity(grants.count)
        for g in grants {
            guard let date = g.lastModified else { continue }
            out.append(TimelineEvent(date: date, kind: .changed, source: .tcc,
                                     fileID: 0,
                                     path: "\(g.serviceLabel) → \(g.clientLabel) (\(g.authValue.label))",
                                     size: 0, isDeleted: false))
        }
        return out.sorted { $0.date < $1.date }
    }

    /// Project KnowledgeC behavioural records onto the timeline. `kind` is
    /// `.changed`; the path encodes `category: summary` (app focus, screen
    /// on/off, media, Safari) so rows read well and search matches. Records
    /// without a start time are dropped.
    public static func build(from records: [KnowledgeEntry]) -> [TimelineEvent] {
        var out: [TimelineEvent] = []
        out.reserveCapacity(records.count)
        for r in records {
            guard let date = r.startDate else { continue }
            out.append(TimelineEvent(date: date, kind: .changed, source: .knowledgeC,
                                     fileID: 0, path: "\(r.category.label): \(r.summary)",
                                     size: 0, isDeleted: false))
        }
        return out.sorted { $0.date < $1.date }
    }

    /// Project macOS recent items onto the timeline. `kind` is `.accessed`;
    /// these stores represent recently opened apps/documents/servers and are
    /// therefore user-activity evidence. Undated items are dropped.
    public static func build(from items: [MacRecentItem]) -> [TimelineEvent] {
        var out: [TimelineEvent] = []
        out.reserveCapacity(items.count)
        for item in items {
            guard let date = item.timestamp else { continue }
            out.append(TimelineEvent(date: date, kind: .accessed, source: .macRecent,
                                     fileID: 0, path: item.timelineSummary,
                                     size: 0, isDeleted: false))
        }
        return out.sorted { $0.date < $1.date }
    }

    /// Project Gatekeeper/XProtect/MRT-style security log events onto the timeline.
    public static func build(from events: [MacSecurityEvent]) -> [TimelineEvent] {
        var out: [TimelineEvent] = []
        out.reserveCapacity(events.count)
        for event in events {
            guard let date = event.timestamp else { continue }
            out.append(TimelineEvent(date: date, kind: .changed, source: .macSecurity,
                                     fileID: 0, path: event.timelineSummary,
                                     size: 0, isDeleted: false))
        }
        return out.sorted { $0.date < $1.date }
    }

    /// Project auditd events onto the timeline. `kind` is `.changed`; the path
    /// encodes the record type + command/summary. Events without a timestamp
    /// are dropped.
    public static func build(from events: [AuditEvent]) -> [TimelineEvent] {
        var out: [TimelineEvent] = []
        out.reserveCapacity(events.count)
        for event in events {
            guard let date = event.timestamp else { continue }
            out.append(TimelineEvent(date: date, kind: .changed, source: .auditd,
                                     fileID: 0, path: "\(event.recordType): \(event.summary)",
                                     size: 0, isDeleted: false))
        }
        return out.sorted { $0.date < $1.date }
    }

    /// Project general syslog/messages entries onto the timeline. Noise
    /// categories (service start/stop, other) are dropped to avoid drowning
    /// the timeline. Undated entries are dropped.
    public static func build(from entries: [SyslogEntry]) -> [TimelineEvent] {
        var out: [TimelineEvent] = []
        out.reserveCapacity(entries.count)
        for entry in entries {
            guard let date = entry.timestamp, !entry.category.isNoise else { continue }
            out.append(TimelineEvent(date: date, kind: .changed, source: .syslog,
                                     fileID: 0, path: "[\(entry.category.label)] \(entry.process): \(entry.message)",
                                     size: 0, isDeleted: false))
        }
        return out.sorted { $0.date < $1.date }
    }

    /// Project lastlog records onto the timeline - one point-in-time last-login
    /// event per account.
    public static func build(from records: [LastlogEntry]) -> [TimelineEvent] {
        var out: [TimelineEvent] = []
        out.reserveCapacity(records.count)
        for record in records {
            guard let date = record.timestamp else { continue }
            let from = record.host.isEmpty ? "" : " from \(record.host)"
            out.append(TimelineEvent(date: date, kind: .accessed, source: .lastlog,
                                     fileID: 0,
                                     path: "Last login: \(record.account) on \(record.line)\(from)",
                                     size: 0, isDeleted: false))
        }
        return out.sorted { $0.date < $1.date }
    }

    /// Project `$MFT` records onto the timeline as their `$STANDARD_INFORMATION`
    /// MACB rows — the *true* NTFS file timeline (the only real one for loose
    /// collections, which otherwise fall back to collection-host times). One row
    /// per distinct non-nil $SI timestamp; an entry without a name is skipped.
    public static func build(from records: [MftEntry]) -> [TimelineEvent] {
        var events: [TimelineEvent] = []
        events.reserveCapacity(records.count)
        for record in records {
            guard record.fileName != nil else { continue }
            let path = record.displayPath
            let macb: [(Date?, MACBKind)] = [
                (record.siModified, .modified), (record.siAccessed, .accessed),
                (record.siChanged, .changed), (record.siCreated, .born),
            ]
            for (date, kind) in macb {
                guard let date else { continue }
                events.append(TimelineEvent(date: date, kind: kind, source: .mft,
                                            fileID: 0, path: path,
                                            size: record.size ?? 0, isDeleted: !record.inUse))
            }
        }
        return events.sorted { $0.date < $1.date }
    }
}
