import Foundation

/// On-disk layout for a Strata case bundle. The bundle is a plain directory
/// with a `.strata` extension - no zip, no top-level SQLite - so a curious
/// user can poke around with Finder if they want.
///
/// MyCase.strata/
///   case.json                metadata { id, name, examiner, createdAt }
///   hosts.json               [{ id, displayName, sourceURL, kind, acquisition, sourceHashes }, ...]
///   custody.json             append-only chain-of-custody log [CustodyEvent], case-wide
///   iocs.json                case-wide indicators [IOC]
///   hosts/<host-uuid>/
///     tsk.db                 SQLite produced by tsk_loaddb
///     events/                scratch dir for extracted .evtx files
///     registry/              scratch dir for extracted hives
public nonisolated enum CaseStore {
    public static let bundleExtension = "strata"

    private static let caseFilename     = "case.json"
    private static let hostsFilename    = "hosts.json"
    private static let hostsDirname     = "hosts"
    private static let tskFilename      = "tsk.db"
    private static let eventsFilename     = "events.json"
    private static let registryFilename   = "registry.json"
    private static let prefetchFilename   = "prefetch.json"
    private static let amcacheFilename     = "amcache.json"
    private static let shimcacheFilename    = "shimcache.json"
    private static let lnkFilename          = "lnk.json"
    private static let jumplistFilename     = "jumplist.json"
    private static let usnFilename          = "usn.json"
    private static let srumFilename         = "srum.json"
    private static let browserHistoryFilename = "browserhistory.json"
    private static let mftFilename            = "mft.json"
    private static let wmiFilename            = "wmi.json"
    private static let authLogFilename    = "authlog.json"
    private static let loginsFilename     = "logins.json"
    private static let shellHistoryFilename = "shellhistory.json"
    private static let linuxPersistenceFilename = "linuxpersistence.json"
    private static let linuxInfoFilename  = "linuxinfo.json"
    private static let macInfoFilename    = "macinfo.json"
    private static let macPersistenceFilename = "macpersistence.json"
    private static let fsEventsFilename   = "fsevents.json"
    private static let linuxAccessFilename = "linuxaccess.json"
    private static let webAccessFilename  = "weblog.json"
    private static let packagesFilename   = "packages.json"
    private static let journaldFilename   = "journald.json"
    private static let unifiedLogFilename = "unifiedlog.json"
    private static let tccFilename        = "tcc.json"
    private static let knowledgeCFilename = "knowledgec.json"
    private static let macRecentItemsFilename = "macrecentitems.json"
    private static let carvedFilename = "carved.json"
    private static let kextsFilename = "kexts.json"
    private static let backgroundItemsFilename = "backgrounditems.json"
    private static let messagesFilename = "messages.json"
    private static let mailFilename = "mail.json"
    private static let networkFilename = "network.json"
    private static let userActivityFilename = "useractivity.json"
    private static let documentVersionsFilename = "docrevisions.json"
    private static let macSecurityFilename = "macsecurity.json"
    private static let auditFilename      = "audit.json"
    private static let syslogFilename     = "syslog.json"
    private static let lastlogFilename    = "lastlog.json"
    private static let findingsFilename   = "findings.json"
    private static let iocsFilename       = "iocs.json"
    private static let iocMatchesFilename = "iocmatches.json"
    private static let custodyFilename    = "custody.json"
    private static let annotationsFilename = "annotations.json"
    private static let notesFilename      = "notes.json"
    private static let enrichmentFilename = "enrichment.json"
    private static let summaryFilename    = "summary.json"

    // MARK: - URLs

    public static func caseFile(in bundle: URL) -> URL {
        bundle.appendingPathComponent(caseFilename)
    }

    public static func hostsFile(in bundle: URL) -> URL {
        bundle.appendingPathComponent(hostsFilename)
    }

    public static func hostDirectory(forHostID id: UUID, in bundle: URL) -> URL {
        bundle.appendingPathComponent(hostsDirname, isDirectory: true)
              .appendingPathComponent(id.uuidString, isDirectory: true)
    }

    public static func tskDatabaseURL(forHostID id: UUID, in bundle: URL) -> URL {
        hostDirectory(forHostID: id, in: bundle).appendingPathComponent(tskFilename)
    }

    public static func eventScratchDirectory(forHostID id: UUID, in bundle: URL) -> URL {
        hostDirectory(forHostID: id, in: bundle)
            .appendingPathComponent("events", isDirectory: true)
    }

    public static func lnkScratchDirectory(forHostID id: UUID, in bundle: URL) -> URL {
        hostDirectory(forHostID: id, in: bundle)
            .appendingPathComponent("lnk", isDirectory: true)
    }

    public static func jumpListScratchDirectory(forHostID id: UUID, in bundle: URL) -> URL {
        hostDirectory(forHostID: id, in: bundle)
            .appendingPathComponent("jumplist", isDirectory: true)
    }

    public static func usnScratchDirectory(forHostID id: UUID, in bundle: URL) -> URL {
        hostDirectory(forHostID: id, in: bundle)
            .appendingPathComponent("usn", isDirectory: true)
    }

    public static func srumScratchDirectory(forHostID id: UUID, in bundle: URL) -> URL {
        hostDirectory(forHostID: id, in: bundle)
            .appendingPathComponent("srum", isDirectory: true)
    }

    public static func browserHistoryScratchDirectory(forHostID id: UUID, in bundle: URL) -> URL {
        hostDirectory(forHostID: id, in: bundle)
            .appendingPathComponent("browser", isDirectory: true)
    }

    public static func mftScratchDirectory(forHostID id: UUID, in bundle: URL) -> URL {
        hostDirectory(forHostID: id, in: bundle)
            .appendingPathComponent("mft", isDirectory: true)
    }

    public static func wmiScratchDirectory(forHostID id: UUID, in bundle: URL) -> URL {
        hostDirectory(forHostID: id, in: bundle)
            .appendingPathComponent("wmi", isDirectory: true)
    }

    public static func registryScratchDirectory(forHostID id: UUID, in bundle: URL) -> URL {
        hostDirectory(forHostID: id, in: bundle)
            .appendingPathComponent("registry", isDirectory: true)
    }

    public static func prefetchScratchDirectory(forHostID id: UUID, in bundle: URL) -> URL {
        hostDirectory(forHostID: id, in: bundle)
            .appendingPathComponent("prefetch", isDirectory: true)
    }

    public static func unifiedLogScratchDirectory(forHostID id: UUID, in bundle: URL) -> URL {
        hostDirectory(forHostID: id, in: bundle)
            .appendingPathComponent("unifiedlog", isDirectory: true)
    }

    // MARK: - Create / load

    public static func createBundle(at bundle: URL, case theCase: ForensicCase) throws {
        let fm = FileManager.default
        try fm.createDirectory(at: bundle, withIntermediateDirectories: true)
        try fm.createDirectory(
            at: bundle.appendingPathComponent(hostsDirname, isDirectory: true),
            withIntermediateDirectories: true)
        try writeCase(theCase, in: bundle)
        try writeHosts([], in: bundle)
    }

    public static func readCase(in bundle: URL) throws -> ForensicCase {
        let data = try Data(contentsOf: caseFile(in: bundle))
        return try jsonDecoder.decode(ForensicCase.self, from: data)
    }

    public static func writeCase(_ theCase: ForensicCase, in bundle: URL) throws {
        let data = try jsonEncoder.encode(theCase)
        try data.write(to: caseFile(in: bundle), options: .atomic)
    }

    public static func readHosts(in bundle: URL) throws -> [Evidence] {
        let url = hostsFile(in: bundle)
        guard FileManager.default.fileExists(atPath: url.path) else { return [] }
        let data = try Data(contentsOf: url)
        var hosts = try jsonDecoder.decode([Evidence].self, from: data)
        // tskDatabaseURL is bundle-relative; rebuild on load so the bundle
        // can move on disk without orphaning host references.
        for i in hosts.indices {
            hosts[i].tskDatabaseURL = tskDatabaseURL(forHostID: hosts[i].id, in: bundle)
        }
        return hosts
    }

    public static func writeHosts(_ hosts: [Evidence], in bundle: URL) throws {
        let data = try jsonEncoder.encode(hosts)
        try data.write(to: hostsFile(in: bundle), options: .atomic)
    }

    public static func removeHostDirectory(forHostID id: UUID, in bundle: URL) {
        try? FileManager.default.removeItem(at: hostDirectory(forHostID: id, in: bundle))
    }

    // MARK: - Parsed artifacts (per host)
    //
    // Events, registry values, and findings are written after the
    // corresponding parse stage so reopening a case doesn't require
    // re-parsing. Encoded compactly (no pretty-print) because event arrays
    // get large and pretty-printing roughly doubles their size on disk.

    public static func eventsFileURL(forHostID id: UUID, in bundle: URL) -> URL {
        hostDirectory(forHostID: id, in: bundle).appendingPathComponent(eventsFilename)
    }
    public static func registryFileURL(forHostID id: UUID, in bundle: URL) -> URL {
        hostDirectory(forHostID: id, in: bundle).appendingPathComponent(registryFilename)
    }
    public static func findingsFileURL(forHostID id: UUID, in bundle: URL) -> URL {
        hostDirectory(forHostID: id, in: bundle).appendingPathComponent(findingsFilename)
    }

    public static func readEvents(forHostID id: UUID, in bundle: URL) throws -> [EventLogRecord]? {
        try readArrayIfPresent(at: eventsFileURL(forHostID: id, in: bundle))
    }
    public static func writeEvents(_ events: [EventLogRecord],
                                   forHostID id: UUID, in bundle: URL) throws {
        try writeArray(events, at: eventsFileURL(forHostID: id, in: bundle))
    }
    /// "Lite" event load: same JSON file, but a Decodable variant that
    /// skips the `payloadXML` field (typically the bulk of each record's
    /// in-memory size). Used by iOS where carrying every event's XML payload
    /// for a 1M+ event case is enough to get the app OOM-killed.
    ///
    /// The on-disk format is unchanged - macOS still reads the full record.
    public static func readEventsLite(forHostID id: UUID, in bundle: URL) throws -> [EventLogRecord]? {
        let url = eventsFileURL(forHostID: id, in: bundle)
        guard FileManager.default.fileExists(atPath: url.path) else { return nil }
        // Memory-map rather than read; large events.json files are common
        // and a straight `Data(contentsOf:)` can already exceed iOS limits
        // before decoding even starts.
        let data = try Data(contentsOf: url, options: .alwaysMapped)
        let lite = try jsonDecoder.decode([EventLogRecordLite].self, from: data)
        return lite.map { $0.materialize() }
    }
    public static func readRegistry(forHostID id: UUID, in bundle: URL) throws -> [RegistryValue]? {
        try readArrayIfPresent(at: registryFileURL(forHostID: id, in: bundle))
    }
    public static func writeRegistry(_ values: [RegistryValue],
                                     forHostID id: UUID, in bundle: URL) throws {
        try writeArray(values, at: registryFileURL(forHostID: id, in: bundle))
    }
    public static func prefetchFileURL(forHostID id: UUID, in bundle: URL) -> URL {
        hostDirectory(forHostID: id, in: bundle).appendingPathComponent(prefetchFilename)
    }
    public static func readPrefetch(forHostID id: UUID, in bundle: URL) throws -> [PrefetchEntry]? {
        try readArrayIfPresent(at: prefetchFileURL(forHostID: id, in: bundle))
    }
    public static func writePrefetch(_ entries: [PrefetchEntry],
                                     forHostID id: UUID, in bundle: URL) throws {
        try writeArray(entries, at: prefetchFileURL(forHostID: id, in: bundle))
    }
    public static func amcacheFileURL(forHostID id: UUID, in bundle: URL) -> URL {
        hostDirectory(forHostID: id, in: bundle).appendingPathComponent(amcacheFilename)
    }
    public static func readAmcache(forHostID id: UUID, in bundle: URL) throws -> [AmcacheEntry]? {
        try readArrayIfPresent(at: amcacheFileURL(forHostID: id, in: bundle))
    }
    public static func writeAmcache(_ entries: [AmcacheEntry],
                                    forHostID id: UUID, in bundle: URL) throws {
        try writeArray(entries, at: amcacheFileURL(forHostID: id, in: bundle))
    }
    public static func shimcacheFileURL(forHostID id: UUID, in bundle: URL) -> URL {
        hostDirectory(forHostID: id, in: bundle).appendingPathComponent(shimcacheFilename)
    }
    public static func readShimcache(forHostID id: UUID, in bundle: URL) throws -> [ShimcacheEntry]? {
        try readArrayIfPresent(at: shimcacheFileURL(forHostID: id, in: bundle))
    }
    public static func writeShimcache(_ entries: [ShimcacheEntry],
                                      forHostID id: UUID, in bundle: URL) throws {
        try writeArray(entries, at: shimcacheFileURL(forHostID: id, in: bundle))
    }
    public static func lnkFileURL(forHostID id: UUID, in bundle: URL) -> URL {
        hostDirectory(forHostID: id, in: bundle).appendingPathComponent(lnkFilename)
    }
    public static func readLnk(forHostID id: UUID, in bundle: URL) throws -> [LnkEntry]? {
        try readArrayIfPresent(at: lnkFileURL(forHostID: id, in: bundle))
    }
    public static func writeLnk(_ entries: [LnkEntry],
                                forHostID id: UUID, in bundle: URL) throws {
        try writeArray(entries, at: lnkFileURL(forHostID: id, in: bundle))
    }
    public static func jumpListFileURL(forHostID id: UUID, in bundle: URL) -> URL {
        hostDirectory(forHostID: id, in: bundle).appendingPathComponent(jumplistFilename)
    }
    public static func readJumpList(forHostID id: UUID, in bundle: URL) throws -> [JumpListEntry]? {
        try readArrayIfPresent(at: jumpListFileURL(forHostID: id, in: bundle))
    }
    public static func writeJumpList(_ entries: [JumpListEntry],
                                     forHostID id: UUID, in bundle: URL) throws {
        try writeArray(entries, at: jumpListFileURL(forHostID: id, in: bundle))
    }
    public static func usnFileURL(forHostID id: UUID, in bundle: URL) -> URL {
        hostDirectory(forHostID: id, in: bundle).appendingPathComponent(usnFilename)
    }
    public static func readUsn(forHostID id: UUID, in bundle: URL) throws -> [UsnRecord]? {
        try readArrayIfPresent(at: usnFileURL(forHostID: id, in: bundle))
    }
    public static func writeUsn(_ records: [UsnRecord],
                                forHostID id: UUID, in bundle: URL) throws {
        try writeArray(records, at: usnFileURL(forHostID: id, in: bundle))
    }
    public static func recycleBinFileURL(forHostID id: UUID, in bundle: URL) -> URL {
        hostDirectory(forHostID: id, in: bundle).appendingPathComponent("recyclebin.json")
    }
    public static func readRecycleBin(forHostID id: UUID, in bundle: URL) throws -> [RecycleBinEntry]? {
        try readArrayIfPresent(at: recycleBinFileURL(forHostID: id, in: bundle))
    }
    public static func writeRecycleBin(_ entries: [RecycleBinEntry],
                                       forHostID id: UUID, in bundle: URL) throws {
        try writeArray(entries, at: recycleBinFileURL(forHostID: id, in: bundle))
    }
    public static func readLaunchItems(forHostID id: UUID, in bundle: URL) throws -> [LaunchItemEntry]? {
        try readArrayIfPresent(at: hostDirectory(forHostID: id, in: bundle).appendingPathComponent("launchitems.json"))
    }
    public static func writeLaunchItems(_ items: [LaunchItemEntry], forHostID id: UUID, in bundle: URL) throws {
        try writeArray(items, at: hostDirectory(forHostID: id, in: bundle).appendingPathComponent("launchitems.json"))
    }
    public static func readQuarantine(forHostID id: UUID, in bundle: URL) throws -> [QuarantineEvent]? {
        try readArrayIfPresent(at: hostDirectory(forHostID: id, in: bundle).appendingPathComponent("quarantine.json"))
    }
    public static func writeQuarantine(_ events: [QuarantineEvent], forHostID id: UUID, in bundle: URL) throws {
        try writeArray(events, at: hostDirectory(forHostID: id, in: bundle).appendingPathComponent("quarantine.json"))
    }
    // APFS evidence has no tsk.db, so its file tree + volumes are persisted as
    // JSON (image hosts re-read these from the TSK database on case open).
    public static func readApfsFiles(forHostID id: UUID, in bundle: URL) throws -> [FileEntry]? {
        try readArrayIfPresent(at: hostDirectory(forHostID: id, in: bundle).appendingPathComponent("apfsfiles.json"))
    }
    public static func writeApfsFiles(_ files: [FileEntry], forHostID id: UUID, in bundle: URL) throws {
        try writeArray(files, at: hostDirectory(forHostID: id, in: bundle).appendingPathComponent("apfsfiles.json"))
    }
    public static func readApfsVolumes(forHostID id: UUID, in bundle: URL) throws -> [VolumeInfo]? {
        try readArrayIfPresent(at: hostDirectory(forHostID: id, in: bundle).appendingPathComponent("apfsvolumes.json"))
    }
    public static func writeApfsVolumes(_ volumes: [VolumeInfo], forHostID id: UUID, in bundle: URL) throws {
        try writeArray(volumes, at: hostDirectory(forHostID: id, in: bundle).appendingPathComponent("apfsvolumes.json"))
    }
    public static func readMacPersistence(forHostID id: UUID, in bundle: URL) throws -> [MacPersistenceItem]? {
        try readArrayIfPresent(at: hostDirectory(forHostID: id, in: bundle).appendingPathComponent(macPersistenceFilename))
    }
    public static func writeMacPersistence(_ items: [MacPersistenceItem], forHostID id: UUID, in bundle: URL) throws {
        try writeArray(items, at: hostDirectory(forHostID: id, in: bundle).appendingPathComponent(macPersistenceFilename))
    }
    public static func readFSEvents(forHostID id: UUID, in bundle: URL) throws -> [FSEventRecord]? {
        try readArrayIfPresent(at: hostDirectory(forHostID: id, in: bundle).appendingPathComponent(fsEventsFilename))
    }
    public static func writeFSEvents(_ records: [FSEventRecord], forHostID id: UUID, in bundle: URL) throws {
        try writeArray(records, at: hostDirectory(forHostID: id, in: bundle).appendingPathComponent(fsEventsFilename))
    }
    public static func srumFileURL(forHostID id: UUID, in bundle: URL) -> URL {
        hostDirectory(forHostID: id, in: bundle).appendingPathComponent(srumFilename)
    }
    public static func readSrum(forHostID id: UUID, in bundle: URL) throws -> [SrumEntry]? {
        try readArrayIfPresent(at: srumFileURL(forHostID: id, in: bundle))
    }
    public static func writeSrum(_ entries: [SrumEntry],
                                 forHostID id: UUID, in bundle: URL) throws {
        try writeArray(entries, at: srumFileURL(forHostID: id, in: bundle))
    }
    public static func browserHistoryFileURL(forHostID id: UUID, in bundle: URL) -> URL {
        hostDirectory(forHostID: id, in: bundle).appendingPathComponent(browserHistoryFilename)
    }
    public static func readBrowserHistory(forHostID id: UUID, in bundle: URL) throws -> [BrowserHistoryEntry]? {
        try readArrayIfPresent(at: browserHistoryFileURL(forHostID: id, in: bundle))
    }
    public static func writeBrowserHistory(_ entries: [BrowserHistoryEntry],
                                           forHostID id: UUID, in bundle: URL) throws {
        try writeArray(entries, at: browserHistoryFileURL(forHostID: id, in: bundle))
    }
    public static func mftFileURL(forHostID id: UUID, in bundle: URL) -> URL {
        hostDirectory(forHostID: id, in: bundle).appendingPathComponent(mftFilename)
    }
    public static func readMft(forHostID id: UUID, in bundle: URL) throws -> [MftEntry]? {
        try readArrayIfPresent(at: mftFileURL(forHostID: id, in: bundle))
    }
    public static func writeMft(_ entries: [MftEntry],
                                forHostID id: UUID, in bundle: URL) throws {
        try writeArray(entries, at: mftFileURL(forHostID: id, in: bundle))
    }
    public static func wmiFileURL(forHostID id: UUID, in bundle: URL) -> URL {
        hostDirectory(forHostID: id, in: bundle).appendingPathComponent(wmiFilename)
    }
    public static func readWmi(forHostID id: UUID, in bundle: URL) throws -> [WmiPersistenceEntry]? {
        try readArrayIfPresent(at: wmiFileURL(forHostID: id, in: bundle))
    }
    public static func writeWmi(_ entries: [WmiPersistenceEntry],
                                forHostID id: UUID, in bundle: URL) throws {
        try writeArray(entries, at: wmiFileURL(forHostID: id, in: bundle))
    }
    public static func readFindings(forHostID id: UUID, in bundle: URL) throws -> [Finding]? {
        try readArrayIfPresent(at: findingsFileURL(forHostID: id, in: bundle))
    }
    public static func writeFindings(_ findings: [Finding],
                                     forHostID id: UUID, in bundle: URL) throws {
        try writeArray(findings, at: findingsFileURL(forHostID: id, in: bundle))
    }

    // MARK: - IOCs (case-wide) and IOC matches (per host)

    public static func iocsFileURL(in bundle: URL) -> URL {
        bundle.appendingPathComponent(iocsFilename)
    }

    public static func iocMatchesFileURL(forHostID id: UUID, in bundle: URL) -> URL {
        hostDirectory(forHostID: id, in: bundle).appendingPathComponent(iocMatchesFilename)
    }

    public static func readIOCs(in bundle: URL) throws -> [IOC] {
        try readArrayIfPresent(at: iocsFileURL(in: bundle)) ?? []
    }

    public static func writeIOCs(_ iocs: [IOC], in bundle: URL) throws {
        try writeArray(iocs, at: iocsFileURL(in: bundle))
    }

    public static func readIOCMatches(forHostID id: UUID, in bundle: URL) throws -> [IOCMatch]? {
        try readArrayIfPresent(at: iocMatchesFileURL(forHostID: id, in: bundle))
    }

    public static func writeIOCMatches(_ matches: [IOCMatch],
                                       forHostID id: UUID, in bundle: URL) throws {
        try writeArray(matches, at: iocMatchesFileURL(forHostID: id, in: bundle))
    }

    // MARK: - Chain of custody (case-wide, append-only)
    //
    // The custody log lives in its own bundle-root file rather than inside
    // `case.json` / `hosts.json` so the frequent rewrites of those files can
    // never truncate the legal-weight, append-only ledger.

    public static func custodyFileURL(in bundle: URL) -> URL {
        bundle.appendingPathComponent(custodyFilename)
    }

    public static func readCustody(in bundle: URL) throws -> [CustodyEvent] {
        try readArrayIfPresent(at: custodyFileURL(in: bundle)) ?? []
    }

    public static func writeCustody(_ events: [CustodyEvent], in bundle: URL) throws {
        try writeArray(events, at: custodyFileURL(in: bundle))
    }

    // MARK: - Linux artifacts (per host)

    public static func linuxScratchDirectory(forHostID id: UUID, in bundle: URL) -> URL {
        hostDirectory(forHostID: id, in: bundle).appendingPathComponent("linux", isDirectory: true)
    }

    public static func readAuthLog(forHostID id: UUID, in bundle: URL) throws -> [AuthLogEntry]? {
        try readArrayIfPresent(at: hostDirectory(forHostID: id, in: bundle)
            .appendingPathComponent(authLogFilename))
    }
    public static func writeAuthLog(_ entries: [AuthLogEntry],
                                    forHostID id: UUID, in bundle: URL) throws {
        try writeArray(entries, at: hostDirectory(forHostID: id, in: bundle)
            .appendingPathComponent(authLogFilename))
    }

    public static func readLogins(forHostID id: UUID, in bundle: URL) throws -> [UtmpRecord]? {
        try readArrayIfPresent(at: hostDirectory(forHostID: id, in: bundle)
            .appendingPathComponent(loginsFilename))
    }
    public static func writeLogins(_ records: [UtmpRecord],
                                   forHostID id: UUID, in bundle: URL) throws {
        try writeArray(records, at: hostDirectory(forHostID: id, in: bundle)
            .appendingPathComponent(loginsFilename))
    }

    public static func readShellHistory(forHostID id: UUID, in bundle: URL) throws -> [ShellHistoryEntry]? {
        try readArrayIfPresent(at: hostDirectory(forHostID: id, in: bundle)
            .appendingPathComponent(shellHistoryFilename))
    }
    public static func writeShellHistory(_ entries: [ShellHistoryEntry],
                                         forHostID id: UUID, in bundle: URL) throws {
        try writeArray(entries, at: hostDirectory(forHostID: id, in: bundle)
            .appendingPathComponent(shellHistoryFilename))
    }

    public static func readLinuxPersistence(forHostID id: UUID, in bundle: URL) throws -> [LinuxPersistenceEntry]? {
        try readArrayIfPresent(at: hostDirectory(forHostID: id, in: bundle)
            .appendingPathComponent(linuxPersistenceFilename))
    }
    public static func writeLinuxPersistence(_ entries: [LinuxPersistenceEntry],
                                             forHostID id: UUID, in bundle: URL) throws {
        try writeArray(entries, at: hostDirectory(forHostID: id, in: bundle)
            .appendingPathComponent(linuxPersistenceFilename))
    }

    public static func readLinuxInfo(forHostID id: UUID, in bundle: URL) throws -> LinuxHostInfo? {
        let url = hostDirectory(forHostID: id, in: bundle).appendingPathComponent(linuxInfoFilename)
        guard FileManager.default.fileExists(atPath: url.path) else { return nil }
        return try jsonDecoder.decode(LinuxHostInfo.self, from: Data(contentsOf: url))
    }
    public static func writeLinuxInfo(_ info: LinuxHostInfo,
                                      forHostID id: UUID, in bundle: URL) throws {
        let url = hostDirectory(forHostID: id, in: bundle).appendingPathComponent(linuxInfoFilename)
        try FileManager.default.createDirectory(at: url.deletingLastPathComponent(),
                                                withIntermediateDirectories: true)
        try jsonEncoder.encode(info).write(to: url, options: .atomic)
    }

    public static func readMacInfo(forHostID id: UUID, in bundle: URL) throws -> MacHostInfo? {
        let url = hostDirectory(forHostID: id, in: bundle).appendingPathComponent(macInfoFilename)
        guard FileManager.default.fileExists(atPath: url.path) else { return nil }
        return try jsonDecoder.decode(MacHostInfo.self, from: Data(contentsOf: url))
    }
    public static func writeMacInfo(_ info: MacHostInfo,
                                    forHostID id: UUID, in bundle: URL) throws {
        let url = hostDirectory(forHostID: id, in: bundle).appendingPathComponent(macInfoFilename)
        try FileManager.default.createDirectory(at: url.deletingLastPathComponent(),
                                                withIntermediateDirectories: true)
        try jsonEncoder.encode(info).write(to: url, options: .atomic)
    }

    public static func readLinuxAccess(forHostID id: UUID, in bundle: URL) throws -> LinuxAccessInfo? {
        let url = hostDirectory(forHostID: id, in: bundle).appendingPathComponent(linuxAccessFilename)
        guard FileManager.default.fileExists(atPath: url.path) else { return nil }
        return try jsonDecoder.decode(LinuxAccessInfo.self, from: Data(contentsOf: url))
    }
    public static func writeLinuxAccess(_ access: LinuxAccessInfo,
                                        forHostID id: UUID, in bundle: URL) throws {
        let url = hostDirectory(forHostID: id, in: bundle).appendingPathComponent(linuxAccessFilename)
        try FileManager.default.createDirectory(at: url.deletingLastPathComponent(),
                                                withIntermediateDirectories: true)
        try jsonEncoder.encode(access).write(to: url, options: .atomic)
    }

    public static func readWebAccess(forHostID id: UUID, in bundle: URL) throws -> [WebAccessLogEntry]? {
        try readArrayIfPresent(at: hostDirectory(forHostID: id, in: bundle)
            .appendingPathComponent(webAccessFilename))
    }
    public static func writeWebAccess(_ entries: [WebAccessLogEntry],
                                      forHostID id: UUID, in bundle: URL) throws {
        try writeArray(entries, at: hostDirectory(forHostID: id, in: bundle)
            .appendingPathComponent(webAccessFilename))
    }

    public static func readPackages(forHostID id: UUID, in bundle: URL) throws -> [PackageEvent]? {
        try readArrayIfPresent(at: hostDirectory(forHostID: id, in: bundle)
            .appendingPathComponent(packagesFilename))
    }
    public static func writePackages(_ events: [PackageEvent],
                                     forHostID id: UUID, in bundle: URL) throws {
        try writeArray(events, at: hostDirectory(forHostID: id, in: bundle)
            .appendingPathComponent(packagesFilename))
    }

    public static func readJournald(forHostID id: UUID, in bundle: URL) throws -> [JournaldEntry]? {
        try readArrayIfPresent(at: hostDirectory(forHostID: id, in: bundle)
            .appendingPathComponent(journaldFilename))
    }
    public static func writeJournald(_ entries: [JournaldEntry],
                                     forHostID id: UUID, in bundle: URL) throws {
        try writeArray(entries, at: hostDirectory(forHostID: id, in: bundle)
            .appendingPathComponent(journaldFilename))
    }

    public static func readUnifiedLog(forHostID id: UUID, in bundle: URL) throws -> [UnifiedLogEntry]? {
        try readArrayIfPresent(at: hostDirectory(forHostID: id, in: bundle)
            .appendingPathComponent(unifiedLogFilename))
    }
    public static func writeUnifiedLog(_ entries: [UnifiedLogEntry],
                                       forHostID id: UUID, in bundle: URL) throws {
        try writeArray(entries, at: hostDirectory(forHostID: id, in: bundle)
            .appendingPathComponent(unifiedLogFilename))
    }

    public static func readTCC(forHostID id: UUID, in bundle: URL) throws -> [TCCAccess]? {
        try readArrayIfPresent(at: hostDirectory(forHostID: id, in: bundle)
            .appendingPathComponent(tccFilename))
    }
    public static func writeTCC(_ entries: [TCCAccess],
                                forHostID id: UUID, in bundle: URL) throws {
        try writeArray(entries, at: hostDirectory(forHostID: id, in: bundle)
            .appendingPathComponent(tccFilename))
    }

    public static func readKnowledgeC(forHostID id: UUID, in bundle: URL) throws -> [KnowledgeEntry]? {
        try readArrayIfPresent(at: hostDirectory(forHostID: id, in: bundle)
            .appendingPathComponent(knowledgeCFilename))
    }
    public static func writeKnowledgeC(_ entries: [KnowledgeEntry],
                                       forHostID id: UUID, in bundle: URL) throws {
        try writeArray(entries, at: hostDirectory(forHostID: id, in: bundle)
            .appendingPathComponent(knowledgeCFilename))
    }

    public static func readMacRecentItems(forHostID id: UUID, in bundle: URL) throws -> [MacRecentItem]? {
        try readArrayIfPresent(at: hostDirectory(forHostID: id, in: bundle)
            .appendingPathComponent(macRecentItemsFilename))
    }
    public static func writeMacRecentItems(_ items: [MacRecentItem],
                                           forHostID id: UUID, in bundle: URL) throws {
        try writeArray(items, at: hostDirectory(forHostID: id, in: bundle)
            .appendingPathComponent(macRecentItemsFilename))
    }

    public static func readMacSecurityEvents(forHostID id: UUID, in bundle: URL) throws -> [MacSecurityEvent]? {
        try readArrayIfPresent(at: hostDirectory(forHostID: id, in: bundle)
            .appendingPathComponent(macSecurityFilename))
    }
    public static func writeMacSecurityEvents(_ events: [MacSecurityEvent],
                                              forHostID id: UUID, in bundle: URL) throws {
        try writeArray(events, at: hostDirectory(forHostID: id, in: bundle)
            .appendingPathComponent(macSecurityFilename))
    }

    public static func readCarved(forHostID id: UUID, in bundle: URL) throws -> [CarvedFile]? {
        try readArrayIfPresent(at: hostDirectory(forHostID: id, in: bundle)
            .appendingPathComponent(carvedFilename))
    }
    public static func writeCarved(_ files: [CarvedFile], forHostID id: UUID, in bundle: URL) throws {
        try writeArray(files, at: hostDirectory(forHostID: id, in: bundle)
            .appendingPathComponent(carvedFilename))
    }

    public static func readKexts(forHostID id: UUID, in bundle: URL) throws -> [MacKextEntry]? {
        try readArrayIfPresent(at: hostDirectory(forHostID: id, in: bundle)
            .appendingPathComponent(kextsFilename))
    }
    public static func writeKexts(_ kexts: [MacKextEntry], forHostID id: UUID, in bundle: URL) throws {
        try writeArray(kexts, at: hostDirectory(forHostID: id, in: bundle)
            .appendingPathComponent(kextsFilename))
    }

    public static func readBackgroundItems(forHostID id: UUID, in bundle: URL) throws -> [MacBackgroundItem]? {
        try readArrayIfPresent(at: hostDirectory(forHostID: id, in: bundle)
            .appendingPathComponent(backgroundItemsFilename))
    }
    public static func writeBackgroundItems(_ items: [MacBackgroundItem], forHostID id: UUID, in bundle: URL) throws {
        try writeArray(items, at: hostDirectory(forHostID: id, in: bundle)
            .appendingPathComponent(backgroundItemsFilename))
    }

    public static func readMessages(forHostID id: UUID, in bundle: URL) throws -> [MessageEntry]? {
        try readArrayIfPresent(at: hostDirectory(forHostID: id, in: bundle)
            .appendingPathComponent(messagesFilename))
    }
    public static func writeMessages(_ messages: [MessageEntry], forHostID id: UUID, in bundle: URL) throws {
        try writeArray(messages, at: hostDirectory(forHostID: id, in: bundle)
            .appendingPathComponent(messagesFilename))
    }
    public static func messagesScratchDirectory(forHostID id: UUID, in bundle: URL) -> URL {
        hostDirectory(forHostID: id, in: bundle).appendingPathComponent("messages", isDirectory: true)
    }

    public static func readMail(forHostID id: UUID, in bundle: URL) throws -> [MailMessageEntry]? {
        try readArrayIfPresent(at: hostDirectory(forHostID: id, in: bundle)
            .appendingPathComponent(mailFilename))
    }
    public static func writeMail(_ mail: [MailMessageEntry], forHostID id: UUID, in bundle: URL) throws {
        try writeArray(mail, at: hostDirectory(forHostID: id, in: bundle)
            .appendingPathComponent(mailFilename))
    }
    public static func mailScratchDirectory(forHostID id: UUID, in bundle: URL) -> URL {
        hostDirectory(forHostID: id, in: bundle).appendingPathComponent("mail", isDirectory: true)
    }

    public static func readNetwork(forHostID id: UUID, in bundle: URL) throws -> [MacNetworkItem]? {
        try readArrayIfPresent(at: hostDirectory(forHostID: id, in: bundle)
            .appendingPathComponent(networkFilename))
    }
    public static func writeNetwork(_ items: [MacNetworkItem], forHostID id: UUID, in bundle: URL) throws {
        try writeArray(items, at: hostDirectory(forHostID: id, in: bundle)
            .appendingPathComponent(networkFilename))
    }

    public static func readUserActivity(forHostID id: UUID, in bundle: URL) throws -> [MacActivityItem]? {
        try readArrayIfPresent(at: hostDirectory(forHostID: id, in: bundle)
            .appendingPathComponent(userActivityFilename))
    }
    public static func writeUserActivity(_ items: [MacActivityItem], forHostID id: UUID, in bundle: URL) throws {
        try writeArray(items, at: hostDirectory(forHostID: id, in: bundle)
            .appendingPathComponent(userActivityFilename))
    }

    public static func readDocumentVersions(forHostID id: UUID, in bundle: URL) throws -> [MacDocumentVersion]? {
        try readArrayIfPresent(at: hostDirectory(forHostID: id, in: bundle)
            .appendingPathComponent(documentVersionsFilename))
    }
    public static func writeDocumentVersions(_ items: [MacDocumentVersion], forHostID id: UUID, in bundle: URL) throws {
        try writeArray(items, at: hostDirectory(forHostID: id, in: bundle)
            .appendingPathComponent(documentVersionsFilename))
    }

    public static func readAudit(forHostID id: UUID, in bundle: URL) throws -> [AuditEvent]? {
        try readArrayIfPresent(at: hostDirectory(forHostID: id, in: bundle).appendingPathComponent(auditFilename))
    }
    public static func writeAudit(_ events: [AuditEvent], forHostID id: UUID, in bundle: URL) throws {
        try writeArray(events, at: hostDirectory(forHostID: id, in: bundle).appendingPathComponent(auditFilename))
    }
    public static func readSyslog(forHostID id: UUID, in bundle: URL) throws -> [SyslogEntry]? {
        try readArrayIfPresent(at: hostDirectory(forHostID: id, in: bundle).appendingPathComponent(syslogFilename))
    }
    public static func writeSyslog(_ entries: [SyslogEntry], forHostID id: UUID, in bundle: URL) throws {
        try writeArray(entries, at: hostDirectory(forHostID: id, in: bundle).appendingPathComponent(syslogFilename))
    }
    public static func readLastlog(forHostID id: UUID, in bundle: URL) throws -> [LastlogEntry]? {
        try readArrayIfPresent(at: hostDirectory(forHostID: id, in: bundle).appendingPathComponent(lastlogFilename))
    }
    public static func writeLastlog(_ records: [LastlogEntry], forHostID id: UUID, in bundle: URL) throws {
        try writeArray(records, at: hostDirectory(forHostID: id, in: bundle).appendingPathComponent(lastlogFilename))
    }

    // MARK: - Annotations + case notes (case-wide analyst work product)
    //
    // Bookmarks/tags and the case narrative live at the bundle root, like the
    // custody ledger: they reference findings and timeline events across hosts
    // and must survive per-host re-parses (artifact JSON rewrites) untouched.

    public static func annotationsFileURL(in bundle: URL) -> URL {
        bundle.appendingPathComponent(annotationsFilename)
    }

    public static func readAnnotations(in bundle: URL) throws -> [Annotation] {
        try readArrayIfPresent(at: annotationsFileURL(in: bundle)) ?? []
    }

    public static func writeAnnotations(_ annotations: [Annotation], in bundle: URL) throws {
        try writeArray(annotations, at: annotationsFileURL(in: bundle))
    }

    /// CTI enrichment verdicts (case-wide, provenance-stamped). Separate file so
    /// per-host re-parses can't touch it, same as annotations/custody.
    public static func enrichmentFileURL(in bundle: URL) -> URL {
        bundle.appendingPathComponent(enrichmentFilename)
    }

    public static func readEnrichment(in bundle: URL) throws -> [EnrichmentVerdict] {
        try readArrayIfPresent(at: enrichmentFileURL(in: bundle)) ?? []
    }

    public static func writeEnrichment(_ verdicts: [EnrichmentVerdict], in bundle: URL) throws {
        try writeArray(verdicts, at: enrichmentFileURL(in: bundle))
    }

    public static func notesFileURL(in bundle: URL) -> URL {
        bundle.appendingPathComponent(notesFilename)
    }

    public static func readNotes(in bundle: URL) throws -> CaseNotes {
        let url = notesFileURL(in: bundle)
        guard FileManager.default.fileExists(atPath: url.path) else { return CaseNotes() }
        return try jsonDecoder.decode(CaseNotes.self, from: Data(contentsOf: url))
    }

    public static func writeNotes(_ notes: CaseNotes, in bundle: URL) throws {
        let data = try jsonEncoder.encode(notes)
        try data.write(to: notesFileURL(in: bundle), options: .atomic)
    }

    /// AI-generated executive summary of the case findings (case-wide, single
    /// object). Separate file so per-host re-parses can't touch it, same as
    /// notes/enrichment. Absent until the first summary is generated.
    public static func summaryFileURL(in bundle: URL) -> URL {
        bundle.appendingPathComponent(summaryFilename)
    }

    public static func readSummary(in bundle: URL) throws -> CaseSummary? {
        let url = summaryFileURL(in: bundle)
        guard FileManager.default.fileExists(atPath: url.path) else { return nil }
        return try jsonDecoder.decode(CaseSummary.self, from: Data(contentsOf: url))
    }

    public static func writeSummary(_ summary: CaseSummary, in bundle: URL) throws {
        let data = try jsonEncoder.encode(summary)
        try data.write(to: summaryFileURL(in: bundle), options: .atomic)
    }

    private static func readArrayIfPresent<T: Decodable>(at url: URL) throws -> [T]? {
        guard FileManager.default.fileExists(atPath: url.path) else { return nil }
        let data = try Data(contentsOf: url)
        return try jsonDecoder.decode([T].self, from: data)
    }

    private static func writeArray<T: Encodable>(_ array: [T], at url: URL) throws {
        try FileManager.default.createDirectory(
            at: url.deletingLastPathComponent(),
            withIntermediateDirectories: true)
        let data = try compactEncoder.encode(array)
        try data.write(to: url, options: .atomic)
    }

    private static var compactEncoder: JSONEncoder {
        let enc = JSONEncoder()
        enc.dateEncodingStrategy = .iso8601
        // No .prettyPrinted - these files can be very large.
        return enc
    }

    // MARK: - JSON

    private static var jsonEncoder: JSONEncoder {
        let enc = JSONEncoder()
        enc.outputFormatting = [.prettyPrinted, .sortedKeys]
        enc.dateEncodingStrategy = .iso8601
        return enc
    }
    private static var jsonDecoder: JSONDecoder {
        let dec = JSONDecoder()
        dec.dateDecodingStrategy = .iso8601
        return dec
    }
}

/// Decoder-only mirror of EventLogRecord that omits `payloadXML`. The decoder
/// still has to scan past the field in the JSON, but it never allocates a
/// String for the value - the saving on a 1M-event case is in the hundreds
/// of MB. `materialize()` rebuilds a real EventLogRecord with empty payload
/// so downstream views and analyzers continue to compile.
private nonisolated struct EventLogRecordLite: Decodable {
    let id: UUID
    let recordNumber: UInt64
    let writtenAt: Date
    let eventID: UInt32
    let level: UInt8
    let channel: String
    let provider: String
    let computer: String
    let sourceFile: String

    func materialize() -> EventLogRecord {
        EventLogRecord(id: id, recordNumber: recordNumber, writtenAt: writtenAt,
                       eventID: eventID, level: level, channel: channel,
                       provider: provider, computer: computer,
                       payloadXML: "", sourceFile: sourceFile)
    }
}
