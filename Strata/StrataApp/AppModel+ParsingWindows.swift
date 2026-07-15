import Foundation
import SwiftUI

#if os(macOS)

extension AppModel {
    /// Parse every .evtx in every loaded evidence that doesn't already have
    /// events. Does NOT run analyzers - the caller is expected to use
    /// `parseArtifacts()` if it wants the full pipeline.
    func parseEventLogs() async {
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

        // Pre-compute the work total across every evidence so the bar is
        // accurate end-to-end, not just per-host.
        let totalCandidates = evidenceList.reduce(0) { acc, evidence in
            guard let state = states[evidence.id], state.events.isEmpty else { return acc }
            return acc + state.files.filter {
                $0.fileExtension == "evtx" && !$0.isDeleted && $0.size > 0
            }.count
        }
        guard totalCandidates > 0 else {
            statusMessage = "No new .evtx files to parse."
            return
        }
        progress = ProgressInfo(current: 0, total: totalCandidates, label: "Parsing event logs")
        var completed = 0

        do {
            let tskEnv = try TSKEnvironment.discover()
            let evtxEnv = try VendoredTool.discover(primaryBinary: "evtxexport", library: "libevtx")
            let parser = EVTXParser(environment: evtxEnv)

            for evidence in evidenceList {
                guard var state = states[evidence.id] else { continue }
                if !state.events.isEmpty { continue }

                let candidates = state.files.filter {
                    $0.fileExtension == "evtx" && !$0.isDeleted && $0.size > 0
                }
                guard !candidates.isEmpty else { continue }

                // Image hosts need TSK to pull each .evtx out of the image;
                // loose folders read the file in place, so skip all of that.
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
                    let dir = CaseStore.eventScratchDirectory(forHostID: evidence.id, in: bundleURL)
                    try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
                    scratch = dir
                }

                var collected: [EventLogRecord] = []
                for entry in candidates {
                    progress = ProgressInfo(
                        current: completed,
                        total: totalCandidates,
                        label: "\(evidence.displayName): \(entry.name)")
                    // Resolve the .evtx to a readable path: the collected file
                    // itself (loose) or an icat extraction into scratch (image).
                    let fileURL: URL
                    if isLoose {
                        guard let disk = entry.diskURL,
                              FileManager.default.fileExists(atPath: disk.path) else {
                            completed += 1; continue
                        }
                        fileURL = disk
                    } else {
                        guard let info = try database!.fetchExtractInfo(forFileID: entry.id) else {
                            completed += 1; continue
                        }
                        let outURL = scratch!.appendingPathComponent("\(entry.id)-\(entry.name.scratchSafeComponent)")
                        do {
                            try await extractor!.extract(metaAddr: info.metaAddr,
                                                         imageOffsetSectors: info.imageOffsetSectors,
                                                         to: outURL)
                        } catch {
                            // One file's extraction failure must not abort the whole
                            // pass (discarding partials + skipping later hosts): record
                            // it and move on. Bytes are adversary-controlled.
                            statusMessage = "\(evidence.displayName): \(entry.name) — extraction failed (\(error.localizedDescription))"
                            completed += 1
                            continue
                        }
                        fileURL = outURL
                    }
                    do {
                        let parsed = try await parser.parse(fileAt: fileURL)
                        collected.append(contentsOf: parsed)
                    } catch {
                        statusMessage = "\(evidence.displayName): \(entry.name) — parse failed (\(error.localizedDescription))"
                    }
                    completed += 1
                }
                collected.sort { $0.writtenAt < $1.writtenAt }
                state.events = collected
                // Drop any prior evtx slice (paranoia for re-parses) and
                // splice the freshly built evtx timeline back in, sorted.
                state.timeline.removeAll { $0.source == .evtx }
                state.timeline.append(contentsOf: TimelineBuilder.build(from: collected))
                state.timeline.sort { $0.date < $1.date }
                states[evidence.id] = state
                if let bundleURL = currentCaseBundleURL {
                    try? CaseStore.writeEvents(collected, forHostID: evidence.id, in: bundleURL)
                }
            }
            progress = ProgressInfo(current: completed, total: totalCandidates,
                                    label: "Event log parse complete")
        } catch {
            self.errorMessage = error.localizedDescription
            self.statusMessage = ""
        }
    }

    // MARK: - LNK parsing

    /// Parse every `.lnk` shortcut in every loaded evidence that doesn't already
    /// have LNK results - extracting with icat for image hosts, or reading the
    /// collected file in place for loose folders. Each `.lnk` yields one
    /// `LnkEntry`. Mirrors `parseEventLogs`; does NOT run analyzers.
    func parseLnk() async {
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

        func candidates(_ state: EvidenceState) -> [FileEntry] {
            state.files.filter { $0.fileExtension == "lnk" && !$0.isDirectory && !$0.isDeleted && $0.size > 0 }
        }

        let totalCandidates = evidenceList.reduce(0) { acc, evidence in
            guard let state = states[evidence.id], state.lnk.isEmpty else { return acc }
            return acc + candidates(state).count
        }
        guard totalCandidates > 0 else {
            statusMessage = "No new .lnk files to parse."
            return
        }
        progress = ProgressInfo(current: 0, total: totalCandidates, label: "Parsing shortcuts")
        var completed = 0

        do {
            let tskEnv = try TSKEnvironment.discover()
            let lnkEnv = try VendoredTool.discover(primaryBinary: "lnkinfo", library: "liblnk")
            let parser = LnkParser(environment: lnkEnv)

            for evidence in evidenceList {
                guard var state = states[evidence.id] else { continue }
                if !state.lnk.isEmpty { continue }

                let found = candidates(state)
                guard !found.isEmpty else { continue }

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
                    let dir = CaseStore.lnkScratchDirectory(forHostID: evidence.id, in: bundleURL)
                    try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
                    scratch = dir
                }

                var collected: [LnkEntry] = []
                for entry in found {
                    progress = ProgressInfo(current: completed, total: totalCandidates,
                                            label: "\(evidence.displayName): \(entry.name)")
                    let fileURL: URL
                    if isLoose {
                        guard let disk = entry.diskURL,
                              FileManager.default.fileExists(atPath: disk.path) else {
                            completed += 1; continue
                        }
                        fileURL = disk
                    } else {
                        guard let info = try database!.fetchExtractInfo(forFileID: entry.id) else {
                            completed += 1; continue
                        }
                        let outURL = scratch!.appendingPathComponent("\(entry.id)-\(entry.name.scratchSafeComponent)")
                        do {
                            try await extractor!.extract(metaAddr: info.metaAddr,
                                                         imageOffsetSectors: info.imageOffsetSectors,
                                                         to: outURL)
                        } catch {
                            // One file's extraction failure must not abort the whole
                            // pass (discarding partials + skipping later hosts): record
                            // it and move on. Bytes are adversary-controlled.
                            statusMessage = "\(evidence.displayName): \(entry.name) — extraction failed (\(error.localizedDescription))"
                            completed += 1
                            continue
                        }
                        fileURL = outURL
                    }
                    // Record the .lnk's own full path as the source so the table
                    // shows where the shortcut lived, not the scratch copy.
                    if let parsed = try? await parser.parse(fileAt: fileURL) {
                        collected.append(Self.rehome(parsed, sourceFile: entry.fullPath))
                    }
                    completed += 1
                }
                collected.sort { ($0.targetModified ?? .distantPast) > ($1.targetModified ?? .distantPast) }
                state.lnk = collected
                // Splice target MAC times onto the timeline (mirrors evtx).
                state.timeline.removeAll { $0.source == .lnk }
                state.timeline.append(contentsOf: TimelineBuilder.build(from: collected))
                state.timeline.sort { $0.date < $1.date }
                states[evidence.id] = state
                if let bundleURL = currentCaseBundleURL {
                    try? CaseStore.writeLnk(collected, forHostID: evidence.id, in: bundleURL)
                }
            }
            progress = ProgressInfo(current: completed, total: totalCandidates,
                                    label: "Shortcut parse complete")
        } catch {
            self.errorMessage = error.localizedDescription
            self.statusMessage = ""
        }
    }

    /// Replace the parser's scratch-path sourceFile with the artifact's real
    /// in-image path (the value-type copy keeps everything else).
    private nonisolated static func rehome(_ entry: LnkEntry, sourceFile: String) -> LnkEntry {
        LnkEntry(id: entry.id, sourceFile: sourceFile, localPath: entry.localPath,
                 networkPath: entry.networkPath, description: entry.description,
                 arguments: entry.arguments, workingDirectory: entry.workingDirectory,
                 iconLocation: entry.iconLocation, targetSize: entry.targetSize,
                 targetCreated: entry.targetCreated, targetModified: entry.targetModified,
                 targetAccessed: entry.targetAccessed, driveType: entry.driveType,
                 volumeLabel: entry.volumeLabel, volumeSerial: entry.volumeSerial,
                 machineIdentifier: entry.machineIdentifier)
    }


    // MARK: - JumpList parsing

    /// Parse every JumpList (*.automaticDestinations-ms / *.customDestinations-ms)
    /// in every loaded evidence that doesn't already have results. Automatic lists
    /// are cracked with olecfexport (OLE) and their embedded LNKs + DestList
    /// metadata merged; custom lists are a flat LNK sequence. Each file yields
    /// multiple JumpListEntry. Mirrors parseLnk; does NOT run analyzers.
    func parseJumpList() async {
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

        func candidates(_ state: EvidenceState) -> [FileEntry] {
            state.files.filter {
                let ext = $0.fileExtension
                return (ext == "automaticdestinations-ms" || ext == "customdestinations-ms")
                    && !$0.isDirectory && !$0.isDeleted && $0.size > 0
            }
        }

        let totalCandidates = evidenceList.reduce(0) { acc, evidence in
            guard let state = states[evidence.id], state.jumpList.isEmpty else { return acc }
            return acc + candidates(state).count
        }
        guard totalCandidates > 0 else {
            statusMessage = "No new JumpLists to parse."
            return
        }
        progress = ProgressInfo(current: 0, total: totalCandidates, label: "Parsing JumpLists")
        var completed = 0

        do {
            let tskEnv = try TSKEnvironment.discover()
            let lnkEnv = try VendoredTool.discover(primaryBinary: "lnkinfo", library: "liblnk")
            let jlEnv = try VendoredTool.discover(primaryBinary: "olecfexport", library: "libolecf")
            let parser = JumpListParser(environment: jlEnv, lnkParser: LnkParser(environment: lnkEnv))

            for evidence in evidenceList {
                guard var state = states[evidence.id] else { continue }
                if !state.jumpList.isEmpty { continue }

                let found = candidates(state)
                guard !found.isEmpty else { continue }

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
                    let dir = CaseStore.jumpListScratchDirectory(forHostID: evidence.id, in: bundleURL)
                    try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
                    scratch = dir
                }

                var collected: [JumpListEntry] = []
                for entry in found {
                    progress = ProgressInfo(current: completed, total: totalCandidates,
                                            label: "\(evidence.displayName): \(entry.name)")
                    let fileURL: URL
                    if isLoose {
                        guard let disk = entry.diskURL,
                              FileManager.default.fileExists(atPath: disk.path) else {
                            completed += 1; continue
                        }
                        fileURL = disk
                    } else {
                        guard let info = try database!.fetchExtractInfo(forFileID: entry.id) else {
                            completed += 1; continue
                        }
                        let outURL = scratch!.appendingPathComponent("\(entry.id)-\(entry.name.scratchSafeComponent)")
                        do {
                            try await extractor!.extract(metaAddr: info.metaAddr,
                                                         imageOffsetSectors: info.imageOffsetSectors,
                                                         to: outURL)
                        } catch {
                            // One file's extraction failure must not abort the whole
                            // pass (discarding partials + skipping later hosts): record
                            // it and move on. Bytes are adversary-controlled.
                            statusMessage = "\(evidence.displayName): \(entry.name) — extraction failed (\(error.localizedDescription))"
                            completed += 1
                            continue
                        }
                        fileURL = outURL
                    }
                    let appID = JumpListAppID.appID(fromFilename: entry.name)
                    let isAutomatic = entry.fileExtension == "automaticdestinations-ms"
                    if let parsed = try? await parser.parse(fileAt: fileURL, appID: appID,
                                                            sourceFile: entry.fullPath,
                                                            isAutomatic: isAutomatic) {
                        collected.append(contentsOf: parsed)
                    }
                    completed += 1
                }
                collected.sort { ($0.lastAccessed ?? .distantPast) > ($1.lastAccessed ?? .distantPast) }
                state.jumpList = collected
                // Splice DestList access times onto the timeline (mirrors evtx).
                state.timeline.removeAll { $0.source == .jumplist }
                state.timeline.append(contentsOf: TimelineBuilder.build(from: collected))
                state.timeline.sort { $0.date < $1.date }
                states[evidence.id] = state
                if let bundleURL = currentCaseBundleURL {
                    try? CaseStore.writeJumpList(collected, forHostID: evidence.id, in: bundleURL)
                }
            }
            progress = ProgressInfo(current: completed, total: totalCandidates,
                                    label: "JumpList parse complete")
        } catch {
            self.errorMessage = error.localizedDescription
            self.statusMessage = ""
        }
    }


    // MARK: - USN journal parsing

    /// Is this tsk_files / loose-folder name the NTFS change journal's `$J`
    /// data stream? On an image it appears as the named ADS `$UsnJrnl:$J`;
    /// KAPE collections name it `$J` or URL-encode the colon (`$UsnJrnl%3A$J`).
    private nonisolated static func isUsnJournalName(_ name: String) -> Bool {
        let n = name.lowercased()
        return n == "$j"
            || n == "$usnjrnl:$j" || n.hasSuffix("$usnjrnl:$j")
            || n == "$usnjrnl%3a$j" || n.hasSuffix("$usnjrnl%3a$j")
    }

    /// Parse the NTFS USN change journal (`$Extend\$UsnJrnl:$J`) for every
    /// loaded evidence that doesn't already have USN results. The journal is a
    /// single (often huge, sparse) named alternate data stream per volume, so:
    ///  - image hosts extract it with icat's `meta-type-id` ADS address form,
    ///    using `-h` so the leading sparse region isn't materialised as zeros;
    ///  - loose folders read the collected `$J` in place.
    /// The byte-parse runs OFF the main actor (`$J` can be 100 MB+). Mirrors
    /// `parseEventLogs` for timeline splicing; does NOT run analyzers.
    func parseUsn() async {
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

        func candidates(_ state: EvidenceState) -> [FileEntry] {
            state.files.filter {
                !$0.isDirectory && $0.size > 0 && Self.isUsnJournalName($0.name)
            }
        }

        let totalCandidates = evidenceList.reduce(0) { acc, evidence in
            guard let state = states[evidence.id], state.usn.isEmpty else { return acc }
            return acc + candidates(state).count
        }
        guard totalCandidates > 0 else {
            statusMessage = "No new USN journal to parse."
            return
        }
        progress = ProgressInfo(current: 0, total: totalCandidates, label: "Parsing USN journal")
        var completed = 0

        do {
            let tskEnv = try TSKEnvironment.discover()

            for evidence in evidenceList {
                guard var state = states[evidence.id] else { continue }
                if !state.usn.isEmpty { continue }

                let found = candidates(state)
                guard !found.isEmpty else { continue }

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
                    let dir = CaseStore.usnScratchDirectory(forHostID: evidence.id, in: bundleURL)
                    try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
                    scratch = dir
                }

                var collected: [UsnRecord] = []
                for entry in found {
                    progress = ProgressInfo(current: completed, total: totalCandidates,
                                            label: "\(evidence.displayName): \(entry.name)")
                    let fileURL: URL
                    if isLoose {
                        guard let disk = entry.diskURL,
                              FileManager.default.fileExists(atPath: disk.path) else {
                            completed += 1; continue
                        }
                        fileURL = disk
                    } else {
                        guard let info = try database!.fetchAttrExtractInfo(forFileID: entry.id) else {
                            completed += 1; continue
                        }
                        let outURL = scratch!.appendingPathComponent("\(entry.id)-usnjrnl-J.bin")
                        do {
                            try await extractor!.extractStream(metaAddr: info.metaAddr,
                                                               attrType: info.attrType,
                                                               attrId: info.attrId,
                                                               imageOffsetSectors: info.imageOffsetSectors,
                                                               to: outURL)
                        } catch {
                            // One file's extraction failure must not abort the whole
                            // pass (discarding partials + skipping later hosts): record
                            // it and move on. Bytes are adversary-controlled.
                            statusMessage = "\(evidence.displayName): \(entry.name) — extraction failed (\(error.localizedDescription))"
                            completed += 1
                            continue
                        }
                        fileURL = outURL
                    }

                    // Read the (potentially huge) stream and parse it off the
                    // main actor so the UI stays responsive. The `[UInt8](data)`
                    // copy faults the whole (attacker-sized) stream into the heap,
                    // so skip an implausibly large one (>4 GB) rather than OOM —
                    // far above a real $J/$MFT/OBJECTS.DATA.
                    guard let data = try? Data(contentsOf: fileURL, options: .mappedIfSafe),
                          data.count <= 4 << 30 else {
                        completed += 1; continue
                    }
                    let bytes = [UInt8](data)
                    let source = entry.fullPath
                    let parsed = await Task.detached(priority: .userInitiated) {
                        UsnJournalParser.parse(bytes: bytes, sourceFile: source)
                    }.value
                    collected.append(contentsOf: parsed)
                    completed += 1
                }

                collected.sort { ($0.timestamp ?? .distantPast) > ($1.timestamp ?? .distantPast) }
                state.usn = collected
                // Drop any prior USN slice (paranoia for re-parses) and splice the
                // freshly built USN timeline back in, sorted.
                state.timeline.removeAll { $0.source == .usn }
                state.timeline.append(contentsOf: TimelineBuilder.build(from: collected))
                state.timeline.sort { $0.date < $1.date }
                states[evidence.id] = state
                if let bundleURL = currentCaseBundleURL {
                    try? CaseStore.writeUsn(collected, forHostID: evidence.id, in: bundleURL)
                }
            }
            progress = ProgressInfo(current: completed, total: totalCandidates,
                                    label: "USN journal parse complete")
        } catch {
            self.errorMessage = error.localizedDescription
            self.statusMessage = ""
        }
    }


    // MARK: - SRUM parsing

    /// Parse the Windows SRUM database (`SRUDB.dat`, an ESE database under
    /// `\Windows\System32\sru\`) for every loaded evidence that doesn't already
    /// have SRUM results. SRUDB.dat is an ordinary file (not a sparse ADS like
    /// `$J`), so it is extracted with the plain icat path that registry/prefetch
    /// use. The actual ESE parse is delegated to `SrumParser`, an actor that
    /// shells out to libesedb's `esedbexport` (so it already runs off the main
    /// actor). Mirrors `parseEventLogs` for timeline splicing; does NOT run analyzers.
    func parseSrum() async {
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

        func candidates(_ state: EvidenceState) -> [FileEntry] {
            state.files.filter {
                !$0.isDirectory && $0.size > 0 && $0.name.lowercased() == "srudb.dat"
            }
        }

        let totalCandidates = evidenceList.reduce(0) { acc, evidence in
            guard let state = states[evidence.id], state.srum.isEmpty else { return acc }
            return acc + candidates(state).count
        }
        guard totalCandidates > 0 else {
            statusMessage = "No new SRUM database to parse."
            return
        }
        progress = ProgressInfo(current: 0, total: totalCandidates, label: "Parsing SRUM")
        var completed = 0

        do {
            let tskEnv = try TSKEnvironment.discover()
            let srumEnv = try VendoredTool.discover(primaryBinary: "esedbexport", library: "libesedb")
            let parser = SrumParser(environment: srumEnv)

            for evidence in evidenceList {
                guard var state = states[evidence.id] else { continue }
                if !state.srum.isEmpty { continue }

                let found = candidates(state)
                guard !found.isEmpty else { continue }

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
                    let dir = CaseStore.srumScratchDirectory(forHostID: evidence.id, in: bundleURL)
                    try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
                    scratch = dir
                }

                var collected: [SrumEntry] = []
                for entry in found {
                    progress = ProgressInfo(current: completed, total: totalCandidates,
                                            label: "\(evidence.displayName): \(entry.name)")
                    let fileURL: URL
                    if isLoose {
                        guard let disk = entry.diskURL,
                              FileManager.default.fileExists(atPath: disk.path) else {
                            completed += 1; continue
                        }
                        fileURL = disk
                    } else {
                        guard let info = try database!.fetchExtractInfo(forFileID: entry.id) else {
                            completed += 1; continue
                        }
                        let outURL = scratch!.appendingPathComponent("\(entry.id)-SRUDB.dat")
                        do {
                            try await extractor!.extract(metaAddr: info.metaAddr,
                                                         imageOffsetSectors: info.imageOffsetSectors,
                                                         to: outURL)
                        } catch {
                            // One file's extraction failure must not abort the whole
                            // pass (discarding partials + skipping later hosts): record
                            // it and move on. Bytes are adversary-controlled.
                            statusMessage = "\(evidence.displayName): \(entry.name) — extraction failed (\(error.localizedDescription))"
                            completed += 1
                            continue
                        }
                        fileURL = outURL
                    }
                    // SrumParser is an actor that shells out to esedbexport, so
                    // the heavy ESE work is already off the main actor. A single
                    // unreadable/dirty SRUDB.dat shouldn't abort the whole run.
                    let parsed = (try? await parser.parse(fileAt: fileURL, sourceFile: entry.fullPath)) ?? []
                    collected.append(contentsOf: parsed)
                    completed += 1
                }

                collected.sort { ($0.timestamp ?? .distantPast) > ($1.timestamp ?? .distantPast) }
                state.srum = collected
                // Drop any prior SRUM slice (paranoia for re-parses) and splice the
                // freshly built SRUM timeline back in, sorted.
                state.timeline.removeAll { $0.source == .srum }
                state.timeline.append(contentsOf: TimelineBuilder.build(from: collected))
                state.timeline.sort { $0.date < $1.date }
                states[evidence.id] = state
                if let bundleURL = currentCaseBundleURL {
                    try? CaseStore.writeSrum(collected, forHostID: evidence.id, in: bundleURL)
                }
            }
            progress = ProgressInfo(current: completed, total: totalCandidates,
                                    label: "SRUM parse complete")
        } catch {
            self.errorMessage = error.localizedDescription
            self.statusMessage = ""
        }
    }


    // MARK: - MFT parsing

    /// Parse the NTFS `$MFT` for every loaded evidence that doesn't already have
    /// results. `$MFT` is an ordinary file (record 0's `$DATA`), so it's extracted
    /// with the plain icat path that registry/SRUM use. The (large) byte parse runs
    /// off the main actor in a detached task (like USN). Yields both `$SI` and
    /// `$FN` MACB so the timestomp analyzer can compare them; spliced onto the
    /// timeline as the true NTFS file MACB. Mirrors `parseUsn`; does NOT run analyzers.
    func parseMft() async {
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

        func candidates(_ state: EvidenceState) -> [FileEntry] {
            state.files.filter {
                !$0.isDirectory && $0.size > 0 && $0.name.lowercased() == "$mft"
            }
        }

        let totalCandidates = evidenceList.reduce(0) { acc, evidence in
            guard let state = states[evidence.id], state.mft.isEmpty else { return acc }
            return acc + candidates(state).count
        }
        guard totalCandidates > 0 else {
            statusMessage = "No new $MFT to parse."
            return
        }
        progress = ProgressInfo(current: 0, total: totalCandidates, label: "Parsing $MFT")
        var completed = 0

        do {
            let tskEnv = try TSKEnvironment.discover()

            for evidence in evidenceList {
                guard var state = states[evidence.id] else { continue }
                if !state.mft.isEmpty { continue }

                let found = candidates(state)
                guard !found.isEmpty else { continue }

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
                    let dir = CaseStore.mftScratchDirectory(forHostID: evidence.id, in: bundleURL)
                    try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
                    scratch = dir
                }

                var collected: [MftEntry] = []
                for entry in found {
                    progress = ProgressInfo(current: completed, total: totalCandidates,
                                            label: "\(evidence.displayName): \(entry.name)")
                    let fileURL: URL
                    if isLoose {
                        guard let disk = entry.diskURL,
                              FileManager.default.fileExists(atPath: disk.path) else {
                            completed += 1; continue
                        }
                        fileURL = disk
                    } else {
                        guard let info = try database!.fetchExtractInfo(forFileID: entry.id) else {
                            completed += 1; continue
                        }
                        let outURL = scratch!.appendingPathComponent("\(entry.id)-MFT.bin")
                        do {
                            try await extractor!.extract(metaAddr: info.metaAddr,
                                                         imageOffsetSectors: info.imageOffsetSectors,
                                                         to: outURL)
                        } catch {
                            statusMessage = "\(evidence.displayName): $MFT extract failed (\(error.localizedDescription))"
                            completed += 1; continue
                        }
                        fileURL = outURL
                    }
                    // Read the (potentially large) $MFT and parse it off the main
                    // actor so the UI stays responsive. Scope `data` so the mapped
                    // region is released before the parse — it isn't held alongside
                    // the [UInt8] copy and the parser's own allocations.
                    let bytes: [UInt8]
                    if let data = try? Data(contentsOf: fileURL, options: .mappedIfSafe),
                       data.count <= 4 << 30 {   // skip an implausibly large stream rather than OOM on the [UInt8] copy
                        bytes = [UInt8](data)
                    } else {
                        completed += 1; continue
                    }
                    let source = entry.fullPath
                    // Per-volume label so a multi-NTFS image (system + recovery)
                    // shows one tree per volume rather than merging identical paths.
                    let volLabel: String
                    if let fs = entry.fsID, let vi = state.volumes.first(where: { $0.id == fs }) {
                        volLabel = vi.label
                    } else if isLoose {
                        volLabel = "Collected $MFT"
                    } else if let fs = entry.fsID {
                        volLabel = "Volume \(fs)"
                    } else {
                        volLabel = "$MFT"
                    }
                    let parsed = await Task.detached(priority: .userInitiated) {
                        MftParser.parse(bytes: bytes, sourceFile: source, volume: volLabel)
                    }.value
                    collected.append(contentsOf: parsed)
                    completed += 1
                }

                collected.sort { $0.recordNumber < $1.recordNumber }
                state.mft = collected
                // Drop any prior MFT slice (paranoia for re-parses). Splice the $SI
                // MACB onto the timeline only for loose folders: an image's FS
                // source already carries those times from TSK, so adding them for
                // images would just double the (often millions of) rows.
                state.timeline.removeAll { $0.source == .mft }
                if isLoose {
                    state.timeline.append(contentsOf: TimelineBuilder.build(from: collected))
                    state.timeline.sort { $0.date < $1.date }
                }
                states[evidence.id] = state
                if let bundleURL = currentCaseBundleURL {
                    try? CaseStore.writeMft(collected, forHostID: evidence.id, in: bundleURL)
                }
            }
            progress = ProgressInfo(current: completed, total: totalCandidates,
                                    label: "$MFT parse complete")
        } catch {
            self.errorMessage = error.localizedDescription
            self.statusMessage = ""
        }
    }


    // MARK: - WMI persistence parsing

    /// Carve the WMI CIM repository (`OBJECTS.DATA`, under
    /// `\Windows\System32\wbem\Repository\`) for event-subscription persistence
    /// for every loaded evidence without results. An ordinary file, extracted with
    /// the plain icat path; the byte carve (`WmiRepositoryParser`) runs off the
    /// main actor. Mirrors `parseMft`; does NOT run analyzers or splice the timeline.
    func parseWmi() async {
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

        func candidates(_ state: EvidenceState) -> [FileEntry] {
            state.files.filter {
                !$0.isDirectory && $0.size > 0 && $0.name.lowercased() == "objects.data"
            }
        }

        let totalCandidates = evidenceList.reduce(0) { acc, evidence in
            guard let state = states[evidence.id], state.wmi.isEmpty else { return acc }
            return acc + candidates(state).count
        }
        guard totalCandidates > 0 else {
            statusMessage = "No new WMI repository to parse."
            return
        }
        progress = ProgressInfo(current: 0, total: totalCandidates, label: "Parsing WMI repository")
        var completed = 0

        do {
            let tskEnv = try TSKEnvironment.discover()

            for evidence in evidenceList {
                guard var state = states[evidence.id] else { continue }
                if !state.wmi.isEmpty { continue }

                let found = candidates(state)
                guard !found.isEmpty else { continue }

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
                    let dir = CaseStore.wmiScratchDirectory(forHostID: evidence.id, in: bundleURL)
                    try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
                    scratch = dir
                }

                var collected: [WmiPersistenceEntry] = []
                for entry in found {
                    progress = ProgressInfo(current: completed, total: totalCandidates,
                                            label: "\(evidence.displayName): WMI repository")
                    let fileURL: URL
                    if isLoose {
                        guard let disk = entry.diskURL,
                              FileManager.default.fileExists(atPath: disk.path) else {
                            completed += 1; continue
                        }
                        fileURL = disk
                    } else {
                        guard let info = try database!.fetchExtractInfo(forFileID: entry.id) else {
                            completed += 1; continue
                        }
                        let outURL = scratch!.appendingPathComponent("\(entry.id)-OBJECTS.DATA")
                        do {
                            try await extractor!.extract(metaAddr: info.metaAddr,
                                                         imageOffsetSectors: info.imageOffsetSectors,
                                                         to: outURL)
                        } catch {
                            statusMessage = "\(evidence.displayName): OBJECTS.DATA extract failed (\(error.localizedDescription))"
                            completed += 1; continue
                        }
                        fileURL = outURL
                    }
                    // Carve the repository off the main actor (scope the mapped
                    // region so it isn't held alongside the [UInt8] copy).
                    let bytes: [UInt8]
                    if let data = try? Data(contentsOf: fileURL, options: .mappedIfSafe),
                       data.count <= 4 << 30 {   // skip an implausibly large stream rather than OOM on the [UInt8] copy
                        bytes = [UInt8](data)
                    } else {
                        completed += 1; continue
                    }
                    let source = entry.fullPath
                    let parsed = await Task.detached(priority: .userInitiated) {
                        WmiRepositoryParser.parse(bytes: bytes, sourceFile: source)
                    }.value
                    collected.append(contentsOf: parsed)
                    completed += 1
                }

                state.wmi = collected
                states[evidence.id] = state
                if let bundleURL = currentCaseBundleURL {
                    try? CaseStore.writeWmi(collected, forHostID: evidence.id, in: bundleURL)
                }
            }
            progress = ProgressInfo(current: completed, total: totalCandidates,
                                    label: "WMI repository parse complete")
        } catch {
            self.errorMessage = error.localizedDescription
            self.statusMessage = ""
        }
    }


    // MARK: - Registry parsing

    /// Locate the standard Windows registry hives in each evidence's file
    /// system and parse them with regfexport - extracting with icat for image
    /// hosts, or reading the collected hive in place for loose folders.
    /// Findings are NOT regenerated here - call `runAnalyzers()` (or
    /// `parseArtifacts`) to surface results.
    func parseRegistry(force: Bool = false) async {
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

        // Pre-flight: an old case re-opened on a different machine often has
        // an evidence.sourceURL (image or loose folder) that no longer
        // resolves. Extraction would just fail silently per hive; surface it
        // up front instead.
        // Hives discovered for an evidence that still need parsing: every
        // standard hive on a first run, or - on a re-run - only those whose
        // label isn't already represented in the parsed values. This lets a case
        // whose registry was parsed *before* a hive (notably Amcache.hve) was
        // captured pick that hive up on a later "Parse artifacts" instead of
        // being permanently skipped by a coarse "registry already parsed" guard.
        func pendingHives(_ id: UUID) -> [HiveCandidate] {
            guard let state = states[id] else { return [] }
            let all = Self.discoverHives(in: state.files)
            guard !force else { return all }
            let present = Set(state.registryValues.map(\.hive))
            return all.filter { !present.contains($0.label) }
        }
        let candidates = evidenceList.filter { !pendingHives($0.id).isEmpty }
        let missingSources = candidates.filter {
            !FileManager.default.fileExists(atPath: $0.sourceURL.path)
        }
        if !missingSources.isEmpty, missingSources.count == candidates.count {
            errorMessage = "Source not found: \(missingSources[0].sourceURL.path). Re-add the host or restore the source to its original path."
            return
        }

        let totalCandidates = evidenceList.reduce(0) { $0 + pendingHives($1.id).count }
        guard totalCandidates > 0 else {
            statusMessage = force
                ? "No registry hives discovered in the file system."
                : "No new registry hives to parse."
            return
        }
        progress = ProgressInfo(current: 0, total: totalCandidates, label: "Parsing registry hives")
        var completed = 0

        do {
            let tskEnv = try TSKEnvironment.discover()
            let regEnv = try VendoredTool.discover(primaryBinary: "regfexport", library: "libregf")
            let parser = RegistryHiveParser(environment: regEnv)

            var hostsTouched = 0
            var hostsCollected = 0
            var amcacheReadButEmpty = false
            for evidence in evidenceList {
                guard var state = states[evidence.id] else { continue }

                // Only the hives not already represented in registryValues (all
                // of them when `force`). A fully-parsed host yields an empty list
                // and is skipped; a host missing just Amcache re-parses just that.
                let candidates = pendingHives(evidence.id)
                guard !candidates.isEmpty else { continue }

                guard FileManager.default.fileExists(atPath: evidence.sourceURL.path) else {
                    statusMessage = "\(evidence.displayName): source missing at \(evidence.sourceURL.path)"
                    completed += candidates.count
                    continue
                }
                hostsTouched += 1

                // Image hosts extract each hive from the image with icat into a
                // scratch dir; loose folders parse the collected hive in place.
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
                    let dir = CaseStore.registryScratchDirectory(forHostID: evidence.id, in: bundleURL)
                    try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
                    scratch = dir
                }

                // Keep the values already parsed (so a re-run that only fills in
                // a previously-missing hive doesn't drop the rest); `force`
                // re-parses every hive from scratch.
                var collected: [RegistryValue] = force ? [] : state.registryValues
                let baselineValueCount = collected.count   // values carried in from prior runs
                for candidate in candidates {
                    progress = ProgressInfo(
                        current: completed,
                        total: totalCandidates,
                        label: "\(evidence.displayName): \(candidate.label)")
                    // Resolve the hive to a readable path.
                    let hiveURL: URL
                    if isLoose {
                        guard let disk = candidate.entry.diskURL,
                              FileManager.default.fileExists(atPath: disk.path) else {
                            completed += 1; continue
                        }
                        hiveURL = disk
                    } else {
                        guard let info = try database!.fetchExtractInfo(forFileID: candidate.entry.id) else {
                            completed += 1; continue
                        }
                        let outURL = scratch!.appendingPathComponent("\(candidate.entry.id)-\(candidate.entry.name.scratchSafeComponent)")
                        do {
                            try await extractor!.extract(metaAddr: info.metaAddr,
                                                         imageOffsetSectors: info.imageOffsetSectors,
                                                         to: outURL)
                        } catch {
                            statusMessage = "\(evidence.displayName): \(candidate.label) failed (\(error.localizedDescription))"
                            completed += 1; continue
                        }
                        hiveURL = outURL
                    }
                    do {
                        let values = try await parser.parse(hiveAt: hiveURL, hiveLabel: candidate.label)
                        collected.append(contentsOf: values)
                    } catch {
                        // A locked / corrupt hive shouldn't kill the whole
                        // run - log and continue. Common for SAM / SECURITY
                        // which are ACL'd and may produce odd output.
                        statusMessage = "\(evidence.displayName): \(candidate.label) failed (\(error.localizedDescription))"
                    }
                    completed += 1
                }
                state.registryValues = collected
                // Reconstruct Amcache entries from the AMCACHE-tagged values
                // (pure; no extra extraction). Shimcache is derived the same way
                // from the SYSTEM AppCompatCache blob.
                let amcache = AmcacheEntry.reconstruct(from: collected)
                state.amcache = amcache
                // Note the silent "hive read but nothing came back" case so an
                // empty Amcache tab isn't indistinguishable from "never parsed";
                // surfaced once after the loop (a mid-loop statusMessage would be
                // clobbered by the next parser in the parseArtifacts chain).
                if candidates.contains(where: { $0.label == "AMCACHE" }), amcache.isEmpty {
                    amcacheReadButEmpty = true
                }
                let shimcache = ShimcacheParser.fromRegistry(collected)
                state.shimcache = shimcache
                // Drop any prior registry-derived slices (paranoia for
                // re-parses) and splice key-write / amcache / shimcache times
                // back onto the timeline (mirrors the evtx splice).
                state.timeline.removeAll {
                    $0.source == .registry || $0.source == .amcache || $0.source == .shimcache
                }
                state.timeline.append(contentsOf: TimelineBuilder.build(from: collected))
                state.timeline.append(contentsOf: TimelineBuilder.build(from: amcache))
                state.timeline.append(contentsOf: TimelineBuilder.build(from: shimcache))
                state.timeline.sort { $0.date < $1.date }
                states[evidence.id] = state
                if let bundleURL = currentCaseBundleURL {
                    try? CaseStore.writeRegistry(collected, forHostID: evidence.id, in: bundleURL)
                    try? CaseStore.writeAmcache(amcache, forHostID: evidence.id, in: bundleURL)
                    try? CaseStore.writeShimcache(shimcache, forHostID: evidence.id, in: bundleURL)
                }
                // Count the host only if THIS run gained values (not the ones
                // carried in from a prior run), so an all-failed partial re-run
                // still trips the louder aggregate error below.
                if collected.count > baselineValueCount { hostsCollected += 1 }
            }
            progress = ProgressInfo(current: completed, total: totalCandidates,
                                    label: "Registry parse complete")
            // If every host we tried extracted nothing, the user's silent-no-op
            // experience needs a louder signal than the flickering statusMessage.
            if hostsTouched > 0, hostsCollected == 0 {
                errorMessage = "Registry parse extracted no values - check that sources are accessible and hives aren't locked."
            } else if amcacheReadButEmpty {
                errorMessage = "Amcache.hve was read but produced no entries - it may be from an unsupported Windows build or be corrupt."
            }
        } catch {
            self.errorMessage = error.localizedDescription
            self.statusMessage = ""
        }
    }

    private struct HiveCandidate {
        let entry: FileEntry
        let label: String   // "SYSTEM", "NTUSER (jdoe)", ...
    }

    /// Standard hive locations on a Windows install. Per-user NTUSER.DAT and
    /// UsrClass.dat get tagged with the owning user's name so analyzers can
    /// attribute findings.
    private static func discoverHives(in files: [FileEntry]) -> [HiveCandidate] {
        var out: [HiveCandidate] = []
        for entry in files where !entry.isDeleted && !entry.isDirectory && entry.size > 0 {
            let upperName = entry.name.uppercased()
            let lowerPath = entry.fullPath.lowercased()
            if lowerPath.hasSuffix("/windows/system32/config/system") {
                out.append(.init(entry: entry, label: "SYSTEM"))
            } else if lowerPath.hasSuffix("/windows/system32/config/software") {
                out.append(.init(entry: entry, label: "SOFTWARE"))
            } else if lowerPath.hasSuffix("/windows/system32/config/sam") {
                out.append(.init(entry: entry, label: "SAM"))
            } else if lowerPath.hasSuffix("/windows/system32/config/security") {
                out.append(.init(entry: entry, label: "SECURITY"))
            } else if lowerPath.hasSuffix("/windows/system32/config/default") {
                out.append(.init(entry: entry, label: "DEFAULT"))
            } else if upperName == "NTUSER.DAT", let user = extractUser(from: entry.fullPath) {
                out.append(.init(entry: entry, label: "NTUSER (\(user))"))
            } else if upperName == "USRCLASS.DAT", let user = extractUser(from: entry.fullPath) {
                out.append(.init(entry: entry, label: "USRCLASS (\(user))"))
            } else if upperName == "AMCACHE.HVE"
                        || lowerPath.hasSuffix("/windows/appcompat/programs/amcache.hve") {
                // Amcache rides the same regfexport pipeline; its values are
                // tagged AMCACHE and reconstructed into AmcacheEntry after parse.
                // Matched by filename too (it's distinctive) so non-standard
                // collection layouts still find it.
                out.append(.init(entry: entry, label: "AMCACHE"))
            }
        }
        // The broadened (by-filename) Amcache match can surface the canonical
        // hive *and* a stray/backup copy, which would merge under one "AMCACHE"
        // label and double-count entries. Keep a single candidate, preferring the
        // one at the canonical AppCompat\Programs path.
        let amcacheHits = out.filter { $0.label == "AMCACHE" }
        if amcacheHits.count > 1 {
            out.removeAll { $0.label == "AMCACHE" }
            let canonical = amcacheHits.first {
                $0.entry.fullPath.lowercased().hasSuffix("/windows/appcompat/programs/amcache.hve")
            }
            out.append(canonical ?? amcacheHits[0])
        }
        return out
    }

    /// Extract `<user>` from paths like "/Users/<user>/NTUSER.DAT" or
    /// "/Users/<user>/AppData/Local/Microsoft/Windows/UsrClass.dat".
    private static func extractUser(from path: String) -> String? {
        let parts = path.split(separator: "/").map(String.init)
        guard let usersIdx = parts.firstIndex(where: { $0.lowercased() == "users" }),
              usersIdx + 1 < parts.count else { return nil }
        return parts[usersIdx + 1]
    }



    /// Parse every `.pf` under `\Windows\Prefetch\` in every loaded evidence
    /// that doesn't already have prefetch - extracting with icat for image
    /// hosts, or reading the collected file in place for loose folders. Each
    /// `.pf` yields one `PrefetchEntry`. Does NOT run analyzers; use
    /// `parseArtifacts()` for the full pipeline.
    /// Parse Windows Recycle Bin `$I` index files (`$Recycle.Bin\<SID>\$I…`) for
    /// every host without results. Each `$I` records a deleted file's original
    /// path, size, and deletion time. Plain files → the prefetch icat-extract
    /// pattern (not the `$J` ADS path). Splices deletion times onto the timeline.
    func parseRecycleBin() async {
        guard !isWorking else { return }   // single-flight: don't overlap parse passes
        guard !evidenceList.isEmpty else { errorMessage = "No evidence loaded."; return }
        errorMessage = nil
        isWorking = true
        defer { isWorking = false; progress = nil }

        func candidates(_ state: EvidenceState) -> [FileEntry] {
            state.files.filter {
                !$0.isDirectory && $0.size > 0
                    && $0.name.hasPrefix("$I")
                    && $0.fullPath.lowercased().contains("$recycle.bin")
            }
        }
        let total = evidenceList.reduce(0) { acc, e in
            guard let s = states[e.id], s.recycleBin.isEmpty else { return acc }
            return acc + candidates(s).count
        }
        guard total > 0 else { statusMessage = "No new Recycle Bin records to parse."; return }
        progress = ProgressInfo(current: 0, total: total, label: "Parsing Recycle Bin")
        var completed = 0
        do {
            let tskEnv = try TSKEnvironment.discover()
            for evidence in evidenceList {
                guard var state = states[evidence.id], state.recycleBin.isEmpty else { continue }
                let found = candidates(state)
                guard !found.isEmpty else { continue }
                let isLoose = evidence.kind == .kapeLooseFolder
                var database: TSKDatabase?
                var extractor: TSKFileExtractor?
                var scratch: URL?
                if !isLoose {
                    guard let dbURL = state.dbURL, let bundleURL = currentCaseBundleURL else { continue }
                    database = try TSKDatabase(path: dbURL)
                    extractor = TSKFileExtractor(environment: tskEnv, imageURL: evidence.sourceURL,
                                                 imageType: TSKImageIngestor.imageType(for: evidence.sourceURL))
                    let dir = CaseStore.prefetchScratchDirectory(forHostID: evidence.id, in: bundleURL)
                        .deletingLastPathComponent().appendingPathComponent("recyclebin")
                    try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
                    scratch = dir
                }
                var collected: [RecycleBinEntry] = []
                for entry in found {
                    progress = ProgressInfo(current: completed, total: total,
                                            label: "\(evidence.displayName): \(entry.name)")
                    defer { completed += 1 }
                    let fileURL: URL
                    if isLoose {
                        guard let disk = entry.diskURL,
                              FileManager.default.fileExists(atPath: disk.path) else { continue }
                        fileURL = disk
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
                        fileURL = outURL
                    }
                    guard let data = try? Data(contentsOf: fileURL) else { continue }
                    // SID = the immediate parent folder name of the $I file.
                    let sid = (entry.parentPath as NSString).lastPathComponent
                    if let e = RecycleBinParser.parse(data: data, recycledName: entry.name,
                                                      sourceFile: entry.fullPath, sid: sid) {
                        collected.append(e)
                    }
                }
                collected.sort { ($0.deletedAt ?? .distantPast) > ($1.deletedAt ?? .distantPast) }
                state.recycleBin = collected
                states[evidence.id] = state
                if let bundleURL = currentCaseBundleURL {
                    try? CaseStore.writeRecycleBin(collected, forHostID: evidence.id, in: bundleURL)
                }
            }
            progress = ProgressInfo(current: completed, total: total, label: "Recycle Bin parse complete")
        } catch {
            errorMessage = error.localizedDescription
        }
    }

    func parsePrefetch() async {
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

        func candidates(_ state: EvidenceState) -> [FileEntry] {
            state.files.filter {
                $0.fileExtension == "pf" && !$0.isDirectory && !$0.isDeleted && $0.size > 0
                    && $0.fullPath.lowercased().contains("/prefetch/")
            }
        }

        let totalCandidates = evidenceList.reduce(0) { acc, evidence in
            guard let state = states[evidence.id], state.prefetch.isEmpty else { return acc }
            return acc + candidates(state).count
        }
        guard totalCandidates > 0 else {
            statusMessage = "No new prefetch files to parse."
            return
        }
        progress = ProgressInfo(current: 0, total: totalCandidates, label: "Parsing prefetch")
        var completed = 0

        do {
            let tskEnv = try TSKEnvironment.discover()
            let prefetchEnv = try VendoredTool.discover(primaryBinary: "sccainfo", library: "libscca")
            let parser = PrefetchParser(environment: prefetchEnv)

            for evidence in evidenceList {
                guard var state = states[evidence.id] else { continue }
                if !state.prefetch.isEmpty { continue }

                let found = candidates(state)
                guard !found.isEmpty else { continue }

                // Image hosts need TSK to pull each .pf out of the image;
                // loose folders read the file in place, so skip all of that.
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
                    let dir = CaseStore.prefetchScratchDirectory(forHostID: evidence.id, in: bundleURL)
                    try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
                    scratch = dir
                }

                var collected: [PrefetchEntry] = []
                for entry in found {
                    progress = ProgressInfo(
                        current: completed,
                        total: totalCandidates,
                        label: "\(evidence.displayName): \(entry.name)")
                    let fileURL: URL
                    if isLoose {
                        guard let disk = entry.diskURL,
                              FileManager.default.fileExists(atPath: disk.path) else {
                            completed += 1; continue
                        }
                        fileURL = disk
                    } else {
                        guard let info = try database!.fetchExtractInfo(forFileID: entry.id) else {
                            completed += 1; continue
                        }
                        let outURL = scratch!.appendingPathComponent("\(entry.id)-\(entry.name.scratchSafeComponent)")
                        do {
                            try await extractor!.extract(metaAddr: info.metaAddr,
                                                         imageOffsetSectors: info.imageOffsetSectors,
                                                         to: outURL)
                        } catch {
                            // One file's extraction failure must not abort the whole
                            // pass (discarding partials + skipping later hosts): record
                            // it and move on. Bytes are adversary-controlled.
                            statusMessage = "\(evidence.displayName): \(entry.name) — extraction failed (\(error.localizedDescription))"
                            completed += 1
                            continue
                        }
                        fileURL = outURL
                    }
                    // A malformed .pf shouldn't abort the whole run.
                    if let parsed = try? await parser.parse(fileAt: fileURL) {
                        collected.append(parsed)
                    }
                    completed += 1
                }
                // Most-recent execution first.
                collected.sort { ($0.lastRun ?? .distantPast) > ($1.lastRun ?? .distantPast) }
                state.prefetch = collected
                // Splice recorded run times onto the timeline (mirrors evtx).
                state.timeline.removeAll { $0.source == .prefetch }
                state.timeline.append(contentsOf: TimelineBuilder.build(from: collected))
                state.timeline.sort { $0.date < $1.date }
                states[evidence.id] = state
                if let bundleURL = currentCaseBundleURL {
                    try? CaseStore.writePrefetch(collected, forHostID: evidence.id, in: bundleURL)
                }
            }
            progress = ProgressInfo(current: completed, total: totalCandidates,
                                    label: "Prefetch parse complete")
        } catch {
            self.errorMessage = error.localizedDescription
            self.statusMessage = ""
        }
    }
}

#endif
