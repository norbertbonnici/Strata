import Foundation

#if os(macOS)

extension AppModel {
    func saveYaraConfiguration() {
        UserDefaults.standard.set(yaraRulesPath, forKey: "yaraRulesPath")
        UserDefaults.standard.set(yaraMaximumFileMB, forKey: "yaraMaximumFileMB")
        UserDefaults.standard.set(yaraMaximumFiles, forKey: "yaraMaximumFiles")
    }

    /// Scan allocated evidence files with an examiner-supplied YARA ruleset.
    /// Invalid rules fail before extraction. Per-file extraction failures are
    /// counted and surfaced, while successfully scanned files retain results.
    func runYaraScan() async {
        guard !isWorking else { return }
        guard let bundleURL = currentCaseBundleURL else {
            errorMessage = "Open a case before running a YARA scan."
            return
        }
        let rulesURL = URL(fileURLWithPath: yaraRulesPath)
        guard FileManager.default.isReadableFile(atPath: rulesURL.path) else {
            errorMessage = "Choose a readable YARA rules file first."
            return
        }

        isWorking = true
        errorMessage = nil
        defer { isWorking = false; progress = nil }

        let scopedEvidence = activeEvidenceID.flatMap { selected in
            evidenceList.first { $0.id == selected }.map { [$0] }
        } ?? evidenceList
        let maxBytes = Int64(yaraMaximumFileMB) * 1_048_576
        let scratch = FileManager.default.temporaryDirectory
            .appendingPathComponent("strata-yara-\(UUID().uuidString)")

        do {
            try FileManager.default.createDirectory(at: scratch, withIntermediateDirectories: true)
            defer { try? FileManager.default.removeItem(at: scratch) }
            let environment = try TSKEnvironment.discover()
            let runner = YaraRunner(environment: environment)
            let compiled = scratch.appendingPathComponent("rules.compiled")
            statusMessage = "Validating YARA rules..."
            let accessed = rulesURL.startAccessingSecurityScopedResource()
            defer { if accessed { rulesURL.stopAccessingSecurityScopedResource() } }
            try await runner.compile(ruleURL: rulesURL, to: compiled)

            var totalScanned = 0
            var totalFailures = 0
            var totalMatches = 0
            var wasLimited = false

            for evidence in scopedEvidence {
                guard var state = states[evidence.id] else { continue }
                let allCandidates = state.files.filter {
                    !$0.isDirectory && !$0.isDeleted && !$0.isSlackEntry
                        && $0.size > 0 && $0.size <= maxBytes
                }
                let candidates = Array(allCandidates.prefix(yaraMaximumFiles))
                wasLimited = wasLimited || allCandidates.count > candidates.count
                progress = ProgressInfo(current: 0, total: candidates.count,
                                        label: "YARA: \(evidence.displayName)")

                let isLoose = evidence.kind == .kapeLooseFolder
                let isAPFS = evidence.kind == .apfs
                var database: TSKDatabase?
                var extractor: TSKFileExtractor?
                var apfsExtractor: FsApfsExtractor?
                if isAPFS {
                    apfsExtractor = FsApfsExtractor(
                        environment: environment,
                        rawURL: evidence.apfsRawURL ?? evidence.sourceURL,
                        credential: fileVaultCredentials[evidence.id])
                } else if !isLoose {
                    guard let dbURL = state.dbURL else { continue }
                    database = try TSKDatabase(path: dbURL)
                    extractor = TSKFileExtractor(
                        environment: environment, imageURL: evidence.sourceURL,
                        imageType: TSKImageIngestor.imageType(for: evidence.sourceURL))
                }

                var matches: [YaraMatch] = []
                for (index, entry) in candidates.enumerated() {
                    try Task.checkCancellation()
                    progress = ProgressInfo(current: index, total: candidates.count,
                                            label: "YARA: \(entry.fullPath)")
                    var temporaryURL: URL?
                    do {
                        let target: URL
                        if isLoose {
                            guard let diskURL = entry.diskURL else { totalFailures += 1; continue }
                            target = diskURL
                        } else {
                            let output = scratch.appendingPathComponent("file-\(evidence.id)-\(entry.id)")
                            temporaryURL = output
                            if isAPFS {
                                guard let apfsExtractor else { totalFailures += 1; continue }
                                let offset = state.volumes.first { $0.id == entry.fsID }?.offsetBytes ?? 0
                                try await apfsExtractor.extract(
                                    volumePath: entry.fullPath, volumeIndex: entry.fsID ?? 0,
                                    offsetBytes: offset, to: output)
                            } else {
                                guard let database, let extractor,
                                      let info = try database.fetchExtractInfo(forFileID: entry.id) else {
                                    totalFailures += 1; continue
                                }
                                try await extractor.extract(metaAddr: info.metaAddr,
                                                            imageOffsetSectors: info.imageOffsetSectors,
                                                            to: output)
                            }
                            target = output
                        }
                        let rules = try await runner.scan(compiledRules: compiled, fileURL: target,
                                                          timeoutSeconds: 30)
                        matches.append(contentsOf: rules.map {
                            YaraMatch(rule: $0, evidenceID: evidence.id, path: entry.fullPath, fileID: entry.id,
                                      fileSize: entry.size)
                        })
                        totalScanned += 1
                    } catch is CancellationError {
                        throw CancellationError()
                    } catch {
                        totalFailures += 1
                    }
                    if let temporaryURL { try? FileManager.default.removeItem(at: temporaryURL) }
                }
                progress = ProgressInfo(current: candidates.count, total: candidates.count,
                                        label: "YARA: \(evidence.displayName)")
                state.yaraMatches = matches
                states[evidence.id] = state
                try CaseStore.writeYaraMatches(matches, forHostID: evidence.id, in: bundleURL)
                totalMatches += matches.count
                appendCustody(.analysed,
                              detail: "YARA scanned \(totalScanned) file(s) with \(rulesURL.lastPathComponent); \(matches.count) match(es).",
                              evidenceID: evidence.id)
            }

            await runAnalyzers(recordCustody: false)
            let limitNote = wasLimited ? " File limit reached; increase it to scan the remainder." : ""
            let failureNote = totalFailures == 0 ? "" : " \(totalFailures) file(s) could not be extracted or scanned."
            statusMessage = "YARA scanned \(totalScanned) file(s): \(totalMatches) match(es).\(failureNote)\(limitNote)"
        } catch is CancellationError {
            statusMessage = "YARA scan cancelled; previous results were preserved for unfinished hosts."
        } catch {
            errorMessage = error.localizedDescription
        }
    }
}

#endif
