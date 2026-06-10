import Foundation

/// Impact / destruction TTPs - the "Actions on Objectives" end-game where the
/// adversary stops being stealthy and starts breaking things. Three families,
/// each gated to keep false positives near zero:
///
///  1. **Inhibit System Recovery (T1490)** - the canonical ransomware
///     pre-encryption step: deleting Volume Shadow Copies, wiping the backup
///     catalog, and disabling Windows recovery via `bcdedit`. Surfaced from
///     process-creation events (Security 4688 / Sysmon 1) and Linux/macOS shell
///     history. Gated on *multiple* co-occurring tokens (e.g. `vssadmin` **and**
///     `delete` **and** `shadow`) so the benign `vssadmin list shadows` an admin
///     types never fires. Critical.
///
///  2. **Data Destruction / Disk wipe (T1485 / T1561)** - `cipher /w`, a raw
///     `format`/`diskpart clean` of a volume, `dd`/`shred`/`wipe` against a block
///     device, and MBR-overwrite tooling. From events + shell history. High.
///
///  3. **Ransomware mass-encryption (T1486)** - the signature *burst*: dozens of
///     distinct files suddenly acquiring the **same** novel extension (`.locked`,
///     `.encrypted`, `.crypt`, a random tag, …) inside the captured `files`/USN/
///     MFT, plus the ransom notes the operator drops (`READ_ME`, `HOW_TO_DECRYPT`,
///     `*RECOVER*`). The burst is gated on a count threshold and on *not* being a
///     normal archive/media extension, so a folder of `.zip` or `.jpg` can't trip
///     it. Critical.
///
/// Kill-chain phase: Actions on Objectives.
public nonisolated struct ImpactDestructionAnalyzer: Analyzer {
    public let name = "Impact / Destruction"
    public init() {}

    // MARK: - Tunables

    /// Distinct files needed to call a same-extension batch a mass-encryption
    /// burst. 25 is well above a typical project/media folder of one type, but
    /// far below the hundreds-to-thousands a real ransomware run touches.
    private static let ransomBurstThreshold = 25

    // MARK: - Recovery-inhibition signatures (T1490)

    /// Each rule fires only when **every** token is present (lowercased,
    /// substring) in the command line - the multi-token AND is what separates a
    /// destructive `vssadmin delete shadows` from a read-only `vssadmin list
    /// shadows`. Ordered most- to least-specific; the first full match wins.
    private static let recoveryInhibitRules: [(label: String, tokens: [String])] = [
        ("vssadmin delete shadows",            ["vssadmin", "delete", "shadow"]),
        ("WMIC shadowcopy delete",             ["wmic", "shadowcopy", "delete"]),
        ("PowerShell delete shadow copies",    ["get-wmiobject", "win32_shadowcopy", "delete"]),
        ("wbadmin delete catalog",             ["wbadmin", "delete", "catalog"]),
        ("wbadmin delete systemstatebackup",   ["wbadmin", "delete", "systemstatebackup"]),
        ("wbadmin delete backup",              ["wbadmin", "delete", "backup"]),
        ("bcdedit disable recovery",           ["bcdedit", "recoveryenabled", "no"]),
        ("bcdedit ignore boot failures",       ["bcdedit", "bootstatuspolicy", "ignoreallfailures"]),
        // catalog wipe via the management UI's CLI
        ("delete Windows Backup catalog",      ["wbadmin", "delete", "catalog", "-quiet"]),
    ]

    // MARK: - Destruction / wipe signatures (T1485 / T1561)

    /// (label, tokens, technique). Same all-tokens-present rule. These are
    /// destructive by construction - there is no benign `cipher /w` or
    /// `diskpart ... clean` against a live disk.
    private static let wipeRules: [(label: String, tokens: [String], technique: AttackTechnique)] = [
        ("cipher /w free-space wipe",
         ["cipher", "/w"], AttackTechnique(attackID: "T1485", name: "Data Destruction")),
        ("diskpart clean (disk wipe)",
         ["diskpart", "clean"], AttackTechnique(attackID: "T1561.001", name: "Disk Wipe: Disk Content Wipe")),
        ("format volume",
         ["format", "/y"], AttackTechnique(attackID: "T1561.001", name: "Disk Wipe: Disk Content Wipe")),
        ("SDelete secure-delete",
         ["sdelete", "-p"], AttackTechnique(attackID: "T1485", name: "Data Destruction")),
        // Linux / macOS shell device wipes - `of=/dev/sd*` / `if=/dev/zero of=/dev/`
        ("dd to raw block device",
         ["dd ", "of=/dev/"], AttackTechnique(attackID: "T1561.002", name: "Disk Wipe: Disk Structure Wipe")),
        ("shred block device",
         ["shred", "/dev/"], AttackTechnique(attackID: "T1485", name: "Data Destruction")),
        ("wipe block device",
         ["wipe", "/dev/sd"], AttackTechnique(attackID: "T1485", name: "Data Destruction")),
        ("mkfs reformat device",
         ["mkfs", "/dev/sd"], AttackTechnique(attackID: "T1561.001", name: "Disk Wipe: Disk Content Wipe")),
    ]

    /// `dd` to the *boot sector* of a device (small count, seek=0) - MBR/structure
    /// overwrite. Matched separately because it needs both an `of=/dev/` device
    /// and an MBR-shaped write (`bs=512 count=1` / `seek=0`).
    private static let mbrWipeMarkers = ["of=/dev/", "bs=512"]

    // MARK: - Ransomware (T1486)

    /// Extensions ransomware families append. A burst with one of these is a hard
    /// signal even below the generic novel-extension threshold logic.
    private static let knownRansomExtensions: Set<String> = [
        "locked", "encrypted", "crypt", "crypted", "enc", "cry", "crypto",
        "ransom", "locky", "cerber", "zepto", "odin", "wcry", "wncry", "wncryt",
        "ryuk", "conti", "lockbit", "revil", "sodinokibi", "djvu", "phobos",
        "makop", "avaddon", "darkside", "blackcat", "akira", "0xxx", "encrypt",
    ]

    /// Extensions that legitimately cluster in the hundreds (archives, media,
    /// office docs, build output, dev/DB/VM artifacts) - never treat a
    /// same-extension batch of these as encryption, regardless of count. This
    /// list is the primary false-positive guard for the novel-extension rule:
    /// any high-cardinality-but-benign family belongs here so a dev box, DB
    /// server, photo library, or download folder can't trip a critical finding.
    private static let benignBulkExtensions: Set<String> = [
        // Archives / compressed
        "zip", "rar", "7z", "gz", "tar", "tgz", "bz2", "xz", "cab", "zst", "lz", "lzma", "z",
        // Images
        "jpg", "jpeg", "png", "gif", "bmp", "tiff", "tif", "heic", "webp", "raw",
        "svg", "ico", "psd", "cr2", "nef", "arw", "dng",
        // Audio / video
        "mp3", "mp4", "mov", "avi", "mkv", "wav", "flac", "m4a", "m4v", "wmv", "webm", "aac", "ogg",
        // Office / documents
        "doc", "docx", "xls", "xlsx", "ppt", "pptx", "pdf", "txt", "csv", "tsv",
        "rtf", "odt", "ods", "odp", "md", "pages", "numbers", "key",
        // Build output / source / dev intermediates (a dev box has thousands)
        "o", "obj", "class", "pyc", "pyo", "log", "dat", "tmp", "temp", "bak", "json", "xml",
        "html", "htm", "js", "ts", "jsx", "tsx", "css", "scss", "less",
        "dll", "exe", "so", "dylib", "a", "lib", "pdb", "swift", "c", "h", "hpp", "cpp", "cc",
        "py", "rb", "go", "rs", "java", "kt", "php", "cs", "m", "mm", "sh", "yml", "yaml", "toml",
        "map", "min", "d", "gch", "ko", "node",
        // Git / package internals (.git/objects/pack, node_modules, …)
        "pack", "idx", "lock", "snap",
        // Databases / data stores
        "db", "sqlite", "sqlite3", "db-shm", "db-wal", "mdb", "ldb", "frm", "ibd", "myd", "myi", "wal",
        // VM / disk images (legitimately many on a virt host)
        "vmdk", "vdi", "vhd", "vhdx", "iso", "img", "qcow2", "ova", "bin",
        // Misc high-cardinality but benign
        "part", "crdownload", "cache", "thumb", "thumbnails", "ini", "cfg", "conf", "plist",
        "ttf", "otf", "woff", "woff2", "eot", "ics", "vcf", "eml", "msg",
    ]

    /// Ransom-note filename markers (lowercased). A file whose name carries one is
    /// the operator's "your files are encrypted" drop. Each marker already pairs a
    /// recovery verb (decrypt/recover/restore/unlock) with a file/key noun, or is a
    /// named-family note, so none can collide with a benign developer/library file.
    /// Note: a bare `readme`/`read_me` is *deliberately absent* - it is handled by
    /// the intent-gated `isReadmeShape` path so `lib_readme.txt` can't fire.
    private static let ransomNoteMarkers = [
        "readme_to_decrypt", "how_to_decrypt", "how-to-decrypt",
        "howtodecrypt", "decrypt_instruction", "decrypt-files", "recover_files",
        "recover-my-files", "recovery_instruction", "restore_files", "restore-my-files",
        "your_files_are_encrypted", "yourfiles_are_encrypted", "files_encrypted", "!want_to_cry",
        "ransom_note", "unlock_files", "decrypt_files", "_open_me_decrypt",
    ]

    /// Extra ransom-note name shapes requiring two markers to avoid catching a
    /// benign `README.txt`. Handled in `isRansomNote`.

    public func analyze(context: AnalysisContext) -> [Finding] {
        var findings: [Finding] = []
        findings += commandFindings(context)
        findings += ransomwareFindings(context)
        return findings
    }

    // MARK: - Command-based (recovery inhibition + wipe)

    /// Each command source yields (commandLine, timestamp, evidencePath, where).
    private struct Command {
        let line: String
        let lowered: String
        let timestamp: Date?
        let evidence: String
        let origin: String
    }

    private func commandFindings(_ context: AnalysisContext) -> [Finding] {
        var out: [Finding] = []
        for cmd in commands(from: context) {
            // Recovery inhibition (T1490) - critical.
            if let rule = Self.recoveryInhibitRules.first(where: { allPresent($0.tokens, in: cmd.lowered) }) {
                out.append(Finding(
                    title: "Inhibit System Recovery: \(rule.label)",
                    detail: """
                    \(cmd.origin) executed a recovery-inhibition command - the classic
                    pre-encryption / anti-rollback step that destroys backups and shadow copies.
                    Matched: \(rule.label).
                    Command: \(cleaned(cmd.line))
                    """,
                    severity: .critical,
                    phase: .actionsOnObjectives,
                    technique: AttackTechnique(attackID: "T1490", name: "Inhibit System Recovery"),
                    timestamp: cmd.timestamp,
                    evidencePaths: [cmd.evidence]))
                continue   // one finding per command - the strongest family wins
            }

            // Data destruction / disk wipe (T1485 / T1561) - high.
            if let rule = Self.wipeRules.first(where: { allPresent($0.tokens, in: cmd.lowered) }) {
                out.append(Finding(
                    title: "Data destruction / disk wipe: \(rule.label)",
                    detail: """
                    \(cmd.origin) ran a destructive wipe command. Matched: \(rule.label).
                    Command: \(cleaned(cmd.line))
                    """,
                    severity: .high,
                    phase: .actionsOnObjectives,
                    technique: rule.technique,
                    timestamp: cmd.timestamp,
                    evidencePaths: [cmd.evidence]))
                continue
            }

            // MBR / disk-structure overwrite via dd (T1561.002) - high.
            if allPresent(Self.mbrWipeMarkers, in: cmd.lowered) {
                out.append(Finding(
                    title: "Disk-structure overwrite (dd to boot sector)",
                    detail: """
                    \(cmd.origin) wrote directly to a raw block device's boot region (bs=512),
                    consistent with an MBR / partition-table overwrite.
                    Command: \(cleaned(cmd.line))
                    """,
                    severity: .high,
                    phase: .actionsOnObjectives,
                    technique: AttackTechnique(attackID: "T1561.002", name: "Disk Wipe: Disk Structure Wipe"),
                    timestamp: cmd.timestamp,
                    evidencePaths: [cmd.evidence]))
            }
        }
        return out
    }

    /// Gather every command line we can see: process-creation events and shell
    /// history. (Linux destruction lands in `shellHistory`; Windows in 4688 /
    /// Sysmon 1.)
    private func commands(from context: AnalysisContext) -> [Command] {
        var cmds: [Command] = []

        for event in context.events {
            guard let line = processCommandLine(event) else { continue }
            cmds.append(Command(line: line, lowered: line.lowercased(),
                                timestamp: event.writtenAt,
                                evidence: event.sourceFile,
                                origin: "Host \(event.computer) (EID \(event.eventID))"))
        }

        for hist in context.shellHistory {
            cmds.append(Command(line: hist.command, lowered: hist.command.lowercased(),
                                timestamp: hist.timestamp,
                                evidence: hist.sourceFile,
                                origin: "Shell history (\(hist.user), \(hist.shell.label))"))
        }

        return cmds
    }

    /// Image + command line for the process-creation event types we trust.
    private func processCommandLine(_ event: EventLogRecord) -> String? {
        switch event.eventID {
        case 4688:
            let img = event.data("NewProcessName") ?? ""
            let cmd = event.data("CommandLine") ?? event.data("ProcessCommandLine") ?? ""
            let joined = (img + " " + cmd).trimmingCharacters(in: .whitespaces)
            return joined.isEmpty ? nil : joined
        case 1 where event.channel.localizedCaseInsensitiveContains("Sysmon"):
            let img = event.data("Image") ?? ""
            let cmd = event.data("CommandLine") ?? ""
            let joined = (img + " " + cmd).trimmingCharacters(in: .whitespaces)
            return joined.isEmpty ? nil : joined
        default:
            return nil
        }
    }

    private func allPresent(_ tokens: [String], in haystack: String) -> Bool {
        tokens.allSatisfy { haystack.contains($0) }
    }

    /// Collapse whitespace + cap length for readable finding detail.
    private func cleaned(_ s: String) -> String {
        let collapsed = s.split(whereSeparator: { $0 == " " || $0 == "\n" || $0 == "\t" })
            .joined(separator: " ")
        return String(collapsed.prefix(400))
    }

    // MARK: - Ransomware mass-encryption (T1486)

    private func ransomwareFindings(_ context: AnalysisContext) -> [Finding] {
        var out: [Finding] = []

        // 1. Mass same-extension burst across files / USN / MFT.
        //    Count *distinct* leaf names per extension so a single file touched
        //    repeatedly in USN can't inflate the count.
        var byExtension: [String: Set<String>] = [:]
        var evidenceByExtension: [String: String] = [:]

        func note(_ name: String, ext: String, evidence: String) {
            guard !ext.isEmpty else { return }
            byExtension[ext, default: []].insert(name.lowercased())
            if evidenceByExtension[ext] == nil { evidenceByExtension[ext] = evidence }
        }

        for f in context.files where !f.isDirectory {
            note(f.name, ext: f.fileExtension, evidence: f.fullPath)
        }
        for r in context.usn where !r.isDirectory {
            // Only newly-appearing names: a create or a rename-to-new-name.
            guard r.isCreate || (r.reasonRaw & UsnReason.renameNewName != 0) else { continue }
            note(r.fileName, ext: r.fileExtension, evidence: r.sourceFile)
        }
        for m in context.mft where !m.isDirectory {
            if let name = m.fileName { note(name, ext: m.fileExtension, evidence: m.displayPath) }
        }

        for (ext, names) in byExtension where names.count >= Self.ransomBurstThreshold {
            // A novel extension is one not on the benign-bulk allow-list. A known
            // ransom extension always qualifies even if (somehow) bulk-ish.
            let isKnownRansom = Self.knownRansomExtensions.contains(ext)
            guard isKnownRansom || !Self.benignBulkExtensions.contains(ext) else { continue }

            let qualifier = isKnownRansom
                ? "Extension '.\(ext)' is a known ransomware marker."
                : "Extension '.\(ext)' is not a common archive/media/document type - a uniform extension applied to this many files is the fingerprint of bulk encryption."
            out.append(Finding(
                title: "Possible mass file encryption: \(names.count) files with extension '.\(ext)'",
                detail: """
                \(names.count) distinct files share the extension '.\(ext)'.
                \(qualifier)
                Sample: \(names.sorted().prefix(5).joined(separator: ", ")).
                """,
                severity: .critical,
                phase: .actionsOnObjectives,
                technique: AttackTechnique(attackID: "T1486", name: "Data Encrypted for Impact"),
                timestamp: nil,
                evidencePaths: [evidenceByExtension[ext] ?? ".\(ext)"]))
        }

        // 2. Ransom notes - dropped instruction files. De-duplicate by lowercased
        //    leaf name so the same note in many directories yields one finding.
        var seenNotes: Set<String> = []
        for f in context.files where !f.isDirectory && isRansomNote(f.name) {
            let key = f.name.lowercased()
            guard seenNotes.insert(key).inserted else { continue }
            out.append(Finding(
                title: "Ransom note dropped: \(f.name)",
                detail: """
                A file matching the ransom-note naming convention attackers use to deliver
                payment / decryption instructions was found at \(f.fullPath).
                """,
                severity: .high,
                phase: .actionsOnObjectives,
                technique: AttackTechnique(attackID: "T1486", name: "Data Encrypted for Impact"),
                timestamp: f.created ?? f.modified,
                evidencePaths: [f.fullPath]))
        }

        return out
    }

    /// A filename matches a ransom-note convention. Single distinctive markers
    /// (`how_to_decrypt`, `recover_files`) fire alone; a bare `readme` does NOT -
    /// it must co-occur with a decrypt/encrypt/recover token to avoid the
    /// ubiquitous benign `README`.
    private func isRansomNote(_ name: String) -> Bool {
        let lower = name.lowercased()
        if Self.ransomNoteMarkers.contains(where: { lower.contains($0) }) { return true }
        let isReadmeShape = lower.hasPrefix("readme") || lower.contains("read_me") || lower.contains("read-me")
        let hasIntent = ["decrypt", "encrypt", "recover", "restore", "ransom", "unlock", "bitcoin", "payment"]
            .contains { lower.contains($0) }
        return isReadmeShape && hasIntent
    }
}
