# CLAUDE.md

Operational context for working on **Strata**. Read this first.
(`AGENTS.md` is a symlink to this file — editing one edits both, so keep it
agent-neutral.)

## What Strata is

A native macOS DFIR triage tool (with an iOS companion viewer). It ingests a
**Windows, Linux, or macOS** disk image (NTFS + ext2/3/4 via the vendored TSK,
APFS/HFS+ via vendored libfsapfs) or a loose collection folder (KAPE / UAC),
enumerates the file system, parses the OS's triage artifacts (Windows: event
logs + registry hives + execution artifacts; Linux: auth logs, login records,
shell history, cron/systemd persistence; macOS: unified log, FSEvents, TCC,
KnowledgeC, launch items, quarantine, …), builds a MACB super-timeline, and
surfaces attacker activity through ATT&CK-tagged detection analyzers, a Cyber
Kill Chain view, an interactive lateral-movement graph, and IOC matching. It can
also write an **on-device, evidence-validated AI case summary**.

- **macOS app** = full pipeline (ingest + analyze). Non-sandboxed; reads raw
  disk images via Full Disk Access.
- **iOS app** = read-only viewer for already-built `.strata` cases. No ingest.
- Forensic file handling is a self-contained, vendored build of The Sleuth Kit +
  libyal (`libevtx`, `libregf`, `libscca`, `liblnk`, `libolecf`, `libesedb`,
  `libfsapfs`, `libewf`, `libvhdi`, `libvmdk`). **No Homebrew / runtime deps.**

## Build / run / test

This is an **Xcode project** (`Strata.xcodeproj`), one multiplatform target
`Strata`. There is **no `Package.swift`** and it must not come back — but the
project does carry one Xcode SPM dependency (**GRDB**, the SQLite layer). New
`.swift` files under `Strata/` are auto-included (file-system-synchronized
group), so adding or moving files needs no `.pbxproj` edit.

```sh
# Vendored TSK toolchain (once; not checked in — Vendor/tsk/ is git-ignored).
# Also builds YARA, bootstrapping pinned m4/autoconf/automake/libtool into the
# private prefix first (upstream ships no generated `configure`), so a stock
# Xcode-CLT machine still needs no Homebrew — but the first run is long:
scripts/build-tsk.sh                 # host arch (arm64). 'universal' for fat binaries.

# Build:
xcodebuild build -project Strata.xcodeproj -scheme Strata -destination 'platform=macOS' -configuration Debug
xcodebuild build -project Strata.xcodeproj -scheme Strata -destination 'generic/platform=iOS Simulator' -configuration Debug

# Test (Swift Testing; runs on macOS) — the whole suite, then a single suite:
xcodebuild test -project Strata.xcodeproj -scheme Strata -destination 'platform=macOS' -only-testing:StrataTests
xcodebuild test -project Strata.xcodeproj -scheme Strata -destination 'platform=macOS' -only-testing:StrataTests/MftParserTests

# Layout guard (fast, no toolchain needed) + lint:
scripts/check-structure.sh
swiftlint                            # .swiftlint.yml — warn-only, signal not a gate
```

**Always build BOTH platforms after touching shared code** — iOS-only views are
`#if !os(macOS)` and won't compile-check in a macOS build (or vice-versa).

**`-only-testing` is safe only down to the *suite*.** Tests are Swift Testing
(`import Testing`; ~950 `@Test`s across 92 files, no XCTest). A per-test filter
(`…/SomeTests/someTest`) **silently matches nothing** — xcodebuild still prints
`** TEST SUCCEEDED **` with zero tests run. A suite is the bare type name
(`MftParserTests`). Confirm "Test case … passed" lines before trusting a pass.

**If SPM resolution dies on GRDB**, it's the git Xcode spawns, not your setup:
it fails cloning GRDB's `SQLiteCustom/src` submodule. Strata links only the
plain `GRDB` product (system libsqlite3), so that submodule is never used. Let a
resolve run once so the checkout exists, then pre-seed it with your own git and
re-resolve (clearing caches/DerivedData does **not** help):

```sh
git -C ~/Library/Developer/Xcode/DerivedData/Strata-*/SourcePackages/checkouts/GRDB.swift \
    submodule update --init
xcodebuild -resolvePackageDependencies -project Strata.xcodeproj -scheme Strata
```

## Release & distribution

```sh
scripts/release.sh 0.1.0-beta.3       # build number auto-derives from the beta suffix
gh release create v0.1.0-beta.3 build/Strata-0.1.0-beta.3.dmg \
  --prerelease --title "Strata 0.1.0 — Beta 3" --notes-file docs/releases/v0.1.0-beta.3.md
```

`release.sh` archives → exports Developer ID → notarizes app → staples → builds
dmg → notarizes + staples dmg. Prereqs: a **Developer ID Application** cert and a
notarytool keychain profile named **`strata-notary`** (`xcrun notarytool
store-credentials`). It **overrides** `CODE_SIGN_ENTITLEMENTS` to the empty
`scripts/StrataRelease.entitlements`, so the notarized build carries no
entitlements. `scripts/ios-testflight.sh` is the iOS counterpart.
Released so far: **v0.1.0-beta.1 … v0.1.0-beta.4, v0.2.0**.
Per-release notes live in `docs/releases/`; keep `CHANGELOG.md` updated.

**Licensing constrains distribution.** Strata's own source is Apache-2.0
(`LICENSE`); the vendored libyal components are **LGPL-3.0** and are **statically
linked** (`NOTICE` carries the full attribution list). Keep `NOTICE` accurate
whenever `build-tsk.sh` gains or drops a library.

## Architecture (folders under `Strata/`)

> **Placement guide:** see [ARCHITECTURE.md](ARCHITECTURE.md) for the
> "where does this go?" decision tree. OS-specific artifact code now lives under
> `Strata/Platforms/<Windows|macOS|Linux|Shared>/{Parsers,Models}/`; `StrataCore`
> is slimmed to cross-cutting `Models/` + `Utilities/`. The per-format folders
> below (StrataEVTX, StrataMac, StrataLinux, …) have been consolidated there —
> the table records their *responsibilities*, which are unchanged.

| Module | Responsibility |
|--------|----------------|
| `StrataCore` | Value types: `FileEntry`, `TimelineEvent`, `EventLogRecord`, `RegistryValue`, `IOC`, `HostProfile`, `VolumeInfo`, case + kill-chain models |
| `StrataTSK` | Vendored TSK binaries, `tsk_loaddb` → SQLite (read via GRDB), `icat` extraction, KAPE source classification, loose-folder walk (`KapeFolderIngestor`). **APFS (macOS) does NOT go through `tsk_loaddb`** — TSK 4.15's APFS parser **aborts (SIGABRT in `APFSJObject`)** on real macOS volumes (confirmed on a macOS-27 E01); instead `build-tsk.sh` vendors libyal's **`fsapfsinfo`** (`libfsapfs`) + **`ewfexport`** + a custom **`fsapfscat`** (`scripts/fsapfscat.c`, statically linked to libfsapfs). The macOS ingest path (`FsApfsIngestor`, `.ingestionCrashed` fallback → `EvidenceKind.apfs`): `ewfexport` (E01→raw, or use raw directly) → `fsapfsinfo -f <i> -H -B` per volume → `BodyfileParser` → `FileEntry` tree + MACB timeline (no `tsk.db`; persisted as `apfsfiles/apfsvolumes.json`). **File content** is read on demand by `FsApfsExtractor` (shells `fsapfscat -o <off> -f <vol> <raw> <path>`, the `icat` analogue), wired into `parseMac` + `parseBrowserHistory` + `parseUnifiedLog` so the macOS analyzers run on APFS images. `fsapfscat -x <name>` also dumps a file's **extended attribute** (used to recover the `com.apple.metadata:kMDItemWhereFroms` download-provenance xattr → `FsApfsExtractor.extract(attribute:)`); rc 3 = attribute absent. **FileVault:** ingest threads a `FileVaultCredential` (held **in memory only — never persisted**) to both tools. `fsapfscat` (content) reads the secret from **stdin** (`-s`, framed `<password>\0<recovery>`), never the world-readable `-p`/`-r` argv (visible via `ps`/`KERN_PROCARGS2`); `fsapfsinfo` (metadata) still takes `-p`/`-r` on argv — the one remaining exposure, a vendored libyal patch being the fix. An encrypted volume that reads empty is surfaced as an `ApfsLockedVolume` instead of aborting ingest; `AppModel` then prompts via `FileVaultUnlockSheet` (auto after ingest, or Tools ▸ Unlock FileVault Volume), re-ingests, and re-runs the macOS/browser/unified-log parsers. *(FileVault path not yet validated against a real encrypted image.)* *Sealed System volume files live in a snapshot → libfsapfs reads 0 bytes; Data-volume artifacts are fine. `fsapfscat` (with the rest of the vendored tools) is bundled via the app's Copy Files phase.* |
| `StrataEVTX` | Parse `.evtx` via `evtxexport` |
| `StrataRegistry` | Parse hives via `regfexport` |
| `StrataSCCA` | Parse Windows Prefetch (`.pf`) via `sccainfo` (libscca) |
| `StrataLNK` | Parse `.lnk` shortcuts via `lnkinfo` (liblnk) |
| `StrataJumpList` | Parse JumpLists - OLE via `olecfexport` (libolecf) + reused `lnkinfo` + a pure DestList decoder |
| `StrataCore` (USN) | Pure-Swift NTFS USN change-journal byte-parser (`UsnJournalParser`, `UsnRecord`) — no vendored tool; reads the `$Extend\$UsnJrnl:$J` ADS extracted via icat |
| `StrataCore` (MFT) | Pure-Swift NTFS `$MFT` byte-parser (`MftParser`, `MftEntry`, `MftNode` tree, `FileTime`) — no vendored tool; applies the USA fixup, decodes `$SI` + `$FN` MACB as **raw FILETIME** (`FileTime.precise` renders the full 100-ns string; `Date` is lossy), resolves paths from parent refs, and captures **resident `$DATA`** (small-file recovery). Enables timestomp detection ($SI vs $FN) and true loose-folder MACB. `$MFT` extracted via icat (images) / read in place (loose) |
| `StrataSRUM` | Parse the SRUM `SRUDB.dat` (ESE database) via `esedbexport` (libesedb); pure `SrumExportDecoder` (`StrataCore`) resolves the export TSV + SruDbIdMapTable foreign keys |
| `StrataBrowser` | Parse web-browser history — Chromium `History` + Firefox `places.sqlite` + Safari `History.db` (`history_items`+`history_visits`, CFAbsoluteTime visit time) — all SQLite, read directly via GRDB (no vendored tool); `BrowserHistoryParser` (macOS) copies the DB to scratch + opens read-write (WAL); pure decoders on `BrowserHistoryEntry` (`StrataCore`) |
| `StrataTimeline` | MACB timeline + per-artifact timeline projections (34 sources) + gap/session analysis |
| `StrataCore` (WMI) | Pure-Swift carve of the WMI CIM repository `OBJECTS.DATA` (`WmiRepositoryParser`, `WmiPersistenceEntry`) — no full CIM parse; keyword-carves event-subscription persistence (bindings + WQL filter + command + script payloads), à la PyWMIPersistenceFinder. `OBJECTS.DATA` extracted via icat (images) / read in place (loose) |
| `StrataLinux` | Pure-Swift Linux artifact parsers (no vendored tool): `AuthLogParser` (syslog classic + RFC3339, year inference), `UtmpParser` (384-byte wtmp/btmp records), `ShellHistoryParser` (bash + zsh extended), `LinuxPersistenceParser` (crontabs + systemd units), `LinuxHostInfoParser` (os-release/hostname/passwd/timezone), `LinuxAccessParser` (authorized_keys/known_hosts/sshd_config/sudoers/group/shadow), `WebLogParser` (nginx/apache access logs, CLF + Combined), `PackageParser` (dpkg/apt/yum/dnf logs), `AuditParser` (auditd `audit.log` - groups records by `audit(epoch:serial)`, hex-decodes fields, rebuilds EXECVE cmdlines, resolves syscalls per-arch), `SyslogParser` (general syslog/messages, classified via the shared `SyslogLineScanner` that `AuthLogParser` also uses), `LastlogParser` (292-byte UID-indexed records), `LinuxNetworkParser` (host IPv4 from netplan/ifupdown static config + journal NetworkManager/dhclient/avahi DHCP-lease lines → Overview); `LinuxPersistenceParser` also covers systemd timers, ld.so.preload, XDG autostart, rc.local/init.d, shell-init. Rotated `.gz` logs read via `StrataCore/GzipDecoder` (Compression framework) |
| `StrataCore` (journald) | Pure-Swift decoder of the systemd **journald** binary journal (`JournaldParser`, `JournaldEntry`) — no vendored tool; parses the `LPKSHHRH` header, entry-array chain, entry + data objects (legacy **and** COMPACT le32-offset layouts), recovering `MESSAGE`/`_COMM`/`PRIORITY`/`_SYSTEMD_UNIT`/etc. **LZ4** values inflated via the Compression framework; **XZ/ZSTD** skipped (not in the framework — loses only large compressed MESSAGE bodies). `.journal` extracted via icat (images) / read in place (loose) |
| `StrataCore` (unified log) | **Full** macOS unified-log (`.tracev3`) decoder (the early "Phase 1 container-only / `parse()` returns `[]`" note is obsolete). **Container:** `TraceV3Parser` parses the flat chunk framing (`tag\|subtag\|size` preambles, 8-byte aligned) + decompresses chunkset payloads via `AppleLZ4` (`bv41`/`bv4-`/`bv4$` → `COMPRESSION_LZ4_RAW`). **Firehose + time:** `FirehoseDecoder` decodes firehose tracepoints (resolving the emitting process via the catalog); `TimesyncParser` converts mach-continuous time → wall clock. **String resolution:** `UUIDTextParser` + `DscParser` + `UnifiedLogStringCatalog` resolve format strings from `.uuidtext` / the `dsc` shared cache, `FirehoseItemDecoder` + `LogFormatter` render the message. `UnifiedLogAssembler` orchestrates the lot → `UnifiedLogEntry` (timestamp/pid/process/subsystem/category/message). Driven by `AppModel.parseUnifiedLog()` (off-main); dedicated **Unified Log** tab + timeline splice (`TimelineSource`). `UnifiedLogAnalyzer` flags sudo (T1548.003), osascript (T1059.002), SSH accept + failed-burst brute force (T1021.004/T1110.001), Screen Sharing/VNC auth (T1021.001), and local account creation (T1136.001). Synthetic-fixture tested across all phases |
| `StrataCore` (carving) | `FileCarver` — pure-Swift **signature carver**: scans an image's raw bytes for file magic and recovers the embedded files independent of the filesystem — reaching deleted files in unallocated space and content libfsapfs won't surface through the volume layer (**sealed System snapshot, locked FileVault**), since it reads raw bytes directly. SQLite/PNG/JPEG/PDF/ZIP sized exactly (header field / footer), bplist/gzip capped + flagged inexact. `CarvedFile` model; opt-in `AppModel.carveArtifacts()` (Tools ▸ Carve Deleted Files) scans each APFS host's raw image off-main **in parallel** (`DispatchQueue.concurrentPerform`, one start-position chunk per **performance core** — `CPUInfo.performanceCoreCount` (sysctl `hw.perflevel0`), run at `.userInitiated` QoS to bias onto P-cores since macOS has no hard affinity API; a `mergeNested` pass keeps the result identical to a serial scan), with a determinate MB-scanned progress bar → `carved.json` + a **Carved Files** tab (offset/type/size/source, Save recovered bytes); **no timeline splice** (no timestamps, like FSEvents). Partially mitigates the deferred APFS-carving + sealed-System-read items. Synthetic-fixture tested (real-image end-to-end pending) |
| `StrataAnalysis` | `Analyzer` protocol, `AnalysisEngine`, **62 analyzers**, IOC matcher, lateral graph, `CorrelationEngine` (case-wide multi-host: shared IOC / pivoting source IP / reused account across ≥2 hosts) |
| `StrataSearch` | `SearchEngine` — pure cross-artifact global search (files/events/registry/timeline/findings → ranked `SearchHit`); drives the **Search** tab |
| `StrataMac` | macOS triage — the widest artifact surface: launch items + a non-launchd persistence sweep, quarantine + `kMDItemWhereFroms` download provenance, TCC, KnowledgeC, **Powerlog** (process execution with PIDs), Messages, Mail, BTM background items, kernel/system extensions, security events (Gatekeeper/XProtect), recent items, network & devices, QuickLook & Trash, document versions, notifications, install history, security-posture configuration, and FSEvents — each a parser (usually + an analyzer), all discovered by `AppModel.parseMac()`. **Per-parser detail, ATT&CK mappings, timeline splices and tab gating: [docs/artifacts.md](docs/artifacts.md).** |
| `StrataTSK` (YARA) | Examiner-supplied rule scanning via the vendored upstream **`yarac`/`yara`** binaries (VirusTotal YARA, added to `build-tsk.sh` TOOLS + the app Copy-Files phase). `YaraRunner` (`StrataTSK`, macOS-only) compiles the ruleset **once** per scan — invalid rules fail before any extraction — then scans each extracted file with `--compiled-rules`; `AppModel.runYaraScan()` walks allocated, non-slack, non-deleted files under a max-file-MB and max-file-count cap (both UserDefaults-backed), scoped to the active evidence or all hosts. `YaraMatch` (`StrataCore`) persists per host; `YaraAnalyzer` groups matches by rule into `.high`/`.delivery` findings that carry **no ATT&CK technique and no timestamp** — a content match is not execution. `AnalysisContext.yaraMatches` feeds it; **Yara Matches** view is cross-platform |
| `StrataCTI` | Tiered CTI enrichment (NSRL → MISP/OpenCTI → VirusTotal). `EnrichmentEngine` cascade (short-circuits on first definitive verdict), `EnrichmentVerdict` (provenance: tier/source/score/ref), actor `EnrichmentCache`, `CTIProvider` protocol; providers `NSRLProvider` (local hash set), `VirusTotalProvider` (v3), `MISPProvider` (restSearch), `OpenCTIProvider` (GraphQL) — each a pure decoder + injectable transport, all opt-in; `KeychainCredentialStore` (SecItem) holds base URL + token; `CTIConfiguration` (UserDefaults) holds the on/off flags + NSRL path. Driven by `AppModel.enrichIndicators()` → `enrichment.json` + custody `.enrichmentPerformed` |
| `StrataAI` | On-device + cloud inference behind one `InferenceBackend` protocol — `OnDeviceBackend` (Apple FoundationModels), `PrivateCloudComputeBackend` (Apple PCC, macOS 27+), `CloudInferenceBackend` (opt-in, BYO key, injectable transport); `SovereigntyTier` (`StrataCore`) labels the tier and is persisted on `CaseSummary`. `FindingsSummarizer` builds an `F01…`-keyed digest (map-reduce for large cases) → `@Generable` types → **`SummaryValidator`** → `CaseSummary` (`summary.json`). `CaseLookupIndex` + `LookupFileTool`/`LookupDownloadOriginTool` let the model query real file facts during generation; `SummaryEval` is the model-free hit/miss scorer behind Tools ▸ Run Summary Self-Eval |
| `StrataApp` | SwiftUI app. `AppModel` — the store, split across `AppModel.swift` (stored `@Published` state + the derived-cache machinery) and 13 `AppModel+*.swift` extensions (`CaseManagement`, `Ingest`, `Parsing{Shared,Windows,MacOS,Linux}`, `Analysis`, `Annotations`, `IOC`, `Custody`, `Inference`, `SourceHash`, `Commands`) — plus `CaseStore` (.strata bundle layout), `CaseLibrary`, `RecentCases`, `Views/` (macOS) + `Views/iOS/` |

`.strata` case bundle = a directory: `case.json`, `hosts.json`, `iocs.json`,
`custody.json`, `annotations.json`, `notes.json`, `enrichment.json`,
`hosts/<uuid>/{tsk.db, events.json, registry.json, findings.json, iocmatches.json,
recyclebin.json, launchitems.json, quarantine.json, …}`.
Registered as a **package UTI** (`com.bonnicilabs.strata-case`) so Finder/Files
treat it as one item. The macOS-only ingest code is gated `#if os(macOS)`.

## Conventions & gotchas (hard-won — don't relearn these)

- **Per-OS tab hiding.** Artifact tabs that can't apply to the evidence's OS are
  hidden: each `SidebarItem` has an `osFamily` (`.windows` for EVTX/registry/
  prefetch/amcache/shimcache/LNK/JumpList/USN/SRUM/MFT/WMI, `.linux` for the
  auth/persistence tabs, `.macos` for Launch Items + Quarantine + Persistence +
  FSEvents + TCC + KnowledgeC + Recent Items + macOS Security + Unified Log +
  Carved Files + Extensions + Background Items + Messages + Mail +
  Network & Devices + QuickLook & Trash + Document Versions + Notifications +
  Powerlog + Configuration + Installs + Download Origins, `nil` =
  cross-platform incl. **Browser History**, always shown).
  **Shell History** is the one multi-OS tab — zsh/bash history exists on both
  Linux *and* macOS, so `ContentView.isVisible` (and the iOS row) gate it via
  `shows(anyOf: [.linux, .macos])` rather than its single `osFamily`; that one
  helper is the single source of truth shared by `visibleSidebarItems` +
  `clampSelection`. macOS `~/Users/*/.zsh_history|.bash_history` are collected in
  `parseMac()` and folded into the shared `shellHistory` collection (the Linux
  parser handles `/home/` + `/root/`). `OSFamily.detect`
  reads each host's volume **fs-type** (NTFS ⇒ Windows, ext ⇒ Linux, APFS/HFS+ ⇒
  macOS; FAT is ignored — every OS carries a FAT ESP), falling back to a
  file-tree sniff for loose folders (a decisive **macOS-only** marker — e.g.
  `/System/Library/`, `.app/Contents/` — vetoes the weaker `/Users/`⇒Windows and
  `/etc/`⇒Linux guesses, since macOS carries those too); stored on `EvidenceState
  .osFamilies` at load/ingest. `AppModel.shows(osFamily:)` gates on the **active
  scope's** union (so "All" with mixed hosts shows everything; an undetermined
  scope shows everything — never hide on a guess). A "Show all tabs" override
  (`showAllArtifactTabs`) appears only when something is hidden. macOS filters
  `SidebarItem.allCases` + clamps the selection to Overview when the current tab
  hides; iOS gates the More-tab rows. **Disk-image *container* formats** (E01/
  VHD/**VMDK**/raw) are a separate layer from the filesystem: ext2/3/4 support is
  unconditional in TSK, but a malformed VMDK descriptor (e.g. out-of-order
  section markers) fails in `libvmdk` *before* the ext4 is ever read — patch the
  descriptor, don't suspect ext support.
- **Swift 6.2 MainActor-by-default isolation is ON.** Value types that run off
  the main actor (in `Task.detached`) must be declared `nonisolated` + `Sendable`
  (e.g. `FileEntry`, `FileNode`, `KapeFolderIngestor`, `AnalysisEngine`).
- **One `.fileImporter` per view tree.** SwiftUI silently no-ops extra ones —
  route multiple pickers through a single importer + an enum mode. Keep the
  *mode* and the *isPresented flag* as **separate** `@Published` properties:
  SwiftUI clears the isPresented binding on dismiss, racing `onCompletion`.
  Same rule for `.sheet` → use one `.sheet(item:)`.
- **The app defines its own `TimelineView`** (the timeline tab). Use
  `SwiftUI.TimelineView` when you need the SDK one (e.g. `.animation`).
- **Don't do heavy work in `body`.** `AppModel` rolls up + **caches** its derived
  collections (`files/events/timeline/findings/...`), invalidated via `didSet` on
  `states`/`activeEvidenceID`; there are count-only accessors (`fileCount`, …)
  and a `dataVersion` token for `.task(id:)`. Views should snapshot a collection
  into one `let` per body and push expensive transforms (tree build, graph build,
  host-profile derive) into `.task(id:)`/`.onChange` → `@State`, NOT compute in
  `body` or via a cancellable detached task (which can leave state empty).
- **Artifact backfill on case open (macOS).** Each parser self-gates (parses a
  bucket only when it's empty *and* the file tree has candidates), so opening a
  case kicks off `AppModel.backfillOnOpen()` in the background: it runs the full
  parser set (`runAllParsers`) so a case parsed by an **older build picks up
  newly-added artifact types** (kexts/BTM/Messages/…) without the analyst knowing
  to re-run Parse. It re-runs analyzers only when a parser actually added data
  (`dataVersion` changed) and **without** a custody entry (it's an automatic
  refresh, not an examiner action). Up-to-date cases do only cheap candidate
  scans; a missing source image degrades to a silent no-op. When you add a new
  artifact type, wiring it into a self-gating parser is what makes old cases
  backfill it for free.
- **macOS cannot be sandboxed / Mac-App-Store'd** — it needs raw disk reads +
  Full Disk Access (a TCC permission, not an entitlement). Therefore **iCloud
  containers, CloudKit, and App Store distribution are off the table** for the
  Mac app. `Strata.entitlements` is intentionally empty.
- **iCloud = files in iCloud Drive**, not an app container. The "Case Library" is
  a user-chosen folder (security-scoped bookmark) that can live in iCloud Drive,
  a mounted SMB/WebDAV share, or locally — transport-agnostic, opt-in by
  placement. Sync = ordinary file I/O + `startDownloadingUbiquitousItem`.
- **Security-scoped bookmarks** for recent cases + the Case Library: plain
  bookmark on (non-sandboxed) macOS, `.minimalBookmark` on iOS; acquire the scope
  around reads.
- **Evidence tree groups by volume** (`FileEntry.fsID` = `tsk_files.fs_obj_id`) —
  a disk image has several filesystems each with its own `$MFT`/`$LogFile`, which
  would otherwise look like duplicates.
- **Forensic confidentiality matters.** Never auto-upload evidence anywhere;
  cloud/network features must be opt-in and clearly labeled.
- iOS strips TSK `*-slack` entries at load (memory); macOS has a "Hide slack"
  toggle. iOS view-internal helpers are `private` + `#if`-gated → extract pure
  logic to `StrataCore`/a shared spot to unit-test it.
- **The AI layer has one invariant: the model selects and narrates — it is never
  the source of a fact.** Every backend (on-device, Apple PCC, third-party
  cloud) runs through the *same* `SummaryValidator`: claims cite findings by
  stable `F01…` ID, phantom refs are stripped, severity/phase are clamped to the
  cited findings, and the paths shown to the analyst are the findings' own
  `evidencePaths` — never anything the model typed. Never add a "trusted"
  backend path that skips it. Backends must be `nonisolated` (Swift 6.2
  MainActor-by-default would otherwise pin inference to the main actor). Cloud
  egress is gated per destination, labeled, and written to the custody ledger —
  resolve the backend **once at the gate** and thread that instance through to
  the runner, or a settings change between gate and run re-points egress (a
  fixed TOCTOU).
- **`AppModel` is one class across 14 files.** Extensions can't hold stored
  properties, so every `@Published`/`var`/`let` stays in `AppModel.swift`; and
  `private`/`private(set)` is *file*-scoped, so anything a sibling extension
  calls must be internal. The four `AppModel+Parsing*` files and `+Inference`
  are wholly `#if os(macOS)`.
- **`scripts/check-structure.sh` guards the layout** — no loose Swift at
  `Strata/` root, the dissolved per-format folders don't come back, the OS homes
  exist, and no two Swift files anywhere share a filename (one module — they'd
  clash). Run it after moving files; moves stay renames-only commits.

## Validation status & known limits

What has shipped is recorded in [CHANGELOG.md](CHANGELOG.md) and the per-release
notes under `docs/releases/`. This section is only the part a change here must
not assume away.

**Decoder validation.** Confirmed against *real* evidence: `$MFT` (libfsntfs
corpus, incl. resident-data + 100-ns fixtures), LNK (real `lnkinfo` output), WMI
(flare-wmi's `wmikatz` repository), the whole Linux layer (a real Ubuntu ext4 VM
image — journald, RFC3339 syslog, passwd and DHCP-IP recovery), and
`kMDItemWhereFroms` (a real APFS E01). Validated against **synthetic fixtures
only** — treat findings as unconfirmed until checked on real evidence:
**Shimcache** (needs a real SYSTEM hive), **JumpList DestList**, **USN** (real
`$J` parse pending), **SRUM** (real `esedbexport`-on-`SRUDB.dat` pending),
**FileCarver**, and the **unified-log** suite. The **FileVault unlock path** is
implemented but has never run against a real encrypted image.

**Known limits.**
- Loose folders: the *file tree* still uses collection-host times (only the
  *timeline* uses `$MFT` `$SI` MACB), and there's no source hash — no single
  image to hash.
- Linux: classic syslog carries no TZ (treated as UTC) and the year is inferred
  from file mtime; `.gz` rotations are read for auth/package logs only; journald
  **XZ/ZSTD** values are skipped (costs only large compressed MESSAGE bodies);
  modern Ubuntu (≥ glibc 2.40) moved to `lastlog2.db`, so last logins come from
  wtmp there; plain bash history is undated and kept off the timeline; utmp
  assumes the standard glibc 384-byte record.
- macOS: sealed System-volume files live in a snapshot, so libfsapfs reads 0
  bytes (the carver is the way in); loose collections strip xattrs, so download
  origins need an APFS image.
- Registry explorer: hives sharing a label (several users' `NTUSER`) merge under
  one node — `hive` is a logical label.
- Annotations: editing is macOS-only; a timeline bookmark's host attribution is
  the active scope at bookmark time (nil under "All"); the narrative is plain
  text, rendered verbatim into the report.
- Custody: the ledger is tamper-evident only by living in its own file — no hash
  chaining.
- A large `$MFT` makes a large `mft.json` (same bracket as `events.json`).
- Timestomp detection is a heuristic — verify a finding against a known-good copy.

## Pending / deferred

- **Known-bad hash matching** has its cores landed (`KnownBadHashProvider` CTI
  tier + `KnownBadHashAnalyzer`); config UI + pipeline wiring still pending.
- **Universal / Intel support** — currently arm64-only (`build-tsk.sh universal`
  builds the fat binaries).
- **iOS distribution** (TestFlight / App Store) — currently build-from-source.
- **Dynamic Type** on the iOS layer — deferred to preserve mockup fidelity.
- **Phase-D iCloud hardening** — `NSFileCoordinator` + robust package
  download-completion; needs on-device validation.
- **AI layer** — optional image input; PCC reasoning level
  (`.light`/`.moderate`/`.deep`) is wired-capable but not surfaced in the UI.
- **`fsapfsinfo` still takes the FileVault secret on argv** (`-p`/`-r`, visible
  via `ps`); `fsapfscat` already reads it from stdin. The fix is a vendored
  libyal patch.
- **Deeper multi-host correlation** — `CorrelationEngine` v1 covers shared IOC /
  pivoting source IP / reused account across ≥ 2 hosts; attack-path stitching
  could extend it.
- **In-app PDF for the examiner report was deliberately dropped** in favour of
  print-ready HTML (browser → Print → Save as PDF); revisit only if a
  hash-stable, canonical PDF is ever needed for legal weight. The
  *chain-of-custody* report **is** a real paginated PDF (`CoCPDFRenderer` —
  CoreText + `CGPDFContext`, no WebKit).
