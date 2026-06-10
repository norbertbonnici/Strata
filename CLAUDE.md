# CLAUDE.md

Operational context for working on **Strata**. Read this first.

## What Strata is

A native macOS DFIR triage tool (with an iOS companion viewer). It ingests a
**Windows or Linux** disk image (NTFS, ext2/3/4 - anything the vendored TSK
enumerates) or a loose collection folder (KAPE / UAC), enumerates the file
system, parses the OS's triage artifacts (Windows: event logs + registry hives
+ execution artifacts; Linux: auth logs, login records, shell history,
cron/systemd persistence), builds a MACB timeline, and surfaces attacker
activity through ATT&CK-tagged detection analyzers, a Cyber Kill Chain view,
an interactive lateral-movement graph, and IOC matching.

- **macOS app** = full pipeline (ingest + analyze). Non-sandboxed; reads raw
  disk images via Full Disk Access.
- **iOS app** = read-only viewer for already-built `.strata` cases. No ingest.
- Forensic file handling is a self-contained, vendored build of The Sleuth Kit +
  libyal (`libevtx`, `libregf`). **No Homebrew / runtime deps.**

## Build / run / test

This is an **Xcode project** (`Strata.xcodeproj`), one multiplatform target
`Strata`. `Package.swift` was removed; do not reintroduce SPM. New `.swift`
files under `Strata/` are auto-included (file-system-synchronized group).

```sh
# Vendored TSK toolchain (once; not checked in — Vendor/tsk/ is git-ignored):
scripts/build-tsk.sh                 # host arch (arm64). 'universal' for fat binaries.

# Build:
xcodebuild build -project Strata.xcodeproj -scheme Strata -destination 'platform=macOS' -configuration Debug
xcodebuild build -project Strata.xcodeproj -scheme Strata -destination 'generic/platform=iOS Simulator' -configuration Debug

# Test (Swift Testing; runs on macOS):
xcodebuild test -project Strata.xcodeproj -scheme Strata -destination 'platform=macOS' -only-testing:StrataTests
```

**Always build BOTH platforms after touching shared code** — iOS-only views are
`#if !os(macOS)` and won't compile-check in a macOS build (or vice-versa).

## Release (Developer ID + notarization)

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
entitlements. Released so far: **v0.1.0-beta.1, v0.1.0-beta.2**.
Per-release notes live in `docs/releases/`; keep `CHANGELOG.md` updated.

## Architecture (folders under `Strata/`)

| Module | Responsibility |
|--------|----------------|
| `StrataCore` | Value types: `FileEntry`, `TimelineEvent`, `EventLogRecord`, `RegistryValue`, `IOC`, `HostProfile`, `VolumeInfo`, case + kill-chain models |
| `StrataTSK` | Vendored TSK binaries, `tsk_loaddb` → SQLite (read via GRDB), `icat` extraction, KAPE source classification, loose-folder walk (`KapeFolderIngestor`) |
| `StrataEVTX` | Parse `.evtx` via `evtxexport` |
| `StrataRegistry` | Parse hives via `regfexport` |
| `StrataSCCA` | Parse Windows Prefetch (`.pf`) via `sccainfo` (libscca) |
| `StrataLNK` | Parse `.lnk` shortcuts via `lnkinfo` (liblnk) |
| `StrataJumpList` | Parse JumpLists - OLE via `olecfexport` (libolecf) + reused `lnkinfo` + a pure DestList decoder |
| `StrataCore` (USN) | Pure-Swift NTFS USN change-journal byte-parser (`UsnJournalParser`, `UsnRecord`) — no vendored tool; reads the `$Extend\$UsnJrnl:$J` ADS extracted via icat |
| `StrataCore` (MFT) | Pure-Swift NTFS `$MFT` byte-parser (`MftParser`, `MftEntry`, `MftNode` tree, `FileTime`) — no vendored tool; applies the USA fixup, decodes `$SI` + `$FN` MACB as **raw FILETIME** (`FileTime.precise` renders the full 100-ns string; `Date` is lossy), resolves paths from parent refs, and captures **resident `$DATA`** (small-file recovery). Enables timestomp detection ($SI vs $FN) and true loose-folder MACB. `$MFT` extracted via icat (images) / read in place (loose) |
| `StrataSRUM` | Parse the SRUM `SRUDB.dat` (ESE database) via `esedbexport` (libesedb); pure `SrumExportDecoder` (`StrataCore`) resolves the export TSV + SruDbIdMapTable foreign keys |
| `StrataBrowser` | Parse web-browser history — Chromium `History` + Firefox `places.sqlite` (both SQLite) read directly via GRDB (no vendored tool); `BrowserHistoryParser` (macOS) copies the DB to scratch + opens read-only; pure decoders on `BrowserHistoryEntry` (`StrataCore`) |
| `StrataTimeline` | MACB timeline + per-artifact timeline projections (15 sources) + gap/session analysis |
| `StrataCore` (WMI) | Pure-Swift carve of the WMI CIM repository `OBJECTS.DATA` (`WmiRepositoryParser`, `WmiPersistenceEntry`) — no full CIM parse; keyword-carves event-subscription persistence (bindings + WQL filter + command + script payloads), à la PyWMIPersistenceFinder. `OBJECTS.DATA` extracted via icat (images) / read in place (loose) |
| `StrataLinux` | Pure-Swift Linux artifact parsers (no vendored tool): `AuthLogParser` (syslog classic + RFC3339, year inference), `UtmpParser` (384-byte wtmp/btmp records), `ShellHistoryParser` (bash + zsh extended), `LinuxPersistenceParser` (crontabs + systemd units), `LinuxHostInfoParser` (os-release/hostname/passwd/timezone) |
| `StrataAnalysis` | `Analyzer` protocol, `AnalysisEngine`, **28 analyzers**, IOC matcher, lateral graph |
| `StrataApp` | SwiftUI app. `AppModel` (the store), `CaseStore` (.strata bundle layout), `CaseLibrary`, `RecentCases`, `Views/` (macOS) + `Views/iOS/` |

`.strata` case bundle = a directory: `case.json`, `hosts.json`, `iocs.json`,
`custody.json`, `annotations.json`, `notes.json`,
`hosts/<uuid>/{tsk.db, events.json, registry.json, findings.json, iocmatches.json}`.
Registered as a **package UTI** (`com.bonnicilabs.strata-case`) so Finder/Files
treat it as one item. The macOS-only ingest code is gated `#if os(macOS)`.

## Conventions & gotchas (hard-won — don't relearn these)

- **Per-OS tab hiding.** Artifact tabs that can't apply to the evidence's OS are
  hidden: each `SidebarItem` has an `osFamily` (`.windows` for EVTX/registry/
  prefetch/amcache/shimcache/LNK/JumpList/USN/SRUM/MFT/WMI, `.linux` for the
  auth/shell/persistence tabs, `nil` = cross-platform incl. **Browser History**,
  always shown). `OSFamily.detect` reads each host's volume **fs-type** (NTFS ⇒
  Windows, ext ⇒ Linux; FAT is ignored — both OSes carry a FAT ESP), falling
  back to a file-tree sniff for loose folders; stored on `EvidenceState
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

## Current status (built so far)

Ingestion (E01/VHD/raw + loose KAPE folders), file tree (volume-grouped, deleted
& slack toggles), MACB timeline (histogram drag-select, gap analysis), EVTX +
registry + prefetch + Amcache/Shimcache + LNK + JumpList + USN-journal + SRUM + browser-history + `$MFT` + WMI-persistence parsing → host profile, 28 ATT&CK analyzers → kill chain, IOC matching,
interactive lateral graph, multi-host `.strata` cases, iOS viewer, Case
Library / iCloud-Drive sync, case reporting & export (HTML/Markdown examiner
report + CSV/JSON data exports; per-endpoint selection + report severity filter),
registry explorer (regedit-style hive→key→value browser, macOS + iOS),
chain of custody & evidence integrity (acquisition metadata, source hashes +
verification, append-only custody ledger, formal PDF CoC report),
super-timeline (15 artifact sources incl. registry/prefetch/LNK/JumpList/
amcache/shimcache) + analyst annotations (bookmarks/tags, case narrative,
report-integrated),
**ext2/3/4 + basic Linux triage** (TSK enumerates ext natively - no toolchain
change; `StrataLinux` parses auth.log/secure (classic-syslog year inference +
RFC3339), wtmp/btmp, bash/zsh history, crontabs + systemd units, and
os-release/hostname/passwd → Linux host profile fallback; 3 Linux sources on
the timeline; AuthLog/ShellHistory/LinuxPersistence analyzers (SSH brute
force incl. btmp-only + success-after-burst, reverse shells, download-pipe-
exec, history tampering, @reboot cron, staging-path services); "Auth &
Logins" / "Shell History" / "Linux Persistence" tabs + iOS drills. Works for
ext images via TSK *and* loose UAC-style collections. **Known limits:**
classic syslog times have no TZ (treated as UTC) and the year is inferred
from file mtime; `.gz` rotations skipped; journald/lastlog not parsed; plain
bash history is undated (kept off the timeline); utmp layout assumes the
standard glibc 384-byte record; not yet E2E-validated against a real ext4
image - parsers validated against synthetic fixtures).
Two betas shipped. A full 56-issue view review was completed and remediated.

## Roadmap

### Known pending / deferred
- ~~**True NTFS MACB for loose folders** + **`$FN` timestamps + timestomping**~~
  — **shipped** via `MftParser` (see roadmap #7 below). Remaining `$MFT` follow-up:
  the loose-folder *file tree* still uses collection-host times (only the
  *timeline* uses the `$MFT` $SI MACB); a large `$MFT` makes a large `mft.json`.
- **YARA scanning + known-bad hash matching.**
- **Universal/Intel support** (currently arm64-only; `build-tsk.sh universal`).
- **iOS distribution** (TestFlight/App Store) — currently build-from-source.
- **Dynamic Type** on the iOS layer (deferred to preserve mockup fidelity).
- Phase-D hardening for iCloud: `NSFileCoordinator` + robust package
  download-completion (needs on-device validation).

### Planned roadmap (owner-approved, roughly prioritized)
1. ~~**Case reporting & export**~~ — **shipped.** Examiner report (HTML +
   Markdown) of host profile + kill chain + findings + timeline excerpts; CSV/JSON
   export of timeline / findings / IOC matches. Endpoint (host) selection + a
   report severity filter; each export is a timestamped folder with a `README.txt`.
   Pure, cross-platform `StrataReport/` module; macOS `ExportSheet` (Tools ▸
   Export…, ⇧⌘E). **In-app PDF was intentionally dropped** in favour of
   print-ready HTML (open in a browser → Print → Save as PDF) — revisit only if a
   hash-stable, canonical PDF is needed for legal weight.
2. ~~**Chain-of-custody & evidence integrity**~~ — **shipped.** Per-evidence
   **acquisition metadata** (`AcquisitionInfo`: examiner, tool, method, date,
   case #, media serial; auto-seeded from the E01 header) + **source hashes**
   (`SourceHash` with origin embedded/computed + verification status) ride on
   `Evidence` in `hosts.json`; the append-only **custody ledger**
   (`CustodyEvent`, every acquire/add/analyse/hash/verify/enrich/export with
   who + when) persists in its own `custody.json` so host-list rewrites can't
   truncate it — all appends funnel through `AppModel.appendCustody`. E01
   embedded MD5/SHA-1 are read via the vendored `ewfinfo` (DFXML + text
   fallback parsers in `StrataTSK/EWFInfo.swift`) and re-checked via
   `ewfverify` — never rehash the image; raw/VHD get on-demand cancellable
   streaming MD5+SHA-256 (`StrataCore/Hashing.swift`). The formal **CoC report
   is a paginated PDF** (`CoCPDFRenderer`: pure CoreText + `CGPDFContext`, no
   WebKit — headless, cross-platform, repeated table headers + "Page N of M"
   footers) with HTML/Markdown mirrors from the same `CoCReportModel`, plus a
   custody-log CSV/JSON, all in the Export sheet. macOS **Custody** sidebar tab
   (`ChainOfCustodyView` + `AcquisitionEditorSheet`); iOS read-only drill.
   This is the legal-weight record, separate from the CTI enrichment audit log
   (which feeds it via `.enrichmentPerformed`). **Known limits:** loose KAPE
   folders get no source hash (no single image to hash); the custody ledger is
   tamper-evident only by being a separate file (no hash chaining).
3. ~~**Registry explorer**~~ — **shipped.** Interactive hive → key → value tree
   browser (SYSTEM/SOFTWARE/SAM/SECURITY/NTUSER/UsrClass…) with key last-write
   times, typed value decoding (REG_SZ/DWORD/BINARY/MULTI_SZ…), and search. Pure
   `RegistryNode.buildTree` (`StrataCore`) groups the already-parsed
   `RegistryValue` set by hive the way `FileNode.buildTree` groups by volume;
   regedit-style two-pane macOS `RegistryView` (key OutlineGroup + value table,
   search flips the left pane to a flat match list) + iOS `RegistryDrillView`
   (breadcrumb drill). Shared display helpers (`typeBadge`/`decodedData`/
   `matches`) live on `RegistryValue`. **Known v1 limit:** hives sharing a label
   (several users' `NTUSER`) merge under one node, since `hive` is a logical label.
4. **More artifact parsers/analyzers** (each plugs into the `Analyzer` protocol):
   - ~~**Prefetch**~~ — **shipped.** `StrataSCCA` parses `.pf` via libscca's
     `sccainfo` (added to `build-tsk.sh`; needs a `pkg-config` shim since the
     newer libscca configure hard-requires it). `PrefetchEntry` (`StrataCore`)
     persisted per host as `prefetch.json`; `AppModel.parsePrefetch()` mirrors
     `parseEventLogs` (icat-extract for images, in-place for loose folders);
     `PrefetchAnalyzer` flags suspicious-path + LOLBin execution (T1204.002 /
     T1218 / T1059). macOS `PrefetchView` + iOS `PrefetchDrillView`.
   - ~~**Amcache/Shimcache**~~ — **shipped.** Both reuse the vendored
     `regfexport` (no `build-tsk.sh` change). Amcache: `Amcache.hve` added to
     `discoverHives` (label `AMCACHE`); pure `AmcacheEntry.reconstruct(from:
     [RegistryValue])` maps `InventoryApplicationFile` + legacy `Root\File`
     keys, recovering SHA-1 from `FileId`. Shimcache: pure `ShimcacheParser`
     byte-decodes the SYSTEM `AppCompatCache` blob (already captured in
     `RegistryValue.data` as hex), version-aware (Win10/8.1/8/7). Both: per-host
     `amcache.json`/`shimcache.json`, derived in `parseRegistry`, `AmcacheAnalyzer`
     + `ShimcacheAnalyzer` (suspicious-path gated; **presence, not execution**),
     macOS views + iOS drills. **Shimcache decoder validated against synthetic
     fixtures only** — confirm against a real SYSTEM hive.
   - ~~**LNK shortcuts**~~ — **shipped.** `StrataLNK` parses `.lnk` via liblnk's
     `lnkinfo` (added to `build-tsk.sh` + the app Copy-Files phase). `LnkEntry`
     (`StrataCore`); `LnkParser` shells out, splits each line on the first `": "`
     and **un-doubles** the backslashes lnkinfo escapes. `parseLnk()` mirrors
     `parseEventLogs` (icat-extract / loose read); per-host `lnk.json`;
     `LnkAnalyzer` flags shortcuts carrying command-line args (lure) + targets in
     suspicious paths. macOS `LnkView` + iOS `LnkDrillView`. Parser validated
     against **real lnkinfo output** (crafted MS-SHLLINK sample).
   - ~~**JumpLists**~~ — **shipped.** `StrataJumpList`. AutomaticDestinations
     (`*.automaticDestinations-ms`) are OLE compound files: `olecfexport`
     (libolecf, added to `build-tsk.sh` + Copy-Files; no pkg-config shim - 2024
     tag) cracks them to `<base>.export/<stream>/StreamData.bin`; each hex stream
     is fed to the reused `lnkinfo`/`LnkParser`, and the `DestList` stream is
     byte-decoded by a pure version-aware `DestListParser` (last-access FILETIME,
     access count, NetBIOS host, pin), joined to its LNK by entry ID.
     CustomDestinations are carved by `ShellLinkCarver` (scan for the SHLLINK
     signature) → `lnkinfo`. `JumpListEntry`/`JumpListAppID` (`StrataCore`);
     per-host `jumplist.json`; `JumpListAnalyzer` flags suspicious-path targets +
     **RDP (mstsc) destinations as lateral movement (T1021.001)**. macOS
     `JumpListView` + iOS `JumpListDrillView`. **DestList decoder validated
     against synthetic fixtures + a hand-built OLE container** (olecfexport's
     `StreamData.bin`-per-dir output confirmed) — confirm against a real jumplist.
   - ~~**USN journal**~~ — **shipped.** Pure-Swift byte-parser (no vendored tool):
     `UsnJournalParser` (`StrataCore`) decodes `USN_RECORD` V2/V3/V4 from the
     `$Extend\$UsnJrnl:$J` sparse named ADS, skipping the leading sparse-zero gap
     (skip-forward to the next non-zero 8-byte boundary — a naive stop-on-zero
     would truncate the parse). `$J` is extracted with icat's `meta-type-id` ADS
     address form + `-h` (suppress sparse holes) via new
     `TSKDatabase.fetchAttrExtractInfo` + `TSKFileExtractor.extractStream`;
     `parseUsn()` reads the (100 MB+) stream and parses it **off-main**
     (`Task.detached`); per-host `usn.json`; spliced onto the timeline
     (`TimelineSource.usn`). `UsnAnalyzer` correlates 3 high-signal sequences:
     created-then-deleted executable (T1070.004), rename-into-executable
     (T1036.003), mass-deletion burst (T1070.004). macOS `UsnView` + iOS
     `UsnDrillView`. **Parser validated against synthetic V2/V3 fixtures only** —
     real `$J` parse-validation is pending a mounted source image.
   - ~~**SRUM**~~ — **shipped.** `StrataSRUM`. `SRUDB.dat` is an ESE database
     (a B-tree — too complex to byte-parse), so we vendor libesedb's `esedbexport`
     (added to `build-tsk.sh` TOOLS + the app Copy-Files phase; 2024 tag, asset is
     `-experimental-` not `-alpha-`, no pkg-config shim) which cracks each table to
     a headered TSV under `<base>.export/`. The actor `SrumParser` shells out and
     hands the table files to the pure, cross-platform `SrumExportDecoder`
     (`StrataCore`), which resolves the **SruDbIdMapTable** foreign keys (IdType 3
     ⇒ binary SID, else UTF-16LE app path), parses the libfdatetime **CTIME**
     timestamps esedbexport renders for the OLE-date `TimeStamp` column, and
     unifies the three high-value provider tables (Network Data Usage, Application
     Resource Usage, Network Connectivity) into `SrumEntry`. `SRUDB.dat` is a plain
     file (icat `extract`, not the `$J` ADS path); per-host `srum.json`; spliced
     onto the timeline (`TimelineSource.srum`). `SrumAnalyzer` flags execution from
     a suspicious path (T1204.002) + outbound network volume from a suspicious-path
     app (T1048). macOS `SrumView` + iOS `SrumDrillView`. **Decoder validated
     against synthetic esedbexport-format fixtures** (TSV/CTIME/IdBlob, all
     primary-source verified) — real `esedbexport`-on-`SRUDB.dat` end-to-end is
     pending a mounted source image.
   - ~~**Browser history**~~ — **shipped.** `StrataBrowser`. Chromium-family
     (`History`) and Firefox (`places.sqlite`) history are SQLite, so there is no
     vendored tool — `BrowserHistoryParser` (macOS) reads them with GRDB (the lib
     already backing `TSKDatabase`). It copies the DB (and its `-wal`/`-shm`
     sidecars) to a private scratch dir and opens that copy **read-write** — the
     evidence file is never opened by SQLite. Read-write is required: Chrome's
     `History` and Firefox's `places.sqlite` are WAL-mode, and a *read-only* open
     of a WAL DB fails outright ("unable to open database file") because it can't
     create the `-shm` wal-index; copying the `-wal` also recovers transactions
     still pending there (the disk-image path extracts the sidecars too). One row
     per distinct URL (visits) + Chromium downloads → `BrowserHistoryEntry`
     (`StrataCore`, with pure chrome/firefox-epoch + browser/profile/host
     decoders); per-host `browserhistory.json`; spliced onto the timeline
     (`TimelineSource.browser`). `BrowserHistoryAnalyzer` flags suspicious
     downloads (risky ext / suspicious host, T1105), activity to
     paste/anon-share/raw-IP infrastructure (T1102), and offensive-tool names in
     URLs/targets (T1588.002). macOS `BrowserHistoryView` + iOS
     `BrowserHistoryDrillView`. **Parser validated end-to-end** against synthetic
     Chromium/Firefox SQLite fixtures (incl. a WAL-mode regression that reproduces
     the read-only-open failure) built in-test via the SQLite3 C API. **Known v1
     limits:** one row per URL (not per individual visit); Firefox downloads
     (stored as `moz_annos`) not parsed.
   - ~~**WMI persistence**~~ — **shipped.** `StrataCore` `WmiRepositoryParser` is a
     pure-Swift **carve** of the WMI CIM repository (`OBJECTS.DATA` under
     `\Windows\System32\wbem\Repository\`). A full CIM parse (pages + `INDEX.BTR`
     B-tree) is too involved, so — like FireEye's PyWMIPersistenceFinder — it
     keyword-carves the high-signal strings of **event-subscription persistence**
     (T1546.003): `__FilterToConsumerBinding` references (`<Type>EventConsumer.Name="..."`
     + `__EventFilter.Name="..."`), the filter WQL (`<name>\0\0<query>`), the
     `CommandLineEventConsumer` command (`marker\0<command>`), and `ActiveScriptEventConsumer`
     script payloads (a printable-run scan gated on script-execution indicators,
     so an unbound `Invoke-Mimikatz` consumer is caught too). `WmiPersistenceEntry`
     (`.binding` / `.scriptConsumer`); per-host `wmi.json`; **no timeline splice**
     (carve yields no per-object timestamps). `WmiAnalyzer` flags every non-built-in
     binding (medium; high on a script consumer or a suspicious command/WQL token)
     and carved script payloads (high), all T1546.003 / `.installation`. macOS
     `WmiView` + iOS `WmiDrillView`; built-in BVT/SCM subscriptions are flagged and
     hidden by default. **Validated against a real repository** (flare-wmi's
     `wmikatz` sample: the BVT binding + WQL + `cscript` command + the
     `Invoke-Mimikatz` PowerShell payload all extracted). **Known limits:** carve
     is heuristic (bindings in unallocated repo space, or consumers whose binding
     wasn't carved, may be missed/partial); built-in subscription names are
     de-emphasised but the canonical PoC `BVTConsumer` is among them.
5. ~~**Super-timeline + tagging/notes**~~ — **shipped.** The timeline now
   unifies **12 sources**: the existing FS MACB / EVTX / USN / SRUM / browser /
   `$MFT` plus **registry key writes** (deduped to one event per key, keyed per
   hive *file* so two users' NTUSER never merge; spliced macOS-only like the FS
   MACB - phone-hostile row counts), **prefetch runs** (one event per recorded
   run time), **shimcache/amcache presence**, **LNK target MACs**, and
   **JumpList DestList accesses** - all folded in at load and re-spliced after
   parse (`removeAll(source:)` + append, the evtx pattern; see
   `TimelineBuilder`). The source chips became a checkable **Sources menu**
   (12 don't fit inline). **Tagging/notes:** `Annotation` (closed `AnalystTag`
   set - malicious/suspicious/benign/follow-up - + free note, carrying a
   denormalized title/timestamp/source snapshot) and `CaseNotes` (free-form
   case narrative) persist **case-wide** (`annotations.json` / `notes.json`,
   custody-ledger style, so per-host re-parses can't touch them). Targets key
   off **stable identity**: `Finding.id` / `TimelineEvent.stableKey`
   (content-derived - the parse-time `TimelineEvent.id` UUID is rebuilt every
   load). Bookmark from the timeline (row context menu, star column,
   "Bookmarked" filter) or the kill-chain inspector (star button); review in
   the new **Annotations** tab (narrative editor with debounced autosave,
   tag-filterable bookmark table, **Reveal in Timeline** pivot →
   `AppModel.timelinePivot` switches tab + zooms ±30 min); iOS gets a
   read-only Annotations drill. The examiner report gains **Analyst
   narrative** + **Bookmarked items** sections (MD + HTML), and annotations
   export as CSV/JSON. **Known limits:** a timeline bookmark's host
   attribution is the active scope at bookmark time (nil under "All");
   annotation editing is macOS-only; the narrative is plain text (rendered
   verbatim into the report).
6. **Global search** across files/events/registry/timeline.
7. ~~**`$MFT` / `$FN` parsing → timestomping detection**~~ — **shipped.**
   `StrataCore` `MftParser` is a pure-Swift `$MFT` byte-parser (no vendored tool,
   like the USN one): applies the update-sequence-array **fixup**, decodes the
   `$STANDARD_INFORMATION` + `$FILE_NAME` MACB sets, and resolves full paths from
   `$FN` parent refs (two-pass, cycle-guarded). `$MFT` is found by name (icat
   `extract` for images, read-in-place for loose), parsed off-main; per-host
   `mft.json`; the `$SI` MACB is spliced onto the timeline (`TimelineSource.mft`,
   **loose-only** — images already get those times from the TSK FS source).
   `MftAnalyzer` flags **possible timestomping** (T1070.006): an executable whose
   `$SI` creation predates its un-settable `$FN` creation by >1 day **and** whose
   `$SI` times are whole-second (the tool fingerprint that separates a stomp from
   a benign timestamp-preserving copy) — high in a staging path, else medium.
   The viewer is a **per-volume tree** (`MftNode.buildTree`, like `FileNode`):
   macOS `MftView` (`OutlineGroup`; `$SI`/`$FN` at full **100-ns** precision via
   `FileTime.precise`; resident `$DATA` hex + Save; "Anomalies only" filter) +
   iOS `MftDrillView` (breadcrumb tree + record detail). **Parser validated
   against real `$MFT` records** (libfsntfs corpus — incl. resident-data + 100-ns
   fixtures). **Known limits:** the loose-folder file *tree* still uses
   collection-host times (only the timeline uses `$MFT`); a huge `$MFT` → a large
   `mft.json` (same bracket as `events.json`); the `MftEntry` Codable schema is
   raw-FILETIME (an `mft.json` from the very first MFT build won't decode — just
   re-parse); detection is a heuristic — verify findings against a known-good copy.
8. **Multi-host correlation** — case-wide lateral movement across hosts.

### CTI enrichment (tiered hash/IOC lookup)
Goal: enrich case IOCs while **minimising VirusTotal API calls** and keeping data
in org control. Waterfall, short-circuiting on a definitive verdict:

    NSRL  →  MISP / OpenCTI  →  VirusTotal

- **NSRL** (local hash set): known-good filter. A hash in NSRL is benign → tag it
  and skip all downstream lookups. Doubles as file-tree noise reduction.
- **MISP / OpenCTI** (self-hosted, org-controlled → confidentiality-friendly):
  look up hash / IP / domain / URL. MISP via REST (`/attributes/restSearch`),
  OpenCTI via GraphQL. A hit records the verdict + source and stops the cascade.
- **VirusTotal** (third-party, rate-limited / paid): last resort, only for
  indicators unresolved above. Hash-only lookups by default.

Design principles:
- Per-instance config (base URL + API token) in **Keychain**; all CTI is
  **opt-in** and clearly labeled — evidence/IOCs leave the host only when enabled.
- **Cache** verdicts (per-case + global) to avoid repeat calls; back off on rate
  limits.
- Record **provenance** on every enrichment (which tier/source produced it).
- IPs / domains / URLs (no NSRL tier): cascade is MISP / OpenCTI → VT.
- Enrichment lookups are recorded in the per-case audit trail that feeds the
  Chain-of-custody feature (#2).
