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
entitlements. Released so far: **v0.1.0-beta.1, v0.1.0-beta.2, v0.1.0-beta.3,
v0.1.0-beta.4**.
Per-release notes live in `docs/releases/`; keep `CHANGELOG.md` updated.

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
| `StrataTSK` | Vendored TSK binaries, `tsk_loaddb` → SQLite (read via GRDB), `icat` extraction, KAPE source classification, loose-folder walk (`KapeFolderIngestor`). **APFS (macOS) does NOT go through `tsk_loaddb`** — TSK 4.15's APFS parser **aborts (SIGABRT in `APFSJObject`)** on real macOS volumes (confirmed on a macOS-27 E01); instead `build-tsk.sh` vendors libyal's **`fsapfsinfo`** (`libfsapfs`) + **`ewfexport`** + a custom **`fsapfscat`** (`scripts/fsapfscat.c`, statically linked to libfsapfs). The macOS ingest path (`FsApfsIngestor`, `.ingestionCrashed` fallback → `EvidenceKind.apfs`): `ewfexport` (E01→raw, or use raw directly) → `fsapfsinfo -f <i> -H -B` per volume → `BodyfileParser` → `FileEntry` tree + MACB timeline (no `tsk.db`; persisted as `apfsfiles/apfsvolumes.json`). **File content** is read on demand by `FsApfsExtractor` (shells `fsapfscat -o <off> -f <vol> <raw> <path>`, the `icat` analogue), wired into `parseMac` + `parseBrowserHistory` + `parseUnifiedLog` so the macOS analyzers run on APFS images. `fsapfscat -x <name>` also dumps a file's **extended attribute** (used to recover the `com.apple.metadata:kMDItemWhereFroms` download-provenance xattr → `FsApfsExtractor.extract(attribute:)`); rc 3 = attribute absent. **FileVault:** both `fsapfsinfo` (metadata) and `fsapfscat` (content) take `-p`/`-r`; ingest threads a `FileVaultCredential` (held **in memory only — never persisted**) through both. An encrypted volume that reads empty is surfaced as an `ApfsLockedVolume` instead of aborting ingest; `AppModel` then prompts via `FileVaultUnlockSheet` (auto after ingest, or Tools ▸ Unlock FileVault Volume), re-ingests, and re-runs the macOS/browser/unified-log parsers. *(FileVault path not yet validated against a real encrypted image.)* *Sealed System volume files live in a snapshot → libfsapfs reads 0 bytes; Data-volume artifacts are fine. `fsapfscat` bundling (Xcode Copy-Files) is a manual step.* |
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
| `StrataAnalysis` | `Analyzer` protocol, `AnalysisEngine`, **61 analyzers**, IOC matcher, lateral graph, `CorrelationEngine` (case-wide multi-host: shared IOC / pivoting source IP / reused account across ≥2 hosts) |
| `StrataSearch` | `SearchEngine` — pure cross-artifact global search (files/events/registry/timeline/findings → ranked `SearchHit`); drives the **Search** tab |
| `StrataMac` | macOS triage: `LaunchItemParser` (launchd plists → `LaunchItemEntry`) + `MacPersistenceAnalyzer` (T1543); `MacPersistenceParser` (non-launchd sweep — cron, site-local `periodic`, `emond` rules, login/logout hooks, `rc` scripts, `.mobileconfig`/Managed Preferences → `MacPersistenceItem`, `StrataCore`) + `MacPersistenceSweepAnalyzer` (T1546.014/T1037.002/T1053.003/T1037.004); `QuarantineParser` (LaunchServices quarantine SQLite → `QuarantineEvent`) + `MacQuarantineAnalyzer` (T1204/T1105); `MacHostInfoParser` (SystemVersion/SystemConfiguration `preferences`/dslocal users → `MacHostInfo`, the macOS host-profile source, `StrataCore`). `TCCParser` / `KnowledgeCParser` (SQLite via GRDB → `TCCAccess` / `KnowledgeEntry`) + `TCCAnalyzer` (sensitive grants to non-Apple clients — T1113/T1125/T1123/T1056.001/…) + `KnowledgeCAnalyzer` (RMM/remote-access app in active use — T1219); `MacRecentItemParser` (`.sfl`/`.sfl2`/`.sfl3` → `MacRecentItem`) + `MacRecentItemsAnalyzer` (remote-server connections T1021.*, staging-path / risky-extension recent items T1204.002); `MacSecurityParser` (Gatekeeper/syspolicyd, XProtect, XProtect Remediator, MRT, `install.log` → `MacSecurityEvent`) + `MacSecurityAnalyzer` (malware detect/remediate T1204.002, allow-after-block trust override + repeated policy blocks T1553.001, control-disabled T1562.001); `MacKextParser` (kext `Info.plist` + `/Library/SystemExtensions/db.plist` → `MacKextEntry`) + `MacKextAnalyzer` (third-party kernel/system extension — T1547.006, high for a `.kext`/kernel, medium for a user-space sysext); `BTMParser` (the `*.btm` Background Task Management store — an NSKeyedArchiver graph decoded via `StrataCore/BinaryPlist`, a UID-aware `bplist00` reader; walked leniently by ivar name → `MacBackgroundItem`) + `MacBackgroundItemAnalyzer` (non-Apple login item/agent/daemon — T1547.015, high in a staging path); `MessagesParser` (the `chat.db` Messages store via GRDB → `MessageEntry`, copy-to-scratch + WAL like browser history, with `attributedBody` text recovered via `BinaryPlist`) + `MacMessagesAnalyzer` (suspicious links in messages — T1566.002 received / T1204.001 sent; spliced onto the timeline as `TimelineSource.messages`); `MailParser` (the Mail `Envelope Index` SQLite DB via GRDB → `MailMessageEntry`: sender/subject/recipients/dates/mailbox, copy-to-scratch + WAL like Messages; bodies live in `.emlx` and aren't parsed) + `MacMailAnalyzer` (suspicious inbound mail — raw-IP sender / suspicious subject link, T1566.002; `TimelineSource.mail`); `MacNetworkParser` (one lenient parser over the network/device plists → `MacNetworkItem`: known Wi-Fi networks (`airport.preferences` + `wifi.known-networks`), DHCP leases (`dhcpclient/leases`), Bluetooth `DeviceCache`, Time Machine `Destinations`, lockdown iOS pairings) + `MacNetworkAnalyzer` (Time Machine backup to a network destination — T1074, high on a raw IP; `TimelineSource.network`); `QuickLookParser` (the QuickLook thumbnail `index.sqlite` via GRDB → `MacActivityItem`: files *previewed*, even if since deleted) + Trash discovery (a file-tree filter over `/.Trash`/`/.Trashes` → `MacActivityItem`) + `MacActivityAnalyzer` (trashed payload — risky-extension file in the Trash, T1070.004; `TimelineSource.userActivity`); `DocumentRevisionsParser` (the Versions store `/.DocumentRevisions-V100/db-V1/db.sqlite` via GRDB → `MacDocumentVersion`: per-document saved generations = edit timeline + recoverable prior versions; context-only, no analyzer; `TimelineSource.docRevisions`); `NotificationParser` (the Notification Center `db2/db` SQLite store under `group.com.apple.usernoted`/legacy `com.apple.notificationcenter` via GRDB → `MacNotification`: app bundle id (side lookup on `app`) + title/body recovered from the per-record `data` bplist via `BinaryPlist` + `CFAbsoluteTime` delivered date; corroborates app activity + can preserve message previews / 2FA codes / phishing content; context-only, no analyzer; `TimelineSource.notifications`); `PowerlogParser` (the powerd analytics `CurrentPowerlog.PLSQL` SQLite store under `/private/var/db/powerlog/` via GRDB → `PowerlogEntry`: process-execution records (PID→name→bundle from `PLPROCESSMONITORAGENT_…_PROCESSID`), app launch/exit lifecycle, the frontmost app, and per-process network volume — one of the few macOS artifacts giving true **process-execution timing with PIDs**, surviving independently of the unified log; **Unix-epoch** times corrected by the `PLSTORAGEOPERATOR_…_TIMEOFFSET` `system` offset (APOLLO's `timestamp + system`), every table feature-detected + null-tolerant against version drift; `TimelineSource.powerlog`) + `PowerlogAnalyzer` (offensive/dual-use tool execution T1059, remote-access/RMM execution T1219 — reusing `KnowledgeCAnalyzer.remoteAccessHints`, osascript AppleScript/JXA T1059.002; aggregated per tool, low-noise — catches headless tooling KnowledgeC's GUI-focus view misses). `MacConfigParser` (a curated sweep of the security-posture preference files no other parser covers, via `PropertyListSerialization` → `MacConfigSetting`: firewall `com.apple.alf` (globalstate/logging/stealth), screen-lock `com.apple.screensaver` askForPassword (per-user, ByHost-aware, absent-key = *undetermined* not insecure), software-update `com.apple.SoftwareUpdate`/`commerce`, Gatekeeper master switch `SystemPolicy-prefs.plist`, **remote-service enablement** from the launchd `com.apple.xpc.launchd/disabled.plist` **inverted-boolean** overrides (`disabled==false` ⇒ ENABLED — SSH/Screen Sharing/ARD/Apple Events/SMB/AFP; also the legacy nested `overrides.plist`), login-window auto-login/guest/`HiddenUsersList`, and ARD `com.apple.RemoteManagement`; `kcpassword` + `com.apple.VNCSettings.txt` are reported by **presence only — the stored credential is never decoded into the case**; no timeline splice, static config like WMI) + `MacConfigAnalyzer` (one finding per flagged setting — weakened defenses T1562.001/.004, enabled remote services T1021.001/.002/.004/.005, auto-login/guest T1078, hidden accounts T1564.002; the per-setting risk/ATT&CK lives in the parser, the analyzer is the projection). `WhereFromsParser` (`StrataCore`, pure — decodes the `com.apple.metadata:kMDItemWhereFroms` xattr bytes, a bplist array of `[download URL, referrer]`, via `BinaryPlist` → `MacWhereFrom`: a file's **download provenance**, surviving even when the quarantine flag was stripped; the bytes come from `fsapfscat -x` on **APFS** images only — loose collections strip xattrs; candidate files are download-likely — the Downloads/Desktop/Documents landing zones + dmg/pkg/iso elsewhere, **excluding `/Library/` and bundle internals** — capped at 2000 per host to bound the one-xattr-read-per-file cost (validated end-to-end on a real APFS E01; needs `scripts/build-tsk.sh` + an Xcode rebuild to re-bundle `fsapfscat`); no timeline splice) + `MacWhereFromsAnalyzer` (download from a **raw IP** T1105 high, or a **paste/anon-share/tunnel** host T1102 medium). `MacInstallHistoryParser` (the software-install record `InstallHistory.plist` (an **array** of events) + PackageKit receipts `/private/var/db/receipts/<id>.plist` (one **dict** each), via `PropertyListSerialization` → `MacInstallEntry`: displayName/version/date/processName/packageIdentifiers/contentType + receipt PackageFileName/InstallPrefixPath — the canonical structured "what software/OS/profile was installed, when, by which process" record complementing the verbose `install.log` stream; `TimelineSource.install`, `.born`) + `MacInstallAnalyzer` (low-noise: a package whose recorded install *process* is a scripting interpreter/network tool rather than the install daemons — programmatic install — T1059, and an installed package whose name/bundle-id matches an **offensive tool** T1588.002 or **RMM/remote-access** product T1219; note the package *origin* isn't in install records — `PackageFileName` is a basename, `InstallPrefixPath` is the destination — so staging provenance is left to the quarantine/FSEvents analyzers). `FSEventsParser` (`StrataCore`) — pure-Swift decode of the `/.fseventsd/` change journal (gzip → DLS v1/v2 pages → `FSEventRecord`: path + coalesced change flags + monotonic event ID, **no per-record timestamp** so **no timeline splice**, like the WMI carve) + `FSEventsAnalyzer` (created-then-removed payloads T1070.004, launchd-dir writes T1543). Discovered + parsed by `AppModel.parseMac()` (FSEvents inflated + decoded **off-main**). **`.macos` OSFamily** detected from APFS/HFS+ fs-type (or a Mac-marker file-tree sniff); dedicated **Launch Items** + **Quarantine** + **Persistence** + **FSEvents** + **TCC** + **KnowledgeC** + **Recent Items** + **macOS Security** + **Unified Log** + **Carved Files** + **Extensions** + **Background Items** + **Messages** + **Mail** + **Network & Devices** + **QuickLook & Trash** + **Document Versions** + **Notifications** + **Powerlog** + **Configuration** + **Installs** + **Download Origins** tabs gated on it (macOS; iOS drills exist only through KnowledgeC — the newer macOS artifact tabs are macOS-only for now), plus the Overview host card via `HostProfile.derive(fromMac:)`. Findings also surface in the cross-platform Kill-Chain/Findings views |
| `StrataCTI` | Tiered CTI enrichment (NSRL → MISP/OpenCTI → VirusTotal). `EnrichmentEngine` cascade (short-circuits on first definitive verdict), `EnrichmentVerdict` (provenance: tier/source/score/ref), actor `EnrichmentCache`, `CTIProvider` protocol; providers `NSRLProvider` (local hash set), `VirusTotalProvider` (v3), `MISPProvider` (restSearch), `OpenCTIProvider` (GraphQL) — each a pure decoder + injectable transport, all opt-in; `KeychainCredentialStore` (SecItem) holds base URL + token; `CTIConfiguration` (UserDefaults) holds the on/off flags + NSRL path. Driven by `AppModel.enrichIndicators()` → `enrichment.json` + custody `.enrichmentPerformed` |
| `StrataApp` | SwiftUI app. `AppModel` (the store), `CaseStore` (.strata bundle layout), `CaseLibrary`, `RecentCases`, `Views/` (macOS) + `Views/iOS/` |

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

## Current status (built so far)

Ingestion (E01/VHD/raw + loose KAPE folders), file tree (volume-grouped, deleted
& slack toggles), MACB timeline (histogram drag-select, gap analysis), EVTX +
registry + prefetch + Amcache/Shimcache + LNK + JumpList + USN-journal + SRUM + browser-history + `$MFT` + WMI-persistence parsing → host profile, 61 ATT&CK analyzers → kill chain, IOC matching,
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
os-release/hostname/passwd → Linux host profile fallback; **SSH trust +
privilege** (authorized_keys/known_hosts/sshd_config/sudoers/group/shadow,
rotated `.gz` auth logs decompressed inline); 3 Linux sources on the
timeline; AuthLog/ShellHistory/LinuxPersistence/**LinuxAccess** analyzers
(SSH brute force incl. btmp-only + success-after-burst, reverse shells,
download-pipe-exec, history tampering, @reboot cron, staging-path services,
**backdoor SSH keys, PermitRootLogin/PermitEmptyPasswords, UID-0/passwordless
accounts, NOPASSWD sudo, docker-group root-equiv**); "Auth & Logins" /
"Shell History" / "Linux Persistence" / "Accounts & SSH" tabs + iOS drills.
Works for ext images via TSK *and* loose UAC-style collections.
**Web server access logs** (nginx/apache CLF+Combined → exploitation/webshell/
scanner analyzer), **package history** (dpkg/apt/yum/dnf → install-timeline +
offensive-tool-install analyzer), an **expanded persistence sweep** (systemd
timers, ld.so.preload, XDG autostart, rc.local/init.d, shell-init), and the
**systemd journal** (`journald` binary parser → Journal tab + SSH/sudo auth
analyzer), **auditd / system-log / lastlog**, and **host IP recovery**
(`LinuxNetworkParser`: netplan + ifupdown static config + journal DHCP-lease →
Overview) round out the Linux layer. **Validated end-to-end against a real
Ubuntu ext4 VM image** (`vulnticketing.vmdk`): journald (1162 entries from an
8 MB journal), RFC3339 syslog, passwd, and DHCP-IP recovery (`192.168.5.160`)
all confirmed on real evidence; the first real run drove a remediation pass
(see CHANGELOG: per-bucket re-parse backfill, browser-history SQLite-magic
guard, timeline default sources, Overview IPs, column-sortable tables).
**Known limits:** classic syslog times have no TZ (treated as UTC) and the year
is inferred from file mtime; `.gz` auth/package rotations are read but other
`.gz` logs are skipped; journald **XZ/ZSTD**-compressed values are skipped
(only large MESSAGE bodies — short fields/messages are uncompressed); the
classic `lastlog` binary is parsed but modern Ubuntu (≥ glibc 2.40) migrated to
an empty `lastlog` + a `lastlog2.db` SQLite store we don't yet read (so last
logins come from wtmp on those hosts); plain bash history is undated (kept off
the timeline); utmp layout assumes the standard glibc 384-byte record.
Two betas shipped. A full 56-issue view review was completed and remediated.

## Roadmap

### Known pending / deferred
- ~~**True NTFS MACB for loose folders** + **`$FN` timestamps + timestomping**~~
  — **shipped** via `MftParser` (see roadmap #7 below). Remaining `$MFT` follow-up:
  the loose-folder *file tree* still uses collection-host times (only the
  *timeline* uses the `$MFT` $SI MACB); a large `$MFT` makes a large `mft.json`.
- **YARA scanning** (still pending — needs a vendored libyara). **Known-bad
  hash matching** has cores landed (`KnownBadHashProvider` CTI tier +
  `KnownBadHashAnalyzer`); config UI + pipeline wiring pending.
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
6. ~~**Global search** across files/events/registry/timeline.~~ — **shipped.**
   `StrataSearch/SearchEngine` ranks a query across files/events/registry/
   timeline/findings; cross-platform **Search** tab, off-main, kind-filterable.
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
8. ~~**Multi-host correlation** — case-wide lateral movement across hosts.~~ —
   **shipped (v1).** `CorrelationEngine` flags shared IOCs / pivoting source IPs
   / reused accounts across ≥2 hosts (run in `runAnalyzers`, surfaced in the
   "All" findings scope). Deeper attack-path stitching can extend it.

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
