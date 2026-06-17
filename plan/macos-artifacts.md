# macOS Artifact Plan

## Goal

Expand Strata's macOS artifact coverage without regressing older cases. Every new
artifact family should be an independent parse bucket so cases parsed by older
builds can backfill newly added data.

## Current Coverage

- LaunchAgents and LaunchDaemons
- LaunchServices quarantine database
- macOS host identity, users, and network interface plist data
- cron, periodic, emond, login/logout hooks, rc scripts, profiles, and managed preferences
- FSEvents
- user shell history
- TCC privacy databases
- KnowledgeC activity databases
- Unified Log tracev3

## Implementation Order

1. Recent Items / LSSharedFileList
   - Parse `.sfl`, `.sfl2`, `.sfl3`, and related plist stores.
   - Cache as `macrecentitems.json`.
   - Add timeline rows for dated recent apps, documents, servers, hosts, volumes, and favorites.
   - Status: **done.** Parser, `macrecentitems.json`, macOS view, and timeline rows shipped earlier; `MacRecentItemsAnalyzer` (registered in `AnalysisEngine.defaultAnalyzers`) now consumes `AnalysisContext.macRecentItems` and emits findings: recent remote-server connections (medium, T1021/.002/.004/.005 by scheme; high on a raw-IP target) and recent items in staging paths or with risky script/installer extensions (medium, T1204.002). Covered by `StrataTests/MacRecentItemsAnalyzerTests.swift`.

2. Safari
   - Parse `History.db`, download metadata, and session/tab state where available.
   - Reuse the existing browser-history model where possible; add Safari-specific fields only where needed.
   - Status: `History.db` visits were already supported; `Downloads.plist` download rows now feed the Browser History model.

3. Gatekeeper / XProtect / MRT
   - Parse assessment, malware-removal, and security-tool logs/reports.
   - Add detections for blocked/quarantined malware, repeated policy failures, and suspicious allow decisions.
   - Status: **done.** Durable Gatekeeper/syspolicyd, XProtect, XProtect Remediator, MRT, and relevant `install.log` rows parse into `macsecurity.json`, appear in a macOS Security tab, and splice dated rows into the timeline. `MacSecurityAnalyzer` (registered in `AnalysisEngine.defaultAnalyzers`) now consumes `AnalysisContext.macSecurityEvents` and emits findings: XProtect/MRT/XPR malware detections & remediations (high, T1204.002), trust override after a block — allow-after-block (high, T1553.001), security control disabled e.g. `spctl --master-disable` (high, T1562.001), and Gatekeeper/policy blocks of untrusted binaries (medium, escalating to high on repeated failures of the same binary, T1553.001). Covered by `StrataTests/MacSecurityAnalyzerTests.swift`.

4. Login / Background Items
   - Parse modern background-task-management and login-item stores.
   - Keep this separate from launchd so persistence views can distinguish user-approved background items from daemon plists.
   - Status: **done.** `BTMParser` (`StrataMac`) decodes the `*.btm` Background Task
     Management store. The `.btm` is an NSKeyedArchiver graph, so `StrataCore/
     BinaryPlist` (a pure, UID-aware `bplist00` reader) decodes it and the parser
     walks the object table leniently by ivar name → `MacBackgroundItem` (name /
     executable / bundle id / developer / team / type / disposition). Discovered/
     parsed in `AppModel.parseMac()`, cached as `backgrounditems.json`, surfaced in
     a **Background Items** tab (third-party-only filter). `MacBackgroundItemAnalyzer`
     flags non-Apple items — T1547.015, **high** when the executable is in a staging
     path. No timeline (no per-item timestamp). Covered by `StrataTests/BTMTests.swift`
     + `BinaryPlistTests.swift`. **Lenient/heuristic** (Apple-private classes vary by
     release); validate field recovery against a real `.btm`.

5. Network / Device Context
   - Known Wi-Fi networks, DHCP leases, Bluetooth devices, USB/iOS pairings, and Time Machine destinations.
   - **done.** `MacNetworkParser` (`StrataMac`) — one lenient parser over the
     network/device plists → `MacNetworkItem` (`StrataCore`, a unified
     kind/name/identifier/timestamp/detail model): known Wi-Fi networks (legacy
     `com.apple.airport.preferences.plist` `KnownNetworks` + modern
     `com.apple.wifi.known-networks.plist`), DHCP leases
     (`/private/var/db/dhcpclient/leases/*`), Bluetooth `DeviceCache`
     (`com.apple.Bluetooth.plist`), Time Machine `Destinations`
     (`com.apple.TimeMachine.plist`), and lockdown iOS pairings
     (`/var/db/lockdown/<UDID>.plist`). Parsed in `AppModel.parseMac()`, cached as
     `network.json`, timestamped items spliced onto the timeline
     (`TimelineSource.network`), surfaced in a **Network & Devices** tab.
     `MacNetworkAnalyzer` flags a Time Machine backup to a network destination
     (T1074, high on a raw IP). Covered by `StrataTests/MacNetworkTests.swift`.
     **Known limits:** plist `<date>` values decode directly, numeric dates are
     guessed CFAbsoluteTime/Unix by magnitude; USB **mass-storage** attachment
     history has no clean static plist on macOS (it lives in the unified log) —
     only iOS device pairings are covered here; validated against synthetic
     plists, not a real host.

## Messages

- **done.** `MessagesParser` (`StrataMac`) reads the Messages database
  (`~/Library/Messages/chat.db`) via GRDB, mirroring the browser-history path
  (copy-to-scratch + `-wal`/`-shm` sidecars, opened read-write — chat.db is
  WAL-mode). Modern rows keep the body in `attributedBody` (an
  NSAttributedString keyed archive) when `text` is NULL, recovered via
  `StrataCore/BinaryPlist`. `MessageEntry` (`StrataCore`) with the chat.db
  nanosecond/second CFAbsoluteTime decoder. Own `AppModel.parseMessages()` (in
  `parseArtifacts` + the post-FileVault re-parse), cached as `messages.json`,
  spliced onto the timeline (`TimelineSource.messages`), surfaced in a
  **Messages** tab. `MacMessagesAnalyzer` flags suspicious links — T1566.002
  (received / spearphishing link) vs T1204.001 (sent). Covered by
  `StrataTests/MessagesTests.swift`.
- **Mail — done.** `MailParser` (`StrataMac`) reads the Mail `Envelope Index`
  SQLite DB (`~/Library/Mail/V*/MailData/Envelope Index`) via GRDB (same
  copy-to-scratch + WAL path), joining `messages` → `subjects`/`addresses`/
  `mailboxes` for sender/subject/mailbox and aggregating `recipients`.
  `MailMessageEntry` (`StrataCore`, Unix-epoch dates). `AppModel.parseMail()`
  (in `runAllParsers` + post-FileVault), cached as `mail.json`, spliced onto the
  timeline (`TimelineSource.mail`), surfaced in a **Mail** tab. `MacMailAnalyzer`
  conservatively flags inbound mail with a raw-IP sender or a suspicious link in
  the subject (T1566.002). Covered by `StrataTests/MailTests.swift`. **Known
  limits:** message bodies + attachments (`.emlx`) aren't parsed; validated
  against the modern Envelope Index schema (Mail V5+) — older layouts degrade to
  an empty result.

## Kernel & System Extensions

- **done.** `MacKextParser` (`StrataMac`) inventories kernel extensions (each
  `Foo.kext/Contents/Info.plist` under `/Library/Extensions` or
  `/System/Library/Extensions`) and modern System Extensions (the
  `/Library/SystemExtensions/db.plist`, walked leniently for any `identifier`).
  `MacKextEntry` (`StrataCore`); discovered/parsed in `AppModel.parseMac()`,
  cached as `kexts.json`, surfaced in an **Extensions** tab (third-party-only
  filter). `MacKextAnalyzer` flags non-Apple extensions — T1547.006, **high** for
  a `.kext` (kernel code), **medium** for a user-space System Extension. No
  timeline (no per-item timestamp). Covered by `StrataTests/MacKextTests.swift`.

## User activity / deleted evidence (QuickLook + Trash)

- **done.** A unified `MacActivityItem` (`StrataCore`) collection:
  - **QuickLook** — `QuickLookParser` (`StrataMac`, GRDB) reads the thumbnail
    `index.sqlite` (under `…/com.apple.QuickLook.thumbnailcache/` or
    `~/Library/.../Quicklook/`): each `files` row is a file that was *previewed*
    (evidence it existed + was viewed, even if since deleted); `last_hit_date`
    (CFAbsoluteTime) + `hit_count` joined from `thumbnails` as a side lookup
    (robust to schema drift — the file rows survive even if `thumbnails` differs).
  - **Trash** — a file-tree filter over `/.Trash` / `/.Trashes` (no extraction);
    the FileEntry's own changed/modified time is the deletion time.
  Parsed in `AppModel.parseMac()`, cached as `useractivity.json`, spliced onto the
  timeline (`TimelineSource.userActivity`, Trash rows marked deleted), surfaced in
  a **QuickLook & Trash** tab. `MacActivityAnalyzer` flags a trashed payload
  (risky-extension file in the Trash → T1070.004). Covered by
  `StrataTests/MacActivityTests.swift`. **Known limits:** macOS Trash keeps no
  "original location" record (only the in-Trash path); QuickLook `last_hit_date`
  treated as CFAbsoluteTime (Unix as a fallback by magnitude); validated against
  synthetic SQLite, not a real index.

## Document Versions

- **done.** `DocumentRevisionsParser` (`StrataMac`, GRDB) reads the macOS Versions
  store (`/.DocumentRevisions-V100/db-V1/db.sqlite`): each `generations` row is a
  saved version of a document → `MacDocumentVersion` (`StrataCore`) with the
  original path (resolved from `files` as a side lookup, robust to schema drift),
  version time, size, and the stored-generation path. This reconstructs a file's
  **edit timeline** and points at a recoverable prior version, **even for files
  no longer on disk**. Parsed in `AppModel.parseMac()`, cached as
  `docrevisions.json`, spliced onto the timeline (`TimelineSource.docRevisions`,
  `.modified`), surfaced in a **Document Versions** tab. Context-only (a recovery
  artifact, no detection rule — like the host-info artifacts). Covered by
  `StrataTests/DocumentRevisionsTests.swift`. **Known limits:** `generation_add_time`
  treated as Unix seconds (CFAbsoluteTime fallback by magnitude); recovering the
  version *content* (the generation blobs) is a follow-up; validated against
  synthetic SQLite.

## Notification Center

- **done.** `NotificationParser` (`StrataMac`, GRDB) reads the Notification Center
  store (`db2/db` under `…/group.com.apple.usernoted/` or the legacy
  `…/com.apple.notificationcenter/`): each `record` row is a delivered
  notification → `MacNotification` (`StrataCore`) with the emitting app's bundle
  id (resolved from the `app` table as a side lookup, robust to schema drift),
  delivered date (`CFAbsoluteTime`, Unix fallback by magnitude), and the title /
  body recovered from the per-record `data` bplist via `BinaryPlist` (searching
  the `titl` / `body` / `mesg` / `subt` keys across layouts). Forensic value:
  corroborates app activity (what notified, and when) and can preserve message
  previews, 2FA codes, or phishing / social-engineering content. Parsed in
  `AppModel.parseMac()`, cached as `notifications.json`, spliced onto the timeline
  (`TimelineSource.notifications`, `.changed`), surfaced in a **Notifications**
  tab. Context-only (no detection rule — like the other content-recovery
  artifacts). Covered by `StrataTests/MacNotificationTests.swift`. **Known
  limits:** the `data` bplist layout varies by macOS version (key search is
  lenient but may miss exotic schemas); attachment / image payloads not recovered;
  validated against synthetic SQLite.

## Powerlog (process-execution activity)

- **done.** `PowerlogParser` (`StrataMac`, GRDB) reads the powerd analytics store
  (`CurrentPowerlog.PLSQL` under `/private/var/db/powerlog/Library/BatteryLife/`)
  → `PowerlogEntry` (`StrataCore`). Powerlog is one of the few macOS artifacts
  giving true **process-execution timing with PIDs**, surviving independently of
  the unified log — it catches headless/background tooling that never comes to
  the foreground (where KnowledgeC's GUI-focus view is blind). v1 parses the
  highest-value tables: `PLPROCESSMONITORAGENT_EVENTFORWARD_PROCESSID`
  (PID→process→bundle), `PLAPPLICATIONAGENT_EVENTFORWARD_APPLIFECYCLE`
  (launch/exit + EVENT), `…_FRONTMOSTAPP` (active app), and
  `PLPROCESSNETWORKAGENT_EVENTINTERVAL_USAGEDIFF` (per-process bytes), with
  `…_EVENTNONE_APPINFO` as a bundle-id→name enrichment lookup.
- **Timestamps:** Powerlog times are **Unix epoch seconds** (NOT CFAbsoluteTime —
  the 2001-epoch reflex is wrong here), recorded against a drifting clock and
  corrected by the signed `system` offset from
  `PLSTORAGEOPERATOR_EVENTFORWARD_TIMEOFFSET` (latest offset at-or-before the
  event, APOLLO's `timestamp + system` formula; binary-searched).
- **Robustness:** Powerlog is a WAL-mode SQLite DB (`.PLSQL` extension), so it
  copies to scratch with its `-wal`/`-shm` sidecars and opens read-write like the
  browser/Messages parsers. Table/column names drift across macOS versions, so
  every table is feature-detected (`tableExists`) and read with `SELECT *` +
  null-tolerant column reads (the #1 parser risk per the research).
- Parsed in `AppModel.parseMac()` (self-gating + backfill), cached as
  `powerlog.json`, spliced onto the timeline (`TimelineSource.powerlog`),
  surfaced in a **Powerlog** tab (kind filter + detail pane). `PowerlogAnalyzer`
  ships **with** the artifact (Powerlog is execution evidence, like SRUM/prefetch
  — KnowledgeC is the precedent): offensive/dual-use tool execution (T1059, high),
  remote-access/RMM execution (T1219, high — reuses
  `KnowledgeCAnalyzer.remoteAccessHints`), and osascript AppleScript/JXA (T1059.002,
  medium), all **aggregated per tool** (one finding per binary, not per launch) to
  stay low-noise. Covered by `StrataTests/PowerlogTests.swift` (offset math,
  enrichment, network summing, schema-drift tolerance, the three detections,
  timeline projection). **Known limits:** archived/rotated `Archives/*.PLSQL.gz`
  DBs (weeks of extra history) are not yet inflated+parsed (live DB only); each
  table is capped at the most-recent N rows; validated against synthetic SQLite —
  real-image end-to-end pending.

## System Preferences / configuration posture

- **done.** `MacConfigParser` (`StrataMac`, pure, `PropertyListSerialization`)
  parses the curated set of **security-posture** preference files no other parser
  reads → `MacConfigSetting` (`StrataCore`). This is the static *capability* half
  (what's configured) complementing the event artifacts (unified log / auth) that
  show a control was *used*. Domains: firewall (`com.apple.alf`:
  globalstate/loggingenabled/stealthenabled/firewallunload), screen-lock
  (`com.apple.screensaver` askForPassword/Delay — per-user, ByHost-aware),
  software-update (`com.apple.SoftwareUpdate`/`commerce`:
  CriticalUpdateInstall/ConfigDataInstall/…), Gatekeeper master switch
  (`/var/db/SystemPolicy-prefs.plist` `enabled`), **remote services** from the
  launchd `…/com.apple.xpc.launchd/disabled.plist` overrides, login-window
  (autoLoginUser/GuestEnabled/HiddenUsersList), and ARD
  (`com.apple.RemoteManagement` ARD_AllLocalUsers).
- **The inverted-boolean trap (the #1 correctness risk):** in `disabled.plist`
  the Bool is the *disabled* flag, so `value == false` means the service is
  **ENABLED** (an override un-disabled it), `true` = off, and an **absent** label
  = bundled default (off for the remote services). The parser flags only
  *present-and-false* labels; it also handles the pre-10.10 nested
  `overrides.plist` (`label → {Disabled: Bool}`).
- **Undetermined ≠ insecure:** for keys whose secure default is implicit and only
  written when disabled (screensaver, several update keys), an **absent key emits
  nothing** rather than a false "disabled" finding.
- **Credentials by presence only:** `/etc/kcpassword` (auto-login password) and
  `com.apple.VNCSettings.txt` (VNC control password) are reported as *present*
  (T1078 / T1021.005) — their recoverable plaintext is **deliberately never
  decoded into the case** (forensic-confidentiality rule).
- Static config, so **no timeline splice** (like WMI/FSEvents/Carved). Ships with
  `MacConfigAnalyzer`: one finding per flagged setting — weakened defenses
  (T1562.001/.004), enabled remote services (T1021.001/.002/.004/.005),
  auto-login/guest (T1078), hidden accounts (T1564.002). The per-setting
  risk/ATT&CK lives in the parser; the analyzer is the thin, testable projection.
  Parsed in `AppModel.parseMac()` (self-gating + backfill), cached as
  `macconfig.json`, surfaced in a **Configuration** tab (flagged-only filter,
  risk-highlighted). Covered by `StrataTests/MacConfigTests.swift`. **Overlap
  avoided:** Gatekeeper *events* (MacSecurityParser), login/logout *hooks* +
  config profiles (MacPersistenceParser), launchd job inventory
  (LaunchItemParser), host identity (MacHostInfoParser). **Known limits:**
  FileVault on/off (derive from the APFS encryption flag, not a pref plist) and
  SIP (NVRAM, not on disk) are out of scope; validated against synthetic plists.

## Software install history

- **done.** `MacInstallHistoryParser` (`StrataMac`, pure, `PropertyListSerialization`)
  parses the canonical structured install record → `MacInstallEntry`
  (`StrataCore`): the system install history `/Library/Receipts/InstallHistory.plist`
  (an **array** of events — displayName / date / displayVersion / processName /
  packageIdentifiers / contentType) and the PackageKit receipts
  `/private/var/db/receipts/<id>.plist` (one **dict** each — PackageIdentifier /
  InstallDate / InstallProcessName / PackageFileName / InstallPrefixPath /
  PackageVersion). This reconstructs *what* software/OS/profile was installed,
  *when*, and *by which process* — complementing the verbose `install.log` event
  stream the MacSecurityParser reads.
- Install events carry real timestamps, so they **splice the timeline**
  (`TimelineSource.install`, `.born`) — unlike the static config-posture artifact.
  Parsed in `AppModel.parseMac()` (self-gating + backfill), cached as
  `installhistory.json`, surfaced in an **Installs** tab. Ships with
  `MacInstallAnalyzer` (low-noise, two rules keyed on what the records actually
  expose): a package whose recorded install *process* is a scripting interpreter
  / network tool rather than the install daemons (installer / softwareupdated /
  storedownloadd) — a programmatic install — (T1059, high), and an installed
  package whose name / bundle id matches a known **offensive tool** (T1588.002) or
  **RMM / remote-access** product (T1219). Covered by
  `StrataTests/MacInstallHistoryTests.swift`.
- **Threat-model lesson (from the adversarial review, verified against real
  receipts):** install records do **not** capture where a package was *staged
  from* — `PackageFileName` is a bare basename and `InstallPrefixPath` is the
  install *destination* (a relative path like `tmp/…`), so a naive "installed from
  a staging path" rule both misfires and false-positives (legit software installs
  components under `tmp/`). Package origin/provenance lives in the quarantine
  store / FSEvents (their own analyzers); the recorded *process* is the install
  daemon, not the invoking shell. The analyzer is modeled around those realities.
- **Overlap avoided:** the `install.log` *event stream* + XProtect/MRT stay with
  MacSecurityParser; this owns the structured install *record*. **Known limits:**
  receipt `.bom` bills-of-materials aren't parsed (just the `.plist` receipts);
  validated against synthetic plists.

## Download provenance (WhereFroms xattrs)

- **done (engine + artifact; real-image validation pending).** Recovers the
  `com.apple.metadata:kMDItemWhereFroms` extended attribute Spotlight writes on
  downloaded files — a bplist array of `[download URL, referrer]` → `MacWhereFrom`
  (`StrataCore`). This is *where a file came from*, and it **survives even when
  the `com.apple.quarantine` flag was stripped**, complementing the quarantine
  store.
- **The fsapfscat C change (the previously-deferred blocker):** `scripts/fsapfscat.c`
  gained a `-x <name>` mode that dumps a file's named extended attribute via
  libfsapfs (`libfsapfs_file_entry_get_extended_attribute_by_utf8_name` +
  `..._extended_attribute_get_size`/`read_buffer`); exit code 3 = attribute
  absent. `FsApfsExtractor.extract(attribute:)` shells it out; `build-tsk.sh` now
  rebuilds fsapfscat when the source changes. **APFS only** — loose KAPE
  collections strip xattrs, and the TSK path doesn't surface them.
- `WhereFromsParser` (`StrataCore`, pure) decodes the xattr bytes via `BinaryPlist`.
  In `AppModel.parseMac()`, the xattr is fetched for download-likely candidate
  files (Downloads/Desktop + installer/archive/script extensions under `/Users`),
  **capped at 2000 per host** to bound the one-xattr-read-per-file cost. Cached as
  `wherefroms.json`, surfaced in a **Download Origins** tab; no timeline splice
  (the xattr carries no timestamp). `MacWhereFromsAnalyzer` flags a download from
  a **raw IP** (T1105, high) or a **paste / anon-share / tunnel** host (T1102,
  medium).
- **Validation:** the pure decoder, host parsing, and analyzer are unit-tested
  (`StrataTests/WhereFromsTests.swift`). The `fsapfscat -x` C path and the
  per-file extraction **cannot be built/run in CI** (needs the vendored libyal
  toolchain) — they require a `scripts/build-tsk.sh` rebuild and a test against a
  **real APFS image** to confirm libfsapfs surfaces inline xattrs correctly.
  **Known limits:** APFS-only; capped candidate set; inline-vs-stream xattr
  read assumed handled by libfsapfs's `read_buffer` (verify on real evidence).

## Recovery

- **Signature carving (deleted / sealed / encrypted recovery).** `FileCarver`
  (`StrataCore`, pure-Swift, synthetic-fixture tested) scans an image's raw bytes
  for file magic headers and recovers the embedded files independent of the
  filesystem — reaching deleted files in unallocated space and content libfsapfs
  won't surface through the volume layer (sealed System snapshot, locked
  FileVault), because it reads raw bytes directly. Recovers SQLite / PNG / JPEG /
  PDF / ZIP with exact sizes (header/footer) and bplist / gzip capped. Opt-in via
  **Tools ▸ Carve Deleted Files** (`AppModel.carveArtifacts()`, runs on each APFS
  host's raw image off-main and **parallelised across cores** with a determinate
  progress bar); results persist as `carved.json`, surface in a
  **Carved Files** tab (offset / type / size / source, with Save-recovered-bytes),
  and carry no timestamps so there's no timeline projection. This partially
  mitigates the two deferred large items (APFS unallocated recovery; sealed
  System-volume reads). *The engine is fully tested; the end-to-end carve over a
  real APFS image is not yet validated (no toolchain build / image in CI).*

## Detection & Access Improvements

- **Unified Log detection breadth.** `UnifiedLogAnalyzer` was expanded beyond the
  original sudo / osascript / SSH-accepted checks with three more high-precision
  rules: SSH failed-login bursts (medium, escalating to high brute force ≥5,
  T1110.001), Screen Sharing / VNC authentication succeeded (high, T1021.001),
  and local account creation via `sysadminctl` / `dscl` (high, T1136.001).
  Covered by `StrataTests/UnifiedLogAnalyzerTests.swift`.
- **FileVault-encrypted Data volume access.** `fsapfsinfo` (metadata) and
  `fsapfscat` (content) already accept `-p`/`-r`; the ingest path now threads a
  `FileVaultCredential` through both. An encrypted volume that comes back empty
  is reported as a locked volume (`ApfsLockedVolume`) instead of aborting the
  ingest; `AppModel` then prompts via `FileVaultUnlockSheet` (auto-shown after
  ingest, or Tools ▸ Unlock FileVault Volume), stores the secret **in memory
  only — never persisted**, re-ingests, and re-runs the macOS / browser /
  unified-log parsers. *Logic is structurally complete and builds on both
  platforms; not yet validated against a real FileVault image.*

## Guardrails

- Add one artifact bucket at a time.
- Keep parse gating per bucket, not per OS.
- Preserve existing cached buckets when backfilling a new one.
- Add timeline projection for timestamped artifacts.
- Keep UI work separate from parser/storage work when other agents have active view edits.
