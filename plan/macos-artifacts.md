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
