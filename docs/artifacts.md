# macOS artifact reference

The per-parser detail behind the `StrataMac` row of [CLAUDE.md](../CLAUDE.md)'s
module table. Everything here is discovered and parsed by `AppModel.parseMac()`;
code lives under `Strata/Platforms/macOS/{Parsers,Models}/` and the analyzers
under `Strata/StrataAnalysis/Analyzers/macOS/` (see
[ARCHITECTURE.md](../ARCHITECTURE.md) for placement).

Each entry is **parser → model → analyzer (ATT&CK)**, plus its timeline splice
(`TimelineSource`) where it has one.

## Persistence

- **`LaunchItemParser`** — launchd plists → `LaunchItemEntry`;
  `MacPersistenceAnalyzer` (T1543).
- **`MacPersistenceParser`** — the non-launchd sweep: cron, site-local
  `periodic`, `emond` rules, login/logout hooks, `rc` scripts,
  `.mobileconfig` / Managed Preferences → `MacPersistenceItem` (`StrataCore`);
  `MacPersistenceSweepAnalyzer` (T1546.014 / T1037.002 / T1053.003 / T1037.004).
- **`BTMParser`** — the `*.btm` Background Task Management store, an
  NSKeyedArchiver graph decoded via `StrataCore/BinaryPlist` (a UID-aware
  `bplist00` reader) and walked leniently by ivar name → `MacBackgroundItem`;
  `MacBackgroundItemAnalyzer` (non-Apple login item / agent / daemon — T1547.015,
  high in a staging path).
- **`MacKextParser`** — kext `Info.plist` + `/Library/SystemExtensions/db.plist`
  → `MacKextEntry`; `MacKextAnalyzer` (third-party kernel/system extension —
  T1547.006; high for a `.kext`/kernel, medium for a user-space sysext).

## Provenance & delivery

- **`QuarantineParser`** — the LaunchServices quarantine SQLite →
  `QuarantineEvent`; `MacQuarantineAnalyzer` (T1204 / T1105).
- **`WhereFromsParser`** (`StrataCore`, pure) — decodes the
  `com.apple.metadata:kMDItemWhereFroms` xattr, a bplist array of
  `[download URL, referrer]`, via `BinaryPlist` → `MacWhereFrom`. A file's
  **download provenance, surviving even when the quarantine flag was stripped**.
  The bytes come from `fsapfscat -x` on **APFS images only** — loose collections
  strip xattrs. Candidate files are download-likely (the Downloads / Desktop /
  Documents landing zones, plus dmg/pkg/iso elsewhere, **excluding `/Library/`
  and bundle internals**), capped at **2000 per host** to bound the
  one-xattr-read-per-file cost. `MacWhereFromsAnalyzer` (download from a **raw
  IP** T1105 high; from a **paste / anon-share / tunnel** host T1102 medium).
  No timeline splice. Validated end-to-end on a real APFS E01 — needs
  `scripts/build-tsk.sh` + an Xcode rebuild to re-bundle `fsapfscat`.
- **`MacInstallHistoryParser`** — `InstallHistory.plist` (an **array** of events)
  + PackageKit receipts `/private/var/db/receipts/<id>.plist` (one **dict** each),
  via `PropertyListSerialization` → `MacInstallEntry` (displayName / version /
  date / processName / packageIdentifiers / contentType + receipt
  PackageFileName / InstallPrefixPath). The canonical structured record of what
  software / OS / profile was installed, when, and by which process —
  complementing the verbose `install.log` stream. `TimelineSource.install`
  (`.born`). `MacInstallAnalyzer`, deliberately low-noise: a package whose
  recorded install *process* is a scripting interpreter or network tool rather
  than the install daemons (programmatic install — T1059), and a package whose
  name / bundle-id matches an **offensive tool** (T1588.002) or **RMM** product
  (T1219). Package *origin* isn't in install records — `PackageFileName` is a
  basename, `InstallPrefixPath` is the destination — so staging provenance is
  left to the quarantine / FSEvents analyzers.

## Privacy, activity & execution

- **`TCCParser`** / **`KnowledgeCParser`** — SQLite via GRDB → `TCCAccess` /
  `KnowledgeEntry`; `TCCAnalyzer` (sensitive grants to non-Apple clients —
  T1113 / T1125 / T1123 / T1056.001 / …) and `KnowledgeCAnalyzer` (RMM /
  remote-access app in active use — T1219).
- **`PowerlogParser`** — the powerd analytics `CurrentPowerlog.PLSQL` store under
  `/private/var/db/powerlog/` via GRDB → `PowerlogEntry`: process-execution
  records (PID → name → bundle from `PLPROCESSMONITORAGENT_…_PROCESSID`), app
  launch/exit lifecycle, the frontmost app, and per-process network volume. One
  of the few macOS artifacts giving true **process-execution timing with PIDs**,
  surviving independently of the unified log. **Unix-epoch** times are corrected
  by the `PLSTORAGEOPERATOR_…_TIMEOFFSET` `system` offset (APOLLO's
  `timestamp + system`); every table is feature-detected and null-tolerant
  against version drift. `TimelineSource.powerlog`. `PowerlogAnalyzer`
  (offensive/dual-use tool execution T1059; remote-access/RMM execution T1219,
  reusing `KnowledgeCAnalyzer.remoteAccessHints`; osascript AppleScript/JXA
  T1059.002) — aggregated per tool, low-noise, and catches headless tooling that
  KnowledgeC's GUI-focus view misses.
- **`MacRecentItemParser`** — `.sfl`/`.sfl2`/`.sfl3` → `MacRecentItem`;
  `MacRecentItemsAnalyzer` (remote-server connections T1021.*, staging-path /
  risky-extension recent items T1204.002).
- **`QuickLookParser`** — the QuickLook thumbnail `index.sqlite` via GRDB →
  `MacActivityItem`: files **previewed, even if since deleted**. Plus Trash
  discovery (a file-tree filter over `/.Trash` / `/.Trashes`, same model).
  `MacActivityAnalyzer` (trashed payload — risky-extension file in the Trash,
  T1070.004). `TimelineSource.userActivity`.
- **`DocumentRevisionsParser`** — the Versions store
  `/.DocumentRevisions-V100/db-V1/db.sqlite` via GRDB → `MacDocumentVersion`:
  per-document saved generations = an edit timeline plus recoverable prior
  versions. Context-only, no analyzer. `TimelineSource.docRevisions`.
- **`NotificationParser`** — the Notification Center `db2/db` store under
  `group.com.apple.usernoted` (legacy `com.apple.notificationcenter`) via GRDB →
  `MacNotification`: app bundle id (side lookup on `app`) + title/body recovered
  from the per-record `data` bplist via `BinaryPlist` + `CFAbsoluteTime`
  delivered date. Corroborates app activity and can preserve message previews,
  2FA codes, and phishing content. Context-only, no analyzer.
  `TimelineSource.notifications`.

## Communication

- **`MessagesParser`** — the `chat.db` Messages store via GRDB → `MessageEntry`,
  copy-to-scratch + WAL like browser history, with `attributedBody` text
  recovered via `BinaryPlist`; `MacMessagesAnalyzer` (suspicious links —
  T1566.002 received / T1204.001 sent). `TimelineSource.messages`.
- **`MailParser`** — the Mail `Envelope Index` SQLite DB via GRDB →
  `MailMessageEntry` (sender / subject / recipients / dates / mailbox),
  copy-to-scratch + WAL like Messages; bodies live in `.emlx` and aren't parsed.
  `MacMailAnalyzer` (suspicious inbound mail — raw-IP sender or suspicious
  subject link, T1566.002). `TimelineSource.mail`.

## Security posture & defenses

- **`MacSecurityParser`** — Gatekeeper/syspolicyd, XProtect, XProtect
  Remediator, MRT, `install.log` → `MacSecurityEvent`; `MacSecurityAnalyzer`
  (malware detect/remediate T1204.002; allow-after-block trust override +
  repeated policy blocks T1553.001; control disabled T1562.001).
- **`MacConfigParser`** — a curated sweep of the security-posture preference
  files no other parser covers, via `PropertyListSerialization` →
  `MacConfigSetting`: firewall `com.apple.alf` (globalstate / logging / stealth);
  screen lock `com.apple.screensaver` askForPassword (per-user, ByHost-aware —
  an **absent key is *undetermined*, not insecure**); software update
  `com.apple.SoftwareUpdate` / `commerce`; the Gatekeeper master switch
  `SystemPolicy-prefs.plist`; **remote-service enablement** from the launchd
  `com.apple.xpc.launchd/disabled.plist` **inverted-boolean** overrides
  (`disabled == false` ⇒ ENABLED — SSH / Screen Sharing / ARD / Apple Events /
  SMB / AFP; also the legacy nested `overrides.plist`); login-window auto-login /
  guest / `HiddenUsersList`; and ARD `com.apple.RemoteManagement`.
  `kcpassword` and `com.apple.VNCSettings.txt` are reported by **presence only —
  the stored credential is never decoded into the case.** No timeline splice
  (static config, like WMI). `MacConfigAnalyzer` emits one finding per flagged
  setting (weakened defenses T1562.001/.004, enabled remote services
  T1021.001/.002/.004/.005, auto-login/guest T1078, hidden accounts T1564.002) —
  the per-setting risk and ATT&CK mapping live in the **parser**; the analyzer is
  just the projection.

## Host identity & network

- **`MacHostInfoParser`** — SystemVersion / SystemConfiguration `preferences` /
  dslocal users → `MacHostInfo` (`StrataCore`), the macOS host-profile source,
  surfaced on the Overview card via `HostProfile.derive(fromMac:)`.
- **`MacNetworkParser`** — one lenient parser over the network/device plists →
  `MacNetworkItem`: known Wi-Fi networks (`airport.preferences` +
  `wifi.known-networks`), DHCP leases (`dhcpclient/leases`), Bluetooth
  `DeviceCache`, Time Machine `Destinations`, lockdown iOS pairings.
  `MacNetworkAnalyzer` (Time Machine backup to a network destination — T1074,
  high on a raw IP). `TimelineSource.network`.

## Change journal

- **`FSEventsParser`** (`StrataCore`) — pure-Swift decode of the `/.fseventsd/`
  change journal: gzip → DLS v1/v2 pages → `FSEventRecord` (path + coalesced
  change flags + monotonic event ID). **No per-record timestamp, so no timeline
  splice** — same as the WMI carve. Inflated and decoded **off-main**.
  `FSEventsAnalyzer` (created-then-removed payloads T1070.004, launchd-dir
  writes T1543).

## Tabs & OS gating

`.macos` `OSFamily` is detected from the APFS/HFS+ fs-type (or a Mac-marker
file-tree sniff). These tabs are gated on it: **Launch Items, Quarantine,
Persistence, FSEvents, TCC, KnowledgeC, Recent Items, macOS Security, Unified
Log, Carved Files, Extensions, Background Items, Messages, Mail, Network &
Devices, QuickLook & Trash, Document Versions, Notifications, Powerlog,
Configuration, Installs, Download Origins**.

iOS drills exist only through KnowledgeC — the newer macOS artifact tabs are
macOS-only for now. Findings from every analyzer above also surface in the
cross-platform Kill-Chain / Findings views.
