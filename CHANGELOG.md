# Changelog

All notable changes to Strata are documented here. The format loosely follows
[Keep a Changelog](https://keepachangelog.com/); versions correspond to git tags.

## [Unreleased]

### Added — Recycle Bin, Global Search, macOS triage, multi-host correlation (Waves 4-7)

- **Recycle Bin recovery** (Wave 4) — pure-Swift `$I` index byte-parser
  (`RecycleBinParser` → `RecycleBinEntry`: original path, size, deletion time,
  SID), discovered + extracted by `parseRecycleBin()`, persisted as
  `recyclebin.json`, with a sortable/filterable **Recycle Bin** tab (Windows) and
  `RecycleBinAnalyzer` (T1070.004: deleted exe/script from staging paths +
  mass-deletion bursts).
- **Global search** (Wave 5, roadmap #6) — `SearchEngine` ranks a case-insensitive
  query across files / events / registry / timeline / findings; a cross-platform
  **Search** tab runs it off-main with kind filters.
- **macOS triage core** (Wave 6) — `StrataMac`: `LaunchItemParser` (launchd
  plists, XML + binary) → `MacPersistenceAnalyzer` (T1543.001/.004) and
  `QuarantineParser` (LaunchServices quarantine SQLite) → `MacQuarantineAnalyzer`
  (T1204/T1105: risky downloads from suspicious origins / non-browser agents).
  `parseMac()` discovers + parses both from an image or loose collection,
  persists `launchitems.json` / `quarantine.json`, and feeds the analyzers.
- **Multi-host correlation** (Wave 7, roadmap #8) — `CorrelationEngine` lines up
  per-host IOC hits, accounts, and inbound-logon source IPs and flags what spans
  ≥2 hosts (shared indicator, pivoting source IP, reused account); surfaced in the
  combined "All" findings scope.
- **Known-bad hash matching** (Wave 7, partial) — `KnownBadHashProvider` (a CTI
  tier emitting `.malicious` for a local bad-hash set) + `KnownBadHashAnalyzer`
  cores landed and tested; **config UI + pipeline wiring still pending**.

Analyzer count: **44**. Two latent bugs were caught during integration: the
suite-wide `NSString.lastPathComponent`-on-Windows-paths basename bug (Wave 1),
and `MacQuarantineAnalyzer.agentMatches` only checking the first path component
(so `/usr/bin/wget` never matched `wget`).

### Added — Linux parser gaps (Wave 3)

Three parsers that fold into existing tabs (no new UI), each unit-tested:

- **`lastlog2.db`** (`Lastlog2Parser`) — modern Ubuntu (glibc ≥ 2.40) replaced
  the binary `/var/log/lastlog` with an empty file + a SQLite `lastlog2.db`. Read
  via GRDB (SQLite-magic-guarded, copy-to-scratch like browser history), mapped
  to the existing `LastlogEntry` and folded into the **Last Login** tab —
  closing the "empty last login on a modern host" gap. UID is resolved by name
  from `/etc/passwd` post-parse.
- **sudo logfile** (`SudoLogParser`) — `/var/log/sudo` (when sudo's `logfile` is
  set), sudo's own format (distinct from auth.log), mapped to `AuthLogEntry`
  (kind `.sudo`) and folded into **Auth & Logins**.
- **App-server request logs** (`AppServerLogParser`) — reverse-proxy-less Rails
  (`Started … Completed` pairs) and puma/Node `[pid]`-prefixed combined logs,
  mapped to `WebAccessLogEntry` and folded into **Web Logs** — closing the
  confirmed gap where a Node app's HTTP traffic was invisible because it logs
  outside nginx/apache.

### Added — CTI enrichment foundation (Wave 2, roadmap "CTI enrichment")

The tiered hash/IOC enrichment waterfall — **NSRL → MISP/OpenCTI →
VirusTotal** — designed to minimise third-party calls and keep data in org
control. New `StrataCTI` module:

- **Cascade engine** (`EnrichmentEngine`) walks providers in tier order and
  **short-circuits on the first definitive verdict** — an NSRL known-good hash
  never reaches MISP/VT; a MISP-confirmed indicator never costs a VirusTotal
  call. Verdicts carry full **provenance** (`EnrichmentVerdict`: which tier/
  source, score, reference, timestamp) — the field `IOCMatch` lacked. Actor-
  backed `EnrichmentCache` resolves each indicator at most once.
- **Four providers**, each with a pure (unit-tested) response decoder and an
  injectable transport: **NSRL** (local known-good hash set, no network, also a
  file-tree noise reducer), **VirusTotal** v3 (hash/ip/domain/url; VT-clean is
  `.unknown`, never `knownGood`), **MISP** (`/attributes/restSearch`), **OpenCTI**
  (GraphQL). All **opt-in**: an unconfigured tier returns nil and is skipped.
- **Per-instance config in the Keychain** (`KeychainCredentialStore`, the app's
  first `SecItem` usage) for base URL + token; the on/off flags + NSRL file path
  persist to `UserDefaults`. Tokens never touch the case bundle.
- Wired into `AppModel.enrichIndicators()` (off-main lookups), persisted
  case-wide as `enrichment.json`, and recorded in the **chain-of-custody
  ledger** (`.enrichmentPerformed`) — the CTI audit trail the roadmap requires.
- UI: the **Enrichment sheet** gained a "Threat-intel lookup" pass with inline
  source configuration; the **IOC tab** gained an *Enrich…* action and a
  provenance-tooltipped verdict pill per indicator.

**Still pending:** live end-to-end validation against real MISP/OpenCTI/VT
instances (decoders validated against fixtures); IP/domain/URL enrichment is
wired but the cascade is currently driven from the loaded IOC list.

### Added — detection coverage (Wave 1, +6 analyzers → 41)

Six new ATT&CK analyzers, each with unit tests, authored in parallel and
adversarially hardened for false-positive risk:

- **Credential Dumping** (T1003/T1558) — LSASS access/dump (Sysmon 10 masks,
  comsvcs MiniDump, procdump), SAM/SECURITY/SYSTEM hive theft (`reg save`, VSS
  copy), NTDS.dit (`ntdsutil ifm`), and mimikatz/Rubeus/gsecdump/nanodump tool
  fingerprints across prefetch/amcache/shimcache/lnk/browser/shell history.
- **Impact / Destruction** (T1485/T1486/T1490/T1561) — recovery inhibition
  (`vssadmin delete shadows`, `wbadmin`, `bcdedit recoveryenabled no`), disk
  wipe (`cipher /w`, `dd of=/dev/sd*`, diskpart clean), and ransomware
  mass-encryption bursts (≥25 distinct files gaining a novel uniform extension)
  + ransom-note filenames, with broad benign-extension exclusions.
- **Lateral Movement Breadth** (T1021.002/.003/.006, T1047) — WinRM/PSRemoting
  (`wsmprovhost` spawning a shell), WMI remote exec (`WmiPrvSE` parent,
  `wmic /node:`), DCOM monikers (MMC20/ShellWindows), and admin-share push —
  complementing the existing RDP/Impacket/SSH coverage.
- **AD Recon** (T1558.003/.004, T1087/T1018/T1046) — Kerberoasting (4769 RC4
  bursts), AS-REP roasting (4768 no-preauth), and discovery-command clustering.
- **Windows MRU** (T1059/T1204 intent) — surfaces suspicious RunMRU /
  RecentDocs / TypedPaths / UserAssist entries already in the registry.
- **Linux Anti-Forensics** (T1070.002/.003/.006) — history clearing/disable,
  `/var/log` truncation, `journalctl --vacuum`, `touch -t/-r` timestomp, and
  auditd/rsyslog tamper — complementing the existing log/history analyzers.

### Fixed — Windows path basename bug (latent, suite-wide)

`ProcessCreationAnalyzer` and `RMMToolAnalyzer` matched process basenames with
`NSString.lastPathComponent`, which splits on `/` only — so a backslash Windows
image path (`C:\…\powershell.exe`) passed through whole and the parent/child
**equality checks silently never fired on real Windows evidence**. Added a
shared backslash-and-slash-aware `WindowsPath.basename` and routed all three
affected analyzers through it. (Caught by the new Lateral-Movement analyzer's
own failing test during integration.)

### Fixed (real ext4-image triage pass)

First end-to-end run against a real Ubuntu ext4 VM image surfaced a batch of
Linux-path issues, all fixed:

- **New artifact types now backfill into already-parsed cases.** `parseLinux`
  replaced its coarse "any Linux artifact present → skip host" guard with a
  per-bucket check: a host is re-parsed when its file tree offers candidates for
  a bucket (Accounts & SSH, Packages, Journal, System Log, …) that has no data
  yet. Cases parsed by an earlier build (auth/logins only) now pick up every
  artifact type added since, instead of being skipped wholesale.
- **"file is not a database" crash on browser-history parse.** A Linux host
  carries unrelated files named `History` (IPython, app state); opening one with
  SQLite threw. The parser now gates on the 16-byte SQLite magic header and
  silently skips name-collisions, and the "extracted no entries" warning only
  fires when a *real* browser DB yielded nothing.
- **Timeline no longer blank on a Linux image.** The default source selection
  was Event Log only (empty on Linux). It now seeds, once, from the case's
  populated *bounded* sources (Event Log on Windows; the auth/journal/syslog/
  login set on Linux); the unbounded sources (filesystem MACB, USN, MFT) stay
  off until enabled.

### Changed

- **Overview shows Linux host IPs.** A new `LinuxNetworkParser` recovers IPv4
  addresses from netplan (`/etc/netplan/*.yaml`) and ifupdown
  (`/etc/network/interfaces`) static config, plus the runtime DHCP lease from the
  journal's NetworkManager / systemd-networkd / dhclient / avahi lines — the
  only record of a DHCP-assigned address (validated against a real journal:
  recovers `192.168.5.160`). Surfaced on the Overview host profile.
- **Linux artifact tables are column-sortable.** Auth events, login records,
  journal, system log, audit, packages, shell history, web logs, and last-login
  tables gained click-to-sort ascending/descending columns (atop the existing
  text filters). Row-capped tables sort before the cap so the visible slice
  honours the order.

### Added

- **auditd, system-log, and lastlog parsing** (new **Audit**, **System Log**,
  **Last Login** tabs) — completes the Linux log layer, all pure-Swift:
  - **auditd** (`/var/log/audit/audit.log`) — groups the multiple records of
    one event by their `audit(epoch:serial)` id and folds them into one row:
    hex-decoded fields, EXECVE command-line reconstruction, per-arch syscall
    resolution, and the immutable login-uid (`auid`) attribution. The **Linux
    Audit** analyzer flags shells/interpreters run under service accounts and
    from staging paths (T1059.004), account/group creation (T1136.001),
    sensitive-file writes — authorized_keys/sudoers/passwd (T1098.004/T1548.003),
    non-SSH PAM auth-failure bursts (T1110), and execmem/execstack SELinux
    denials (T1211).
  - **system log** (`/var/log/syslog`, `/var/log/messages`) — the non-auth
    kernel/systemd/cron telemetry, classified into categories (USB insertion,
    OOM, segfault, disk error, service crash-loop, cron exec, …) via the same
    line scanner `auth.log` uses. The **System Log** analyzer flags USB
    mass-storage attachment (T1091), segfault bursts on network daemons
    (T1203), unknown-unit crash loops (T1543.002), and download-pipe cron
    commands (T1053.003).
  - **lastlog** (`/var/log/lastlog`) — the per-UID last-login binary database
    (292-byte records, positional UID, username resolved via `/etc/passwd`).
    The **Last Login** analyzer flags a non-interactive service account that
    has logged in (T1078.003) and a privileged account whose last login came
    from a public/external host (T1078).
  - All three feed the timeline (three new sources) and auto-hide on Windows
    evidence. The shared syslog prefix parser was factored out of
    `AuthLogParser` into `SyslogLineScanner`.

- **systemd journal (journald) parsing** (new **Journal** tab) — a pure-Swift
  decoder for the binary journal format (`/var/log/journal/**/*.journal`), no
  vendored tool. On a modern systemd host the journal is often the *only* place
  auth/service/kernel events live (`auth.log`/`secure` may not exist), so this
  closes the biggest Linux log-coverage gap. Parses the `LPKSHHRH` header, the
  entry-array chain, and entry/data objects — both the legacy and **COMPACT**
  (systemd ≥ 252, 32-bit offsets) layouts — recovering `MESSAGE`, `_COMM`,
  `PRIORITY`, `_SYSTEMD_UNIT`, `SYSLOG_IDENTIFIER`, `_PID`, `_HOSTNAME`, etc.
  **LZ4**-compressed values are inflated via the Compression framework; **XZ/
  ZSTD** values are skipped (those codecs aren't in the framework — only large
  compressed MESSAGE bodies are lost; short fields/messages are uncompressed).
  Entries feed the timeline (new Journal source). A new **Journald** analyzer
  runs the same SSH brute-force (with success-after-burst escalation) and
  sudo-failure detections as the auth-log analyzer, over the journal's
  messages. Priority-coloured macOS table view + iOS drill. Parser validated
  against journals built byte-by-byte to the documented format (legacy +
  compact + LZ4).

- **Expanded Linux persistence + package history.** The **Linux Persistence**
  analyzer now sweeps the full set of auto-run locations beyond cron + systemd
  services: **systemd timers**, **`/etc/ld.so.preload`** (library injection —
  any entry flagged), **XDG autostart** (`~/.config/autostart/*.desktop`),
  **boot/init scripts** (`/etc/rc.local`, `/etc/init.d`, `/etc/cron.{hourly,
  daily,weekly,monthly}`), and **shell-init files** (`~/.bashrc`,
  `/etc/profile.d` — surfaced only for execution-bearing lines, so a normal
  `.bashrc` is silent), each mapped to its own ATT&CK technique. A new **Package
  History** tab parses **dpkg / apt / yum / dnf** logs into an install/remove/
  upgrade timeline; its analyzer flags **offensive/dual-use tool installs**
  (nmap, socat, netcat, sqlmap, … — `T1588.002`) and **mass-removal bursts**
  (cleanup / anti-forensics — `T1070`). Both feed the timeline (package events
  as a new source). macOS views + iOS drills.

- **Web server access logs** (new **Web Logs** tab) — parses nginx/apache
  access logs (Common + Combined Log Format) into per-request rows, with the
  request's real (timezone-explicit) timestamp on the timeline. A new **Web
  Access Log** analyzer flags exploitation against the application itself:
  SQL injection / path traversal / command injection / XSS probes (`T1190`,
  severity escalating when the request got a 2xx/3xx), webshell-shaped paths
  (`T1505.003`, critical on a 200), scanner user-agents — sqlmap/nikto/
  gobuster/etc. (`T1595.002`), and 404-burst directory brute-forcing
  (`T1595.003`). Rotated `.gz` access logs are read too. macOS table view
  (status-coloured, errors-only filter) + iOS drill. (Tagged a Linux tab —
  discovery is `/var/log/{nginx,apache2,httpd}`; IIS/W3C logs aren't parsed.)

- **Linux access & privilege artifacts** (new **Accounts & SSH** tab) — parses
  the "who can get in, and as whom" sources: SSH `authorized_keys` and
  `known_hosts` (with `command=`/`from=` options), `sshd_config`, `sudoers`
  (+ `sudoers.d`), `/etc/group`, and `/etc/shadow` password state. A new
  **Linux Access & Privilege** analyzer flags backdoor-shaped SSH keys
  (forced-command, root-authorized), dangerous sshd settings
  (`PermitRootLogin`, `PermitEmptyPasswords`), UID-0 non-root and passwordless
  accounts, passwordless full `sudo` (NOPASSWD ALL), and root-equivalent group
  membership (`docker`/`lxd`). Rotated **`.gz` auth logs** (`auth.log.2.gz`)
  are now read too — decompressed inline via a new `GzipDecoder` (Compression
  framework, no new dependency) — extending the auth-log window we cover. macOS
  view + iOS drill.
- **Per-OS artifact tabs.** Tabs that can't apply to an evidence item's OS are
  now hidden — a Linux (ext4) case no longer shows Registry / Prefetch / EVTX /
  Amcache / MFT / WMI etc., and a Windows case hides the Auth & Logins / Shell
  History / Linux Persistence tabs. The OS is detected per host from its
  filesystem type (NTFS ⇒ Windows, ext ⇒ Linux), with a file-tree fallback for
  loose collection folders. Hiding follows the active scope — the combined "All"
  view shows the union across hosts, and anything undetermined shows everything.
  A **"Show all tabs"** toggle reveals the hidden tabs when needed (shown only
  when something is actually hidden). Browser History stays visible on both
  (Chrome/Firefox run on either OS). Also: ext2/3/4, HFS+, and APFS volumes now
  get proper names in the Evidence/volume labels instead of `FS(0x…)`.
- **ext3/4 support + basic Linux triage.** The vendored Sleuth Kit already
  enumerates ext2/3/4, so Linux disk images get the file tree and FS MACB
  timeline like Windows images do (loose UAC-style collection folders work
  too). New `StrataLinux` parsers (all pure Swift - no new vendored tools)
  feed the rest of the pipeline:
  - **Auth log** (`auth.log`/`secure`; classic syslog with year inference from
    file mtime, plus modern RFC 3339 lines) — classified SSH logins/failures,
    sudo, session and account-change events.
  - **Login records** (`wtmp`/`btmp`) — binary utmp parsing; btmp rows are
    failed logins, often the only brute-force evidence left after log rotation.
  - **Shell history** (bash + zsh) — zsh extended / bash `HISTTIMEFORMAT`
    timestamps land on the timeline; plain bash history stays list-only.
  - **Persistence** — system + user crontabs (incl. `@reboot`) and systemd
    service units (`ExecStart`, `User=`, description).
  - **Linux host profile** — `os-release`/`hostname`/`passwd`/`timezone` fill
    the Overview host card and report profile when there's no registry.
  - **Three new analyzers**: SSH brute force (per-IP bursts, password spraying,
    "burst then accepted login" critical escalation, account creation, direct
    root logins), shell-history tradecraft (reverse shells, download-pipe-exec,
    history tampering, staging-dir chmod, base64 decode), and cron/systemd
    persistence (staging paths, download/decode tooling, boot-persistent
    `@reboot` jobs).
  - **Three new timeline sources** (Auth Log, Logins, Shell History) and three
    new tabs — "Auth & Logins" (segmented auth/utmp), "Shell History", "Linux
    Persistence" — with iOS drill equivalents.
  - Known v1 limits: classic syslog timestamps carry no timezone (treated as
    UTC); `.gz`-rotated logs and journald are not parsed; undated bash history
    is kept off the timeline by design.

- **Super-timeline** — the timeline now unifies **12 artifact sources**. New
  splices: **registry key writes** (deduped to one event per key; kept per
  hive *file* so two users' NTUSER hives stay distinct), **prefetch runs**
  (one event per recorded run time — execution evidence on the timeline),
  **shimcache** and **amcache** presence timestamps, **LNK target MAC times**
  (file-access evidence that survives the target's deletion), and **JumpList
  DestList access times**. The source filter became a compact checkable
  **Sources** menu. The registry splice is macOS-only (like the FS MACB
  timeline) to protect iPhone memory.
- **Analyst annotations & case narrative** (new **Annotations** tab) — the
  tagging/notes layer of the analyst workflow:
  - **Bookmark any timeline event or finding** — right-click a timeline row or
    click the star in the kill-chain inspector — with a verdict **tag**
    (Malicious / Suspicious / Benign / Follow up) and a free-form **note**.
    Bookmarked timeline rows show a tag-colored star and a **Bookmarked**
    filter; bookmarks survive re-parses by keying off stable identities
    (`Finding.id`, a content-derived `TimelineEvent.stableKey`), persisted
    case-wide in `annotations.json`.
  - **Case narrative** — a free-form running "story of the incident"
    (`notes.json`), edited in the Annotations tab with debounced autosave.
  - **Annotations tab** — narrative editor + tag-filterable bookmark table,
    chronological by the target's own timestamp, with edit/delete and a
    **Reveal in Timeline** pivot that jumps the Timeline tab to ±30 minutes
    around the bookmarked moment. iOS gains a read-only Annotations drill.
  - **Report integration** — the examiner report (Markdown + HTML) gains
    **Analyst narrative** and **Bookmarked items** sections, and annotations
    export as CSV/JSON alongside the other data exports.

- **WMI persistence parsing** (new **WMI** tab) — carves the WMI CIM repository
  (`OBJECTS.DATA`) for **event-subscription persistence** (T1546.003). A full CIM
  parse is intractable, so — like FireEye's PyWMIPersistenceFinder — it
  keyword-carves the high-signal strings: `__FilterToConsumerBinding` references,
  the `__EventFilter` WQL trigger, the `CommandLineEventConsumer` command line,
  and `ActiveScriptEventConsumer` script payloads (so an `Invoke-Mimikatz`
  consumer is caught even unbound). A new **WMI Persistence** analyzer flags every
  non-built-in binding (high when it runs a script or carries an attacker tell
  like encoded PowerShell or a LOLBin), and built-in Microsoft (BVT/SCM)
  subscriptions are marked and hidden by default. macOS table view + iOS drill.
  Validated against a real WMI repository (flare-wmi's `wmikatz` sample).
- **NTFS `$MFT` parsing + timestomping detection** (new **MFT** tab) — a
  pure-Swift `$MFT` byte parser (no vendored tool) that applies the NTFS fixup,
  decodes both the `$STANDARD_INFORMATION` and `$FILE_NAME` MACB sets, and
  reconstructs full paths from parent references. The MFT tab is a **per-volume
  tree** (like the Evidence tab) with `$SI`/`$FN` times shown at **full lossless
  100-ns precision** (stored as raw FILETIME — `Date` can't represent it) and an
  "Anomalies only" filter. **Resident `$DATA`** is captured, so small files
  stored inside the MFT record are recoverable — shown as a hex dump with a
  macOS Save button. A new **MFT Timestomp** analyzer flags *possible*
  timestomping (T1070.006) — an executable whose visible `$SI` creation predates
  its un-settable `$FN` creation and whose `$SI` times are whole-second (the
  timestomp-tool fingerprint). For loose KAPE collections, the `$MFT` `$SI` MACB
  is spliced onto the timeline as a true NTFS file timeline (loose folders
  otherwise fall back to collection-host times). The parser is validated against
  real `$MFT` records (incl. resident-data + 100-ns-precision fixtures).

### Fixed

- **Amcache stayed empty after parsing.** Registry parsing skipped a host
  entirely once it had *any* parsed values, so a case whose registry was parsed
  before `Amcache.hve` was captured could never pick it up — the Amcache tab
  stayed "not parsed yet" with no signal why. Registry re-parsing is now
  per-hive: a re-run parses only the hives not yet represented and merges them
  in, so pressing **Parse artifacts** again recovers Amcache (and any other
  late-added hive) without re-ingesting. `Amcache.hve` is also matched by
  filename (for non-standard collection layouts), and an `Amcache.hve` that
  reads but reconstructs to nothing now reports it instead of failing silently.

### Added

- **Browser history** (new **Browser History** tab) — parses Chromium-family
  (`History`) and Firefox (`places.sqlite`) databases, both SQLite, read directly
  with GRDB (no vendored tool). Surfaces page visits (one row per URL, with
  visit/typed counts and last-visit time) and downloads (target path, bytes,
  originating page), with the browser + profile recovered from the source path.
  Forensic-safe: the database (with its `-wal`/`-shm` sidecars) is copied to
  scratch and opened there — the evidence file is never opened by SQLite. Rows
  are folded onto the timeline
  (Browser History source). A new **Browser History** analyzer flags suspicious
  downloads (executable/script/archive or pulled from a paste / anonymous-sharing
  / tunnel host or raw IP, T1105), activity to suspicious infrastructure (T1102),
  and offensive-tool names in URLs/targets (T1588.002). macOS table view + iOS
  drill-down.
- **Chain of custody & evidence integrity** (new **Custody** tab) — a
  legal-weight, append-only record of each case:
  - **Acquisition metadata** per evidence item (examiner, tool, method,
    acquisition date, case #, media serial, notes), editable in-app. For **E01**
    images this is auto-extracted from the container header via the vendored
    `ewfinfo`.
  - **Source hashes** with a verification status. E01 **embedded** MD5/SHA-1 are
    read from the header (no rehashing the image) and can be re-checked with
    `ewfverify`; raw/VHD images get on-demand, cancellable **MD5 + SHA-256**
    computation with a progress bar.
  - **Custody log** — every acquire / add / analyse / hash / verify / enrich /
    export action is recorded with who + when, persisted to `custody.json`.
  - **Chain-of-custody report** — a formal, paginated **PDF** (A4, repeated
    table headers across page breaks, "Page N of M" footers; rendered in-app
    with CoreText, no browser round-trip) plus HTML + Markdown mirrors, and a
    **custody-log CSV/JSON** export, all wired into the existing Export sheet.
    The iOS viewer gains a read-only custody screen.
  - Vendored `ewfinfo` / `ewfverify` added to the TSK toolchain build.
- **Case reporting & export** (Tools ▸ Export…, ⇧⌘E) — generate an examiner
  report and data exports in one pass, written as a timestamped set into a
  chosen folder:
  - **Endpoint selection** — choose one, several, or all hosts; both the report
    and the data exports cover exactly the selected endpoints.
  - **Examiner report** (Markdown + HTML) — per-host profile, findings grouped
    by Cyber Kill Chain phase with ATT&CK tags, IOC matches, and a
    findings-anchored timeline excerpt. The HTML is print-ready (paginates
    cleanly from a browser's Print dialog). A **severity filter** chooses which
    severities the report includes (the raw data exports stay complete).
  - **Data exports** (CSV + JSON) of the timeline, findings, and IOC matches,
    with stable, documented schemas and per-host attribution.
  - Each export folder gets a `README.txt` documenting its contents. All
    timestamps are ISO-8601 / UTC. There is no in-app PDF renderer by design —
    the HTML report is print-ready, so open it in a browser and Print → Save as
    PDF.

## [0.1.0-beta.2] — 2026-06-06

### Added

- **iOS viewer companion** — open a `.strata` case on iPhone/iPad and review the
  overview, timeline, events, kill chain, lateral movement, filesystem, and IOCs
  (read-only; ingestion stays on macOS).
- **Evidence tree grouped by volume** — each filesystem (EFI/FAT, main NTFS,
  recovery NTFS, …) is its own node, so per-volume metadata (`$MFT`, `$LogFile`,
  …) no longer looks like duplicates.
- **"Hide slack" toggle** on the Evidence tab.

### Changed

- Major performance pass: AppModel rolls up and caches its derived collections,
  and views snapshot/derive heavy data off the render path — removing repeated
  main-thread sorts on million-row cases.
- Recent cases use security-scoped bookmarks; the force-directed lateral layout
  is capped on very large graphs; accessibility and contrast improvements.

### Fixed

- Timeline histogram drag-select coordinate skew and zero-width selections.
- IOC match table now defaults to chronological order and is sortable.
- Kill-chain inspector can be dismissed; level-0 events badge as INFO.
- Evidence tree no longer drops same-path (deleted vs live) entries; the
  selection revalidates on scope change; the tree no longer renders empty.
- iOS: filesystem browser navigates below root; lists are lazy/paged; newest-
  first paging; UTC timestamps; precise Sysmon filter.

[0.1.0-beta.2]: https://github.com/norbertbonnici/Strata/releases/tag/v0.1.0-beta.2

## [0.1.0-beta.1] — 2026-06-05

First public beta.

### Added

- Evidence ingestion: E01/EX01/S01, VHD/VHDX (KAPE `--vhd`), and raw `dd` images
  via The Sleuth Kit; loose KAPE/triage folders read directly off disk.
- Self-contained, vendored TSK + libyal toolchain (`libevtx`, `libregf`) built
  from source — no Homebrew or other runtime dependencies.
- Multi-host `.strata` case bundles with a recent-cases list.
- File-system enumeration (`tsk_loaddb` → SQLite via GRDB); recursive walk for
  loose folders.
- MACB timeline with a drag-to-select histogram and gap analysis (quiet periods
  and activity sessions).
- Windows event log (`.evtx`) and registry-hive parsing, projected into a typed
  host profile.
- 15 detection analyzers emitting ATT&CK-tagged findings into a Cyber Kill Chain
  view.
- IOC matching for IPs, domains, URLs, and hashes.
- Interactive lateral-movement graph: pan, zoom, drag nodes, and an optional
  force-directed layout.

### Known limitations

- Apple Silicon (arm64) only.
- Loose-folder timelines use collection-host timestamps; `$MFT`-based MACB is
  pending.
- `$FILE_NAME` timestamps / timestomping detection not yet implemented.
- No YARA or known-bad hashing yet.

[0.1.0-beta.1]: https://github.com/norbertbonnici/Strata/releases/tag/v0.1.0-beta.1
