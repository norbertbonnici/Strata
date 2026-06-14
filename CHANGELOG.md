# Changelog

All notable changes to Strata are documented here. The format loosely follows
[Keep a Changelog](https://keepachangelog.com/); versions correspond to git tags.

## [Unreleased]

### Added — macOS Unified Log, M6: integration (tab + timeline + analyzer)

The unified-log decoder is now wired into the app end-to-end — **the macOS
unified log finally appears in Strata**, the payoff of the M1–M5 decoder arc.

- **`AppModel.parseUnifiedLog()`** (macOS) discovers the diagnostics logs
  (durable **Persist** + short-term **Special**; Signpost/HighVolume skipped as
  low-signal + high-volume), the `timesync` database, and the **referenced**
  `.uuidtext`/`dsc` string catalogs, extracts them all via the existing
  loose/`icat`/`fsapfscat` closure, and assembles timestamped, message-bearing
  `UnifiedLogEntry`s off-main. Runs after `parseMac()` in `parseArtifacts()`.
- **`UnifiedLogAssembler`** (`StrataCore`) ties the layers together: walk each
  `.tracev3`'s chunks → catalog (M3) → firehose tracepoints (M4) → resolve +
  render via the string catalogs (M5) → `UnifiedLogEntry` with timestamp (M2),
  pid, level, process, and message. `referencedUUIDs` enumerates the catalog
  files to extract.
- **Unified Log tab** (`UnifiedLogView`, macOS — level-coloured, filterable,
  row-capped table + detail pane) + **iOS drill** (`UnifiedLogDrillView`), gated
  to `.macos` evidence. Persisted as `unifiedlog.json`; spliced onto the
  **timeline** (`TimelineSource.unifiedLog`, a default macOS source); reloads on
  case open.
- **`UnifiedLogAnalyzer`** (`StrataAnalysis`) — high-precision checks: `sudo`
  privilege escalation (T1548.003), `osascript`/AppleScript execution
  (T1059.002), and accepted SSH logins (T1021.004).
- **Per-entry subsystem/category** — `FirehoseItemDecoder` now parses the
  firehose **optional header deterministically** by flag (`has_current_aid` /
  `has_private_data` / `pc_id` / `has_large_offset` / `has_subsystem` /
  `has_rules` / `has_oversize`, order confirmed against the real image) instead
  of only anchoring on the descriptor block. That both locates the item block
  exactly (the anchor is now a fallback) and recovers the **subsystem
  identifier**, which the assembler resolves to `subsystem`/`category` strings
  via the catalog's per-process subsystem table. The header parse also accounts
  for the extra u16 that **absolute (`0x08`) / `0x0c`** format-string types carry,
  so subsystem now resolves for those high-volume buckets too (e.g. ~79% of
  `0x0c` tracepoints). **Validated on the real image:** all `has_subsystem`
  tracepoints of the resolvable types map to a real subsystem (e.g.
  `com.apple.kvs/Misc`) — 128,164 of one Persist file's 349,533 entries carry a
  subsystem.
- **Validated against the real macOS-12 image**: the assembler produces 22,186
  fully timestamped entries from one Special file with messages, process names,
  and subsystem/category resolved; both platforms build; 39 unit tests pass.
- **Known limits:** message/process coverage depends on the referenced
  `.uuidtext` being present (absolute/uuid-relative `flags 0x0c` ≈17% still need
  loaded-image resolution — deferred, since a wrong-image heuristic would harm
  forensic integrity); a busy **Persist** log is hundreds of thousands of
  entries → a large `unifiedlog.json` (same bracket as `events.json`).

### Added — Unified-log decode, M5b: argument items → rendered messages

The piece that turns a format string + raw arg bytes into the **readable log
message** — the whole point of the unified-log decode.

- **`FirehoseItemDecoder`** (`StrataCore`) decodes a tracepoint's argument items:
  `item`/`number_items`, then per-item `type`/`type_size` (+ `(offset,size)` for
  string/data items), then the value region. The flag-driven optional header is
  underdocumented, so instead of parsing it the decoder **anchors** on the
  self-describing descriptor block — scanning for the start whose descriptors
  parse in-bounds and whose value region is consumed exactly (preferring the
  format string's specifier count). Handles string/object, private/redacted
  (`<private>`), sensitive, and inline-number items.
- **`LogFormatter`** (`StrataCore`) renders the format string against the items:
  `%@`/`%s`, the integer family (`%d %u %x %o`, length modifiers), `%f`/`%c`/`%p`,
  `%%`, and Apple's `%{…}` annotations (`%{public}`/`%{private}`/`%{sensitive}`
  visibility, `%{errno}`/`%{BOOL}` hints). Unparseable specifiers are kept intact
  so a message is never lost.
- **`UnifiedLogStringCatalog.render(...)`** ties it together: resolve the format
  string (M5a) → decode items → render → `{process, library, message}`.
- **Validated against the real macOS-12 image**: real messages render fully —
  *"About to adopt persona BA08DA59-3A00-4EA5-869A-26B1137AA2CD"*, *"Adopted
  persona BA08DA59-… and copied context <UMUserPersonaContext: 0x7fd655110780>"*
  (2 args), *"Getting sync manager for lookup key=PersonalPersona
  storeType=NoEncryption container=<CKContainerID: …>"* (3 args), and shared-cache
  messages via the `dsc`. ~90% of resolvable tracepoints render cleanly; the rest
  are the absolute/uuid-relative (`flags 0x0c`) loaded-image gap (M6 follow-up).
  Synthetic byte-level unit tests cover the item decoder (single/multi/private
  args) + the formatter (specifiers, annotations, escapes, end-to-end via the
  catalog).

### Added — Unified-log decode, M5a: format-string catalogs (`.uuidtext` / `dsc`)

Parses the out-of-file string catalogs the unified log points at, and resolves a
tracepoint's **format string** + **emitting process name** — the inputs M5b needs
to render readable messages.

- **`UUIDTextParser`** / **`UUIDTextFile`** (`StrataCore`) parse a `.uuidtext`
  file (`/var/db/uuidtext/XX/YYYY…`, magic `0x66778899`): the entry range table +
  per-range format-string blocks + the trailing image path. `formatString(at:)`
  resolves a main-executable format string; `processName` is the image path leaf.
- **`DscParser`** / **`DscFile`** (`StrataCore`) parse a `dsc` shared-cache
  strings file (`/var/db/uuidtext/dsc/<uuid>`, magic `hcsd`, v2/Monterey+): the
  range + UUID tables. `resolve(offset:)` binary-searches the covering range →
  the shared-cache format string + owning library path.
- **`UnifiedLogStringCatalog`** (`StrataCore`) holds the loaded `.uuidtext`/`dsc`
  set and dispatches by the tracepoint's format-string-type flags
  (`flags & 0x0e`): `0x02` main-exe → the process's main `.uuidtext`, `0x04`
  shared-cache → the `dsc`; `0x08`/`0x0a`/`0x0c` (absolute / uuid-relative) keep
  the process name and defer the string to M5b's loaded-image resolution.
- **Validated against the real macOS-12 image**: real format strings resolve —
  e.g. `syncdefaultsd`'s *"Adopted persona %@ and copied context %@"* (main-exe)
  and shared-cache strings from `dsc` with library paths like
  `/usr/lib/system/libsystem_blocks.dylib`. The flag dispatch is clean on real
  data: **100%** of `shared-cache` (`0x04`) tracepoints resolved via the `dsc`,
  and all `main-exe` (`0x02`) tracepoints for a process resolved via its
  `.uuidtext` (≈83% of all tracepoints covered with just the one `dsc` + one
  `.uuidtext`; the rest are absolute/uuid-relative, M5b). Synthetic byte-level
  unit tests cover both parsers + the resolver dispatch. (`.uuidtext`/`dsc` live
  on the Data volume, so `fsapfscat` reads them fine — not sealed.)

This is M5a of the unified-log arc (M1 → M2 timesync → M3 catalog → M4 firehose →
**M5a string catalogs** → M5b message rendering → M6 tab/timeline/analyzer).

### Added — Unified-log decode, M4: firehose tracepoints → timestamped entries

Decodes the firehose chunks (`0x6001`) — the actual log records — into
`UnifiedLogEntry`s, joining M2 (time) and M3 (process/subsystem identity). This
is the first layer that produces real, timestamped log entries.

- **`FirehoseDecoder`** (`StrataCore`, pure Swift) decodes a firehose chunk's
  preamble (the emitting `(first,second)` proc-id pair, public-data size, base
  mach-continuous time) and walks its fixed-24-byte tracepoint headers
  (`data_size` bytes each, 8-byte aligned), emitting **`FirehoseTracepoint`**s.
  Absolute time is `base + ((deltaUpper<<32)|deltaLower)`; the process (PID/EUID)
  comes from the M3 catalog; activity type → event type, log type → level.
- **`TraceV3Parser.parse(_:sourceFile:timesyncByBoot:)`** now walks the top-level
  chunks in order (tracking the current catalog), decompresses each chunkset, and
  decodes every firehose chunk against that catalog, resolving each tracepoint's
  wall-clock through the timesync boot that matches the file header's boot UUID.
- **M4 scope:** entries carry timestamp, PID, event type and level. The
  `process`/`subsystem`/`category`/`message` fields stay empty until M5 resolves
  the out-of-file `.uuidtext`/`dsc` format strings; the `FirehoseTracepoint`
  carries the format-string location + raw data slice forward for that.
- **Validated against the real macOS-12 image**: 22,186 entries from one Special
  file (all in its boot window, 2025-03-24 08:41→09:35) and **349,533** from one
  Persist file (multi-day, 2025-03-21→22); the time math holds for both base=0
  and non-zero-base chunks; level/type distributions and 180–300 distinct PIDs
  per file are realistic. Synthetic byte-level unit tests cover the preamble +
  tracepoint walk, the upper/lower delta combination, activity/level mapping,
  zero-padding termination, and the partial-entry projection. (Cross-checking
  rendered output against `log show` waits on M5 + reconstructing a
  `.logarchive`.)

This is M4 of the unified-log arc (M1 harness → M2 timesync → M3 catalog →
**M4 firehose** → M5 message resolution → M6 tab/timeline/analyzer).

### Added — Unified-log decode, M3: header + catalog (`.tracev3`)

Decodes the two top-level metadata chunks of a `.tracev3` file — the layers that
say *which boot, which process, which subsystem* a log entry belongs to. Builds
on M2 (timesync); together they give the time and identity context the firehose
tracepoints (M4) reference.

- **`TraceV3Header`** (`StrataCore`) — `TraceV3Parser.header(of:)` parses the
  `0x1000` header chunk and its tagged sub-records: boot UUID (`0x6102`), mach
  timebase + continuous-time base, OS build + hardware model (`0x6101`), and the
  timezone path + bias (`0x6103`). The **boot UUID ties a file to its
  `TimesyncBoot`** session.
- **`TraceV3Catalog`** / **`CatalogProcessInfo`** / **`CatalogSubchunk`**
  (`StrataCore`) — `TraceV3Parser.catalog(fromData:)` / `catalogs(of:)` decode
  the `0x600B` catalog: the UUID array, the variable-length process-info entries
  (keyed by the `(first,second)` proc-id pair → PID/EUID, main-exe + `dsc` UUID
  indices, 16-byte loaded-image sub-entries, and the 6-byte subsystem/category
  string map a tracepoint resolves through), and the subchunk continuous-time
  windows. `processInfo(first:second:)` is the tracepoint→process join.
- **Validated against the real macOS-12 image**: header boot UUID
  (`224489B3…` / `E569F361…`) **confirmed present in the M2 timesync**; build
  `21H1320`, model `MacBookAir7,2`, tz `Europe/Tallinn`; 94 catalogs parsed from
  one Persist file with every process-info entry resolving to real subsystems
  (`com.apple.network/connection`, `powerd/sleepWake`, …) and all entries filling
  the entry region exactly (the 16-byte uuid-entry stride was brute-forced
  against the real layout). Synthetic byte-level unit tests cover the header
  sub-records, the catalog UUID array / NUL-string pool / variable proc-info
  walk (with and without uuid sub-entries) / subchunk windows.

This is M3 of the unified-log arc (M1 harness → M2 timesync → **M3 catalog** →
M4 firehose → M5 message resolution → M6 tab/timeline/analyzer).

### Added — Unified-log decode, M2: timesync (continuous-time → wall-clock)

Groundwork for decoding the macOS **unified log** (`.tracev3`). The log stores
tracepoint times as mach-continuous time (monotonic ticks since boot); the
**timesync** database is what converts those to real dates.

- **`TimesyncParser`** (`StrataCore`, pure Swift, no vendored tool) parses
  `/var/db/diagnostics/timesync/*.timesync` — boot records (signature `0xBBB0`:
  boot UUID, mach timebase numerator/denominator, boot walltime) followed by
  their periodic sync records (signature `"Ts "`: continuous-time → walltime
  anchors). One file holds several boot sessions; `parseAll` merges files keyed
  by boot UUID.
- **`TimesyncBoot`** (`StrataCore`, `Codable`) exposes
  `walltime(forContinuousTime:)` — picks the latest anchor at or before the
  continuous time and adds the timebase-scaled delta (the boot itself is the
  implicit `ct 0 → bootTime` anchor).
- **Validated against the real macOS-12 image**: 4 boot sessions recovered from
  one `.timesync`, boot times 2025-03-21…24 (matching the evidence), every sync
  anchor self-converts with 0 ns error. Synthetic byte-level unit tests cover
  framing, nearest-anchor selection, Apple-Silicon 125/3 timebase scaling, and
  multi-boot files.

This is M2 of the multi-PR unified-log arc (M1 real-data harness → M2 timesync →
M3 catalog → M4 firehose → M5 message resolution → M6 tab/timeline/analyzer).

### Added — APFS file-content extraction (`fsapfscat`) — macOS analyzers run on APFS images

The macOS APFS ingest path gave the file tree + timeline but no file *bytes*, so
the macOS analyzers silently skipped APFS *images*. They now run end-to-end:

- **`fsapfscat`** — a small custom C tool (`scripts/fsapfscat.c`) linking the
  vendored **libfsapfs** (built + statically linked by `build-tsk.sh`): opens the
  APFS container at the byte offset, resolves a volume-relative path, and writes
  the file's bytes to stdout — the macOS-image equivalent of TSK's `icat`. Pure
  byte-level read (no host-OS mount), FileVault-capable (`-p`/`-r`). **Validated
  against the real macOS-27 image** (extracted `/private/etc/hosts` byte-perfect).
- **`FsApfsExtractor`** (`StrataTSK`, macOS) — Swift actor wrapping `fsapfscat`,
  mirroring `TSKFileExtractor`.
- **`EvidenceKind.apfs`** — the `.ingestionCrashed` fallback now reclassifies the
  host as `.apfs` and records `Evidence.apfsRawURL` (the source raw, or the
  `ewfexport` scratch for an E01). The APFS tree + volumes persist as JSON
  (`apfsfiles/apfsvolumes.json`; `FileEntry`/`VolumeInfo` are now `Codable`) and
  reload on case open (there's no `tsk.db`).
- **`parseMac` + `parseBrowserHistory`** extend their extract closures with an
  `.apfs` branch (offset from `VolumeInfo`, volume index from `fsID`, path from
  `fullPath`), so Launch Items / Quarantine / Persistence / FSEvents / host info /
  shell history / Safari+Chrome+Firefox all parse from an APFS image.
- **Known limit:** the **sealed System volume**'s files live in a snapshot, so
  libfsapfs reads 0 bytes for them (e.g. `SystemVersion.plist`); user-data
  artifacts on the Data volume extract fine. **Bundling** `fsapfscat` into the
  app (Xcode Copy-Files phase) is a manual step, like `fsapfsinfo`.
- Tested (`BodyfileParserTests`, `FsApfsIngestorMappingTests`, `ApfsEvidenceTests`);
  macOS + iOS build.

### Added — macOS APFS ingest path (via libfsapfs)

Strata can now ingest the macOS APFS images The Sleuth Kit crashes on. When
`tsk_loaddb` SIGABRTs (the APFS case), `AppModel.ingest` falls back to a new
libfsapfs path instead of failing:

- **`BodyfileParser` + `BodyfileEntry`** (`StrataCore`) — pure decoder for the
  TSK `mactime` **bodyfile** (`fsapfsinfo -H -B`): the 11 pipe-delimited fields
  (`MD5|name|inode|mode|UID|GID|size|atime|mtime|ctime|crtime`) → a typed record
  with the MACB set, handling libfsapfs **nanosecond** times (`<sec>.<ns>`),
  symlink `name -> target` splitting, and paths containing `|` (anchors on the
  9 fixed trailing fields). Pinned against **real** `fsapfsinfo` lines from a
  macOS-27 image.
- **`FsApfsIngestor`** (`StrataTSK`, macOS) — orchestrates the path: convert an
  E01 to raw with `ewfexport` (a raw/dd image is used directly), find the APFS
  container offset via `mmls`, enumerate volumes, then run
  `fsapfsinfo -f <i> -H -B` per volume and map the bodyfile → `FileEntry`s
  grouped per volume (`fsID`) + a `VolumeInfo` each. No `tsk.db` is produced
  (like the loose-folder path); it strips libfsapfs' `/{volume-uuid}/` path
  prefix. Wired into `ingest()` as the `.ingestionCrashed` fallback.
- **Gives the file tree + MACB timeline.** Per-file **content extraction** (so
  the artifact parsers can run on the recovered files) is the next step —
  `fsapfsinfo -H -B` lists + times but doesn't dump bytes. **Known limit:**
  enumerating a large Data volume over a slow bus can take a while (it walks the
  whole catalog); validated on the container + Recovery volume, the full-volume
  run is the user's first real exercise.
- macOS + iOS build; `BodyfileParserTests` + `FsApfsIngestorMappingTests` (pinned
  to real `-H -B` lines) pass.

### Added — Vendor libfsapfs (APFS reader) for macOS images

- **The Sleuth Kit crashes on real macOS APFS.** Validated against a real Mac
  E01 (macOS 27, 6-volume APFS container): `tsk_loaddb` **aborts (SIGABRT, in
  `APFSJObject`)** partway through parsing — a TSK APFS-parser defect, not
  encryption (it reaches file objects first) and not a Strata bug. So Mac
  evidence can't go through `tsk_loaddb`.
- **`build-tsk.sh` now also builds libyal's `libfsapfs` (`fsapfsinfo`)** — an
  actively-maintained, dedicated APFS reader — plus libewf's **`ewfexport`**.
  `fsapfsinfo` reads a *raw* image at a volume offset (`-o`), lists the
  container's volumes + full file hierarchy, can emit a TSK-style **bodyfile**
  (`-B`, with MACB times), and supports **FileVault** (`-p`/`-r` password). It
  has no EWF glue, so the macOS path converts an E01 to raw with `ewfexport`
  first. **Validated end-to-end** on the real image: `fsapfsinfo` cleanly
  enumerated all 6 volumes (Macintosh HD / Preboot / Recovery / Data / …) and
  walked the file tree where `tsk_loaddb` crashed.
- **Pending (follow-up phases):** the macOS ingest path itself
  (`ewfexport` → raw → `fsapfsinfo -B` bodyfile → `FileEntry`/timeline; file
  *content* extraction for artifact parsing is a further step, since
  `fsapfsinfo` lists + times but doesn't dump file bytes).

### Added — Unified Logs (`.tracev3`) Phase 1: container decoder

- **`TraceV3Parser` + `AppleLZ4`** (`StrataCore`) — the foundation of the macOS
  unified-log decoder. `.tracev3` is a flat sequence of chunks
  (`tag|subtag|size` 16-byte preamble, 8-byte aligned); `TraceV3Parser` parses
  that framing (size-driven, so unknown chunks are skipped, not fatal),
  enumerates the top-level header / catalog / **chunkset** chunks, and
  decompresses each chunkset's Apple-LZ4 block stream (`bv41` compressed /
  `bv4-` stored / `bv4$` end, inflated through `COMPRESSION_LZ4_RAW`) to tally
  the inner firehose / oversize / statedump / simpledump chunks into a
  `Structure`. `UnifiedLogEntry` (`StrataCore`) is the target record shape.
- **Scope:** this phase is the *container layer only* — it confirms the file
  parses and counts its chunks. It does **not** yet emit `UnifiedLogEntry`s
  (`parse()` returns `[]`) and adds no tab. Decoding firehose tracepoints into
  entries needs the catalog + timesync (Phase 2); rendering messages needs the
  out-of-file `.uuidtext` / `dsc` string resolution (Phase 3).
- Synthetic-fixture tested (`AppleLZ4Tests`, `TraceV3FramingTests`: framing +
  alignment, `bv4-`/`bv41` decompression incl. a real Compression round-trip,
  chunk tally); macOS + iOS both build. **Not yet validated against a real
  `.tracev3`** (same standing caveat as the rest of the macOS arc).

### Fixed — distinguish a tsk_loaddb crash from a clean error

- `TSKImageIngestor` now checks `terminationReason`: when `tsk_loaddb` is killed
  by a **signal** (e.g. `SIGABRT` from The Sleuth Kit's APFS parser crashing on a
  macOS image), it throws the new `TSKError.ingestionCrashed(signal:…)` —
  *"tsk_loaddb crashed (signal 6 / SIGABRT) … a known Sleuth Kit limitation
  parsing some APFS (macOS) volumes"* — instead of the misleading
  `ingestionFailed(exitCode: 6)` ("exit 6"), which conflated the signal number
  with an exit code. (TSK's `terminationStatus` is the *signal number* on a
  signal kill, not a status.)

### Added — macOS shell history

- **macOS zsh/bash history** — `parseMac()` now collects each user's
  `~/Library`-adjacent `.zsh_history` / `.bash_history` (under `/Users/`) and
  parses them with the existing `ShellHistoryParser` (extended-zsh timestamps,
  bash `HISTTIMEFORMAT`), folding them into the shared `shellHistory` collection
  alongside the Linux `/home/` + `/root/` history. `ShellHistoryParser.user(
  fromPath:)` learned the macOS `/Users/<user>/` layout.
- **Shell History is now a multi-OS tab.** zsh/bash history exists on both Linux
  and macOS, so the tab is shown for *either* via a new
  `AppModel.shows(anyOf:)`; `ContentView.isVisible` centralises that rule for the
  sidebar filter + the selection clamp, and the iOS More-tab row gates the same
  way. The macOS shell history also feeds the timeline + `ShellHistoryAnalyzer`
  unchanged (both were already OS-agnostic).
- Unit-tested (`ShellHistoryParser.user(fromPath:)` macOS case); macOS + iOS
  both build.

### Added — Safari browser history

- **Safari history** — `BrowserHistoryParser` now reads Safari's
  `~/Library/Safari/History.db` (SQLite) alongside the existing Chromium
  `History` and Firefox `places.sqlite`. Safari splits URLs (`history_items`)
  from per-visit rows (`history_visits`); we collapse to one row per URL using
  its latest visit (SQLite's `MAX()` bare-column rule carries the matching
  title), decoding the `CFAbsoluteTime` `visit_time` via the new
  `BrowserHistoryEntry.safariTime`. Surfaces in the existing cross-platform
  **Browser History** tab + timeline source + `BrowserHistoryAnalyzer`; no new
  tab. Discovery gates the `History.db` name on a `/Safari/` path so unrelated
  databases of that name aren't probed. **Known limit:** Safari downloads
  (`Downloads.plist`, a separate file) aren't parsed.
- Unit-tested end to end against a synthetic Safari SQLite fixture
  (`BrowserHistoryParserTests.parsesSafariHistory`) plus the `safariTime`
  decoder + path-classification helpers; macOS + iOS both build.

### Added — macOS FSEvents change history

- **`FSEventsParser` + `FSEventRecord`** (`StrataCore`) — a pure-Swift decoder of
  the macOS FSEvents store (`/.fseventsd/`), the kernel's coalesced filesystem-
  change journal (the macOS analogue of the NTFS USN journal). Inflates each
  gzip log (reusing `GzipDecoder`) and decodes the **DLS v1 / v2** pages → one
  record per path with its coalesced change flags (Created/Removed/Renamed/…)
  and monotonic event ID; DLS v2 also yields the node ID (inode). Parsed in
  `AppModel.parseMac()` with the inflate + decode run **off-main** (a busy store
  is many MB); persisted as `fsevents.json`.
- **No timeline splice.** FSEvents records carry only an event ID, not a
  timestamp, so — like the WMI carve — they are surfaced in their own tab and
  scored, but not placed on the super-timeline (we don't fabricate times).
- **`FSEventsAnalyzer`** — flags created-then-removed payloads in staging paths
  (the drop-run-delete footprint, T1070.004) and launchd-directory plist
  writes recoverable even after the plist is gone (T1543).
- **FSEvents tab** — a fourth `.macos`-gated tab (macOS `FSEventsView` with a
  "Changes only" filter + iOS `FSEventsDrillView`); `fsEvents` joined the
  `AppModel` derived rollup + `AnalysisContext`.
- Unit-tested with synthetic DLS v1/v2 pages (`FSEventsParserTests`,
  `FSEventsAnalyzerTests`); macOS + iOS both build.

### Added — macOS persistence sweep (non-launchd)

- **`MacPersistenceParser` + `MacPersistenceItem`** (`StrataMac` / `StrataCore`) —
  a pure-Swift sweep of the macOS auto-run / event-triggered locations *outside*
  launchd: **cron** (`/etc/crontab` 6-field + per-user spool 5-field, `@reboot`
  nicknames), **site-local `periodic`** (`/usr/local/etc/periodic/*` — Apple-stock
  `/etc/periodic` is deliberately not swept, it would be all-noise), **`emond`**
  rule `RunCommand` actions, **login/logout hooks** (`com.apple.loginwindow`),
  **`rc` scripts** (`rc.local`/`rc.common`), and **configuration profiles**
  (`.mobileconfig` / Managed Preferences). Parsed in `AppModel.parseMac()`,
  persisted as `macpersistence.json`.
- **`MacPersistenceSweepAnalyzer`** — high-signal by construction: `emond` rules
  and login/logout hooks are flagged on presence (deprecated, abuse-only
  mechanisms; T1546.014 / T1037.002), `rc.local` on presence (macOS ships none;
  T1037.004), and cron / periodic only when the command is suspicious (`@reboot`,
  staging path, or interpreter/downloader; T1053.003 / T1053). Configuration
  profiles surface in the tab but are never flagged (benign on managed fleets).
- **Persistence tab** — a third `.macos`-gated tab (macOS `MacPersistenceView` +
  iOS `MacPersistenceDrillView`), alongside Launch Items and Quarantine;
  `macPersistence` joined the `AppModel` derived rollup + `AnalysisContext`.
- Unit-tested end to end (`MacPersistenceParserTests`,
  `MacPersistenceSweepAnalyzerTests`); macOS + iOS both build.

### Added — macOS evidence support (`.macos` OSFamily + dedicated tabs)

- **`.macos` OS detection** — `OSFamily` gains a `.macos` case, detected from the
  volume fs-type (APFS / HFS+) or, for loose collections, a file-tree sniff where
  a decisive macOS-only marker (`/System/Library/`, `/Library/Preferences/`,
  `.app/Contents/`, `/private/var/db/`) vetoes the weaker `/Users/`⇒Windows and
  `/etc/`,`/var/log/`⇒Linux guesses macOS would otherwise trip. A pure-Mac image
  now hides every Windows and Linux tab instead of showing them all.
- **macOS host profile** — `MacHostInfoParser` (`StrataMac`) folds
  `SystemVersion.plist`, the SystemConfiguration `preferences.plist` /
  `NetworkInterfaces.plist`, and the dslocal user plists into a `MacHostInfo`
  (`StrataCore`); `HostProfile.derive(fromMac:)` drives the **Overview** host card
  (OS/version/build, computer name, primary user, IPs). Parsed by
  `AppModel.parseMac()`, persisted as `macinfo.json`.
- **Launch Items + Quarantine tabs** — the already-parsed launchd jobs and the
  LaunchServices download-provenance store now have dedicated, `.macos`-gated
  tabs: macOS `LaunchItemsView` / `QuarantineView` (filter + table/detail split +
  empty-state Parse) and iOS `LaunchItemsDrillView` / `QuarantineDrillView`
  (paged lists). `launchItems` / `quarantine` joined the `AppModel` derived
  rollup with scoped + count accessors.
- Validated: macOS + iOS both build; OSFamily detection and the
  `MacHostInfoParser` projection are unit-tested (`OSFamilyTests`,
  `MacHostInfoParserTests`). **Known limit:** APFS readability depends on the
  vendored TSK enumerating the volume (a FileVault-encrypted APFS won't), still to
  be confirmed end-to-end on a real Mac image.

### Added — On-device AI findings summary (Apple Intelligence)

- **AI executive summary** — a new `StrataAI/FindingsSummarizer` generates a
  concise executive summary of the case detection findings **entirely on-device**
  via Apple Intelligence (FoundationModels `SystemLanguageModel`), so no evidence
  leaves the host. Uses `.permissiveContentTransformations` guardrails (forensic
  content trips the defaults) and Apple's chunk-then-combine recipe for large
  finding sets. Availability is surfaced (device ineligible / Apple Intelligence
  off / model downloading) so the control disables with a reason.
- The summary is **case-wide** (combined "All" scope + correlation findings),
  persisted to `summary.json`, recorded in the custody ledger (new `.summarized`
  action), and threaded into the examiner report as an **Executive Summary**
  section (HTML + Markdown).
- **macOS generates**, via a Generate/Regenerate control on the **Kill Chain** and
  **Overview** tabs (`CaseSummaryCard`); the **iOS** viewer displays the persisted
  summary read-only. **Known limits:** one case-wide summary (per-host is future
  work); plain-text, rendered verbatim; requires an Apple-Intelligence-capable Mac.

## [0.1.0-beta.3] — 2026-06-11

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
