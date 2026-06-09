# Changelog

All notable changes to Strata are documented here. The format loosely follows
[Keep a Changelog](https://keepachangelog.com/); versions correspond to git tags.

## [Unreleased]

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
  - **Chain-of-custody report** (HTML + Markdown) and a **custody-log CSV/JSON**
    export, wired into the existing Export sheet. The iOS viewer gains a
    read-only custody screen.
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
