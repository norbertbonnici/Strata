# Strata

A native macOS DFIR triage tool. Strata ingests a Windows disk image or KAPE
collection, enumerates the file system, parses Windows event logs and registry
hives, builds a MACB timeline, and runs a set of detection analyzers that tag
attacker activity onto a Cyber Kill Chain view.

The forensic file handling is done by a self-contained build of
[The Sleuth Kit](https://www.sleuthkit.org/) (TSK) and the
[libyal](https://github.com/libyal) toolchain (`libevtx`, `libregf`), all
statically linked and vendored — **there is no Homebrew or other runtime
dependency**.

## What it does

- **Evidence ingestion** — E01/EX01/S01, VHD/VHDX (KAPE `--vhd`), and raw `dd`
  images go through TSK; **loose KAPE/triage folders** (no image container) are
  walked directly off disk. Both feed the same downstream pipeline.
- **Multi-host cases** — a `.strata` bundle holds one or more hosts. Add hosts,
  reopen recent cases, keep examiner/case metadata.
- **File system enumeration** via `tsk_loaddb` into SQLite (images), read back
  with GRDB; loose folders are enumerated with a direct recursive walk.
- **MACB timeline** expanded from NTFS `$STANDARD_INFORMATION` timestamps, with
  a drag-to-select histogram usable on million-row datasets and **gap analysis**
  that surfaces quiet periods (missing telemetry, powered-off windows) and
  bursts of interactive operator activity.
- **Windows Event Logs** parsed from `.evtx` via `evtxexport`.
- **Registry hives** parsed via `regfexport`, projected into a typed
  **host profile** (hostname, domain, OS build, install/shutdown times, primary
  user, time zone, IPs).
- **Detection analyzers** — 15 independent rules (logon failures/success,
  PowerShell, process creation, service install, scheduled tasks, log clearing,
  persistence files, Run keys, services-registry persistence, USB history,
  Impacket-style remote exec, RMM tooling, password spray, credential pivots)
  that emit ATT&CK-tagged `Finding`s into the kill-chain phases.
- **IOC matching** — paste IPs, domains, URLs, and hashes; matches are scanned
  across logon fields and timeline/event data.
- **Interactive lateral-movement graph** built from remote logon events
  (Security 4624/4625, logon types 3/7/8/10): pan, zoom, drag nodes, and an
  optional force-directed layout. Click a host for its inbound/outbound logons.

## UI

A SwiftUI app (macOS 14+) with a sidebar: **Overview**, **Evidence**,
**Timeline**, **Events**, **Lateral**, **Kill Chain**, **IOCs**.

## Layout

| Module            | Responsibility                                                        |
|-------------------|-----------------------------------------------------------------------|
| `StrataCore`      | Shared value types: `FileEntry`, `TimelineEvent`, `EventLogRecord`, `RegistryValue`, `IOC`, `HostProfile`, case + kill-chain models |
| `StrataTSK`       | Locate vendored TSK binaries, run `tsk_loaddb`, read its SQLite via GRDB; KAPE source classification, image extraction, and direct loose-folder walk |
| `StrataEVTX`      | Parse `.evtx` event logs by shelling out to `evtxexport`              |
| `StrataRegistry`  | Parse registry hives via `regfexport`                                 |
| `StrataTimeline`  | Expand MACB timestamps into timeline events; gap / session analysis   |
| `StrataAnalysis`  | `Analyzer` protocol, `AnalysisEngine`, the analyzer set, IOC matcher, lateral graph |
| `StrataApp`       | SwiftUI app: sidebar, evidence tree, timeline histogram, events, kill chain, IOC and enrichment views |

## Building

### 1. Build the TSK toolchain

The vendored binaries are **not checked in** (`Vendor/tsk/` is git-ignored), so
build them first. The script downloads pinned source for TSK, `libewf` (E01),
`libvhdi` (VHD/VHDX), `libvmdk` (VMDK), `libevtx`, and `libregf`, then compiles
them statically against the macOS SDK. Only the Xcode Command Line Tools are
required at build time.

```sh
scripts/build-tsk.sh            # host arch
scripts/build-tsk.sh arm64
scripts/build-tsk.sh x86_64
scripts/build-tsk.sh universal  # build both, lipo into Vendor/tsk/bin/universal/
```

Output lands in `Vendor/tsk/bin/<arch>/` (`tsk_loaddb`, `fls`, `icat`,
`evtxexport`, `regfexport`, …).

### 2. Build the app

Open `Strata.xcodeproj` in Xcode and build/run the **Strata** scheme. The
vendored binaries are copied into the app bundle.

Because Strata reads raw disk images it **cannot be sandboxed**. For a shippable
build, sign with a Developer ID, **notarize it**, and grant the app **Full Disk
Access** (System Settings → Privacy & Security). Raw device reads may
additionally need a privileged helper via `SMAppService`.

## Notes & rough edges

- Timestamps are NTFS `$STANDARD_INFORMATION` times. `$FILE_NAME` (`$FN`) times
  and full timestomping detection are not yet implemented.
- The TSK SQLite schema is read with raw SQL against TSK 4.x column names.
- `build-tsk.sh` patches two TSK quirks: a `libewf` symbol rename in current
  experimental releases, and the partition-walk aborting on no-filesystem GPT
  partitions (e.g. the Microsoft Reserved Partition) before reaching the NTFS
  volume.
- libyal "experimental"/"alpha" release tags rotate by date; if a download
  404s, bump the matching `*_VERSION` env var to a current tag.

## Roadmap

- True NTFS MACB for loose folders by parsing a collected `$MFT` (the direct
  walk currently surfaces the collection host's modified/created times only).
- `$FILE_NAME` timestamps and timestomping detection.
- YARA scanning and known-bad hash matching.
