# Strata

A native **macOS DFIR triage tool** (with an iOS viewer) for **Windows, Linux,
and macOS** evidence. Strata ingests a disk image or a loose collection folder,
enumerates the file system, parses the OS's triage artifacts, builds a MACB
super-timeline, and surfaces attacker activity through **61 ATT&CK-tagged
detection analyzers**, a Cyber Kill Chain view, an interactive lateral-movement
graph, and IOC matching — and can write an **on-device, evidence-validated AI
case summary**.

All forensic file handling is a self-contained, vendored build of
[The Sleuth Kit](https://www.sleuthkit.org/) + the
[libyal](https://github.com/libyal) toolchain (`libevtx`, `libregf`, `libscca`,
`liblnk`, `libolecf`, `libesedb`, `libfsapfs`, `libewf`, `libvhdi`, `libvmdk`),
statically linked. **There is no Homebrew or runtime dependency.**

- **macOS app** = the full pipeline (ingest + analyze). Non-sandboxed; reads raw
  disk images via Full Disk Access.
- **iOS app** = a read-only viewer for already-built `.strata` cases.

## What it does

### Ingestion

- **Disk images** — E01/EX01/S01 (`libewf`), VHD/VHDX (`libvhdi`), VMDK
  (`libvmdk`), and raw `dd`.
- **Loose collections** — KAPE / UAC triage folders (no image container) walked
  directly off disk.
- **Filesystems** — NTFS and ext2/3/4 via TSK; **APFS / HFS+** via a vendored
  `libfsapfs` + a custom `fsapfscat` (TSK's own APFS parser crashes on real
  macOS volumes). FileVault volumes unlock in-memory (credential never persisted).
- **Multi-host cases** — a `.strata` bundle holds one or more hosts with
  examiner / acquisition metadata; reopen from a recent list or a Case Library
  folder (which can live in iCloud Drive or on a share).

The evidence OS is auto-detected (NTFS ⇒ Windows, ext ⇒ Linux, APFS/HFS+ ⇒
macOS), and artifact tabs that don't apply to it are hidden.

### Artifacts

**Windows** — Event Logs (`.evtx`), registry hives (with a regedit-style
explorer), Prefetch, Amcache, Shimcache, LNK shortcuts, JumpLists, the USN
change journal, a pure-Swift `$MFT` parser (with `$SI`/`$FN` timestomping
detection), SRUM, WMI event-subscription persistence, and Recycle Bin recovery.

**Linux** — auth/secure logs, the **systemd journal** (`journald` binary
decoder), auditd, syslog, wtmp/btmp/lastlog, per-user shell history, persistence
(cron, systemd units/timers, ld.so.preload, autostart, rc/init), web-server
access logs, package history, and SSH trust + privilege (authorized_keys,
sudoers, …). Validated end-to-end against a real Ubuntu ext4 image.

**macOS** — a full triage suite reading APFS content directly: the **unified
log** (`.tracev3`), FSEvents, **TCC**, **KnowledgeC**, launch items + a
non-launchd persistence sweep, quarantine + **download origins**
(`kMDItemWhereFroms`), **Messages**, **Mail**, **Background Task Management**,
kernel + system **extensions**, **network & devices** (Wi-Fi / DHCP / Bluetooth
/ Time Machine / iOS pairings), QuickLook & Trash, document versions,
notifications, **Powerlog** (process execution with PIDs), configuration
posture, install history, security events (Gatekeeper / XProtect), recent items,
and a signature **file carver** that recovers deleted files from unallocated
space (including the sealed System snapshot and locked FileVault volumes).

**Cross-OS** — web-browser history (Chromium / Firefox / Safari).

### Analysis

- **Super-timeline** unifying file-system MACB with ~30+ artifact sources
  (registry writes, prefetch, USN, SRUM, browser, `$MFT`, messages, mail,
  powerlog, …), a drag-to-select histogram usable on million-row datasets, and
  **gap / session analysis** that surfaces quiet periods and operator bursts.
- **61 detection analyzers** emitting ATT&CK-tagged `Finding`s into the
  **Cyber Kill Chain**, with analyst **annotations** (bookmarks, tags, narrative).
- **Interactive lateral-movement graph** from remote-logon events.
- **IOC matching** (IPs / domains / URLs / hashes) and **global search** across
  files, events, registry, timeline, and findings.
- **Multi-host correlation** — shared IOC / pivoting source IP / reused account
  across two or more hosts.
- **Tiered CTI enrichment** — a **NSRL → MISP / OpenCTI → VirusTotal** waterfall
  that short-circuits on the first definitive verdict; per-instance credentials
  in the Keychain; strictly opt-in (nothing leaves the host unless enabled).

### AI case summary

Generate a factual, kill-chain-structured **executive summary** of a case's
findings. Every claim is **validated against real evidence** — the model can
only cite findings that exist, phantom IDs and invented paths are stripped or
flagged, and severity/phase come from the cited findings. **Sovereignty is a
setting, not a rewrite:** the same validated pipeline runs **on-device** (Apple
Intelligence, nothing leaves the host), via **Apple Private Cloud Compute**, or
through a credentialed **third-party cloud** model — egress is gated, labeled,
and recorded in the chain of custody, and only finding summaries ever leave.

### Reporting & custody

Examiner report (HTML / Markdown) and CSV/JSON data exports; a paginated
**chain-of-custody PDF** with acquisition metadata, source hashes + verification,
and an append-only custody ledger.

## Requirements

- **Apple Silicon Mac, macOS 26.5 or later** for the app. (The on-device AI layer
  links the current FoundationModels framework, which set the deployment target;
  the **Apple Private Cloud Compute** summary tier additionally needs macOS 27.)
- Grant **Full Disk Access** on first launch (System Settings ▸ Privacy &
  Security) — Strata reads raw disk images and can't be sandboxed.

## Building

This is an Xcode project (`Strata.xcodeproj`), one multiplatform target.

### 1. Build the vendored TSK toolchain

The binaries are **not checked in** (`Vendor/tsk/` is git-ignored). The script
downloads pinned source for TSK + the libyal libraries and compiles them
statically against the macOS SDK; only the Xcode Command Line Tools are needed.

```sh
scripts/build-tsk.sh            # host arch (arm64)
scripts/build-tsk.sh universal  # build both arches, lipo into bin/universal/
```

### 2. Build the app

```sh
xcodebuild build -project Strata.xcodeproj -scheme Strata -destination 'platform=macOS'
xcodebuild build -project Strata.xcodeproj -scheme Strata -destination 'generic/platform=iOS Simulator'
xcodebuild test  -project Strata.xcodeproj -scheme Strata -destination 'platform=macOS' -only-testing:StrataTests
```

Or open `Strata.xcodeproj` and run the **Strata** scheme. The vendored binaries
are copied into the app bundle.

### 3. Release (Developer ID + notarization)

Because Strata reads raw disk images it can't be sandboxed or shipped through the
App Store; the only clean distribution path is Developer ID + notarization:

```sh
scripts/release.sh 0.1.0-beta.4   # archive → sign → notarize → staple → dmg
```

Prereqs: a Developer ID Application certificate and a notarytool keychain profile
(`strata-notary`).

## Layout

Source is partitioned by OS family (see [`ARCHITECTURE.md`](ARCHITECTURE.md) for
the "where does this go?" decision tree):

| Path | Holds |
|------|-------|
| `Strata/StrataCore/` | Cross-cutting value types (`FileEntry`, `TimelineEvent`, `IOC`, …) + utilities (hashing, gzip/LZ4, byte parsers shared across OSes) |
| `Strata/Platforms/<Windows\|macOS\|Linux\|Shared>/{Parsers,Models}/` | OS-specific artifact parsers + their value types |
| `Strata/StrataTSK/` | Vendored-TSK ingest (`tsk_loaddb` → SQLite via GRDB, `icat`, the APFS path) |
| `Strata/StrataAnalysis/Analyzers/<OS\|CrossPlatform>/` | The 61 analyzers + `AnalysisEngine`, IOC matcher, lateral graph, correlation |
| `Strata/StrataAI/` | On-device + cloud inference backends, the findings summarizer, evidence-reference validator |
| `Strata/StrataCTI/`, `StrataReport/`, `StrataSearch/`, `StrataTimeline/` | CTI enrichment, reporting/export, global search, timeline builders |
| `Strata/StrataApp/` | The SwiftUI app — `AppModel` (split into per-concern extensions) + `Views/<OS>/` + `Views/iOS/` |

## Status & known limits

Two betas shipped early; **beta 4** is the current release. The full pipeline is
in use across Windows, Linux, and macOS evidence, validated against real images.
Some decoders are still validated against synthetic fixtures only (Shimcache,
parts of SRUM/USN/JumpList) — see `CHANGELOG.md` and per-release notes in
`docs/releases/`. The FileVault unlock path is implemented but not yet validated
against a real encrypted image; journald XZ/ZSTD-compressed values are skipped.

## Feedback

Please file issues at <https://github.com/norbertbonnici/Strata/issues>.
