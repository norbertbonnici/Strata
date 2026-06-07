# CLAUDE.md

Operational context for working on **Strata**. Read this first.

## What Strata is

A native macOS DFIR triage tool (with an iOS companion viewer). It ingests a
Windows disk image or KAPE collection, enumerates the file system, parses event
logs + registry hives, builds a MACB timeline, and surfaces attacker activity
through ATT&CK-tagged detection analyzers, a Cyber Kill Chain view, an
interactive lateral-movement graph, and IOC matching.

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
| `StrataTimeline` | MACB timeline + gap/session analysis |
| `StrataAnalysis` | `Analyzer` protocol, `AnalysisEngine`, **15 analyzers**, IOC matcher, lateral graph |
| `StrataApp` | SwiftUI app. `AppModel` (the store), `CaseStore` (.strata bundle layout), `CaseLibrary`, `RecentCases`, `Views/` (macOS) + `Views/iOS/` |

`.strata` case bundle = a directory: `case.json`, `hosts.json`,
`hosts/<uuid>/{tsk.db, events.json, registry.json, findings.json, iocmatches.json}`.
Registered as a **package UTI** (`com.bonnicilabs.strata-case`) so Finder/Files
treat it as one item. The macOS-only ingest code is gated `#if os(macOS)`.

## Conventions & gotchas (hard-won — don't relearn these)

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
registry parsing → host profile, 15 ATT&CK analyzers → kill chain, IOC matching,
interactive lateral graph, multi-host `.strata` cases, iOS viewer, Case
Library / iCloud-Drive sync. Two betas shipped. A full 56-issue view review was
completed and remediated.

## Roadmap

### Known pending / deferred
- **True NTFS MACB for loose folders** via a collected `$MFT` (loose walk
  currently uses collection-host timestamps).
- **`$FILE_NAME` (`$FN`) timestamps + timestomping detection.**
- **YARA scanning + known-bad hash matching.**
- **Universal/Intel support** (currently arm64-only; `build-tsk.sh universal`).
- **iOS distribution** (TestFlight/App Store) — currently build-from-source.
- **Dynamic Type** on the iOS layer (deferred to preserve mockup fidelity).
- Phase-D hardening for iCloud: `NSFileCoordinator` + robust package
  download-completion (needs on-device validation).

### Planned roadmap (owner-approved, roughly prioritized)
1. **Case reporting & export** — examiner report (PDF/HTML/Markdown) of host
   profile + kill chain + findings + timeline excerpts; CSV/JSON export of
   timeline / findings / IOC matches.
2. **Chain-of-custody & evidence integrity** — capture acquisition metadata
   (examiner, acquisition method/tool, date/time, case #) and **source hashes**
   per evidence item, with a verification status and a custody log (acquired /
   added / analysed / exported, each with who + when). Produce a formal **CoC
   report** (PDF). For E01, read the format's *embedded* acquisition MD5/SHA-1
   rather than rehashing a huge image (add `ewfinfo`/`ewfverify` to the vendored
   tools in `build-tsk.sh` — libewf is already built); compute for raw/VHD.
   This is the legal-weight record, separate from the CTI enrichment audit log.
3. **Registry explorer** — interactive hive → key → value tree browser
   (SYSTEM/SOFTWARE/SAM/SECURITY/NTUSER/UsrClass…), with key last-write times,
   typed value decoding (REG_SZ/DWORD/BINARY/MULTI_SZ…), and search. Build the
   tree from the already-parsed `RegistryValue` set the way `FileNode.buildTree`
   builds the file tree; add a "Registry" sidebar tab (+ iOS drill view).
4. **More artifact parsers/analyzers** (each plugs into the `Analyzer` protocol):
   Prefetch, Amcache/Shimcache, USN journal (`$J`), LNK/JumpLists, SRUM, browser
   history, WMI persistence.
5. **Super-timeline + tagging/notes** — unify FS MACB + EVTX + registry (+ future
   artifacts) into one pivotable timeline; bookmark/tag findings, analyst notes,
   case narrative.
6. **Global search** across files/events/registry/timeline.
7. **`$MFT` / `$FN` parsing → timestomping detection** (also unlocks true
   loose-folder MACB).
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
