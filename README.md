# Strata

A native macOS DFIR triage tool. The Sleuth Kit (TSK) does the forensic file
handling; Strata reads its output to enumerate the file system, build a MACB
timeline, and present a kill-chain view of detected attacker activity.

This is the **phase-1 scaffold**: E01 / KAPE (.vhd) input, Windows artifacts,
TSK enumeration + timeline. The kill-chain view is wired to the real data model
and seeded with clearly-marked sample findings; phase-2 analyzers replace them.

## Prerequisites

```sh
brew install sleuthkit          # provides tsk_loaddb, fls, icat, etc.
```

Verify your build reads the formats you need:

- **E01** requires TSK compiled with `libewf`. Check: `tsk_loaddb -i list` should
  list `ewf`. Homebrew's bottle usually includes it.
- **KAPE** must be collected to a **`.vhd` container** (`kape.exe ... --vhd`), not
  a loose triage folder. TSK ingests *images*, not directories. Loose folders are
  detected and flagged — a direct-artifact parser is phase-2 work.

## Layout

| Module           | Responsibility                                              |
|------------------|-------------------------------------------------------------|
| `StrataCore`     | Shared value types: `FileEntry`, `TimelineEvent`, kill-chain models |
| `StrataTSK`      | Locate TSK binaries, run `tsk_loaddb`, read its SQLite via GRDB |
| `StrataTimeline` | Expand MACB timestamps into timeline events (the `mactime` model) |
| `StrataApp`      | SwiftUI app: evidence tree, timeline, kill-chain view       |

## Running

For quick dev iteration:

```sh
swift run Strata
```

For a **shippable build**, this tool reads raw disk images, so it cannot be
sandboxed. Create an Xcode macOS App target that depends on these SPM modules,
sign it with a Developer ID, **notarize it**, and grant it **Full Disk Access**
(System Settings -> Privacy & Security). Raw device reads may additionally need a
privileged helper via `SMAppService`.

## Known scaffold rough edges

- `TSKImageIngestor` streams `tsk_loaddb` stderr for progress; the readability
  handler may surface Swift concurrency warnings to tidy up in Xcode.
- TSK timestamp columns are NTFS `$STANDARD_INFORMATION` times. `$FILE_NAME`
  (`$FN`) times and full timestomping detection are phase-2.
- The TSK SQLite schema is read with raw SQL against TSK 4.x column names.

## Roadmap

1. **(this scaffold)** TSK ingestion, evidence tree, MACB timeline, kill-chain UI shell.
2. Detection analyzers feeding ATT&CK-tagged `Finding`s into the kill-chain phases.
3. KAPE loose-folder direct-artifact parser; YARA + known-bad hashing.
