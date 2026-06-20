# Strata — code map & "where does this go?"

This is the one-screen guide to where code lives. (CLAUDE.md has the deep
per-module responsibilities; this is the placement decision tree.)

Strata is **one Xcode target** built from a single recursive
file-system-synchronized group rooted at `Strata/`. So: any `.swift` anywhere
under `Strata/` is compiled automatically — **no `.pbxproj` edits to add/move
files**, and it's **one Swift module** so there are no `import`s between folders.
Folders are purely for humans. (No SPM — `Package.swift` is intentionally absent.)

## Layout

```
Strata/
├── Platforms/<Windows|macOS|Linux|Shared>/   # everything meaningful to ONE OS family
│   ├── Parsers/    # artifact parsers/decoders (Vendored/ shells out; ByteParsers/ pure-Swift)
│   ├── Models/     # value types for that OS's artifacts (MftEntry, TCCAccess, JournaldEntry…)
│   └── Analyzers/  # (macOS only, historically) — most analyzers live under StrataAnalysis
├── StrataCore/
│   ├── Models/     # cross-cutting value types: FileEntry, TimelineEvent, IOC, Case, KillChain, OSFamily…
│   └── Utilities/  # cross-cutting helpers: Hashing, GzipDecoder, SafeInt, FileTime, FileCarver, BinaryPlist…
├── StrataTSK/      # disk-image + APFS + KAPE ingest (cross-OS)
├── StrataTimeline/ # MACB super-timeline
├── StrataAnalysis/ # Analyzer protocol + AnalysisContext + AnalysisEngine + correlation/IOC/graph
│   └── Analyzers/<Windows|macOS|Linux|CrossPlatform>/   # the 60+ ATT&CK analyzers
├── StrataCTI/  StrataReport/  StrataSearch/  StrataAI/   # cross-cutting feature modules
└── StrataApp/
    └── Views/<Windows|macOS|Linux|Shared>/ + Views/iOS/  # per-artifact views by OS; iOS viewer
```

## Where does X go? (decision tree)

- **A new artifact parser/decoder** → `Strata/Platforms/<OS>/Parsers/`.
  Shells out to a vendored tool (`Process`)? → `Parsers/Vendored/`. Pure-Swift
  byte/text parser? → `Parsers/ByteParsers/` (or the folder root). Cross-OS
  artifact (e.g. browser history)? → `Platforms/Shared/Parsers/`.
- **A value type for an OS-specific artifact** (its records) → `Platforms/<OS>/Models/`.
- **A new ATT&CK analyzer** → `StrataAnalysis/Analyzers/<OS|CrossPlatform>/`, then
  register it in `AnalysisEngine.defaultAnalyzers`.
- **A new artifact view** → `StrataApp/Views/<OS>/` (or `Views/Shared/` if cross-OS;
  iOS drill → `Views/iOS/`). Add its tab to `SidebarItem` with the right `osFamily`.
- **A cross-cutting helper/codec** (used by ≥2 OS families, or by ingest/case
  regardless of OS) → `StrataCore/Utilities/`.
- **A cross-cutting value type** (case/host/timeline/IOC/kill-chain) → `StrataCore/Models/`.

### The rule

> A file belongs in `Platforms/<OS>/` **iff its behaviour is meaningful for
> exactly one OS family** — it parses an artifact that exists only on that OS, or
> is `#if os`-gated to a tool that only runs there. It belongs in
> `StrataCore/Utilities/` (or `StrataCore/Models/`) if it's consumed by **more
> than one** OS family, or by the ingest/case layer regardless of OS.

Worked examples: `GzipDecoder` stays in core (Linux `.gz` logs **and** macOS
FSEvents use it). `BinaryPlist` stays in core (a generic Apple codec). `AppleLZ4`
lives with the unified-log suite (its only consumer). `MftParser` is Windows-only
→ `Platforms/Windows/Parsers/ByteParsers/`.

## Conventions

- **OS is modelled by `OSFamily`** (`StrataCore/Models/OSFamily.swift`:
  `windows | linux | macos`) — folder names mirror it. `SidebarItem.osFamily`
  drives per-OS tab hiding; `OSFamily.detect` infers it from the evidence.
- **Two blessed parser shapes** (no shared protocol — signatures genuinely
  differ): a *pure* parser is a `nonisolated`/`static func parse(bytes:/text:) ->
  [Entry]` (testable without IO); a *vendored/IO* parser is an `actor`/`struct`
  `func parse(fileAt:) async throws -> [Entry]` that shells out via a discovery
  helper. Pick the matching shape.
- **macOS-only ingest code** is `#if os(macOS)`-gated (iOS is a read-only viewer).
  The gate travels with the file.
- **Moving files is a refactor, not a feature** — keep reorg commits renames-only
  (`git mv`); never mix a move with an edit in the same commit.
- **Tests** mirror the source tree under `StrataTests/` (its own synchronized
  root); name them `<Thing>Tests.swift`.
