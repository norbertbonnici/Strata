# Strata UI — build brief

Goal: bring the mocked-up Strata surfaces into the Swift app as idiomatic
SwiftUI, fidelity-matched to the design references, on top of the model layer
provided here.

## What's in this drop

| File | Role | Status |
|---|---|---|
| `DesignSystem.swift` | tokens, type scale, shared components | ready to use |
| `Domain.swift` | OS taxonomy, exhibits, case (+ lifecycle), settings, evidence model | ready to use |
| `CustodyChain.swift` | per-entry SHA-256 hash chain + verify + mismatch path | ready; **port the self-check into a unit test first** |
| `ActivityLog.swift` | append-only, hash-chained examiner journal (reuses `Hashing`) | ready; port its self-check too |
| `SampleData.swift` | seed/preview data (Linux evidence, custody, activity, lifecycle) | ready to use |
| `CLAUDE.md` | standing conventions + scope | read first |
| `/DesignReference/*.html` | pixel-accurate visual + behavioral specs | reference only — do not transpile |

## First steps

1. Add the five `.swift` files to the app target. Add the `/DesignReference`
   folder (HTML) to the repo for reference (not the target).
2. Register the three fonts (header note in `DesignSystem.swift`).
3. Ship OS glyph assets (`os.macOS`, `os.windows`, `os.linux`, `os.iOS`,
   `os.android`) — see the `<symbol>` SVGs in any reference file for the shapes.
4. **Write tests that call `CustodyChain.runSelfCheck()` and
   `ActivityLog.runSelfCheck()` and assert true.** This locks both hash chains
   before any UI depends on them.

## Screens to build (order = lowest risk first)

Each maps to a reference HTML. Match layout/spacing/flow; implement natively.

1. **Settings** — `strata-settings.html` (Settings tab).
   Editable catalogues bound to `StrataSettings`; toggles for tool/algorithm
   availability; chip editors for taxonomies. Every other screen's pickers read
   from here. *Build this first — it feeds the rest.*

2. **New case** — `strata-settings.html` / `strata-custody.html` (New case tab).
   `DigitalCase` form; pickers from Settings; live summary; classification chip.

3. **Custody — Collection & Transfer** — `strata-custody.html` +
   `strata-settings.html` (custody tabs).
   Collection writes chain entry 0; Transfer renders the hash-chained timeline,
   gates on `verifyEvidence(...)` (wire the **mismatch alert** path), and shows
   per-entry `entryHash`/`prevHash`. Include the "verify chain integrity" action.

4. **Evidence intake** — `strata-intake.html`.
   Drop target → queue of `Exhibit`s with OS/encryption detection → batch
   processing (parallelism, locked-image policy, per-row progress, pause/stop).
   Port the scheduler behavior; back it with an `@Observable` BatchProcessor.

5. **Exhibit detail / Stratify** — `strata-hybrid.html`.
   The core-sample column + parser inspector for one exhibit; the unlock cascade
   (locked encryption layer → enables user-data parsers). Optional but the nicest
   signature screen.

6. **Evidence viewer** — `strata-viewer.html`.
   OS-aware: `EvidenceSet` drives Artifacts (category → records → detail),
   Timeline (`EvidenceSet.timeline(filter:)`), Files (`FileNode` tree), and
   Search (`EvidenceSet.search(_:)`). Records show provenance + bookmarking.
   Port the 5 OS corpora from the HTML `CATS`/`FILES` objects into
   `ArtifactCategory`/`FileNode`.

7. **Case activity & lifecycle** — `strata-activity.html`.
   Two parts. *Activity* renders `ActivityLog` as a chronological, category-
   filterable journal (the integrity-mismatch entry reads as an alert) with a
   "verify journal" action calling `ActivityLog.verify()`. *Lifecycle* shows the
   `CaseState` stepper, retention/disposition pickers (from the enums), and the
   gated close/dispose actions (type-to-confirm; see `strata-states.html`).

(The five ingest *concepts* in `strata-ingest.html` were exploration — pick the
direction you want; the intake screen above is the converged version.
`strata-admin.html` is **superseded** by `strata-activity.html`: roles/permissions
and the sign-in screen are out of scope — see CLAUDE.md "Scope".)

## Acceptance checks

- `CustodyChain.runSelfCheck()` and `ActivityLog.runSelfCheck()` pass in CI.
- A `verifyEvidence` mismatch visibly blocks the transfer and shows the alert.
- Editing a recorded custody/activity entry then re-verifying flags the broken link.
- Adding an examiner / disabling a tool in Settings immediately changes the
  pickers in the case + collection forms.
- Switching the exhibit in the viewer swaps the entire artifact taxonomy.
- `advanceState()` walks open → … → archived, stamps `closedDate` on close, and
  closing freezes the case read-only (`CaseState.isFrozen`).
- Everything renders correctly in both iOS and macOS targets, light/dark, with
  Dynamic Type and VoiceOver.

## Don't

- Don't transpile the HTML/CSS. Match the look with idiomatic SwiftUI.
- Don't hardcode colors/fonts/radii — use DesignSystem tokens.
- Don't move custody/activity/hashing logic into views or managed objects.
- Don't change `canonical()` ordering or the separator without versioning.
- Don't build auth, sign-in, or RBAC for the single-Mac target (see Scope).
- Don't add edit/delete to ActivityLog — it's append-only by contract.
```
