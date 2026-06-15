# macOS Artifact Plan

## Goal

Expand Strata's macOS artifact coverage without regressing older cases. Every new
artifact family should be an independent parse bucket so cases parsed by older
builds can backfill newly added data.

## Current Coverage

- LaunchAgents and LaunchDaemons
- LaunchServices quarantine database
- macOS host identity, users, and network interface plist data
- cron, periodic, emond, login/logout hooks, rc scripts, profiles, and managed preferences
- FSEvents
- user shell history
- TCC privacy databases
- KnowledgeC activity databases
- Unified Log tracev3

## Implementation Order

1. Recent Items / LSSharedFileList
   - Parse `.sfl`, `.sfl2`, `.sfl3`, and related plist stores.
   - Cache as `macrecentitems.json`.
   - Add timeline rows for dated recent apps, documents, servers, hosts, volumes, and favorites.

2. Safari
   - Parse `History.db`, download metadata, and session/tab state where available.
   - Reuse the existing browser-history model where possible; add Safari-specific fields only where needed.
   - Status: `History.db` visits were already supported; `Downloads.plist` download rows now feed the Browser History model.

3. Gatekeeper / XProtect / MRT
   - Parse assessment, malware-removal, and security-tool logs/reports.
   - Add detections for blocked/quarantined malware, repeated policy failures, and suspicious allow decisions.
   - Status: **done.** Durable Gatekeeper/syspolicyd, XProtect, XProtect Remediator, MRT, and relevant `install.log` rows parse into `macsecurity.json`, appear in a macOS Security tab, and splice dated rows into the timeline. `MacSecurityAnalyzer` (registered in `AnalysisEngine.defaultAnalyzers`) now consumes `AnalysisContext.macSecurityEvents` and emits findings: XProtect/MRT/XPR malware detections & remediations (high, T1204.002), trust override after a block — allow-after-block (high, T1553.001), security control disabled e.g. `spctl --master-disable` (high, T1562.001), and Gatekeeper/policy blocks of untrusted binaries (medium, escalating to high on repeated failures of the same binary, T1553.001). Covered by `StrataTests/MacSecurityAnalyzerTests.swift`.

4. Login / Background Items
   - Parse modern background-task-management and login-item stores.
   - Keep this separate from launchd so persistence views can distinguish user-approved background items from daemon plists.

5. Network / Device Context
   - Known Wi-Fi networks, DHCP leases, Bluetooth devices, USB/iOS pairings, and Time Machine destinations.

## Guardrails

- Add one artifact bucket at a time.
- Keep parse gating per bucket, not per OS.
- Preserve existing cached buckets when backfilling a new one.
- Add timeline projection for timestamped artifacts.
- Keep UI work separate from parser/storage work when other agents have active view edits.
