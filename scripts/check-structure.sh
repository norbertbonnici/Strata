#!/usr/bin/env bash
# Guards the OS-partitioned source layout (see ARCHITECTURE.md) so it can't drift
# back. Fast, no toolchain needed — runs in CI on any runner.
set -euo pipefail
cd "$(dirname "$0")/.."

fail=0
note() { echo "STRUCTURE: $1"; fail=1; }

# 1. No Swift files loose at the Strata/ root — everything lives in a subfolder.
loose=$(find Strata -maxdepth 1 -name '*.swift' || true)
[ -n "$loose" ] && note "Swift files at Strata/ root (move into a subfolder):"$'\n'"$loose"

# 2. The dissolved per-format folders must not reappear — OS code goes under Platforms/<OS>/.
for d in StrataEVTX StrataRegistry StrataSCCA StrataLNK StrataJumpList StrataSRUM \
         StrataBrowser StrataMac StrataLinux; do
  [ -d "Strata/$d" ] && note "Strata/$d/ is back — OS-specific code belongs in Strata/Platforms/<OS>/."
done

# 3. The OS homes must exist.
for d in Platforms/Windows Platforms/macOS Platforms/Linux; do
  [ -d "Strata/$d" ] || note "missing Strata/$d/"
done

# 4. No duplicate Swift filenames anywhere under Strata/ (one module — would clash).
dups=$(find Strata -name '*.swift' -exec basename {} \; | sort | uniq -d || true)
[ -n "$dups" ] && note "duplicate Swift filenames under Strata/:"$'\n'"$dups"

if [ "$fail" -ne 0 ]; then
  echo "✗ structure check failed (see above)"; exit 1
fi
echo "✓ structure OK"
