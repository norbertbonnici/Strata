#!/usr/bin/env bash
#
# Archive, sign, export, and (optionally) upload the iOS viewer to TestFlight.
#
# The iOS app is a read-only .strata viewer — no ingest, so it carries none of
# the vendored TSK toolchain and can ship through the App Store / TestFlight
# (unlike the macOS app, which needs raw disk access and is Developer ID only).
#
# ── One-time prerequisites ────────────────────────────────────────────────
#   1. Apple Developer Program membership.
#   2. An "Apple Distribution" certificate in the login keychain
#        security find-identity -v -p codesigning | grep "Apple Distribution"
#   3. An Apple-ID account signed into Xcode (Settings ▸ Accounts) with the
#      App Manager or Admin role, so automatic signing can register the App ID
#      and mint the App Store provisioning profile during archive.
#   4. For UPLOAD: an App Store Connect API key
#        App Store Connect ▸ Users and Access ▸ Integrations ▸ App Store Connect API ▸ +
#      Put AuthKey_<KEYID>.p8 in ~/.appstoreconnect/private_keys/ and export:
#        ASC_KEY_ID=<KEYID> ASC_ISSUER_ID=<ISSUER-UUID>
#   5. An App Store Connect app record for the bundle id must already exist
#      (My Apps ▸ + ▸ New App, bundle id com.bonnicilabs.Strata).
#
# ── Usage ─────────────────────────────────────────────────────────────────
#   scripts/ios-testflight.sh 0.1.0-beta.3            # archive + export only
#   ASC_KEY_ID=ABC123 ASC_ISSUER_ID=<uuid> \
#     scripts/ios-testflight.sh 0.1.0-beta.3          # … and upload to TestFlight
#
set -euo pipefail

VERSION="${1:?usage: scripts/ios-testflight.sh <version>   e.g. 0.1.0-beta.3}"
SHORT_VERSION="${VERSION%%-*}"                 # 0.1.0-beta.3 -> 0.1.0 (CFBundleShortVersionString)
case "$VERSION" in
    *-beta.*) DEFAULT_BUILD="${VERSION##*-beta.}" ;;
    *)        DEFAULT_BUILD=1 ;;
esac
BUILD_NUMBER="${BUILD:-$DEFAULT_BUILD}"        # CFBundleVersion — must be unique per upload
TEAM_ID="${TEAM_ID:-96ZD8RMB92}"
SCHEME="Strata"
ASC_KEY_ID="${ASC_KEY_ID:-}"
ASC_ISSUER_ID="${ASC_ISSUER_ID:-}"

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BUILD="$ROOT/build/ios"
ARCHIVE="$BUILD/Strata-iOS.xcarchive"
EXPORT="$BUILD/export"
EXPORT_PLIST="$ROOT/scripts/ExportOptions-AppStore.plist"

log() { printf '\n\033[1;34m>>> %s\033[0m\n' "$*"; }

# ── Preflight ──────────────────────────────────────────────────────────────
log "Preflight"
if ! security find-identity -v -p codesigning | grep -q "Apple Distribution"; then
    echo "ERROR: no 'Apple Distribution' certificate in the keychain." >&2
    exit 1
fi

rm -rf "$BUILD"; mkdir -p "$BUILD"

# ── Archive (iOS, Release, automatic signing) ──────────────────────────────
log "Archiving iOS $VERSION ($SHORT_VERSION build $BUILD_NUMBER)"
xcodebuild archive \
    -project "$ROOT/Strata.xcodeproj" \
    -scheme "$SCHEME" \
    -configuration Release \
    -destination 'generic/platform=iOS' \
    -archivePath "$ARCHIVE" \
    -allowProvisioningUpdates \
    DEVELOPMENT_TEAM="$TEAM_ID" \
    MARKETING_VERSION="$SHORT_VERSION" \
    CURRENT_PROJECT_VERSION="$BUILD_NUMBER"

# ── Export a signed .ipa for App Store Connect ─────────────────────────────
log "Exporting App Store .ipa"
xcodebuild -exportArchive \
    -archivePath "$ARCHIVE" \
    -exportOptionsPlist "$EXPORT_PLIST" \
    -exportPath "$EXPORT" \
    -allowProvisioningUpdates

IPA="$(find "$EXPORT" -maxdepth 1 -name '*.ipa' -print -quit)"
if [ -z "$IPA" ] || [ ! -f "$IPA" ]; then
    echo "ERROR: no .ipa found in $EXPORT after export." >&2
    exit 1
fi
log "Built: $IPA"

# ── Upload to TestFlight (only when an API key is configured) ───────────────
if [ -n "$ASC_KEY_ID" ] && [ -n "$ASC_ISSUER_ID" ]; then
    log "Validating + uploading to TestFlight"
    xcrun altool --validate-app --type ios --file "$IPA" \
        --apiKey "$ASC_KEY_ID" --apiIssuer "$ASC_ISSUER_ID"
    xcrun altool --upload-app --type ios --file "$IPA" \
        --apiKey "$ASC_KEY_ID" --apiIssuer "$ASC_ISSUER_ID"
    log "Uploaded. Processing in App Store Connect takes a few minutes; then assign testers in TestFlight."
else
    log "No ASC_KEY_ID / ASC_ISSUER_ID set — skipped upload."
    echo "    Artifact ready: $IPA"
    echo "    To upload: ASC_KEY_ID=<id> ASC_ISSUER_ID=<uuid> scripts/ios-testflight.sh $VERSION"
fi
