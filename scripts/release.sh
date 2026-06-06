#!/usr/bin/env bash
#
# Build, Developer ID-sign, notarize, staple, and package Strata into a
# distributable .dmg for a GitHub release.
#
# Strata reads raw disk images, so it can't be sandboxed and can't ship through
# the App Store. The only distribution path that opens cleanly on other Macs is
# Developer ID + notarization, which is what this script automates.
#
# ── One-time prerequisites ────────────────────────────────────────────────
#   1. Apple Developer Program membership (paid).
#   2. A "Developer ID Application" certificate in your login keychain:
#        Xcode ▸ Settings ▸ Accounts ▸ <team> ▸ Manage Certificates ▸ +
#        Verify:  security find-identity -v -p codesigning | grep "Developer ID"
#   3. A notarytool credential profile (stored in the keychain):
#        xcrun notarytool store-credentials "$NOTARY_PROFILE" \
#          --apple-id "<your-apple-id>" --team-id "$TEAM_ID" \
#          --password "<app-specific password from appleid.apple.com>"
#   4. The vendored TSK toolchain built:  scripts/build-tsk.sh
#
# ── Usage ─────────────────────────────────────────────────────────────────
#   scripts/release.sh 0.1.0-beta.1
#   NOTARY_PROFILE=my-profile TEAM_ID=XXXX scripts/release.sh 0.1.0-beta.1
#
# The argument is the release/tag version (may include a -beta.N suffix for the
# dmg name); the bundle's CFBundleShortVersionString is the numeric prefix
# (e.g. 0.1.0), since Apple rejects non-numeric short versions.
#
set -euo pipefail

VERSION="${1:?usage: scripts/release.sh <version>   e.g. 0.1.0-beta.1}"
SHORT_VERSION="${VERSION%%-*}"                 # 0.1.0-beta.2 -> 0.1.0 (CFBundleShortVersionString)
# Build number (CFBundleVersion): default to the beta number so successive
# betas differ, else 1. Override with BUILD=...
case "$VERSION" in
    *-beta.*) DEFAULT_BUILD="${VERSION##*-beta.}" ;;
    *)        DEFAULT_BUILD=1 ;;
esac
BUILD="${BUILD:-$DEFAULT_BUILD}"
TEAM_ID="${TEAM_ID:-96ZD8RMB92}"
NOTARY_PROFILE="${NOTARY_PROFILE:-strata-notary}"
SCHEME="Strata"
APP_NAME="Strata"

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BUILD="$ROOT/build/release"
ARCHIVE="$BUILD/$APP_NAME.xcarchive"
EXPORT="$BUILD/export"
APP="$EXPORT/$APP_NAME.app"
DMG="$ROOT/build/$APP_NAME-$VERSION.dmg"
ENTITLEMENTS="$ROOT/scripts/StrataRelease.entitlements"
EXPORT_PLIST="$ROOT/scripts/ExportOptions-DeveloperID.plist"

log() { printf '\n\033[1;34m>>> %s\033[0m\n' "$*"; }

# ── Preflight ──────────────────────────────────────────────────────────────
log "Preflight"
if ! security find-identity -v -p codesigning | grep -q "Developer ID Application"; then
    echo "ERROR: no 'Developer ID Application' certificate in the keychain." >&2
    echo "       Create one: Xcode ▸ Settings ▸ Accounts ▸ Manage Certificates ▸ +" >&2
    exit 1
fi
if ! xcrun notarytool history --keychain-profile "$NOTARY_PROFILE" >/dev/null 2>&1; then
    echo "ERROR: notarytool profile '$NOTARY_PROFILE' not found. Create it with:" >&2
    echo "  xcrun notarytool store-credentials \"$NOTARY_PROFILE\" \\" >&2
    echo "    --apple-id <your-apple-id> --team-id $TEAM_ID --password <app-specific-pw>" >&2
    exit 1
fi
if [ ! -x "$ROOT/Vendor/tsk/bin/$(uname -m)/tsk_loaddb" ]; then
    echo "ERROR: vendored TSK not built for $(uname -m). Run scripts/build-tsk.sh first." >&2
    exit 1
fi

rm -rf "$BUILD" "$DMG"
mkdir -p "$BUILD"

# ── Archive: Release, manual Developer ID signing, hardened runtime, ────────
#    stripped entitlements, secure timestamp. CodeSignOnCopy in the project
#    re-signs the embedded TSK binaries with this same identity.
log "Archiving $APP_NAME $VERSION (CFBundleShortVersionString $SHORT_VERSION)"
xcodebuild archive \
    -project "$ROOT/Strata.xcodeproj" \
    -scheme "$SCHEME" \
    -configuration Release \
    -destination 'generic/platform=macOS' \
    -archivePath "$ARCHIVE" \
    CODE_SIGN_STYLE=Manual \
    CODE_SIGN_IDENTITY="Developer ID Application" \
    DEVELOPMENT_TEAM="$TEAM_ID" \
    PROVISIONING_PROFILE_SPECIFIER="" \
    CODE_SIGN_ENTITLEMENTS="$ENTITLEMENTS" \
    ENABLE_HARDENED_RUNTIME=YES \
    MARKETING_VERSION="$SHORT_VERSION" \
    CURRENT_PROJECT_VERSION="$BUILD" \
    OTHER_CODE_SIGN_FLAGS="--timestamp"

# ── Export the Developer ID-signed app ─────────────────────────────────────
log "Exporting signed app"
xcodebuild -exportArchive \
    -archivePath "$ARCHIVE" \
    -exportOptionsPlist "$EXPORT_PLIST" \
    -exportPath "$EXPORT"

# ── Verify the signature looks right before we spend minutes notarizing ─────
log "Verifying signature"
codesign --verify --deep --strict --verbose=2 "$APP"
codesign -dvv "$APP" 2>&1 | grep -E "Authority=Developer ID Application|flags=.*runtime" \
    || { echo "ERROR: app is not Developer ID-signed with hardened runtime." >&2; exit 1; }

# ── Notarize the app, then staple the ticket into the bundle ───────────────
log "Notarizing app (a few minutes)"
ZIP="$BUILD/$APP_NAME.zip"
ditto -c -k --keepParent "$APP" "$ZIP"
xcrun notarytool submit "$ZIP" --keychain-profile "$NOTARY_PROFILE" --wait
xcrun stapler staple "$APP"
xcrun stapler validate "$APP"

# ── Package a .dmg (app + /Applications drop target) ───────────────────────
log "Building DMG"
STAGE="$BUILD/dmg"
rm -rf "$STAGE"; mkdir -p "$STAGE"
cp -R "$APP" "$STAGE/"
ln -s /Applications "$STAGE/Applications"
hdiutil create -volname "$APP_NAME $VERSION" -srcfolder "$STAGE" \
    -fs HFS+ -format UDZO -ov "$DMG"

# ── Sign + notarize + staple the DMG so the download itself passes Gatekeeper
log "Signing + notarizing DMG"
codesign --sign "Developer ID Application" --timestamp "$DMG"
xcrun notarytool submit "$DMG" --keychain-profile "$NOTARY_PROFILE" --wait
xcrun stapler staple "$DMG"

log "Done"
echo "    Artifact: $DMG"
echo "    Gatekeeper check: spctl -a -vvv -t install \"$DMG\""
echo "    Next: tag the release and attach this dmg (see scripts/release.sh header / README)."
