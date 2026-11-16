#!/usr/bin/env bash
# Build dist/Vaultage.app: Rust core (static lib) + SwiftUI app, signed with the hardened runtime.
# Usage: scripts/build-app.sh [--debug]     CODESIGN_IDENTITY=<identity> to sign with a real identity.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONFIG=release
case "${1:-}" in
  --debug) CONFIG=debug ;;
  "") ;;
  *) echo "usage: $0 [--debug]" >&2; exit 2 ;;
esac

VERSION=0.1.0
APP="$ROOT/dist/Vaultage.app"
export MACOSX_DEPLOYMENT_TARGET=14.0

echo "==> Rust core (release)"
cargo build --release --locked -p vaultage-ffi --manifest-path "$ROOT/Cargo.toml"

echo "==> Swift app ($CONFIG)"
BIN="$(swift build -c "$CONFIG" --package-path "$ROOT/app" --show-bin-path)/Vaultage"
# SwiftPM doesn't track the Rust static lib: force a relink so a rebuilt core is picked up.
rm -f "$BIN" "$(dirname "$BIN")/vaultage-selftest"
swift build -c "$CONFIG" --package-path "$ROOT/app" --product Vaultage

echo "==> Bundle"
rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"
cp "$BIN" "$APP/Contents/MacOS/Vaultage"

ICON_KEY=""
if swift "$ROOT/scripts/make-icon.swift" "$APP/Contents/Resources/Vaultage.iconset" >/dev/null 2>&1 \
   && iconutil -c icns -o "$APP/Contents/Resources/Vaultage.icns" "$APP/Contents/Resources/Vaultage.iconset"; then
  ICON_KEY="<key>CFBundleIconFile</key><string>Vaultage</string>"
else
  echo "    (icon generation skipped)"
fi
rm -rf "$APP/Contents/Resources/Vaultage.iconset"

cat > "$APP/Contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleIdentifier</key><string>local.coffer.app</string>
  <key>CFBundleName</key><string>Vaultage</string>
  <key>CFBundleDisplayName</key><string>Vaultage</string>
  <key>CFBundleExecutable</key><string>Vaultage</string>
  <key>CFBundlePackageType</key><string>APPL</string>
  <key>CFBundleShortVersionString</key><string>$VERSION</string>
  <key>CFBundleVersion</key><string>$VERSION</string>
  <key>CFBundleInfoDictionaryVersion</key><string>6.0</string>
  <key>CFBundleDevelopmentRegion</key><string>en</string>
  <key>LSMinimumSystemVersion</key><string>14.0</string>
  <key>LSApplicationCategoryType</key><string>public.app-category.productivity</string>
  <key>NSHighResolutionCapable</key><true/>
  <key>NSSupportsAutomaticTermination</key><false/>
  <key>NSSupportsSuddenTermination</key><false/>
  <key>NSFaceIDUsageDescription</key><string>Vaultage uses Touch ID to unlock your vaults.</string>
  $ICON_KEY
</dict>
</plist>
PLIST
plutil -lint -s "$APP/Contents/Info.plist"

echo "==> Sign (hardened runtime, no entitlements)"
codesign --force --options runtime --timestamp=none --sign "${CODESIGN_IDENTITY:--}" "$APP"
codesign --verify --strict "$APP"
codesign -dv --verbose=4 "$APP" 2>&1 | grep -E '^(Identifier|Format|CodeDirectory|Signature|Runtime Version)'

echo "==> $APP"
