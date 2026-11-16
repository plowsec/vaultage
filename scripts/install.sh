#!/usr/bin/env bash
# Build Vaultage and install it on this Mac. Re-run to update.
# Usage: scripts/install.sh [--no-cli] [--open]
#   APP_DIR            where Vaultage.app goes       (default /Applications)
#   BIN_DIR            where the `vaultage` CLI goes (default ~/.local/bin)
#   CODESIGN_IDENTITY  signing identity            (default ad-hoc)
# Vault data (~/Library/Application Support/Vaultage, or .../Coffer from before the rename) is never touched.
# Nothing is deleted: a replaced app is moved to a temp folder (path printed).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
APP_DIR="${APP_DIR:-/Applications}"
BIN_DIR="${BIN_DIR:-$HOME/.local/bin}"
BUNDLE_ID=local.coffer.app   # pre-rename id, kept: Touch ID keys and permissions belong to it
# Same value as build-app.sh and .cargo/config.toml, or cargo rebuilds C deps on every run.
export MACOSX_DEPLOYMENT_TARGET=14.0
CLI=1
OPEN=0
for arg in "$@"; do
  case "$arg" in
    --no-cli) CLI=0 ;;
    --open) OPEN=1 ;;
    *) echo "usage: $0 [--no-cli] [--open]" >&2; exit 2 ;;
  esac
done

die() { echo "error: $*" >&2; exit 1; }
bundle_id() { /usr/libexec/PlistBuddy -c 'Print :CFBundleIdentifier' "$1/Contents/Info.plist" 2>/dev/null || true; }

[ "$(uname -s)" = Darwin ] || die "macOS only (server: see deploy/README.md)"
for tool in cargo swift codesign ditto; do
  command -v "$tool" >/dev/null || die "$tool not found"
done
case "$APP_DIR" in /*) ;; *) die "APP_DIR must be an absolute path: $APP_DIR" ;; esac
case "$BIN_DIR" in /*) ;; *) die "BIN_DIR must be an absolute path: $BIN_DIR" ;; esac

SRC="$ROOT/dist/Vaultage.app"
DEST="$APP_DIR/Vaultage.app"

# Check everything that can refuse before spending time on the build.
if [ -e "$DEST" ] && [ "$(bundle_id "$DEST")" != "$BUNDLE_ID" ]; then
  die "$DEST exists and is not Vaultage ($BUNDLE_ID). Not replacing it."
fi
if pgrep -x Vaultage >/dev/null || pgrep -x Coffer >/dev/null; then
  die "Vaultage is running. Quit it (Cmd-Q) and run this again."
fi
# The app was called Coffer before; the old copy is moved aside with the replaced one.
OLD="$APP_DIR/Coffer.app"
{ [ -e "$OLD" ] && [ "$(bundle_id "$OLD")" = "$BUNDLE_ID" ]; } || OLD=""
mkdir -p "$APP_DIR"
[ -w "$APP_DIR" ] || die "$APP_DIR is not writable. Try APP_DIR=\$HOME/Applications"

"$ROOT/scripts/build-app.sh"
[ "$(bundle_id "$SRC")" = "$BUNDLE_ID" ] || die "build did not produce $SRC"

if [ "$CLI" = 1 ]; then
  echo "==> CLI (release)"
  cargo build --release --locked -p vaultage-cli --manifest-path "$ROOT/Cargo.toml"
fi

echo "==> Install"
ASIDE=""
if [ -e "$DEST" ]; then
  ASIDE="$(mktemp -d "${TMPDIR:-/tmp}/vaultage-previous.XXXXXX")"
  mv "$DEST" "$ASIDE/Vaultage.app"
fi
if [ -n "$OLD" ]; then
  [ -n "$ASIDE" ] || ASIDE="$(mktemp -d "${TMPDIR:-/tmp}/vaultage-previous.XXXXXX")"
  mv "$OLD" "$ASIDE/Coffer.app"
fi
if ! { ditto "$SRC" "$DEST" && codesign --verify --strict "$DEST"; }; then
  # Put the previous version back; keep the broken copy next to it for inspection.
  if [ -n "$ASIDE" ]; then
    [ -e "$DEST" ] && mv "$DEST" "$ASIDE/Vaultage-failed.app"
    if [ -e "$ASIDE/Vaultage.app" ]; then mv "$ASIDE/Vaultage.app" "$DEST"; fi
    if [ -n "$OLD" ]; then mv "$ASIDE/Coffer.app" "$OLD"; fi
    die "install failed; previous version restored (broken copy, if any: $ASIDE)"
  fi
  die "install failed; remove the incomplete $DEST by hand"
fi
echo "    app  $DEST"
[ -n "$ASIDE" ] && echo "    previous version moved to $ASIDE (macOS clears it later)"

if [ "$CLI" = 1 ]; then
  mkdir -p "$BIN_DIR"
  install -m 755 "$ROOT/target/release/vaultage" "$BIN_DIR/vaultage"
  # Hardened runtime, like the app: blocks DYLD_INSERT_LIBRARIES injection.
  codesign --force --options runtime --timestamp=none --identifier local.vaultage.cli \
    --sign "${CODESIGN_IDENTITY:--}" "$BIN_DIR/vaultage"
  echo "    cli  $BIN_DIR/vaultage"
  case ":$PATH:" in
    *":$BIN_DIR:"*) ;;
    *) echo "    note: $BIN_DIR is not on PATH" ;;
  esac
  if [ -e "$BIN_DIR/coffer" ]; then
    echo "    note: the old CLI $BIN_DIR/coffer is still there; remove it when you no longer need it"
  fi
fi

if [ "$OPEN" = 1 ]; then
  open "$DEST"
fi
