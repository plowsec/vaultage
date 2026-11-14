#!/usr/bin/env bash
# Build Coffer and install it on this Mac. Re-run to update.
# Usage: scripts/install.sh [--no-cli] [--open]
#   APP_DIR            where Coffer.app goes       (default /Applications)
#   BIN_DIR            where the `coffer` CLI goes (default ~/.local/bin)
#   CODESIGN_IDENTITY  signing identity            (default ad-hoc)
# Vault data (~/Library/Application Support/Coffer) is never touched.
# Nothing is deleted: a replaced app is moved to a temp folder (path printed).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
APP_DIR="${APP_DIR:-/Applications}"
BIN_DIR="${BIN_DIR:-$HOME/.local/bin}"
BUNDLE_ID=local.coffer.app
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

SRC="$ROOT/dist/Coffer.app"
DEST="$APP_DIR/Coffer.app"

# Check everything that can refuse before spending time on the build.
if [ -e "$DEST" ] && [ "$(bundle_id "$DEST")" != "$BUNDLE_ID" ]; then
  die "$DEST exists and is not Coffer ($BUNDLE_ID). Not replacing it."
fi
if pgrep -x Coffer >/dev/null; then
  die "Coffer is running. Quit it (Cmd-Q) and run this again."
fi
mkdir -p "$APP_DIR"
[ -w "$APP_DIR" ] || die "$APP_DIR is not writable. Try APP_DIR=\$HOME/Applications"

"$ROOT/scripts/build-app.sh"
[ "$(bundle_id "$SRC")" = "$BUNDLE_ID" ] || die "build did not produce $SRC"

if [ "$CLI" = 1 ]; then
  echo "==> CLI (release)"
  cargo build --release --locked -p coffer-cli --manifest-path "$ROOT/Cargo.toml"
fi

echo "==> Install"
ASIDE=""
if [ -e "$DEST" ]; then
  ASIDE="$(mktemp -d "${TMPDIR:-/tmp}/coffer-previous.XXXXXX")"
  mv "$DEST" "$ASIDE/Coffer.app"
fi
if ! { ditto "$SRC" "$DEST" && codesign --verify --strict "$DEST"; }; then
  # Put the previous version back; keep the broken copy next to it for inspection.
  if [ -n "$ASIDE" ]; then
    [ -e "$DEST" ] && mv "$DEST" "$ASIDE/Coffer-failed.app"
    mv "$ASIDE/Coffer.app" "$DEST"
    die "install failed; previous version restored (broken copy, if any: $ASIDE)"
  fi
  die "install failed; remove the incomplete $DEST by hand"
fi
echo "    app  $DEST"
[ -n "$ASIDE" ] && echo "    previous version moved to $ASIDE (macOS clears it later)"

if [ "$CLI" = 1 ]; then
  mkdir -p "$BIN_DIR"
  install -m 755 "$ROOT/target/release/coffer" "$BIN_DIR/coffer"
  echo "    cli  $BIN_DIR/coffer"
  case ":$PATH:" in
    *":$BIN_DIR:"*) ;;
    *) echo "    note: $BIN_DIR is not on PATH" ;;
  esac
fi

if [ "$OPEN" = 1 ]; then
  open "$DEST"
fi
