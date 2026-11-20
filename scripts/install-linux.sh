#!/usr/bin/env bash
# Build Vaultage for Linux (GTK 4 app + CLI) and install it for this user. Re-run to update.
# Usage: scripts/install-linux.sh [--no-cli]
#   PREFIX            install root (default ~/.local): bin/, share/applications/, share/icons/
#   CARGO_TARGET_DIR  honoured (default: linux/target for the GUI, target/ for the CLI)
# Needs: cargo, pkg-config, GTK >= 4.14 and libadwaita >= 1.5 dev files
#   (Ubuntu 24.04 / Debian 13: apt install build-essential pkg-config libgtk-4-dev libadwaita-1-dev).
# Vault data (~/.local/share/vaultage, or $VAULTAGE_HOME) is never touched.
# Nothing is deleted: each file is written next to its target, then renamed over it.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PREFIX="${PREFIX:-$HOME/.local}"
APP_ID=local.vaultage.app
CLI=1
for arg in "$@"; do
  case "$arg" in
    --no-cli) CLI=0 ;;
    *) echo "usage: $0 [--no-cli]" >&2; exit 2 ;;
  esac
done

die() { echo "error: $*" >&2; exit 1; }

[ "$(uname -s)" = Linux ] || die "Linux only (macOS: scripts/install.sh)"
for tool in cargo pkg-config install; do
  command -v "$tool" >/dev/null || die "$tool not found"
done
case "$PREFIX" in /?*) ;; *) die "PREFIX must be an absolute path: $PREFIX" ;; esac
pkg-config --atleast-version=4.14 gtk4 || die "GTK 4.14+ dev files missing (libgtk-4-dev)"
pkg-config --atleast-version=1.5 libadwaita-1 || die "libadwaita 1.5+ dev files missing (libadwaita-1-dev)"
[ -f "$ROOT/linux/Cargo.lock" ] || die "run from a Vaultage checkout ($ROOT/linux/Cargo.lock missing)"

BIN="$PREFIX/bin"
APPS="$PREFIX/share/applications"
ICONS="$PREFIX/share/icons/hicolor/256x256/apps"

echo "==> GUI (release)"
cargo build --release --locked --manifest-path "$ROOT/linux/Cargo.toml" --bin vaultage-gui
GUI_OUT="${CARGO_TARGET_DIR:-$ROOT/linux/target}/release/vaultage-gui"
[ -x "$GUI_OUT" ] || die "build did not produce $GUI_OUT"
if [ "$CLI" = 1 ]; then
  echo "==> CLI (release)"
  cargo build --release --locked -p vaultage-cli --manifest-path "$ROOT/Cargo.toml"
  CLI_OUT="${CARGO_TARGET_DIR:-$ROOT/target}/release/vaultage"
  [ -x "$CLI_OUT" ] || die "build did not produce $CLI_OUT"
fi

# put SRC DEST MODE: copy to DEST.new in the same folder, then rename (atomic, works while running).
put() {
  local src="$1" dest="$2" mode="$3"
  install -d -m 755 "$(dirname "$dest")"
  install -m "$mode" "$src" "$dest.new"
  mv -f "$dest.new" "$dest"
  echo "    $dest"
}

echo "==> install to $PREFIX"
put "$GUI_OUT" "$BIN/vaultage-gui" 755
[ "$CLI" = 1 ] && put "$CLI_OUT" "$BIN/vaultage" 755
put "$ROOT/linux/data/$APP_ID.png" "$ICONS/$APP_ID.png" 644
# Absolute Exec: ~/.local/bin is not on PATH in every desktop session.
DESKTOP_TMP="$(mktemp)"
trap 'rm -f -- "${DESKTOP_TMP:?}"' EXIT
sed "s|^Exec=vaultage-gui\$|Exec=$BIN/vaultage-gui|" "$ROOT/linux/data/$APP_ID.desktop" > "$DESKTOP_TMP"
put "$DESKTOP_TMP" "$APPS/$APP_ID.desktop" 644

# Refresh menus and icons where the tools exist (harmless if missing).
command -v update-desktop-database >/dev/null && update-desktop-database -q "$APPS" || true
command -v gtk-update-icon-cache >/dev/null && gtk-update-icon-cache -q -t "$PREFIX/share/icons/hicolor" 2>/dev/null || true

echo "==> done. Start: Vaultage in the app grid, or $BIN/vaultage-gui"
case ":$PATH:" in *":$BIN:"*) ;; *) echo "    note: $BIN is not on PATH (only matters for the CLI)";; esac
