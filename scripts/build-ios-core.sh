#!/usr/bin/env bash
# Build libvaultage_ffi.a for iOS. Run by the Xcode target, or by hand:
#   scripts/build-ios-core.sh [sim|device] [debug|release]
# Debug = Rust dev profile (stays debuggable). Release on a device refuses debuggers.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
case "${1:-${PLATFORM_NAME:-iphonesimulator}}" in
  sim|iphonesimulator) TARGET=aarch64-apple-ios-sim ;;
  device|iphoneos) TARGET=aarch64-apple-ios ;;
  *) echo "usage: $0 [sim|device] [debug|release]" >&2; exit 2 ;;
esac
case "$(echo "${2:-${CONFIGURATION:-Debug}}" | tr '[:upper:]' '[:lower:]')" in
  release) PROFILE=(--release) ;;
  *) PROFILE=() ;;
esac

# Clean environment: Xcode's SDKROOT and flags for the iOS SDK break build scripts compiled for the host.
exec env -i HOME="$HOME" PATH="$HOME/.cargo/bin:/usr/bin:/bin:/usr/sbin:/sbin" \
  cargo build --locked -p vaultage-ffi --target "$TARGET" ${PROFILE[@]+"${PROFILE[@]}"} --manifest-path "$ROOT/Cargo.toml"
