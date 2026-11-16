# Vaultage

End-to-end-encrypted file vaults. macOS app, iOS app, CLI, optional zero-knowledge sync server.

- Files are ciphertext on disk, on the wire and on the server. Plaintext exists only in the app's memory.
- Vaults are local-only or synced. Any number of each.
- Sync never overwrites: concurrent edits keep both versions; every version stays restorable until you purge it.
- Revoke a device or person by rotating keys. Share a vault with an invite line.

| Part | Path | Binary |
|---|---|---|
| Core (crypto, vault, sync) | `crates/core` | — |
| Server | `crates/server` | `vaultaged` |
| CLI | `crates/cli` | `vaultage` |
| C ABI for the app | `crates/ffi` | `libvaultage_ffi.a` |
| macOS app (SwiftUI) | `app/` | `dist/Vaultage.app` |
| iOS app (SwiftUI): files + notes with on-device dictation | separate repository | uses `app/Sources/CofferKit` and `crates/ffi` from here |
| Deploy (Docker, systemd, GCE) | `deploy/` | see `deploy/README.md` |

Docs: [docs/SECURITY.md](docs/SECURITY.md) (threat model, crypto, limits) · [docs/SYNC.md](docs/SYNC.md) (conflict rules).

## Install (macOS)

```sh
scripts/install.sh            # build, then /Applications/Vaultage.app + ~/.local/bin/vaultage; re-run to update
scripts/install.sh --open     # same, then launch the app
```

| Knob | Default | Use |
|---|---|---|
| `APP_DIR` | `/Applications` | where the app goes |
| `BIN_DIR` | `~/.local/bin` | where the CLI goes |
| `CODESIGN_IDENTITY` | ad-hoc | signing identity for app and CLI |
| `--no-cli` | | app only |

- Quit Vaultage before updating; the script refuses while it runs.
- A replaced app is moved to a temp folder, not deleted. Vault data (`~/Library/Application Support/Vaultage`) is not touched.
- Uninstall: drag `Vaultage.app` to the Trash, remove `~/.local/bin/vaultage`. Vaults stay until you delete that data folder.

## Build

```sh
cargo build --release --locked            # vaultaged, vaultage
scripts/build-app.sh                      # dist/Vaultage.app, hardened-runtime signed (ad-hoc)
CODESIGN_IDENTITY="Developer ID Application: …" scripts/build-app.sh
cargo test --locked                       # unit, sync scenarios, fuzz, HTTP end-to-end (both server stores)
swift build -c release --package-path app --product vaultage-selftest && VAULTAGE_HOME=$(mktemp -d) app/.build/release/vaultage-selftest
```

## Server (local try-out)

```sh
openssl rand -hex 32 > enroll_token
VAULTAGE_ENROLL_TOKEN_FILE=enroll_token target/release/vaultaged --data ./data --listen 127.0.0.1:8787
```

Production: TLS in front (Caddy, or `tailscale serve` for a tailnet-only server), or Cloud Run with a GCS bucket (`--store gcs://bucket/prefix`). See `deploy/README.md`. Clients refuse `http://` except to loopback.

| Server flag | Default | Use |
|---|---|---|
| `--store fs` / `gcs://bucket[/prefix]` | `fs` | where state lives |
| `--gc-grace-secs` | 86400 | how long an unreferenced chunk survives after a purge |
| `--vault-quota-bytes` | none | per-vault chunk storage limit (507 when full) |
| `--chunks bucket` / `gdrive://<folder-id>` | `bucket` | with a GCS store: chunk bytes in Google Drive, the bucket keeps the log and a pointer per chunk. See `deploy/README.md` (f) |

## CLI

```sh
vaultage new Work --server https://vault.example.com --token-file enroll_token --passphrase
vaultage new Private                         # local-only vault
vaultage join Work --server https://vault.example.com --vault <vault-id>   # second device
vaultage Work add ~/Documents/taxes --move   # encrypt, verify, delete originals
vaultage Work ls taxes
vaultage Work cat taxes/2026.pdf > /dev/null
vaultage Work get taxes --out ~/Desktop --move   # decrypt to disk, remove from vault
vaultage Work versions taxes/2026.pdf
vaultage Work restore taxes/2026.pdf 2
vaultage Work trash
vaultage Work sync --watch
vaultage Work empty-trash                    # erase trashed files everywhere, for good
vaultage Work prune taxes/2026.pdf           # keep only the current version
vaultage Private connect --server https://vault.example.com --token-file enroll_token   # local -> synced
vaultage Work invite Sam --qr                # one-time invite, 24 h (--hours N, max 168); QR on stderr
vaultage Work invites                        # waiting / used / expired / revoked
vaultage Work invites revoke 5aff71d8        # cancel an unused one
vaultage join Work --invite                  # on Sam's machine: prints Sam's own recovery key
vaultage Work rotate --passphrase            # new keys: other devices, passphrases, invites are out
vaultage Work adopt                          # on each device that stays, with the NEW secret
vaultage Work usage
vaultage trust https://vault.example.com --ca ca.pem   # pin the server to your CA / self-signed cert; `vaultage trust` lists
vaultage --help
```

| Env | Use |
|---|---|
| `VAULTAGE_HOME` | state dir (default `~/Library/Application Support/Vaultage`, Linux `~/.local/share/vaultage`; an existing `Coffer` / `coffer` folder from before the rename is used instead) |
| `VAULTAGE_PASSPHRASE`, `VAULTAGE_RECOVERY_KEY` | non-interactive unlock |
| `VAULTAGE_NEW_PASSPHRASE`, `VAULTAGE_YES=1`, `VAULTAGE_INVITE` | scripted `rotate` / `join --invite` |

Renamed from Coffer: `COFFER_*` names still work. The macOS bundle id stays `local.coffer.app` (Touch ID keys and permissions belong to it); `scripts/install.sh` moves an old `Coffer.app` aside.

The app and the CLI cannot open the same vault at the same time (directory lock).

## Unlocking

| Slot | Where | Notes |
|---|---|---|
| Touch ID (Secure Enclave) | app, per Mac | key cannot leave the chip; never uploaded |
| Passphrase | app, CLI | Argon2id, 128 MiB |
| Recovery key | app, CLI | shown once at creation; the way in on a new device |
| Invite | app, CLI | one-time, server-held, 24 h; the joiner gets their own recovery key. See docs/SECURITY.md → Sharing |

Second Mac: Join Existing Vault → server URL + vault ID + passphrase or recovery key.

## Status

| Area | Verified by |
|---|---|
| Crypto, vault format, key slots, key epochs | unit tests |
| Sync rules, crash/offline/lost-reply, malicious server | scenario tests + fuzz (in-memory and real HTTP) |
| Purge + garbage collection (local, server, other devices, new devices) | scenario tests, fuzz with random purges (in-memory and HTTP), server tests |
| Key rotation, revoked device, adopting device, invites (once only, revoke, expiry, rotation, old-style), local→synced | `crates/server/tests/features.rs` over real HTTP; invites also on the GCS store across two instances (`client_gcs.rs`) |
| Server (filesystem store) | API tests: commits, races, restart, torn log, prune/GC, rekey, quota, rate limits |
| Server (GCS store, for Cloud Run) | same API tests against an in-process fake GCS, two-instance races, lost replies, outages; client fuzz on top. Never run against real GCS |
| Server (GCS store + Drive chunks) | all API and GC tests again with a fake Drive; Drive-only tests (`crates/server/tests/gdrive.rs`): two-instance races, lost replies, orphan sweep, outages, rate limits, full Drive, token refresh, bucket chunks from before, `gdrive-login`; client fuzz on top |
| CLI | two-device runs against a local server, incl. prune, empty-trash, rotate, adopt, invite |
| App logic | headless self-test through the app's Swift client (`app/.build/release/vaultage-selftest`), incl. Touch ID slot, rotation, purge, in-memory media; with `VAULTAGE_TEST_URL`/`VAULTAGE_TEST_TOKEN` also attach, invite/join, rotate/adopt on a second process |
| App UI | driven by hand on test data: unlock, browse, previews (image, text, audio), thumbnails, versions, restore, new vault, recovery key, lock, live sync, empty trash, vault settings + usage, invite, key rotation |
| Hardened runtime | signed build blocks `DYLD_INSERT_LIBRARIES`; unsigned build does not |

Not exercised in the UI (logic is covered above): anything typed into a password field (passphrase, recovery key, enrollment token, invite), a real Touch ID prompt, Add Files panel and Finder drag-and-drop, Export / Move Out, Open With / external editing, the rotated-elsewhere and unfinished-rotation banners, auto-lock timers, audio playback (the player loads; I did not play sound). Run live once (2026-11-16): deploy (f) on Cloud Run + GCS + Drive, `gdrive-login` consent; a 9 MB file and a note synced between two devices. Not yet seen live: prune deleting Drive files. Not run at all: compose stack with real TLS, systemd unit.

## Not done

- Finder/File Provider mount (deliberately: a mount exposes plaintext to every process).
- Read-only members, per-file sharing links, roles. An invite is full access; revocation is key rotation.
- Re-encrypting old data on rotation.
- Windows, Linux GUI.
