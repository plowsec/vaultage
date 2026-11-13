# Sync

Model: every file/folder is an entry with numbered revisions. The server keeps an append-only log of encrypted revisions and immutable encrypted chunks. It accepts revision N+1 of an entry only if N is still current (compare-and-swap).

## Order of operations

1. Pull the log from the local cursor. Merge.
2. Upload chunks the server lacks. Then commit the revision. Server rejects a commit whose chunks are missing.
3. On reject (someone was first): pull, merge, retry.
4. Download chunks for live files (full local replica).

Every step is idempotent. Kill the app or the network anywhere and repeat.

## Conflict rules

| This device | Other device | Result |
|---|---|---|
| edit | edit (different content) | both kept; local becomes `name (conflict <device> <time>).ext` |
| edit | same edit | one file |
| edit | delete | file stays, with the edit |
| delete | edit / rename | file stays |
| rename | edit | renamed file with the edit |
| rename | rename | other device's name |
| new `a.txt` | new `a.txt` | both kept, one renamed |
| file `x` | folder `x/…` | file renamed |
| folder renamed | file added in old folder | file stays under the old folder name |
| purge (empty trash / drop old versions) | edit | edit wins; nothing purged |
| purge | purge / delete | purged |

Path collisions resolve the same way on every device (committed beats uncommitted, then lowest id).

## Failure cases

| Case | Behaviour |
|---|---|
| Offline | changes queue in the encrypted journal; pushed later, in order |
| App quit / crash with unsynced changes | journal is fsynced per change; resumes after unlock |
| Reply lost after server committed | next pull sees own record; no duplicate, no self-conflict |
| Upload interrupted | only missing chunks are re-sent |
| Torn journal / server log tail | incomplete last record dropped (it was never acknowledged) |
| Damage elsewhere in a log | hard error; nothing truncated |
| Local chunk corrupt | detected by hash; re-fetched from server |
| Two saves offline before sync | only the last one is pushed (like saving twice) |
| Clock skew > 5 min | server rejects signatures (401); fix the clock |

## Deletes and history

- Delete = tombstone revision. Trash lists them; restore brings back any earlier revision.
- Nothing is removed until you purge (empty trash, delete older versions). Purge is permanent and propagates: see SECURITY.md → Purging.
- Server keeps unreferenced chunks for a grace period (default 24 h) so an upload in flight is never collected.

## Local vault → synced

`coffer Private connect --server URL --token-file F` / Vault Settings → Sync with a Server…

- Uploads the kept history in order, then flips the vault to synced. Read-only while it runs.
- Interrupted: run it again; it verifies what the server already has and continues.

## Key slots across devices

- Passphrase / recovery / invite slots sync through the server header; a passphrase added on one device works on the others after their next sync.
- Touch ID slots never leave the Mac.
- Keys rotated elsewhere: sync stops with "keys were rotated" until the device adopts the new keys. Unsynced local changes are kept and pushed afterwards.

## Tests

| Test | Where |
|---|---|
| Rules above, one scenario each | `crates/core/src/sync_tests.rs` |
| Fuzz: 2–4 devices, random edits, 30–60 % packet loss, then assert convergence + every synced version still readable | `testkit::fuzz` (in-memory server, 40 seeds; real HTTP server, 6 seeds) |
| Malicious server: rollback, gap, tamper, replay, bad chunk | `sync_tests::malicious_server_is_detected` |
| Two-Mac flow with server restart | `crates/server/tests/e2e.rs` |
| Purge, placeholders, purge vs edit, offline purge | `sync_tests.rs` (`empty_trash_*`, `new_device_*`, `purge_*`) |
| Fuzz with random purges: convergence, remaining history readable, server chunk set consistent | `sync_tests::fuzz_with_purges_*` |
| Purge / local→synced / rotation / invites over HTTP | `crates/server/tests/features.rs` |
