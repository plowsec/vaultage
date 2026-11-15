# Security

## Threat model

| Attacker | Gets | Does not get |
|---|---|---|
| Server operator, cloud provider, stolen server disk | ciphertext; vault id; record count, timing; chunk sizes (padded); which chunks belong to one record | names, content, folder structure, keys |
| Network attacker (TLS broken) | same as server | same |
| Malicious server | can withhold new data, refuse service | cannot forge, alter, reorder, drop or roll back records unnoticed (see Integrity) |
| Stolen Mac, powered off / vault locked | ciphertext; Argon2id-wrapped key if a passphrase is set | Secure Enclave key (needs your finger + that chip) |
| Stolen iPhone, locked | nothing readable: app storage is Data Protection class Complete on top of the vault's own encryption | Secure Enclave key (needs your face/finger + that chip) |
| Stolen iPhone, unlocked, app locked | ciphertext (with a jailbreak or forensic tool); Argon2id-wrapped key if a passphrase is set | names, content, keys |
| Other process, same user, vault unlocked | cannot read app memory, attach, or inject (hardened runtime + SIP); sees files you export or open externally | keys, unopened files |
| Root with SIP on | same as above for memory; can replace the app binary, log keystrokes | — |
| Root with SIP off, kernel exploit, malicious app update | everything while unlocked | out of scope |

## Keys

```
VMK (random 256-bit, per vault, per key epoch)
 ├─ wrapped by each key slot ─ passphrase: Argon2id(m=128 MiB,t=3) → KEK
 │                             recovery:   256-bit random, shown once → KEK
 │                             Touch ID:   ECDH(Secure Enclave P-256 key, stored ephemeral pub) → KEK
 ├─ metadata key   → encrypts entry records (path, size, chunk list)
 ├─ journal key    → encrypts the local journal
 ├─ content root   → per-file key (by content key id) → chunk enc key + nonce key
 ├─ server auth    → Ed25519 key that signs every request
 ├─ header MAC key → detects key-slot tampering
 └─ chain link     → encrypts the previous epoch's VMK (new key reads old data, never the reverse)
```

| Primitive | Use |
|---|---|
| XChaCha20-Poly1305 | all encryption |
| BLAKE3 | hashes, KDF, MAC, chunk ids |
| Argon2id | passphrase slot |
| Ed25519 | request signatures |
| P-256 ECDH (CryptoKit, Secure Enclave) | Touch ID slot |

- Derived keys live in `mlock`ed memory, zeroed on lock. Lock = keys dropped.
- Chunks: 4 MiB, last one padded (Padmé, ≤12 %). Nonce = MAC(plaintext) under a per-file key, so an unchanged chunk re-encrypts to the same bytes (dedup across versions; equality leaks only within one file).
- Records: AEAD-bound to (vault, entry, revision); padded to 256-byte blocks.
- Secure Enclave slot stays on the Mac that made it. The server only gets passphrase/recovery slots.
- Header (key slots) is public data. Anyone with the vault id can fetch it from the server and try passphrases offline: use a strong passphrase or none (Touch ID + recovery key).

## Key rotation (revoking a device, a person, a leaked passphrase)

```sh
coffer Work rotate --passphrase     # app: Vault Settings → Rotate Keys…
coffer Work adopt                   # on every device that stays, with the NEW secret
```

| Step | Effect |
|---|---|
| prepare | new VMK + new recovery key staged on disk, sealed under the current key; nothing in effect; shown to you first |
| commit | server switches to the new signing key and header in one step; local header replaced |
| after | old recovery key, every passphrase, every invite, every Touch ID slot and every other device are out |
| other devices | server answers 401; client shows "keys were rotated"; `adopt` with the new recovery key/passphrase; it checks the new header descends from the vault it already has |

- New records and new file content use the new key. Old chunks are not re-encrypted: a revoked device keeps whatever it had already downloaded, and can no longer fetch or write anything.
- Interrupted between prepare and commit: staging survives; finish or cancel after the next unlock. Interrupted mid-commit: commit again (it detects the server already switched).
- Any device holding the current key can rotate. A device you are about to revoke can do it first and take over the server copy; your local data stays intact.

## Sharing

`coffer Work invite Sam [--qr] [--hours N]` / Vault Settings → Invite Someone… prints `server#vault-id#secret`. Full read/write access for whoever uses it first.

| Property | How |
|---|---|
| Works once | the server holds the invite and hands its payload out once; later claims get 410 "already used" |
| Leaked line after use | opens nothing: the secret is in no key slot, the server refuses the payload |
| Payload erased from the server | on revoke; else by the next claim of that invite or the next request from any member, once it is used (+10 min) or expired |
| Leaked line before use | the thief joins; your recipient then gets "already used" → rotate keys |
| Lost reply, or a join that fails after the claim | this device keeps its claim nonce (`claims.json`) and may fetch the payload again for 10 min; nobody else. Local checks and the header fetch run before the claim |
| Junk claims | bad signatures and unknown ids are rate-limited per vault; a valid claim is never refused for them |
| Expiry | 24 h default, 7 days max; revocable while unused (`coffer Work invites revoke <id>`, Vault Settings → Sharing) |
| Rotation | drops every open invite |
| Server's view | invite id, claim public key, sealed payload, sealed label, times. Never the secret, the vault key or the label |
| Joiner | gets a recovery key of their own (new slot, shown once); the invite key is not a way in |

Derivation (BLAKE3 from the 32-byte secret): invite id, Ed25519 claim key (signs the claim), wrap key (seals vault key + label, bound to vault and invite id).

- Not protected: a server operator who keeps the payload and later reads the line. Treat the server like the chat: it alone can't open anything; both together can.
- Same for old copies of the server's data: backups, snapshots and bucket soft-delete can hold a payload after it is erased. Such a copy plus the line opens the vault as it was before the next rotation.
- QR code (Mac invite sheet, iPhone invite sheet, `--qr`): scan it in Vaultage (Join → Scan QR Code). The iPhone Camera app would open the `https://` line in Safari and keep it in history.
- Old-style invites (a recovery slot labelled "Invite…", created before this change) still join and keep working until removed under Unlock Methods.
- Per-file links and read-only members do not exist. Someone who already joined is only removed by rotating keys.

## Purging

| Action | Erases |
|---|---|
| Empty trash / delete permanently | every version of the trashed entries |
| Delete older versions | all but the current version of a file |

- Takes effect when the purge marker is committed; then: local chunks deleted, local journal rewritten without the old records, server replaces the old records by placeholders and deletes chunks nothing else references (after its grace period), other devices do the same on their next sync.
- A concurrent edit on another device wins; then nothing is purged.
- New devices see placeholders. They accept one only if an authentic later record of the same entry announces the purge; a server blanking records on its own is an integrity error.
- Not a forensic erase: SSD wear levelling, APFS snapshots, Time Machine, server-side backups/snapshots and bucket soft-delete can retain old bytes.

## Integrity

| Check | Catches |
|---|---|
| chunk id = BLAKE3(ciphertext), verified on every read | bit rot, swapped chunks |
| whole-file BLAKE3 inside the encrypted record | wrong/missing/reordered chunks |
| record AAD = vault, entry, revision | records moved or replayed |
| log must continue at cursor+1, revisions +1 | dropped or reordered records |
| head ≥ cursor | rollback |
| known revision must be byte-identical | history rewrite |
| header MAC | swapped key slots |
| placeholder must be covered by an authentic purge marker | server hiding records as "purged" |
| adopted header must unwrap to the key we already hold | server swapping in a different vault at rotation |

Any failure stops sync with an `integrity` error. Nothing is auto-repaired or dropped.
Not detectable: a server that simply stops showing new records (looks like "no changes").

## Process hardening (macOS)

| Measure | Effect | Verified here |
|---|---|---|
| Hardened runtime signature, no `get-task-allow` | kernel denies task ports, debugger attach, `DYLD_INSERT_LIBRARIES`, unsigned dylibs | `DYLD_INSERT_LIBRARIES`: injects into unsigned build, blocked on signed build. Debugger attach not tested (needs Developer Mode prompt). |
| `ptrace(PT_DENY_ATTACH)` (release builds) | second line against attach | set; not attack-tested |
| `RLIMIT_CORE=0` | no core dumps with keys | set |
| `mlock` on keys | not swapped | set |
| No plaintext cache, no temp files | nothing to scrape on disk | tests grep vault dir and server dir for names/content |
| Window excluded from screen capture | screenshots/recording | best effort; newer capture APIs may ignore it |

The app shows the live state (shield icon): hardened runtime, debuggable, SIP.
Ad-hoc signing gives the runtime protections but not identity: anyone can re-sign a modified copy. Use a Developer ID + notarization for a build you install elsewhere.

## Transport

| Layer | Protects |
|---|---|
| End-to-end encryption (above) | names, content, structure: from the server and from anyone on the path |
| Ed25519 signature on every request (method, path, time, body) | writes and reads can't be forged or altered; replay window 5 min |
| TLS 1.2/1.3 (rustls), bundled Mozilla roots, no redirects, `https://` only (loopback excepted) | vault id, sizes, timing, enrollment token; from the network |
| Certificate pinning (optional, per server) | same, against a rogue or compromised public CA; lets a private CA / self-signed server work without weakening checks |

- Pinned server: the chain must end in a pinned certificate. Public CAs no longer count for it. A self-signed server certificate must be `CA:FALSE`.
- Certificate failure = nothing sent. The apps report it as an identity problem, not as "offline".
- Timeouts: connect 10 s, 20 s without progress, 180 s per request. Then back off (2 s … 64 s) and retry; a network change retries at once (iOS).

## iOS

| Measure | Effect | Verified here |
|---|---|---|
| Data Protection class Complete on the app's storage (entitlement + set on the directory) | vault files unreadable while the device is locked | set; Simulator doesn't enforce or report it |
| Storage excluded from iCloud / Finder backups | the passphrase-wrapped key header never leaves the device in a backup | flag set and read back |
| Face ID / Touch ID slot: Secure Enclave P-256 key, `biometryCurrentSet` | key can't leave the chip; re-enrolling a face/finger invalidates the slot (recovery key or passphrase still work) | slot created and used in the Simulator with an ungated key; real Face ID prompt not tested |
| Lock on leaving the app (at once, or 20 s grace), on device lock, on idle | keys dropped; the UI locks immediately, the core as soon as its in-flight request ends (≤ 20 s stall timeout) | lock on leaving the app and idle timer: yes; device lock: not in Simulator |
| Privacy cover while inactive / in the app switcher | no file names or previews in the switcher snapshot | yes (switcher shows the cover) |
| Cover while the screen is recorded or mirrored (setting) | no content in recordings / AirPlay | not exercised |
| Third-party keyboards refused | nothing typed (passphrase, recovery key) reaches a keyboard extension | set |
| Previews and thumbnails decoded in memory only | no plaintext cache on disk | app container scanned after import and share: no plaintext files; see below for the two exceptions |
| `ptrace(PT_DENY_ATTACH)` on device release builds, `RLIMIT_CORE=0`, `mlock` | debugger attach refused; no core files | set; not attack-tested |
| Secrets copied to the pasteboard: local-only, expire after 60 s | no Universal Clipboard, no lingering key | set |

Plaintext on disk on iOS, both in a protected scratch directory (class Complete, not backed up), wiped after use, on lock and at launch:

| When | What |
|---|---|
| Share… / export | decrypted copy handed to the share sheet; the receiving app keeps its own copy |
| Import from Photos | the picked photo/video is staged, encrypted, verified, then deleted |

Notes and dictation (iOS):

| Thing | Where it lives |
|---|---|
| Note text | encrypted vault file; in memory while the vault is unlocked (search index included); dropped on lock |
| Unsaved edits | memory; written to the vault before the keys are dropped at lock |
| Dictated audio | microphone → an on-device engine, in memory. Not recorded. iOS 26+ with the enhanced model: `SpeechAnalyzer` (local by design). Otherwise `SFSpeechRecognizer` with `requiresOnDeviceRecognition` always set. No fallback to a server |
| Enhanced speech model | system asset. Downloaded from Apple only when you tap Download in Settings › Voice Notes (Apple sees a model request for the language, no audio or text) |
| What iOS may keep | the system keyboard learns from note text typed with autocorrect on (as in any app); Reset Keyboard Dictionary clears it |

Not covered on iOS: a jailbroken device or a malicious build while a vault is unlocked; screenshots you take yourself; iOS keeps the full local replica (no selective sync), so a large vault uses the same space on the phone.

## Where plaintext leaves the boundary

| Action | Result |
|---|---|
| Export / Move out of vault | plaintext file where you put it |
| Open in external app | temp plaintext copy until lock/quit; the other app can keep its own copies |
| Preview | decrypted into app memory only |
| Copy recovery key | pasteboard, cleared after 60 s |
| CLI `cat`, `get` | stdout / files |
| Import with move | original deleted after verify — not a secure erase (SSD/APFS snapshots, Time Machine) |

## Known gaps

- No independent audit. Crypto crates are RustCrypto/dalek/BLAKE3; composition is ours.
- Certificate pinning is opt-in and pins a CA or a self-signed server certificate you supply (`coffer trust`, iOS: Certificate Pinning). No trust-on-first-use, no public-key pinning of a public-CA leaf. Unpinned servers are checked against the bundled Mozilla roots.
- Rotation does not re-encrypt old data; a revoked device keeps what it already downloaded.
- Any member can purge, rotate, invite or revoke invites. There are no roles.
- Passphrase typed into the app can be keylogged by root/accessibility malware. Touch ID avoids typing.
- File names and content pass through Swift/AppKit objects that cannot be reliably zeroed.
- Preview parsers (images, PDF) run in the same process as the keys.
- Paths are not Unicode-normalised.
