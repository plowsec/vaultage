//! Wire protocol shared by client and server. The server never sees keys or plaintext.
//!
//! Routes (JSON unless noted):
//!   GET  /healthz
//!   POST /v1/vaults                      CreateVaultReq, header `X-Coffer-Enroll: <token>`  -> 201 | 403 | 409
//!   GET  /v1/vaults/{vid}/header         unauthenticated (vault id is the capability)       -> header JSON
//!   PUT  /v1/vaults/{vid}/header         signed; body.version must be > stored              -> 200 | 409
//!   GET  /v1/vaults/{vid}/log?after=N&limit=M   signed                                      -> LogResp
//!   POST /v1/vaults/{vid}/commit         signed; CommitReq -> 200 CommitResp | 409 ConflictResp | 422 MissingResp
//!   POST /v1/vaults/{vid}/missing        signed; MissingReq -> MissingResp
//!   PUT  /v1/vaults/{vid}/chunks/{cid}   signed; raw body; blake3(body) must equal cid      -> 200 | 507 (quota)
//!   GET  /v1/vaults/{vid}/chunks/{cid}   signed                                             -> raw body | 404
//!   POST /v1/vaults/{vid}/prune          signed; PruneReq -> PruneResp
//!   POST /v1/vaults/{vid}/rekey          signed with the CURRENT key; RekeyReq -> 200 | 409
//!   GET  /v1/vaults/{vid}/usage          signed -> UsageResp
//!   POST /v1/vaults/{vid}/invites        signed; InviteCreateReq -> 201 | 409 (id known) | 400
//!   GET  /v1/vaults/{vid}/invites        signed -> InvitesResp
//!   POST /v1/vaults/{vid}/invites/{iid}/revoke   signed -> 200 | 404
//!   POST /v1/vaults/{vid}/invites/{iid}/claim    signed with the INVITE's claim key; InviteClaimReq
//!                                        -> 200 InviteClaimResp | 404 | 410 (used, expired, revoked)
//! Errors: `{ "error": "..." }` with 400/401/403/404/409/413/422/429/507.
//!
//! Signed requests carry `Authorization: Coffer ts=<unix_ms>,sig=<hex ed25519>` over
//! `signing_message(method, path_and_query, ts, body)`, verified against the vault's `auth_pub`.
//!
//! Prune: for each item, every record of `entry` with rev < `below` becomes a placeholder (blob
//! dropped for good; seq/entry/rev stay, so the log remains gapless). `below` must be <= the
//! entry's current rev: the newest record is never pruned. Chunks no longer referenced by any
//! unpruned record are then deleted, unless uploaded within the grace period (in-flight uploads).
//! Idempotent. Pruned records come back from `log` with an empty `blob`.
//!
//! Invites: one-time. A claim returns the sealed payload once and marks the invite used; the same
//! `nonce` may claim again for `INVITE_RETRY_MS` (lost reply). A payload past that window, expired
//! or revoked is never handed out; it is erased from storage by the next claim of that invite or
//! the next signed request from a member. Used/expired/revoked invites stay as tombstones (no
//! payload) so an id is never reused. Rekey drops every invite. Failed claims (bad signature,
//! unknown id) are rate-limited per vault; a correctly signed claim is not.
//!
//! Rekey: atomically replaces the vault's `auth_pub` and header (header.version must increase).
//! From then on only the new key signs.

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};

use crate::hexutil;

/// Plaintext chunk size. Ciphertext adds 40 bytes (24 nonce + 16 tag).
pub const CHUNK_SIZE: usize = 4 * 1024 * 1024;
/// Largest chunk body the server accepts.
pub const MAX_CHUNK_BODY: usize = CHUNK_SIZE + 1024;
/// Largest JSON body the server accepts.
pub const MAX_JSON_BODY: usize = 32 * 1024 * 1024;
/// Allowed clock skew for signed requests.
pub const MAX_SKEW_MS: i64 = 5 * 60 * 1000;
pub const ENROLL_HEADER: &str = "X-Coffer-Enroll";

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct CreateVaultReq {
    /// 16 bytes hex.
    pub vault_id: String,
    /// Ed25519 public key, 32 bytes hex.
    pub auth_pub: String,
    /// Portable key-slot header (opaque to the server except `version`).
    pub header: serde_json::Value,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct WireRecord {
    pub seq: u64,
    /// Entry id, 16 bytes hex.
    pub entry: String,
    pub rev: u64,
    /// Encrypted entry metadata, hex. Empty = this revision was purged.
    pub blob: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct LogResp {
    /// Highest seq in the vault log.
    pub head: u64,
    /// Records with seq > after, ascending, contiguous.
    pub records: Vec<WireRecord>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct CommitReq {
    pub entry: String,
    /// Revision the client built on (0 = new entry). Accepted only if it is the entry's current rev.
    pub base_rev: u64,
    /// Must be base_rev + 1.
    pub rev: u64,
    pub blob: String,
    /// Chunk ids the record references; all must already be stored.
    pub refs: Vec<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct CommitResp {
    pub seq: u64,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ConflictResp {
    pub current_rev: u64,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct MissingReq {
    pub ids: Vec<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct MissingResp {
    pub missing: Vec<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PruneItem {
    pub entry: String,
    /// Records of `entry` with rev < below are purged.
    pub below: u64,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PruneReq {
    pub items: Vec<PruneItem>,
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct PruneResp {
    /// Records newly turned into placeholders.
    pub records: u64,
    /// Chunks deleted and their total size.
    pub chunks: u64,
    pub bytes: u64,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct RekeyReq {
    /// New Ed25519 public key, 32 bytes hex.
    pub auth_pub: String,
    /// New portable header; `version` must be greater than the stored one.
    pub header: serde_json::Value,
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct UsageResp {
    /// Stored chunk bytes.
    pub bytes: u64,
    pub chunks: u64,
    pub records: u64,
    /// Per-vault chunk byte limit, if the server enforces one.
    pub quota: Option<u64>,
}

/// Longest lifetime the server accepts for an invite.
pub const INVITE_MAX_TTL_MS: i64 = 7 * 24 * 3600 * 1000;
/// Unclaimed, unexpired invites per vault.
pub const INVITE_MAX_PENDING: usize = 32;
/// After a claim, the same claimer may fetch the payload again for this long.
pub const INVITE_RETRY_MS: i64 = 10 * 60 * 1000;
/// Largest `blob` / `info`, hex characters.
pub const INVITE_MAX_FIELD: usize = 4096;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct InviteCreateReq {
    /// 16 bytes hex, derived from the invite secret.
    pub id: String,
    /// Ed25519 public key (hex) that must sign the claim.
    pub claim_pub: String,
    /// Sealed payload, hex. Handed out once.
    pub blob: String,
    /// Label sealed under the vault key, hex. For members only.
    pub info: String,
    pub expires_ms: i64,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct InviteClaimReq {
    /// 16 random bytes hex, kept by the claimer for the retry window: the same device may claim
    /// again after a lost reply or a join that failed later.
    pub nonce: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct InviteClaimResp {
    pub blob: String,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct InviteInfo {
    pub id: String,
    pub info: String,
    pub created_ms: i64,
    pub expires_ms: i64,
    pub claimed_ms: Option<i64>,
    pub revoked_ms: Option<i64>,
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct InvitesResp {
    pub invites: Vec<InviteInfo>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ErrorResp {
    pub error: String,
}

pub fn signing_message(method: &str, path_and_query: &str, ts_ms: i64, body: &[u8]) -> Vec<u8> {
    format!(
        "coffer-req-v1\n{}\n{}\n{}\n{}",
        method.to_ascii_uppercase(),
        path_and_query,
        ts_ms,
        blake3::hash(body).to_hex()
    )
    .into_bytes()
}

/// Value for the `Authorization` header.
pub fn sign_request(key: &SigningKey, method: &str, path_and_query: &str, ts_ms: i64, body: &[u8]) -> String {
    let sig = key.sign(&signing_message(method, path_and_query, ts_ms, body));
    format!("Coffer ts={},sig={}", ts_ms, hexutil::encode(&sig.to_bytes()))
}

/// Verify an `Authorization` header value. `now_ms` bounds replay to `MAX_SKEW_MS`.
pub fn verify_request(
    auth_pub: &[u8; 32],
    authorization: &str,
    method: &str,
    path_and_query: &str,
    body: &[u8],
    now_ms: i64,
) -> bool {
    let Some(rest) = authorization.strip_prefix("Coffer ") else { return false };
    let (mut ts, mut sig) = (None, None);
    for part in rest.split(',') {
        match part.trim().split_once('=') {
            Some(("ts", v)) => ts = v.parse::<i64>().ok(),
            Some(("sig", v)) => sig = hexutil::decode_array::<64>(v),
            _ => {}
        }
    }
    let (Some(ts), Some(sig)) = (ts, sig) else { return false };
    if (now_ms - ts).abs() > MAX_SKEW_MS {
        return false;
    }
    let Ok(vk) = VerifyingKey::from_bytes(auth_pub) else { return false };
    vk.verify_strict(&signing_message(method, path_and_query, ts, body), &Signature::from_bytes(&sig))
        .is_ok()
}
