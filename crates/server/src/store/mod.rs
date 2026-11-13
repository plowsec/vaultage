//! Storage backends. `Store` is the vault-level API the HTTP layer calls (blocking).
//!
//! Every signed operation takes `key`: the auth key the request signature was verified with.
//! The backend re-checks it against its authoritative copy (FS: under the vault lock;
//! GCS: cached meta, see gcs.rs) so a request verified just before a rekey cannot slip through.

pub mod fs;
pub mod gcs;

use std::time::{SystemTime, UNIX_EPOCH};

use coffer_core::proto::{PruneResp, UsageResp};
use serde::{Deserialize, Serialize};

pub type Id16 = [u8; 16];
pub type Cid = [u8; 32];

pub enum SErr {
    NoVault,
    Exists,
    BadSig,
    /// Commit base mismatch: current rev.
    Conflict(u64),
    StaleHeader,
    Missing(Vec<Cid>),
    Bad(String),
    Quota,
    NoChunk,
    /// Transient backend failure: client should retry (503).
    Unavailable(String),
    Internal(String),
}

pub type R<T> = Result<T, SErr>;

pub struct Rec {
    pub seq: u64,
    pub entry: Id16,
    pub rev: u64,
    pub refs: Vec<Cid>,
    /// Empty = placeholder (pruned).
    pub blob: Vec<u8>,
}

pub struct CommitIn {
    pub entry: Id16,
    pub base_rev: u64,
    pub rev: u64,
    pub blob: Vec<u8>,
    /// Deduplicated.
    pub refs: Vec<Cid>,
}

pub trait Store: Send + Sync {
    fn create(&self, vid: &Id16, auth_pub: &[u8; 32], header: &[u8]) -> R<()>;
    /// Current auth key. `fresh` asks a caching backend to re-read it.
    fn auth_key(&self, vid: &Id16, fresh: bool) -> R<[u8; 32]>;
    fn header(&self, vid: &Id16) -> R<Vec<u8>>;
    fn put_header(&self, vid: &Id16, key: &[u8; 32], header: &[u8], version: u64) -> R<()>;
    fn rekey(&self, vid: &Id16, key: &[u8; 32], new_pub: &[u8; 32], header: &[u8], version: u64) -> R<()>;
    /// (head, records after `after`, at most `limit`, blob bytes capped at `max_bytes` after the first).
    fn log(&self, vid: &Id16, key: &[u8; 32], after: u64, limit: usize, max_bytes: usize) -> R<(u64, Vec<Rec>)>;
    fn commit(&self, vid: &Id16, key: &[u8; 32], c: &CommitIn) -> R<u64>;
    fn missing(&self, vid: &Id16, key: &[u8; 32], ids: &[Cid]) -> R<Vec<Cid>>;
    fn put_chunk(&self, vid: &Id16, key: &[u8; 32], cid: &Cid, data: &[u8]) -> R<()>;
    fn get_chunk(&self, vid: &Id16, key: &[u8; 32], cid: &Cid) -> R<Vec<u8>>;
    /// Items must be validated (ids) by the caller.
    fn prune(&self, vid: &Id16, key: &[u8; 32], items: &[(Id16, u64)]) -> R<PruneResp>;
    fn usage(&self, vid: &Id16, key: &[u8; 32]) -> R<UsageResp>;
}

pub fn hex(b: &[u8]) -> String {
    coffer_core::hexutil::encode(b)
}

pub fn is_hex(s: &str, len: usize) -> bool {
    s.len() == len && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

pub fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// Process-unique, time-based id.
pub fn unique_id() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static C: AtomicU64 = AtomicU64::new(0);
    let n = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let seed = format!("{}-{n}-{}", std::process::id(), C.fetch_add(1, Ordering::Relaxed));
    blake3::hash(seed.as_bytes()).to_hex()[..32].to_owned()
}

pub fn header_version(v: &serde_json::Value) -> Option<u64> {
    v.as_object()?.get("version")?.as_u64()
}

/// Vault metadata: auth key and header in ONE document, so rekey is a single atomic write.
#[derive(Serialize, Deserialize, Clone, PartialEq)]
pub struct Meta {
    pub auth_pub: String,
    pub created_ms: i64,
    /// Header JSON text, stored verbatim.
    pub header: String,
    /// Unique per create: tells our own create (reply lost) from someone else's.
    #[serde(default)]
    pub create_id: String,
}

#[derive(Clone)]
pub struct MetaParsed {
    pub auth_pub: [u8; 32],
    pub header: Vec<u8>,
    pub version: u64,
}

impl Meta {
    /// `create_id` None = fresh one (vault creation).
    pub fn new(auth_pub: &[u8; 32], header: &[u8], created_ms: i64, create_id: Option<&str>) -> R<Meta> {
        Ok(Meta {
            create_id: create_id.map_or_else(unique_id, str::to_owned),
            auth_pub: hex(auth_pub),
            created_ms,
            header: String::from_utf8(header.to_vec()).map_err(|_| SErr::Bad("header not utf-8".into()))?,
        })
    }

    pub fn encode(&self) -> Vec<u8> {
        serde_json::to_vec(self).expect("meta serializes")
    }

    pub fn decode(b: &[u8]) -> Result<(Meta, MetaParsed), String> {
        let m: Meta = serde_json::from_slice(b).map_err(|e| format!("parse meta: {e}"))?;
        let auth_pub = coffer_core::hexutil::decode_array::<32>(&m.auth_pub).ok_or("meta: bad auth_pub")?;
        let hv: serde_json::Value = serde_json::from_str(&m.header).map_err(|e| format!("meta header: {e}"))?;
        let version = header_version(&hv).ok_or("meta header: no version")?;
        let p = MetaParsed {
            auth_pub,
            header: m.header.clone().into_bytes(),
            version,
        };
        Ok((m, p))
    }
}

// ---- record frames (FS log and GCS log objects) ----
// frame   = len u32 | payload | tag (blake3(payload)[..16])
// payload = seq u64 | entry 16 | rev u64 | nrefs u32 | refs 32*n | blob   (all LE)

pub const LEN: usize = 4;
pub const TAG: usize = 16;
pub const FIXED: usize = 8 + 16 + 8 + 4;
/// Blob and refs come from one JSON body as hex: together at most half of it.
pub const MAX_PAYLOAD: usize = FIXED + coffer_core::proto::MAX_JSON_BODY / 2;
pub const MAX_FRAME: u64 = (LEN + MAX_PAYLOAD + TAG) as u64;

pub fn payload_len(refs: usize, blob: usize) -> usize {
    FIXED + 32 * refs + blob
}

pub fn encode_frame(seq: u64, entry: &Id16, rev: u64, refs: &[Cid], blob: &[u8]) -> Vec<u8> {
    let plen = payload_len(refs.len(), blob.len());
    let mut f = Vec::with_capacity(LEN + plen + TAG);
    f.extend_from_slice(&(plen as u32).to_le_bytes());
    f.extend_from_slice(&seq.to_le_bytes());
    f.extend_from_slice(entry);
    f.extend_from_slice(&rev.to_le_bytes());
    f.extend_from_slice(&(refs.len() as u32).to_le_bytes());
    for r in refs {
        f.extend_from_slice(r);
    }
    f.extend_from_slice(blob);
    let tag = blake3::hash(&f[LEN..]);
    f.extend_from_slice(&tag.as_bytes()[..TAG]);
    f
}

pub fn placeholder_frame(seq: u64, entry: &Id16, rev: u64) -> Vec<u8> {
    encode_frame(seq, entry, rev, &[], &[])
}

pub fn len_ok(len: usize) -> bool {
    (FIXED..=MAX_PAYLOAD).contains(&len)
}

pub fn tag_ok(payload: &[u8], tag: &[u8]) -> bool {
    blake3::hash(payload).as_bytes()[..TAG] == *tag
}

/// Payload with a valid tag. None if internally inconsistent.
pub fn decode_payload(p: &[u8]) -> Option<Rec> {
    if p.len() < FIXED {
        return None;
    }
    let n = u32::from_le_bytes(p[32..36].try_into().unwrap()) as usize;
    let refs_end = FIXED.checked_add(n.checked_mul(32)?)?;
    if refs_end > p.len() {
        return None;
    }
    let refs = p[FIXED..refs_end].chunks(32).map(|c| c.try_into().unwrap()).collect();
    let blob = p[refs_end..].to_vec();
    if blob.is_empty() && n != 0 {
        return None;
    }
    Some(Rec {
        seq: u64::from_le_bytes(p[0..8].try_into().unwrap()),
        entry: p[8..24].try_into().unwrap(),
        rev: u64::from_le_bytes(p[24..32].try_into().unwrap()),
        refs,
        blob,
    })
}

/// A whole frame held in memory (GCS objects).
pub fn decode_frame(f: &[u8]) -> Result<Rec, String> {
    if f.len() < LEN + TAG {
        return Err("short frame".into());
    }
    let len = u32::from_le_bytes(f[..LEN].try_into().unwrap()) as usize;
    if !len_ok(len) || f.len() != LEN + len + TAG {
        return Err("bad frame length".into());
    }
    let (p, t) = f[LEN..].split_at(len);
    if !tag_ok(p, t) {
        return Err("checksum mismatch".into());
    }
    decode_payload(p).ok_or_else(|| "bad payload".into())
}
