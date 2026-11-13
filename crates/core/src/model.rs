//! Entry metadata and its encrypted form.

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::crypto::{self, Key};
use crate::error::{Error, Result};
use crate::hexutil;

macro_rules! hex_id {
    ($name:ident, $n:expr) => {
        #[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
        pub struct $name(pub [u8; $n]);
        impl $name {
            pub fn hex(&self) -> String {
                hexutil::encode(&self.0)
            }
            pub fn parse(s: &str) -> Result<Self> {
                hexutil::decode_array::<$n>(s).map($name).ok_or_else(|| Error::Invalid(format!("bad id: {s}")))
            }
        }
        impl std::fmt::Debug for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "{}", self.hex())
            }
        }
        impl Serialize for $name {
            fn serialize<S: Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
                s.serialize_str(&self.hex())
            }
        }
        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
                let s = String::deserialize(d)?;
                Self::parse(&s).map_err(serde::de::Error::custom)
            }
        }
    };
}

hex_id!(EntryId, 16);
hex_id!(ChunkId, 32);
hex_id!(Hash32, 32);

/// Who is writing: shown in version history and conflict names.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Device {
    pub id: String,
    pub name: String,
}

impl Device {
    pub fn new(name: &str) -> Device {
        Device { id: hexutil::encode(&crypto::random::<8>()), name: name.to_string() }
    }
}

impl EntryId {
    pub fn random() -> Self {
        EntryId(crypto::random::<16>())
    }
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    File,
    Dir,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct ChunkRef {
    pub id: ChunkId,
    /// Plaintext length (the stored chunk may be padded).
    pub len: u32,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Content {
    /// Selects the content key (derived from the vault key). Stays the same across revisions of
    /// a file, and follows the content into a conflict copy.
    pub kid: EntryId,
    /// Key epoch the chunks are encrypted under (see key rotation).
    #[serde(default)]
    pub epoch: u32,
    /// BLAKE3 of the plaintext.
    pub hash: Hash32,
    pub chunks: Vec<ChunkRef>,
}

/// One revision of one entry. Encrypted before it leaves memory.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Meta {
    pub id: EntryId,
    pub rev: u64,
    /// Vault-relative, '/'-separated.
    pub path: String,
    pub kind: Kind,
    #[serde(default)]
    pub deleted: bool,
    pub size: u64,
    /// File mtime, unix ms.
    pub mtime: i64,
    pub content: Option<Content>,
    /// Name of the device that wrote this revision.
    pub device: String,
    /// Stable random id of that device.
    #[serde(default)]
    pub origin: String,
    /// When it was written, unix ms.
    pub ts: i64,
    /// This revision purges every earlier revision of the entry (empty trash / drop old versions).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub purge: bool,
    /// Revisions below this were purged earlier (carried forward by later revisions).
    #[serde(default, skip_serializing_if = "is_zero")]
    pub prune_below: u64,
}

fn is_zero(n: &u64) -> bool {
    *n == 0
}

impl Meta {
    pub fn hash(&self) -> Option<Hash32> {
        self.content.as_ref().map(|c| c.hash)
    }
    /// Same user-visible state (ignores rev, device, timestamps).
    pub fn same_state(&self, o: &Meta) -> bool {
        self.deleted == o.deleted && (self.deleted || (self.path == o.path && self.kind == o.kind && self.hash() == o.hash()))
    }
    /// Revisions of this entry below the returned number are purged.
    pub fn floor(&self) -> u64 {
        if self.purge { self.rev } else { self.prune_below }
    }
    pub fn refs(&self) -> Vec<ChunkId> {
        let mut v: Vec<ChunkId> = self.content.iter().flat_map(|c| c.chunks.iter().map(|r| r.id)).collect();
        v.sort();
        v.dedup();
        v
    }
}

fn meta_aad(epoch: u32, vault: &[u8; 16], entry: &EntryId, rev: u64) -> Vec<u8> {
    let mut a = b"coffer/meta/v1".to_vec();
    a.extend_from_slice(&epoch.to_le_bytes());
    a.extend_from_slice(vault);
    a.extend_from_slice(&entry.0);
    a.extend_from_slice(&rev.to_le_bytes());
    a
}

/// AEAD-bound to (vault, entry, rev): the server cannot move a record to another slot or replay an
/// old revision as a newer one. Padded to hide path length. Layout: epoch u32 LE | sealed.
pub fn encrypt_meta(key: &Key, epoch: u32, vault: &[u8; 16], m: &Meta) -> Vec<u8> {
    let json = serde_json::to_vec(m).expect("meta serialises");
    let mut pt = (json.len() as u32).to_le_bytes().to_vec();
    pt.extend_from_slice(&json);
    pt.resize(pt.len().div_ceil(256) * 256, 0);
    let mut out = epoch.to_le_bytes().to_vec();
    out.extend_from_slice(&crypto::seal(key, &meta_aad(epoch, vault, &m.id, m.rev), &pt));
    out
}

/// Key epoch a record blob was written under.
pub fn blob_epoch(blob: &[u8]) -> Result<u32> {
    blob.get(..4).map(|b| u32::from_le_bytes(b.try_into().unwrap())).ok_or(Error::Crypto("ciphertext too short"))
}

/// `key` must be the metadata key of `blob_epoch(blob)`.
pub fn decrypt_meta(key: &Key, vault: &[u8; 16], entry: &EntryId, rev: u64, blob: &[u8]) -> Result<Meta> {
    let epoch = blob_epoch(blob)?;
    let pt = crypto::open(key, &meta_aad(epoch, vault, entry, rev), &blob[4..])?;
    let bad = || Error::Format("metadata record".into());
    let len = u32::from_le_bytes(pt.get(..4).ok_or_else(bad)?.try_into().unwrap()) as usize;
    let m: Meta = serde_json::from_slice(pt.get(4..4 + len).ok_or_else(bad)?)?;
    if m.id != *entry || m.rev != rev {
        return Err(Error::Integrity("record does not match its slot".into()));
    }
    normalize_path(&m.path).ok().filter(|p| *p == m.path).ok_or_else(|| Error::Integrity("record has an unsafe path".into()))?;
    Ok(m)
}

/// Canonical vault path: no leading/trailing '/', no empty, '.' or '..' parts, no control chars.
pub fn normalize_path(p: &str) -> Result<String> {
    let mut parts = Vec::new();
    for part in p.split('/') {
        match part {
            "" | "." => continue,
            ".." => return Err(Error::Invalid("'..' is not allowed in vault paths".into())),
            _ if part.chars().any(|c| c.is_control()) => return Err(Error::Invalid("control character in path".into())),
            _ if part.len() > 255 => return Err(Error::Invalid("name too long".into())),
            _ => parts.push(part),
        }
    }
    Ok(parts.join("/"))
}

pub fn parent(path: &str) -> &str {
    path.rsplit_once('/').map(|(p, _)| p).unwrap_or("")
}

pub fn basename(path: &str) -> &str {
    path.rsplit_once('/').map(|(_, n)| n).unwrap_or(path)
}

pub fn join(dir: &str, name: &str) -> String {
    if dir.is_empty() {
        name.to_string()
    } else {
        format!("{dir}/{name}")
    }
}

/// True if `path` is `dir` or inside it.
pub fn is_under(path: &str, dir: &str) -> bool {
    dir.is_empty() || path == dir || (path.len() > dir.len() && path.starts_with(dir) && path.as_bytes()[dir.len()] == b'/')
}

pub fn now_ms() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis() as i64).unwrap_or(0)
}

/// "2026-11-13 14.02.11" (UTC); safe in file names.
pub fn stamp(ts_ms: i64) -> String {
    let secs = ts_ms.div_euclid(1000);
    let (days, rem) = (secs.div_euclid(86400), secs.rem_euclid(86400));
    let z = days + 719468;
    let era = z.div_euclid(146097);
    let doe = z.rem_euclid(146097);
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + if m <= 2 { 1 } else { 0 };
    format!("{y:04}-{m:02}-{d:02} {:02}.{:02}.{:02}", rem / 3600, rem % 3600 / 60, rem % 60)
}

/// "dir/name (tag).ext"
pub fn tagged_path(path: &str, tag: &str) -> String {
    let (dir, name) = (parent(path), basename(path));
    let (stem, ext) = match name.rfind('.') {
        Some(i) if i > 0 => (&name[..i], &name[i..]),
        _ => (name, ""),
    };
    join(dir, &format!("{stem} ({tag}){ext}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paths() {
        assert_eq!(normalize_path("/a//b/./c/").unwrap(), "a/b/c");
        assert!(normalize_path("a/../b").is_err());
        assert_eq!(normalize_path("").unwrap(), "");
        assert_eq!(parent("a/b/c"), "a/b");
        assert_eq!(parent("a"), "");
        assert!(is_under("a/b", "a") && !is_under("ab", "a") && is_under("a", "a") && is_under("x", ""));
        assert_eq!(tagged_path("d/report.final.pdf", "conflict"), "d/report.final (conflict).pdf");
        assert_eq!(tagged_path(".env", "x"), ".env (x)");
        assert_eq!(stamp(1_794_578_531_000), "2026-11-13 14.02.11");
    }

    #[test]
    fn meta_is_bound_to_slot() {
        let (k, v) = (Key::random(), [7u8; 16]);
        let m = Meta { id: EntryId::random(), rev: 3, path: "a/b.txt".into(), kind: Kind::File, deleted: false, size: 1, mtime: 2, content: None, device: "d".into(), origin: "o".into(), ts: 5, purge: false, prune_below: 0 };
        let blob = encrypt_meta(&k, 2, &v, &m);
        assert_eq!(blob.len() % 256, (4 + 24 + 16) % 256);
        assert_eq!(blob_epoch(&blob).unwrap(), 2);
        let mut other_epoch = blob.clone();
        other_epoch[0] = 3;
        assert!(decrypt_meta(&k, &v, &m.id, 3, &other_epoch).is_err());
        assert_eq!(decrypt_meta(&k, &v, &m.id, 3, &blob).unwrap(), m);
        assert!(decrypt_meta(&k, &v, &m.id, 4, &blob).is_err());
        assert!(decrypt_meta(&k, &v, &EntryId::random(), 3, &blob).is_err());
        assert!(decrypt_meta(&k, &[8u8; 16], &m.id, 3, &blob).is_err());
    }
}
