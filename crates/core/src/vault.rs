//! A vault: encrypted chunks + an encrypted journal of entry revisions, both ciphertext at rest.
//! Plaintext exists only in this process's memory.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use crate::crypto::{self, Key};
use crate::error::{Error, Result};
use crate::header::Header;
use crate::hexutil;
use crate::model::*;
use crate::proto::CHUNK_SIZE;
use crate::remote::Remote;
use crate::store::{atomic_write, ChunkStore, Journal};

const CHUNK_AAD: &[u8] = b"coffer/chunk/v1";

#[derive(Serialize, Deserialize, Clone, Default, Debug)]
pub struct VaultConfig {
    /// Sync server base URL. None = local-only vault.
    pub remote: Option<String>,
    /// Header version the server is known to have. Lower than the header's = slot changes to upload.
    #[serde(default)]
    pub header_pushed: u64,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(tag = "t", rename_all = "lowercase")]
pub(crate) enum Event {
    /// A committed revision (acknowledged by the server, or final in a local vault).
    Base { seq: u64, meta: Meta },
    /// A local change waiting to be pushed. Replaces any earlier pending change of the entry.
    Pending { meta: Meta },
    Unpend { id: EntryId },
    /// Server log position we have pulled through.
    Cursor { seq: u64 },
    /// The server holds only a placeholder for revisions up to `rev` (they were purged).
    Pruned { entry: EntryId, rev: u64 },
    /// The server still has to be told to purge `entry` below `below`.
    PruneTodo { entry: EntryId, below: u64 },
    PruneDone { entry: EntryId },
}

#[derive(Clone, Debug)]
pub struct Rev {
    pub seq: u64,
    pub meta: Meta,
}

#[derive(Default, Debug)]
pub struct EntryState {
    /// Every committed revision that was not purged, oldest first.
    pub history: Vec<Rev>,
    pub pending: Option<Meta>,
    /// Revisions below this are purged.
    pub floor: u64,
    /// Highest revision we only ever saw as a server placeholder.
    pub pruned_through: u64,
}

impl EntryState {
    pub fn base(&self) -> Option<&Meta> {
        self.history.last().map(|r| &r.meta)
    }
    pub fn base_rev(&self) -> u64 {
        self.base().map(|m| m.rev).unwrap_or(0).max(self.pruned_through)
    }
    pub fn current(&self) -> Option<&Meta> {
        self.pending.as_ref().or_else(|| self.base())
    }
}

#[derive(Default)]
pub(crate) struct State {
    pub entries: BTreeMap<EntryId, EntryState>,
    pub cursor: u64,
    pub prune_todo: BTreeMap<EntryId, u64>,
    /// Something was purged: local chunks and journal should be cleaned up.
    pub dirty: bool,
}

impl State {
    pub fn apply(&mut self, e: Event) {
        match e {
            Event::Base { seq, meta } => {
                let e = self.entries.entry(meta.id).or_default();
                let floor = meta.floor();
                e.history.push(Rev { seq, meta });
                if floor > e.floor {
                    e.floor = floor;
                    e.history.retain(|r| r.meta.rev >= floor);
                    self.dirty = true;
                }
            }
            Event::Pending { meta } => {
                let id = meta.id;
                self.entries.entry(id).or_default().pending = Some(meta)
            }
            Event::Unpend { id } => {
                if let Some(e) = self.entries.get_mut(&id) {
                    e.pending = None
                }
            }
            Event::Cursor { seq } => self.cursor = self.cursor.max(seq),
            Event::Pruned { entry, rev } => {
                let e = self.entries.entry(entry).or_default();
                e.pruned_through = e.pruned_through.max(rev);
            }
            Event::PruneTodo { entry, below } => {
                let b = self.prune_todo.entry(entry).or_insert(0);
                *b = (*b).max(below);
            }
            Event::PruneDone { entry } => {
                self.prune_todo.remove(&entry);
            }
        }
    }
}

pub(crate) struct EpochKeys {
    meta: Key,
    content: Key,
}

/// Working keys. One set per key epoch (old epochs stay readable); the newest signs and encrypts.
pub struct Keys {
    pub(crate) vmk: Key,
    epochs: Vec<EpochKeys>,
    pub(crate) journal: Key,
    pub auth: SigningKey,
}

impl Keys {
    /// `masters`: master key of every epoch, oldest first (see `Header::masters`).
    pub fn new(masters: Vec<Key>) -> Keys {
        let vmk = masters.last().expect("at least one key").clone();
        let seed = vmk.derive("coffer v1 server auth");
        Keys {
            epochs: masters.iter().map(|k| EpochKeys { meta: k.derive("coffer v1 metadata"), content: k.derive("coffer v1 content") }).collect(),
            // Local only, so it can stay with the first epoch and survive rotations.
            journal: masters[0].derive("coffer v1 journal"),
            auth: SigningKey::from_bytes(seed.expose()),
            vmk,
        }
    }
    pub fn epoch(&self) -> u32 {
        self.epochs.len() as u32 - 1
    }
    fn of(&self, epoch: u32) -> Result<&EpochKeys> {
        self.epochs.get(epoch as usize).ok_or_else(|| Error::Invalid("data was written with newer keys than this device has (keys were rotated)".into()))
    }
    pub(crate) fn seal_meta(&self, vault: &[u8; 16], m: &Meta) -> Vec<u8> {
        encrypt_meta(&self.epochs[self.epoch() as usize].meta, self.epoch(), vault, m)
    }
    pub(crate) fn open_meta(&self, vault: &[u8; 16], entry: &EntryId, rev: u64, blob: &[u8]) -> Result<Meta> {
        decrypt_meta(&self.of(blob_epoch(blob)?)?.meta, vault, entry, rev, blob)
    }
    pub fn auth_pub_hex(&self) -> String {
        hexutil::encode(self.auth.verifying_key().as_bytes())
    }
}

struct ContentKeys {
    enc: Key,
    nonce: Key,
}

fn content_keys(keys: &Keys, epoch: u32, kid: &EntryId) -> Result<ContentKeys> {
    let k = keys.of(epoch)?.content.derive_with(&kid.0);
    Ok(ContentKeys { enc: k.derive("coffer v1 chunk enc"), nonce: k.derive("coffer v1 chunk nonce") })
}

/// Encrypts a byte stream into chunks. Detached from the vault so big imports don't hold its lock.
pub struct Ingester {
    pub id: EntryId,
    kid: EntryId,
    epoch: u32,
    keys: ContentKeys,
    chunks: ChunkStore,
    /// Held until dropped: local garbage collection waits while an import has uncommitted chunks.
    /// Keep the ingester alive until `commit_file` returned.
    in_flight: Arc<AtomicUsize>,
}

impl Drop for Ingester {
    fn drop(&mut self) {
        self.in_flight.fetch_sub(1, Ordering::SeqCst);
    }
}

impl Ingester {
    pub fn ingest(&self, r: &mut dyn Read) -> Result<(Content, u64)> {
        let mut hasher = blake3::Hasher::new();
        let (mut refs, mut total) = (Vec::new(), 0u64);
        let mut buf: Vec<u8> = Vec::new();
        loop {
            buf.zeroize();
            buf.clear();
            if let Err(e) = r.take(CHUNK_SIZE as u64).read_to_end(&mut buf) {
                buf.zeroize();
                return Err(e.into());
            }
            let n = buf.len();
            if n == 0 {
                break;
            }
            hasher.update(&buf);
            total += n as u64;
            // Only the last chunk is short; pad it so its size leaks little.
            if n < CHUNK_SIZE {
                buf.resize(crypto::padded_len(n).min(CHUNK_SIZE), 0);
            }
            let sealed = crypto::seal_deterministic(&self.keys.enc, &self.keys.nonce, CHUNK_AAD, &buf);
            refs.push(ChunkRef { id: self.chunks.put(&sealed)?, len: n as u32 });
            if n < CHUNK_SIZE {
                break;
            }
        }
        buf.zeroize();
        Ok((Content { kid: self.kid, epoch: self.epoch, hash: Hash32(*hasher.finalize().as_bytes()), chunks: refs }, total))
    }
}

/// Decrypts one file revision. Detached from the vault lock.
pub struct FileReader {
    /// The revision being read.
    pub meta: Meta,
    keys: ContentKeys,
    chunks: ChunkStore,
}

impl FileReader {
    fn chunk(&self, r: &ChunkRef, remote: Option<&dyn Remote>) -> Result<Vec<u8>> {
        let blob = match self.chunks.get(&r.id) {
            Ok(b) => b,
            Err(e @ (Error::NotFound(_) | Error::Integrity(_))) => {
                // Missing or rotted locally: the server copy is authenticated by its hash.
                let Some(remote) = remote else { return Err(e) };
                let b = remote.get_chunk(&r.id)?;
                self.chunks.discard(&r.id);
                self.chunks.put_verified(&r.id, &b)?;
                b
            }
            Err(e) => return Err(e),
        };
        let mut pt = crypto::open(&self.keys.enc, CHUNK_AAD, &blob)?;
        if pt.len() < r.len as usize {
            pt.zeroize();
            return Err(Error::Integrity("chunk shorter than recorded".into()));
        }
        pt.truncate(r.len as usize);
        Ok(pt)
    }

    /// Stream the plaintext; fails (after writing) if the whole-file hash does not match.
    pub fn write_to(&self, w: &mut dyn Write, remote: Option<&dyn Remote>) -> Result<u64> {
        let content = self.meta.content.as_ref().ok_or_else(|| Error::Invalid("entry has no content".into()))?;
        let (mut hasher, mut total) = (blake3::Hasher::new(), 0u64);
        for r in &content.chunks {
            let mut pt = self.chunk(r, remote)?;
            hasher.update(&pt);
            total += pt.len() as u64;
            let res = w.write_all(&pt);
            pt.zeroize();
            res?;
        }
        if hasher.finalize().as_bytes() != &content.hash.0 || total != self.meta.size {
            return Err(Error::Integrity(format!("{} does not match its recorded hash", self.meta.path)));
        }
        Ok(total)
    }

    pub fn read_all(&self, remote: Option<&dyn Remote>) -> Result<Vec<u8>> {
        let mut out = Vec::with_capacity(self.meta.size as usize);
        match self.write_to(&mut out, remote) {
            Ok(_) => Ok(out),
            Err(e) => {
                out.zeroize();
                Err(e)
            }
        }
    }

    /// Decrypt to `dest` (must not exist): temp file, fsync, verify, then rename into place.
    pub fn export_to(&self, dest: &Path, remote: Option<&dyn Remote>) -> Result<()> {
        let dir = dest.parent().ok_or_else(|| Error::Invalid("destination has no parent".into()))?;
        fs::create_dir_all(dir)?;
        let tmp = dir.join(format!(".coffer-export-{}", hexutil::encode(&crypto::random::<6>())));
        let res = (|| -> Result<()> {
            let mut f = fs::OpenOptions::new().write(true).create_new(true).open(&tmp)?;
            self.write_to(&mut f, remote)?;
            f.sync_all()?;
            if dest.exists() {
                return Err(Error::Exists(dest.display().to_string()));
            }
            fs::rename(&tmp, dest)?;
            Ok(())
        })();
        if res.is_err() {
            let _ = fs::remove_file(&tmp);
        }
        res
    }
}

#[derive(Serialize, Clone, Debug)]
pub struct Item {
    pub name: String,
    pub path: String,
    pub is_dir: bool,
    /// File size, or total size of everything inside a folder.
    pub size: u64,
    pub mtime: i64,
    pub id: Option<String>,
    /// Has changes not yet on the server.
    pub pending: bool,
    /// Files inside (folders only).
    pub count: u64,
    pub rev: u64,
    pub device: String,
}

#[derive(Serialize, Clone, Debug)]
pub struct Version {
    pub rev: u64,
    pub ts: i64,
    pub device: String,
    pub size: u64,
    pub path: String,
    pub deleted: bool,
    pub pending: bool,
    pub current: bool,
}

#[derive(Serialize, Clone, Debug)]
pub struct TrashItem {
    pub id: String,
    pub path: String,
    pub size: u64,
    pub deleted_ts: i64,
    pub device: String,
}

#[derive(Serialize, Clone, Debug, Default)]
pub struct Summary {
    pub files: u64,
    pub bytes: u64,
    pub pending: u64,
    pub trashed: u64,
}

pub struct Vault {
    pub dir: PathBuf,
    pub header: Header,
    pub config: VaultConfig,
    pub device: Device,
    pub(crate) id: [u8; 16],
    pub(crate) keys: Arc<Keys>,
    pub(crate) chunks: ChunkStore,
    pub(crate) journal: Journal,
    pub(crate) state: State,
    /// Applied in memory, not yet durable (only non-empty after a failed journal write).
    unflushed: Vec<Event>,
    /// Bumped on every visible change (cheap "did anything change" check for UIs).
    pub generation: u64,
    /// Human-readable notes about conflicts resolved since unlock.
    pub conflicts: Vec<String>,
    /// Writes are refused while the vault is being connected to a server.
    pub(crate) frozen: bool,
    /// Unreferenced chunks younger than this survive local garbage collection.
    pub gc_min_age: std::time::Duration,
    in_flight: Arc<AtomicUsize>,
    _lock: File,
}

fn lock_dir(dir: &Path) -> Result<File> {
    let f = fs::OpenOptions::new().create(true).truncate(false).write(true).open(dir.join("lock"))?;
    #[cfg(unix)]
    {
        use std::os::unix::io::AsRawFd;
        if unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            return Err(Error::Invalid("vault is open in another Vaultage process".into()));
        }
    }
    Ok(f)
}

impl Vault {
    /// Lay out a new vault directory for an existing header (new vault, or joining one).
    pub fn init(dir: &Path, header: &Header, remote: Option<String>) -> Result<()> {
        if dir.exists() && fs::read_dir(dir)?.next().is_some() {
            return Err(Error::Exists(dir.display().to_string()));
        }
        fs::create_dir_all(dir.join("chunks"))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?;
        }
        atomic_write(&dir.join("config.json"), &serde_json::to_vec_pretty(&VaultConfig { remote, header_pushed: header.version })?)?;
        header.save(&dir.join("header.json"))
    }

    /// Create a vault. Returns it unlocked plus the recovery key (the caller must show it once).
    pub fn create(dir: &Path, remote: Option<String>, device: &Device) -> Result<(Vault, String)> {
        let (header, vmk, recovery) = Header::create();
        Vault::init(dir, &header, remote)?;
        Ok((Vault::open(dir, vmk, device)?, recovery))
    }

    pub fn open(dir: &Path, vmk: Key, device: &Device) -> Result<Vault> {
        let header = Header::load(&dir.join("header.json"))?;
        header.verify(&vmk)?;
        let config: VaultConfig = serde_json::from_slice(&fs::read(dir.join("config.json"))?)?;
        let id = header.vault_id()?;
        let lock = lock_dir(dir)?;
        let keys = Keys::new(header.masters(&vmk)?);
        let (journal, events) = Journal::open::<Event>(&dir.join("journal"), keys.journal.clone(), &id)?;
        let mut state = State::default();
        events.into_iter().for_each(|e| state.apply(e));
        Ok(Vault {
            dir: dir.to_path_buf(),
            chunks: ChunkStore::new(dir.join("chunks"))?,
            keys: Arc::new(keys),
            header,
            config,
            device: device.clone(),
            id,
            journal,
            state,
            unflushed: vec![],
            generation: 1,
            conflicts: vec![],
            frozen: false,
            gc_min_age: std::time::Duration::from_secs(60),
            in_flight: Arc::new(AtomicUsize::new(0)),
            _lock: lock,
        })
    }

    /// Re-read header, config and journal from disk under a (possibly new) master key, in place.
    pub fn reload(&mut self, vmk: Key) -> Result<()> {
        self.flush()?;
        let header = Header::load(&self.dir.join("header.json"))?;
        header.verify(&vmk)?;
        let keys = Keys::new(header.masters(&vmk)?);
        let config: VaultConfig = serde_json::from_slice(&fs::read(self.dir.join("config.json"))?)?;
        let (journal, events) = Journal::open::<Event>(&self.dir.join("journal"), keys.journal.clone(), &self.id)?;
        let mut state = State::default();
        events.into_iter().for_each(|e| state.apply(e));
        self.header = header;
        self.config = config;
        self.keys = Arc::new(keys);
        self.journal = journal;
        self.state = state;
        self.frozen = false;
        self.generation += 1;
        Ok(())
    }

    /// What a fresh server log must contain to mirror this local vault: every kept revision in
    /// commit order, each entry's revisions renumbered from 1 (purged ones leave no trace).
    pub(crate) fn attach_plan(&self) -> Vec<Meta> {
        let mut revs: Vec<(u64, Meta)> = Vec::new();
        for e in self.state.entries.values() {
            if e.history.iter().all(|r| r.meta.content.is_none() && r.meta.deleted) {
                continue; // nothing but a tombstone
            }
            revs.extend(e.history.iter().enumerate().map(|(i, r)| (r.seq, Meta { rev: i as u64 + 1, purge: false, prune_below: 0, ..r.meta.clone() })));
        }
        revs.sort_by_key(|(seq, _)| *seq);
        revs.into_iter().map(|(_, m)| m).collect()
    }

    /// The server now holds exactly `plan` as records 1..n: switch this vault to synced mode.
    pub(crate) fn become_synced(&mut self, plan: &[Meta], url: &str) -> Result<()> {
        let mut events: Vec<Event> = plan.iter().enumerate().map(|(i, m)| Event::Base { seq: i as u64 + 1, meta: m.clone() }).collect();
        events.push(Event::Cursor { seq: plan.len() as u64 });
        // Journal first: if we crash before the config flips, the vault is still a consistent
        // local vault and connecting again resumes from the server's copy.
        self.journal = Journal::rewrite(&self.dir.join("journal"), self.keys.journal.clone(), &self.id, &events)?;
        let mut state = State::default();
        events.into_iter().for_each(|e| state.apply(e));
        self.state = state;
        self.config.remote = Some(url.to_string());
        self.config.header_pushed = self.header.version;
        atomic_write(&self.dir.join("config.json"), &serde_json::to_vec_pretty(&self.config)?)?;
        self.frozen = false;
        self.generation += 1;
        Ok(())
    }

    pub fn id_hex(&self) -> String {
        hexutil::encode(&self.id)
    }
    pub fn synced(&self) -> bool {
        self.config.remote.is_some()
    }
    pub fn keys(&self) -> Arc<Keys> {
        self.keys.clone()
    }
    pub fn cursor(&self) -> u64 {
        self.state.cursor
    }
    pub fn entry(&self, id: &EntryId) -> Option<&EntryState> {
        self.state.entries.get(id)
    }

    /// Change key slots; persists the header.
    pub fn edit_header(&mut self, f: impl FnOnce(&mut Header, &Key) -> Result<String>) -> Result<String> {
        let mut h = self.header.clone();
        let out = f(&mut h, &self.keys.vmk)?;
        h.save(&self.dir.join("header.json"))?;
        self.header = h;
        self.generation += 1;
        Ok(out)
    }
    /// Record that the server has header version `version`.
    pub fn set_header_pushed(&mut self, version: u64) -> Result<()> {
        if self.config.header_pushed != version {
            self.config.header_pushed = version;
            atomic_write(&self.dir.join("config.json"), &serde_json::to_vec_pretty(&self.config)?)?;
        }
        Ok(())
    }

    pub fn portable_header(&self) -> Header {
        self.header.portable(&self.keys.vmk)
    }

    pub(crate) fn stage(&mut self, e: Event) {
        self.unflushed.push(e.clone());
        self.state.apply(e);
    }
    /// Make staged events durable. On failure they stay queued and go out with the next flush,
    /// so the journal never has holes.
    pub(crate) fn flush(&mut self) -> Result<()> {
        if !self.unflushed.is_empty() {
            self.journal.append(&self.unflushed)?;
            self.unflushed.clear();
            self.generation += 1;
        }
        Ok(())
    }
    pub(crate) fn log(&mut self, events: Vec<Event>) -> Result<()> {
        events.into_iter().for_each(|e| self.stage(e));
        self.flush()
    }

    /// Record local changes: pending (synced vault) or committed at once (local vault).
    pub(crate) fn commit_changes(&mut self, metas: Vec<Meta>) -> Result<()> {
        self.commit_with(metas, false)
    }

    /// `purge`: each new revision also purges all earlier revisions of its entry.
    fn commit_with(&mut self, metas: Vec<Meta>, purge: bool) -> Result<()> {
        if self.frozen {
            return Err(Error::Invalid("vault is being connected to a server; try again in a moment".into()));
        }
        let (now, mut seq, mut events) = (now_ms(), self.state.cursor, Vec::new());
        for mut m in metas {
            m.device = self.device.name.clone();
            m.origin = self.device.id.clone();
            m.ts = now;
            let entry = self.state.entries.get(&m.id);
            m.rev = entry.map(|e| e.base_rev()).unwrap_or(0) + 1;
            m.purge = purge;
            m.prune_below = entry.map(|e| e.floor).unwrap_or(0);
            if self.synced() {
                events.push(Event::Pending { meta: m });
            } else {
                seq += 1;
                events.push(Event::Base { seq, meta: m });
                events.push(Event::Cursor { seq });
            }
        }
        self.log(events)
    }

    // ---- views ----

    pub fn live(&self) -> impl Iterator<Item = &Meta> {
        self.state.entries.values().filter_map(|e| e.current()).filter(|m| !m.deleted)
    }
    pub fn find(&self, path: &str) -> Option<&Meta> {
        self.live().find(|m| m.path == path)
    }
    pub fn is_dir(&self, path: &str) -> bool {
        path.is_empty() || self.live().any(|m| (m.path == path && m.kind == Kind::Dir) || (m.path != path && is_under(&m.path, path)))
    }
    fn occupied(&self, path: &str) -> bool {
        self.live().any(|m| is_under(&m.path, path))
    }
    fn free_path(&self, wanted: String) -> String {
        let mut p = wanted.clone();
        let mut n = 2;
        while self.occupied(&p) {
            p = tagged_path(&wanted, &n.to_string());
            n += 1;
        }
        p
    }
    fn check_parents(&self, path: &str) -> Result<()> {
        let mut dir = parent(path);
        while !dir.is_empty() {
            if self.find(dir).map(|m| m.kind == Kind::File).unwrap_or(false) {
                return Err(Error::Invalid(format!("'{dir}' is a file, not a folder")));
            }
            dir = parent(dir);
        }
        Ok(())
    }

    /// Direct children of `dir`. Folders exist explicitly or implicitly (as a prefix of a file).
    pub fn list(&self, dir: &str) -> Result<Vec<Item>> {
        let dir = normalize_path(dir)?;
        let mut out: BTreeMap<String, Item> = BTreeMap::new();
        for (id, e) in &self.state.entries {
            let Some(m) = e.current().filter(|m| !m.deleted && m.path != dir && is_under(&m.path, &dir)) else { continue };
            let rel = if dir.is_empty() { &m.path[..] } else { &m.path[dir.len() + 1..] };
            let pending = e.pending.is_some();
            match rel.split_once('/') {
                None if m.kind == Kind::File => {
                    out.insert(
                        rel.to_string(),
                        Item { name: rel.into(), path: m.path.clone(), is_dir: false, size: m.size, mtime: m.mtime, id: Some(id.hex()), pending, count: 0, rev: m.rev, device: m.device.clone() },
                    );
                }
                other => {
                    let name = other.map(|(first, _)| first).unwrap_or(rel);
                    let it = out.entry(name.to_string()).or_insert_with(|| Item {
                        name: name.into(), path: join(&dir, name), is_dir: true, size: 0, mtime: 0, id: None, pending: false, count: 0, rev: 0, device: String::new(),
                    });
                    if !it.is_dir {
                        continue; // a file shadows a same-named folder until collisions are resolved
                    }
                    it.pending |= pending;
                    if m.kind == Kind::File {
                        it.size += m.size;
                        it.count += 1;
                        it.mtime = it.mtime.max(m.mtime);
                    } else {
                        it.mtime = it.mtime.max(m.ts);
                    }
                }
            }
        }
        Ok(out.into_values().collect())
    }

    /// Every live file at or under `path` (for export / delete / search).
    pub fn files_under(&self, path: &str) -> Vec<Meta> {
        let mut v: Vec<Meta> = self.live().filter(|m| m.kind == Kind::File && is_under(&m.path, path)).cloned().collect();
        v.sort_by(|a, b| a.path.cmp(&b.path));
        v
    }

    pub fn search(&self, query: &str) -> Vec<Item> {
        let q = query.to_lowercase();
        let mut v: Vec<Item> = self
            .state
            .entries
            .iter()
            .filter_map(|(id, e)| {
                let m = e.current().filter(|m| !m.deleted && m.kind == Kind::File && basename(&m.path).to_lowercase().contains(&q))?;
                Some(Item { name: basename(&m.path).into(), path: m.path.clone(), is_dir: false, size: m.size, mtime: m.mtime, id: Some(id.hex()), pending: e.pending.is_some(), count: 0, rev: m.rev, device: m.device.clone() })
            })
            .collect();
        v.sort_by(|a, b| a.path.cmp(&b.path));
        v
    }

    pub fn summary(&self) -> Summary {
        let mut s = Summary::default();
        for e in self.state.entries.values() {
            s.pending += e.pending.is_some() as u64;
            match e.current() {
                Some(m) if !m.deleted && m.kind == Kind::File => {
                    s.files += 1;
                    s.bytes += m.size;
                }
                Some(m) if m.deleted && m.kind == Kind::File && !m.purge && e.history.iter().any(|r| r.meta.content.is_some()) => s.trashed += 1,
                _ => {}
            }
        }
        s
    }

    pub fn versions(&self, id: &EntryId) -> Result<Vec<Version>> {
        let e = self.entry(id).ok_or_else(|| Error::NotFound("entry".into()))?;
        let ver = |m: &Meta, pending: bool, current: bool| Version { rev: m.rev, ts: m.ts, device: m.device.clone(), size: m.size, path: m.path.clone(), deleted: m.deleted, pending, current };
        let mut v: Vec<Version> = e.history.iter().enumerate().map(|(i, r)| ver(&r.meta, false, e.pending.is_none() && i + 1 == e.history.len())).collect();
        if let Some(p) = &e.pending {
            v.push(ver(p, true, true));
        }
        v.reverse();
        Ok(v)
    }

    pub fn trash(&self) -> Vec<TrashItem> {
        let mut v: Vec<TrashItem> = self
            .state
            .entries
            .iter()
            .filter_map(|(id, e)| {
                let m = e.current().filter(|m| m.deleted && m.kind == Kind::File && !m.purge)?;
                e.history.iter().any(|r| r.meta.content.is_some()).then(|| TrashItem { id: id.hex(), path: m.path.clone(), size: m.size, deleted_ts: m.ts, device: m.device.clone() })
            })
            .collect();
        v.sort_by(|a, b| b.deleted_ts.cmp(&a.deleted_ts));
        v
    }

    // ---- reading ----

    /// Reader for an entry's current revision, or a specific committed one.
    pub fn reader(&self, id: &EntryId, rev: Option<u64>) -> Result<FileReader> {
        let e = self.entry(id).ok_or_else(|| Error::NotFound("entry".into()))?;
        let meta = match rev {
            None => e.current(),
            Some(r) => e.pending.as_ref().filter(|p| p.rev == r && e.history.iter().all(|h| h.meta.rev != r)).or_else(|| e.history.iter().find(|h| h.meta.rev == r).map(|h| &h.meta)),
        }
        .ok_or_else(|| Error::NotFound("revision".into()))?
        .clone();
        let content = meta.content.as_ref().ok_or_else(|| Error::Invalid("this revision has no content".into()))?;
        Ok(FileReader { keys: content_keys(&self.keys, content.epoch, &content.kid)?, chunks: self.chunks.clone(), meta })
    }

    // ---- writing ----

    /// Start importing to `path`. If a file lives there, the import becomes its next revision.
    pub fn ingester(&self, path: &str) -> Result<Ingester> {
        let path = normalize_path(path)?;
        let existing = self.find(&path).filter(|m| m.kind == Kind::File);
        let id = existing.map(|m| m.id).unwrap_or_else(EntryId::random);
        // Same content key across revisions of a file, so unchanged chunks dedup. New data always
        // goes under the current key epoch.
        let kid = existing.and_then(|m| m.content.as_ref()).map(|c| c.kid).unwrap_or(id);
        let epoch = self.keys.epoch();
        self.in_flight.fetch_add(1, Ordering::SeqCst);
        Ok(Ingester { id, kid, epoch, keys: content_keys(&self.keys, epoch, &kid)?, chunks: self.chunks.clone(), in_flight: self.in_flight.clone() })
    }

    pub fn commit_file(&mut self, id: EntryId, path: &str, content: Content, size: u64, mtime: i64) -> Result<EntryId> {
        let path = normalize_path(path)?;
        if path.is_empty() {
            return Err(Error::Invalid("empty path".into()));
        }
        if self.is_dir(&path) {
            return Err(Error::Exists(format!("'{path}' is a folder")));
        }
        self.check_parents(&path)?;
        if let Some(c) = self.entry(&id).and_then(|e| e.current()) {
            if !c.deleted && c.path == path && c.hash() == Some(content.hash) {
                return Ok(id); // unchanged
            }
        }
        self.commit_changes(vec![Meta { id, rev: 0, path, kind: Kind::File, deleted: false, size, mtime, content: Some(content), device: String::new(), origin: String::new(), ts: 0, purge: false, prune_below: 0 }])?;
        self.resolve_collisions()?;
        Ok(id)
    }

    pub fn put_bytes(&mut self, path: &str, data: &[u8], mtime: i64) -> Result<EntryId> {
        let ing = self.ingester(path)?;
        let (content, size) = ing.ingest(&mut &data[..])?;
        self.commit_file(ing.id, path, content, size, mtime)
    }

    // ---- purging ----

    /// Permanently drop everything about trashed entries except a bare tombstone: all their
    /// versions become unrecoverable, here and (after sync) on the server and other devices.
    pub fn purge(&mut self, ids: &[EntryId]) -> Result<usize> {
        let dead: Vec<Meta> = ids
            .iter()
            .filter_map(|id| self.entry(id).and_then(|e| e.current()))
            .filter(|m| m.deleted)
            .map(|m| Meta { content: None, ..m.clone() })
            .collect();
        let n = dead.len();
        self.commit_with(dead, true)?;
        self.maintain()?;
        Ok(n)
    }

    pub fn empty_trash(&mut self) -> Result<usize> {
        let ids: Vec<EntryId> = self.trash().iter().filter_map(|t| EntryId::parse(&t.id).ok()).collect();
        self.purge(&ids)
    }

    /// Keep only the current version of a file; older versions become unrecoverable.
    pub fn prune_versions(&mut self, id: &EntryId) -> Result<()> {
        let cur = self.entry(id).and_then(|e| e.current()).filter(|m| !m.deleted).cloned().ok_or_else(|| Error::NotFound("entry".into()))?;
        self.commit_with(vec![cur], true)?;
        self.maintain()
    }

    /// Delete local chunks nothing refers to any more. Returns (chunks, bytes).
    pub fn gc(&mut self) -> Result<(u64, u64)> {
        if self.in_flight.load(Ordering::SeqCst) > 0 {
            return Ok((0, 0)); // an import has chunks on disk that are not committed yet
        }
        let mut keep: BTreeSet<ChunkId> = BTreeSet::new();
        for e in self.state.entries.values() {
            e.history.iter().for_each(|r| keep.extend(r.meta.refs()));
            e.pending.iter().for_each(|m| keep.extend(m.refs()));
        }
        self.chunks.sweep(&keep, self.gc_min_age)
    }

    /// Rewrite the journal from live state, so purged revisions are gone from the file too.
    pub fn compact(&mut self) -> Result<()> {
        self.flush()?;
        let mut events = Vec::new();
        for (id, e) in &self.state.entries {
            if e.pruned_through > 0 {
                events.push(Event::Pruned { entry: *id, rev: e.pruned_through });
            }
            events.extend(e.history.iter().map(|r| Event::Base { seq: r.seq, meta: r.meta.clone() }));
            events.extend(e.pending.iter().map(|m| Event::Pending { meta: m.clone() }));
        }
        events.extend(self.state.prune_todo.iter().map(|(entry, below)| Event::PruneTodo { entry: *entry, below: *below }));
        events.push(Event::Cursor { seq: self.state.cursor });
        self.journal = Journal::rewrite(&self.dir.join("journal"), self.keys.journal.clone(), &self.id, &events)?;
        Ok(())
    }

    /// After a purge took effect: reclaim chunks and scrub the journal.
    pub fn maintain(&mut self) -> Result<()> {
        if self.state.dirty && self.in_flight.load(Ordering::SeqCst) == 0 {
            self.gc()?;
            self.compact()?;
            self.state.dirty = false;
            self.generation += 1;
        }
        Ok(())
    }

    // ---- key rotation (two steps, so the new recovery key is seen before anything changes) ----

    fn rotation_file(&self) -> PathBuf {
        self.dir.join("rotate.json")
    }

    pub fn rotation_pending(&self) -> bool {
        self.rotation_file().exists()
    }

    /// Stage a rotation: new master key, new recovery key, optional new passphrase. Nothing is
    /// in effect yet. Calling again returns the same staged recovery key.
    pub fn rotate_prepare(&mut self, passphrase: Option<&[u8]>, kdf: Option<crate::crypto::KdfParams>) -> Result<String> {
        if self.rotation_pending() {
            return Ok(self.rotate_staged()?.2);
        }
        let (mut h, new, recovery) = self.header.rotate(&self.keys.vmk)?;
        if let Some(p) = passphrase {
            h.add_slot(&new, crate::header::SlotKind::Passphrase, "Passphrase", p, kdf, serde_json::Value::Null)?;
        }
        // Sealed under the current key: only this unlocked vault can pick the rotation back up.
        let mut secret = new.expose().to_vec();
        secret.extend_from_slice(recovery.as_bytes());
        let sealed = crypto::seal(&self.keys.vmk.derive("coffer v1 rotation staging"), &self.id, &secret);
        secret.zeroize();
        let doc = serde_json::json!({ "header": h, "sealed": hexutil::encode(&sealed) });
        atomic_write(&self.rotation_file(), &serde_json::to_vec_pretty(&doc)?)?;
        self.generation += 1;
        Ok(recovery)
    }

    /// The staged (header, new master key, recovery key text).
    pub fn rotate_staged(&self) -> Result<(Header, Key, String)> {
        let doc: serde_json::Value = serde_json::from_slice(&fs::read(self.rotation_file()).map_err(|_| Error::NotFound("no key rotation in progress".into()))?)?;
        let header: Header = serde_json::from_value(doc["header"].clone())?;
        let sealed = hexutil::decode(doc["sealed"].as_str().unwrap_or("")).ok_or_else(|| Error::Format("rotation file".into()))?;
        let mut secret = crypto::open(&self.keys.vmk.derive("coffer v1 rotation staging"), &self.id, &sealed)?;
        let key = Key::from_slice(&secret[..32.min(secret.len())]);
        let recovery = String::from_utf8_lossy(&secret[32.min(secret.len())..]).into_owned();
        secret.zeroize();
        let key = key?;
        header.verify(&key)?;
        Ok((header, key, recovery))
    }

    pub fn rotate_discard(&mut self) -> Result<()> {
        match fs::remove_file(self.rotation_file()) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
        self.generation += 1;
        Ok(())
    }

    /// Make the staged header the vault's header. The caller reopens the vault with the new key.
    pub fn rotate_finish(&mut self, header: &Header) -> Result<()> {
        header.save(&self.dir.join("header.json"))?;
        self.rotate_discard()
    }

    /// Replace the header (key slots changed elsewhere / keys rotated elsewhere).
    pub fn replace_header(&mut self, header: Header) -> Result<()> {
        header.save(&self.dir.join("header.json"))?;
        self.header = header;
        self.generation += 1;
        Ok(())
    }

    pub fn mkdir(&mut self, path: &str) -> Result<()> {
        let path = normalize_path(path)?;
        if path.is_empty() || self.is_dir(&path) {
            return Ok(());
        }
        if self.find(&path).is_some() {
            return Err(Error::Exists(format!("'{path}' is a file")));
        }
        self.check_parents(&path)?;
        self.commit_changes(vec![Meta { id: EntryId::random(), rev: 0, path, kind: Kind::Dir, deleted: false, size: 0, mtime: now_ms(), content: None, device: String::new(), origin: String::new(), ts: 0, purge: false, prune_below: 0 }])
    }

    /// Move/rename a file or a whole folder.
    pub fn rename(&mut self, from: &str, to: &str) -> Result<usize> {
        let (from, to) = (normalize_path(from)?, normalize_path(to)?);
        if from.is_empty() || to.is_empty() {
            return Err(Error::Invalid("empty path".into()));
        }
        if from == to {
            return Ok(0);
        }
        if is_under(&to, &from) {
            return Err(Error::Invalid("cannot move a folder into itself".into()));
        }
        if self.occupied(&to) {
            return Err(Error::Exists(to));
        }
        self.check_parents(&to)?;
        let moved: Vec<Meta> = self
            .live()
            .filter(|m| is_under(&m.path, &from))
            .map(|m| Meta { path: format!("{to}{}", &m.path[from.len()..]), ..m.clone() })
            .collect();
        if moved.is_empty() {
            return Err(Error::NotFound(from));
        }
        let n = moved.len();
        self.commit_changes(moved)?;
        Ok(n)
    }

    /// Soft delete: a tombstone revision. Earlier revisions stay restorable.
    pub fn delete(&mut self, path: &str) -> Result<usize> {
        let path = normalize_path(path)?;
        if path.is_empty() {
            return Err(Error::Invalid("refusing to delete the vault root".into()));
        }
        let dead: Vec<Meta> = self.live().filter(|m| is_under(&m.path, &path)).map(|m| Meta { deleted: true, content: None, ..m.clone() }).collect();
        if dead.is_empty() {
            return Err(Error::NotFound(path));
        }
        let n = dead.len();
        self.commit_changes(dead)?;
        Ok(n)
    }

    /// Bring back an old revision (also un-deletes). Returns the path it was restored to.
    pub fn restore(&mut self, id: &EntryId, rev: Option<u64>) -> Result<String> {
        let e = self.entry(id).ok_or_else(|| Error::NotFound("entry".into()))?;
        let old = match rev {
            Some(r) => e.history.iter().find(|h| h.meta.rev == r),
            None => e.history.iter().rev().find(|h| !h.meta.deleted),
        }
        .map(|h| h.meta.clone())
        .filter(|m| !m.deleted)
        .ok_or_else(|| Error::NotFound("restorable revision".into()))?;
        let cur = e.current().cloned().ok_or_else(|| Error::NotFound("entry".into()))?;
        let mut path = if cur.deleted { old.path.clone() } else { cur.path.clone() };
        if self.live().any(|m| m.id != *id && is_under(&m.path, &path)) || self.check_parents(&path).is_err() {
            path = self.free_path(tagged_path(&path, "restored"));
        }
        self.commit_changes(vec![Meta { path: path.clone(), deleted: false, ..old }])?;
        Ok(path)
    }

    /// Make paths unique. Deterministic so every device reaches the same result:
    /// committed beats uncommitted, then lowest id wins; the loser is renamed (files) or dropped
    /// (duplicate folder markers). A file that collides with a folder is renamed too.
    pub fn resolve_collisions(&mut self) -> Result<usize> {
        let mut total = 0;
        for _ in 0..8 {
            let mut by_path: BTreeMap<&str, Vec<(bool, EntryId)>> = BTreeMap::new();
            let mut dirs: BTreeSet<&str> = BTreeSet::new();
            for (id, e) in &self.state.entries {
                let Some(m) = e.current().filter(|m| !m.deleted) else { continue };
                by_path.entry(&m.path).or_default().push((e.history.is_empty(), *id));
                let mut d = parent(&m.path);
                while !d.is_empty() && dirs.insert(d) {
                    d = parent(d);
                }
            }
            let mut losers: Vec<EntryId> = Vec::new();
            for (path, group) in by_path.iter_mut() {
                group.sort();
                losers.extend(group.iter().skip(1).map(|g| g.1));
                let (_, first) = group[0];
                if dirs.contains(path) && self.entry(&first).and_then(|e| e.current()).map(|m| m.kind == Kind::File).unwrap_or(false) {
                    losers.push(first);
                }
            }
            if losers.is_empty() {
                break;
            }
            let mut changes = Vec::new();
            let mut taken: BTreeSet<String> = BTreeSet::new();
            for id in losers {
                let m = self.entry(&id).and_then(|e| e.current()).unwrap().clone();
                if m.kind == Kind::Dir {
                    changes.push(Meta { deleted: true, ..m });
                    continue;
                }
                let wanted = tagged_path(&m.path, &format!("conflict {} {}", m.device, stamp(m.ts)));
                let (mut p, mut n) = (wanted.clone(), 2);
                while self.occupied(&p) || !taken.insert(p.clone()) {
                    p = tagged_path(&wanted, &n.to_string());
                    n += 1;
                }
                self.conflicts.push(format!("Two files wanted the name '{}'. Kept both: '{}'.", m.path, basename(&p)));
                changes.push(Meta { path: p, ..m });
            }
            total += changes.len();
            self.commit_changes(changes)?;
        }
        Ok(total)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vault(remote: Option<&str>) -> (tempfile::TempDir, Vault, String) {
        let d = tempfile::tempdir().unwrap();
        let (v, rec) = Vault::create(&d.path().join("v"), remote.map(String::from), &Device::new("mac")).unwrap();
        (d, v, rec)
    }

    fn read(v: &Vault, path: &str) -> Vec<u8> {
        v.reader(&v.find(path).unwrap().id, None).unwrap().read_all(None).unwrap()
    }

    #[test]
    fn local_vault_lifecycle_survives_reopen() {
        let (d, mut v, rec) = vault(None);
        v.put_bytes("docs/a.txt", b"one", 1).unwrap();
        v.put_bytes("docs/a.txt", b"two", 2).unwrap();
        v.put_bytes("docs/deep/b.bin", &vec![7u8; 5000], 3).unwrap();
        v.mkdir("empty").unwrap();
        assert_eq!(read(&v, "docs/a.txt"), b"two");
        let root = v.list("").unwrap();
        assert_eq!(root.iter().map(|i| (i.name.as_str(), i.is_dir, i.count)).collect::<Vec<_>>(), [("docs", true, 2), ("empty", true, 0)]);
        assert_eq!(v.list("docs").unwrap().len(), 2);

        v.rename("docs", "papers").unwrap();
        assert!(v.find("docs/a.txt").is_none());
        assert_eq!(read(&v, "papers/deep/b.bin"), vec![7u8; 5000]);
        assert!(v.rename("papers", "papers/x").is_err());
        assert!(v.rename("papers/a.txt", "empty").is_err());

        let id = v.find("papers/a.txt").unwrap().id;
        assert_eq!(v.delete("papers/a.txt").unwrap(), 1);
        assert_eq!(v.trash().len(), 1);
        assert_eq!(v.versions(&id).unwrap().len(), 4);
        // Restore the first version's content.
        v.restore(&id, Some(1)).unwrap();
        assert_eq!(read(&v, "docs/a.txt"), b"one");

        // Reopen from disk with the recovery key.
        let dir = v.dir.clone();
        drop(v);
        let h = Header::load(&dir.join("header.json")).unwrap();
        let vmk = h.unlock_any(crate::header::SlotKind::Recovery, rec.as_bytes()).unwrap();
        let v = Vault::open(&dir, vmk, &Device::new("mac")).unwrap();
        assert_eq!(read(&v, "docs/a.txt"), b"one");
        assert_eq!(v.summary().files, 2);
        assert!(Vault::open(&dir, Key::random(), &Device::new("mac")).is_err());
        drop(d);
    }

    #[test]
    fn nothing_readable_at_rest() {
        let (d, mut v, _) = vault(None);
        let secret = b"TOP-SECRET-PLAINTEXT-MARKER-0123456789".repeat(50);
        v.put_bytes("private/SECRET-FILENAME.txt", &secret, 1).unwrap();
        drop(v);
        fn walk(p: &Path, out: &mut Vec<u8>) {
            for e in fs::read_dir(p).unwrap() {
                let e = e.unwrap().path();
                if e.is_dir() { walk(&e, out) } else { out.extend(fs::read(&e).unwrap()) }
            }
        }
        let mut all = Vec::new();
        walk(d.path(), &mut all);
        let has = |needle: &[u8]| all.windows(needle.len()).any(|w| w == needle);
        assert!(!has(b"TOP-SECRET") && !has(b"SECRET-FILENAME") && !has(b"private"));
    }

    #[test]
    fn large_file_chunks_dedup_and_padding() {
        let (_d, mut v, _) = vault(None);
        let mut data = vec![0u8; CHUNK_SIZE * 2 + 12345];
        for (i, b) in data.iter_mut().enumerate() {
            *b = (i * 31 % 251) as u8;
        }
        let id = v.put_bytes("big.bin", &data, 1).unwrap();
        let c1 = v.entry(&id).unwrap().current().unwrap().content.clone().unwrap();
        assert_eq!(c1.chunks.len(), 3);
        assert_eq!(read(&v, "big.bin"), data);
        // Change only the tail: the first two chunks are reused.
        let n = data.len();
        data[n - 1] ^= 1;
        v.put_bytes("big.bin", &data, 2).unwrap();
        let c2 = v.entry(&id).unwrap().current().unwrap().content.clone().unwrap();
        assert_eq!(c1.chunks[..2], c2.chunks[..2]);
        assert_ne!(c1.chunks[2], c2.chunks[2]);
        assert_eq!(read(&v, "big.bin"), data);
        // Empty file.
        v.put_bytes("empty", b"", 1).unwrap();
        assert_eq!(read(&v, "empty"), b"");
    }

    #[test]
    fn corrupted_chunk_is_detected_not_returned() {
        let (_d, mut v, _) = vault(None);
        let id = v.put_bytes("a", b"payload", 1).unwrap();
        let cid = v.entry(&id).unwrap().current().unwrap().content.as_ref().unwrap().chunks[0].id;
        let p = v.dir.join("chunks").join(&cid.hex()[..2]).join(cid.hex());
        let mut b = fs::read(&p).unwrap();
        b[30] ^= 1;
        fs::write(&p, b).unwrap();
        assert!(matches!(v.reader(&id, None).unwrap().read_all(None), Err(Error::Integrity(_))));
    }

    #[test]
    fn export_verifies_and_never_overwrites() {
        let (d, mut v, _) = vault(None);
        let id = v.put_bytes("a.txt", b"hello", 1).unwrap();
        let out = d.path().join("out/a.txt");
        v.reader(&id, None).unwrap().export_to(&out, None).unwrap();
        assert_eq!(fs::read(&out).unwrap(), b"hello");
        assert!(matches!(v.reader(&id, None).unwrap().export_to(&out, None), Err(Error::Exists(_))));
        assert_eq!(fs::read_dir(out.parent().unwrap()).unwrap().count(), 1);
    }

    #[test]
    fn second_process_cannot_open_same_vault() {
        let (_d, v, _) = vault(None);
        assert!(Vault::open(&v.dir, v.keys.vmk.clone(), &Device::new("x")).is_err());
    }
}
