//! Filesystem backend: per vault `meta.json`, append-only framed `log`, `chunks/xx/<cid>`.
//! Single process only; concurrency via in-process per-vault locks.

use std::collections::{HashMap, HashSet};
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufReader, BufWriter, Read, Write};
use std::os::unix::fs::FileExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use coffer_core::proto::{PruneResp, UsageResp};

use super::*;

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

fn unique() -> String {
    static C: AtomicU64 = AtomicU64::new(0);
    let n = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!("{}-{}-{}", std::process::id(), n, C.fetch_add(1, Ordering::Relaxed))
}

fn fsync_dir(p: &Path) -> io::Result<()> {
    File::open(p)?.sync_all()
}

/// temp file + fsync + rename + fsync dir.
fn write_atomic(dir: &Path, name: &str, data: &[u8]) -> io::Result<()> {
    let tmp = dir.join(format!(".tmp-{name}-{}", unique()));
    let res = (|| {
        let mut f = OpenOptions::new().write(true).create_new(true).open(&tmp)?;
        f.write_all(data)?;
        f.sync_all()?;
        drop(f);
        fs::rename(&tmp, dir.join(name))?;
        fsync_dir(dir)
    })();
    if res.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    res
}

fn chunk_path(dir: &Path, cid: &str) -> PathBuf {
    dir.join("chunks").join(&cid[..2]).join(cid)
}

/// Read one frame by offset.
fn read_frame(f: &File, off: u64) -> io::Result<Rec> {
    let bad = |m: &str| io::Error::new(io::ErrorKind::InvalidData, format!("log frame at {off}: {m}"));
    let mut lb = [0u8; LEN];
    f.read_exact_at(&mut lb, off)?;
    let len = u32::from_le_bytes(lb) as usize;
    if !len_ok(len) {
        return Err(bad("bad length"));
    }
    let mut buf = vec![0u8; len + TAG];
    f.read_exact_at(&mut buf, off + LEN as u64)?;
    let (p, t) = buf.split_at(len);
    if !tag_ok(p, t) {
        return Err(bad("checksum mismatch"));
    }
    decode_payload(p).ok_or_else(|| bad("bad payload"))
}

/// All 256 chunk subdirs exist up front so chunk writes never create directories.
fn ensure_chunk_dirs(dir: &Path) -> io::Result<()> {
    let chunks = dir.join("chunks");
    let mut created = false;
    match fs::create_dir(&chunks) {
        Ok(()) => created = true,
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
        Err(e) => return Err(e),
    }
    for i in 0..=255u8 {
        match fs::create_dir(chunks.join(hex(&[i]))) {
            Ok(()) => created = true,
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(e),
        }
    }
    if created {
        fsync_dir(&chunks)?;
        fsync_dir(dir)?;
    }
    Ok(())
}

fn remove_tmps(dir: &Path) -> io::Result<()> {
    for e in fs::read_dir(dir)? {
        let e = e?;
        if e.file_name().to_string_lossy().starts_with(".tmp-") {
            fs::remove_file(e.path())?;
        }
    }
    Ok(())
}

struct ChunkFile {
    cid: Cid,
    path: PathBuf,
    size: u64,
    mtime: SystemTime,
}

/// Every stored chunk. Also removes stray temp files when `clean`.
fn walk_chunks(dir: &Path, clean: bool) -> io::Result<Vec<ChunkFile>> {
    let mut out = Vec::new();
    for i in 0..=255u8 {
        let sub = dir.join("chunks").join(hex(&[i]));
        for e in fs::read_dir(&sub)? {
            let e = e?;
            let name = e.file_name();
            let name = name.to_string_lossy();
            if name.starts_with(".tmp-") {
                if clean {
                    fs::remove_file(e.path())?;
                }
                continue;
            }
            let Some(cid) = is_hex(&name, 64)
                .then(|| coffer_core::hexutil::decode_array::<32>(&name))
                .flatten()
            else {
                continue;
            };
            let md = match e.metadata() {
                Ok(m) => m,
                Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
                Err(e) => return Err(e),
            };
            out.push(ChunkFile {
                cid,
                path: e.path(),
                size: md.len(),
                mtime: md.modified()?,
            });
        }
    }
    Ok(out)
}

#[derive(Default, Clone, Copy)]
struct Usage {
    bytes: u64,
    chunks: u64,
}

struct Vault {
    dir: PathBuf,
    meta: Meta,
    auth_pub: [u8; 32],
    header_version: u64,
    log: File,
    log_len: u64,
    /// offsets[seq-1] = frame start.
    offsets: Vec<u64>,
    /// entry -> (current rev, seq of that rev)
    entries: HashMap<Id16, (u64, u64)>,
}

impl Vault {
    /// Caller holds the vault's lock and has checked it does not exist.
    fn create(dir: &Path, meta: &Meta) -> io::Result<()> {
        // A dir without meta.json is a crashed create: nothing in it was ever served.
        if dir.try_exists()? {
            fs::remove_dir_all(dir)?;
        }
        let parent = dir.parent().unwrap();
        fs::create_dir_all(parent)?;
        fs::create_dir(dir)?;
        fsync_dir(parent)?;
        File::create(dir.join("log"))?.sync_all()?;
        ensure_chunk_dirs(dir)?;
        fsync_dir(dir)?;
        // meta.json last: its presence means the vault exists.
        write_atomic(dir, "meta.json", &meta.encode())
    }

    /// Load and replay. `Ok(None)` if the vault does not exist.
    fn open(dir: &Path) -> Result<Option<(Vault, Usage)>, String> {
        let ctx = |what: &str, e: &dyn std::fmt::Display| format!("{}: {what}: {e}", dir.display());
        let meta = match fs::read(dir.join("meta.json")) {
            Ok(b) => b,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(ctx("read meta.json", &e)),
        };
        let (meta, parsed) = Meta::decode(&meta).map_err(|e| ctx("meta.json", &e))?;
        // Leftovers of interrupted atomic writes (incl. a log rewrite holding pruned data).
        remove_tmps(dir).map_err(|e| ctx("remove temp files", &e))?;
        ensure_chunk_dirs(dir).map_err(|e| ctx("chunk dirs", &e))?;
        // No chunk upload for this vault can be in flight before its first load.
        let chunks = walk_chunks(dir, true).map_err(|e| ctx("scan chunks", &e))?;
        let usage = Usage {
            bytes: chunks.iter().map(|c| c.size).sum(),
            chunks: chunks.len() as u64,
        };

        let log = OpenOptions::new()
            .read(true)
            .write(true)
            .open(dir.join("log"))
            .map_err(|e| ctx("open log", &e))?;
        let file_len = log.metadata().map_err(|e| ctx("stat log", &e))?.len();
        let mut v = Vault {
            dir: dir.to_owned(),
            meta,
            auth_pub: parsed.auth_pub,
            header_version: parsed.version,
            log,
            log_len: 0,
            offsets: Vec::new(),
            entries: HashMap::new(),
        };
        let good = v.replay(file_len).map_err(|e| ctx("replay log", &e))?;
        if good < file_len {
            eprintln!(
                "cofferd: {}: truncating torn log tail ({} bytes at offset {good})",
                dir.display(),
                file_len - good
            );
            v.log.set_len(good).map_err(|e| ctx("truncate log", &e))?;
            v.log.sync_all().map_err(|e| ctx("fsync log", &e))?;
        }
        v.log_len = good;
        Ok(Some((v, usage)))
    }

    /// Returns the length of the valid prefix. Only a bad *final* frame is treated as torn.
    fn replay(&mut self, file_len: u64) -> Result<u64, String> {
        let mut r = BufReader::with_capacity(1 << 20, &self.log);
        let mut buf = Vec::new();
        let mut off = 0u64;
        while off < file_len {
            let rem = file_len - off;
            if rem < LEN as u64 {
                break;
            }
            let mut lb = [0u8; LEN];
            r.read_exact(&mut lb).map_err(|e| e.to_string())?;
            let len = u32::from_le_bytes(lb) as usize;
            if !len_ok(len) {
                // A single unacknowledged append is at most MAX_FRAME long.
                if rem <= MAX_FRAME {
                    break;
                }
                return Err(format!("bad frame length {len} at offset {off}"));
            }
            let end = off + (LEN + len + TAG) as u64;
            if end > file_len {
                break;
            }
            buf.resize(len + TAG, 0);
            r.read_exact(&mut buf).map_err(|e| e.to_string())?;
            let (p, t) = buf.split_at(len);
            if !tag_ok(p, t) {
                if end == file_len {
                    break;
                }
                return Err(format!("checksum mismatch at offset {off}"));
            }
            let rec = decode_payload(p).ok_or_else(|| format!("bad payload at offset {off}"))?;
            let want_seq = self.offsets.len() as u64 + 1;
            if rec.seq != want_seq {
                return Err(format!("seq {} at offset {off}, expected {want_seq}", rec.seq));
            }
            let prev = self.entries.get(&rec.entry).map_or(0, |e| e.0);
            if rec.rev != prev + 1 {
                return Err(format!("seq {}: rev {} after rev {prev}", rec.seq, rec.rev));
            }
            self.offsets.push(off);
            self.entries.insert(rec.entry, (rec.rev, rec.seq));
            off = end;
        }
        Ok(off)
    }

    fn head(&self) -> u64 {
        self.offsets.len() as u64
    }

    fn read(&self, seq: u64) -> io::Result<Rec> {
        let off = *self
            .offsets
            .get((seq as usize).wrapping_sub(1))
            .ok_or_else(|| io::Error::other(format!("seq {seq} out of range")))?;
        read_frame(&self.log, off)
    }

    /// Append + fsync. On error the file may hold a partial frame: caller must poison the vault.
    fn append(&mut self, entry: &Id16, rev: u64, refs: &[Cid], blob: &[u8]) -> io::Result<u64> {
        let seq = self.head() + 1;
        let frame = encode_frame(seq, entry, rev, refs, blob);
        self.log.write_all_at(&frame, self.log_len)?;
        self.log.sync_all()?;
        self.offsets.push(self.log_len);
        self.log_len += frame.len() as u64;
        self.entries.insert(*entry, (rev, seq));
        Ok(seq)
    }

    fn set_meta(&mut self, meta: Meta) -> io::Result<()> {
        write_atomic(&self.dir, "meta.json", &meta.encode())?;
        let (meta, p) = Meta::decode(&meta.encode()).map_err(io::Error::other)?;
        self.auth_pub = p.auth_pub;
        self.header_version = p.version;
        self.meta = meta;
        Ok(())
    }

    /// Rewrite the log turning matching records into placeholders. Returns (records changed,
    /// chunk ids referenced by every remaining unpruned record).
    fn rewrite_pruned(&mut self, below: &HashMap<Id16, u64>) -> Result<(u64, HashSet<Cid>), Fail> {
        let fatal = |e: &dyn std::fmt::Display| Fail::Fatal(format!("prune: {e}"));
        let mut refs = HashSet::new();
        let mut changed = 0u64;
        let tmp_name = format!(".tmp-log-{}", unique());
        let tmp = self.dir.join(&tmp_name);
        let mut new_offsets = Vec::with_capacity(self.offsets.len());
        let res = (|| -> io::Result<u64> {
            let f = OpenOptions::new().write(true).create_new(true).open(&tmp)?;
            let mut w = BufWriter::with_capacity(1 << 20, f);
            let mut pos = 0u64;
            for seq in 1..=self.head() {
                let rec = self.read(seq)?;
                let prune = !rec.blob.is_empty() && below.get(&rec.entry).is_some_and(|b| rec.rev < *b);
                let frame = if prune {
                    changed += 1;
                    placeholder_frame(rec.seq, &rec.entry, rec.rev)
                } else {
                    refs.extend(rec.refs.iter().copied());
                    encode_frame(rec.seq, &rec.entry, rec.rev, &rec.refs, &rec.blob)
                };
                new_offsets.push(pos);
                w.write_all(&frame)?;
                pos += frame.len() as u64;
            }
            let f = w.into_inner().map_err(|e| e.into_error())?;
            f.sync_all()?;
            Ok(pos)
        })();
        let new_len = match res {
            Ok(l) => l,
            Err(e) => {
                let _ = fs::remove_file(&tmp);
                // Live log untouched; reading it may have failed though.
                return Err(fatal(&e));
            }
        };
        if changed == 0 {
            let _ = fs::remove_file(&tmp);
            return Ok((0, refs));
        }
        if let Err(e) = fs::rename(&tmp, self.dir.join("log")) {
            let _ = fs::remove_file(&tmp);
            return Err(Fail::Http(SErr::Internal(format!("prune rename: {e}"))));
        }
        // From here the live log is the new one (once the dir entry is durable).
        fsync_dir(&self.dir).map_err(|e| fatal(&e))?;
        self.log = OpenOptions::new()
            .read(true)
            .write(true)
            .open(self.dir.join("log"))
            .map_err(|e| fatal(&e))?;
        self.log_len = new_len;
        self.offsets = new_offsets;
        Ok((changed, refs))
    }
}

/// Error from inside a vault operation. `Fatal` poisons the vault until restart.
enum Fail {
    Http(SErr),
    Fatal(String),
}

impl From<SErr> for Fail {
    fn from(e: SErr) -> Self {
        Fail::Http(e)
    }
}

enum State {
    Unloaded,
    Loaded(Box<Vault>),
    Broken,
}

struct Slot {
    st: Mutex<State>,
    /// Valid once the vault is loaded. Separate lock: chunk PUTs don't take the vault lock.
    usage: Mutex<Usage>,
}

pub struct FsStore {
    vaults_dir: PathBuf,
    grace: Duration,
    quota: Option<u64>,
    slots: Mutex<HashMap<Id16, Arc<Slot>>>,
}

fn key_check(v: &Vault, key: &[u8; 32]) -> Result<(), Fail> {
    if v.auth_pub == *key {
        Ok(())
    } else {
        Err(SErr::BadSig.into())
    }
}

impl FsStore {
    pub fn new(data_dir: &Path, grace: Duration, quota: Option<u64>) -> io::Result<FsStore> {
        let vaults_dir = data_dir.join("vaults");
        fs::create_dir_all(&vaults_dir)?;
        Ok(FsStore {
            vaults_dir,
            grace,
            quota,
            slots: Mutex::new(HashMap::new()),
        })
    }

    fn vault_dir(&self, vid: &Id16) -> PathBuf {
        self.vaults_dir.join(hex(vid))
    }

    /// Slots exist only for vaults that exist (or are being created): probing can't grow the map.
    fn slot(&self, vid: &Id16, create: bool) -> R<Option<Arc<Slot>>> {
        let mut m = lock(&self.slots);
        if let Some(s) = m.get(vid) {
            return Ok(Some(s.clone()));
        }
        if !create {
            let exists = self
                .vault_dir(vid)
                .join("meta.json")
                .try_exists()
                .map_err(|e| SErr::Internal(format!("stat meta.json: {e}")))?;
            if !exists {
                return Ok(None);
            }
        }
        let s = Arc::new(Slot {
            st: Mutex::new(State::Unloaded),
            usage: Mutex::new(Usage::default()),
        });
        m.insert(*vid, s.clone());
        Ok(Some(s))
    }

    /// Lock the vault (loading it on first use) and run `f`.
    fn with_vault<T>(&self, vid: &Id16, f: impl FnOnce(&mut Vault, &Slot) -> Result<T, Fail>) -> R<T> {
        let Some(slot) = self.slot(vid, false)? else {
            return Err(SErr::NoVault);
        };
        let mut g = lock(&slot.st);
        if let State::Unloaded = *g {
            match Vault::open(&self.vault_dir(vid)) {
                Ok(Some((v, u))) => {
                    *lock(&slot.usage) = u;
                    *g = State::Loaded(Box::new(v));
                }
                Ok(None) => return Err(SErr::NoVault),
                Err(e) => {
                    eprintln!("cofferd: vault unusable: {e}");
                    *g = State::Broken;
                }
            }
        }
        let v = match &mut *g {
            State::Loaded(v) => v,
            State::Broken => return Err(SErr::Internal("vault storage error".into())),
            State::Unloaded => unreachable!(),
        };
        match f(v, &slot) {
            Ok(r) => Ok(r),
            Err(Fail::Http(e)) => Err(e),
            Err(Fail::Fatal(e)) => {
                eprintln!("cofferd: vault {} poisoned: {e}", hex(vid));
                *g = State::Broken;
                Err(SErr::Internal("vault storage error".into()))
            }
        }
    }

    fn update_meta(
        &self,
        vid: &Id16,
        key: &[u8; 32],
        new_pub: Option<&[u8; 32]>,
        header: &[u8],
        version: u64,
    ) -> R<()> {
        self.with_vault(vid, |v, _| {
            key_check(v, key)?;
            if version <= v.header_version {
                return Err(SErr::StaleHeader.into());
            }
            let mut meta = Meta::new(
                new_pub.unwrap_or(&v.auth_pub),
                header,
                v.meta.created_ms,
                Some(&v.meta.create_id),
            )?;
            if new_pub.is_none() {
                meta.invites = v.meta.invites.clone(); // rekey drops them: they carry old keys
            }
            // On failure the rename may or may not have landed: cached state is unreliable.
            v.set_meta(meta).map_err(|e| Fail::Fatal(format!("write meta: {e}")))
        })
    }

    fn gc_candidates(&self, dir: &Path, live: &HashSet<Cid>) -> R<Vec<ChunkFile>> {
        let cutoff = SystemTime::now().checked_sub(self.grace).unwrap_or(UNIX_EPOCH);
        let all = walk_chunks(dir, false).map_err(|e| SErr::Internal(format!("scan chunks: {e}")))?;
        Ok(all
            .into_iter()
            .filter(|c| !live.contains(&c.cid) && c.mtime <= cutoff)
            .collect())
    }
}

impl Store for FsStore {
    fn create(&self, vid: &Id16, auth_pub: &[u8; 32], header: &[u8]) -> R<()> {
        let meta = Meta::new(auth_pub, header, now_ms(), None)?;
        let slot = self.slot(vid, true)?.expect("create=true always yields a slot");
        let mut g = lock(&slot.st);
        let dir = self.vault_dir(vid);
        let exists = match &*g {
            State::Loaded(_) | State::Broken => true,
            State::Unloaded => dir
                .join("meta.json")
                .try_exists()
                .map_err(|e| SErr::Internal(format!("stat meta.json: {e}")))?,
        };
        if exists {
            return Err(SErr::Exists);
        }
        Vault::create(&dir, &meta).map_err(|e| SErr::Internal(format!("create vault: {e}")))?;
        *g = State::Unloaded;
        Ok(())
    }

    fn auth_key(&self, vid: &Id16, _fresh: bool) -> R<[u8; 32]> {
        self.with_vault(vid, |v, _| Ok(v.auth_pub))
    }

    fn header(&self, vid: &Id16) -> R<Vec<u8>> {
        self.with_vault(vid, |v, _| Ok(v.meta.header.clone().into_bytes()))
    }

    fn put_header(&self, vid: &Id16, key: &[u8; 32], header: &[u8], version: u64) -> R<()> {
        self.update_meta(vid, key, None, header, version)
    }

    fn rekey(&self, vid: &Id16, key: &[u8; 32], new_pub: &[u8; 32], header: &[u8], version: u64) -> R<()> {
        self.update_meta(vid, key, Some(new_pub), header, version)
    }

    fn log(&self, vid: &Id16, key: &[u8; 32], after: u64, limit: usize, max_bytes: usize) -> R<(u64, Vec<Rec>)> {
        let (head, offs, file) = self.with_vault(vid, |v, _| {
            key_check(v, key)?;
            let start = after.min(v.head()) as usize;
            let end = start.saturating_add(limit).min(v.offsets.len());
            let file = v
                .log
                .try_clone()
                .map_err(|e| SErr::Internal(format!("clone log: {e}")))?;
            Ok((v.head(), v.offsets[start..end].to_vec(), file))
        })?;
        // Read without the lock. A prune swaps in a new file; this handle keeps the old
        // inode, whose frames match these offsets.
        let mut out = Vec::with_capacity(offs.len());
        let mut bytes = 0usize;
        for off in offs {
            let rec = read_frame(&file, off).map_err(|e| SErr::Internal(format!("read log: {e}")))?;
            if !out.is_empty() && bytes + rec.blob.len() > max_bytes {
                break;
            }
            bytes += rec.blob.len();
            out.push(rec);
        }
        Ok((head, out))
    }

    fn commit(&self, vid: &Id16, key: &[u8; 32], c: &CommitIn) -> R<u64> {
        self.with_vault(vid, |v, _| {
            key_check(v, key)?;
            let (cur, cur_seq) = v.entries.get(&c.entry).copied().unwrap_or((0, 0));
            if cur != c.base_rev {
                if cur == c.rev {
                    let stored = v.read(cur_seq).map_err(|e| Fail::Fatal(format!("read log: {e}")))?;
                    // A placeholder (empty blob) never matches: commit blobs are non-empty.
                    if stored.blob == c.blob {
                        return Ok(cur_seq);
                    }
                }
                return Err(SErr::Conflict(cur).into());
            }
            // Under the vault lock: GC deletes chunks only under this lock too.
            let mut missing = Vec::new();
            for id in &c.refs {
                match chunk_path(&v.dir, &hex(id)).try_exists() {
                    Ok(true) => {}
                    Ok(false) => missing.push(*id),
                    Err(e) => return Err(SErr::Internal(format!("stat chunk: {e}")).into()),
                }
            }
            if !missing.is_empty() {
                return Err(SErr::Missing(missing).into());
            }
            v.append(&c.entry, c.rev, &c.refs, &c.blob)
                .map_err(|e| Fail::Fatal(format!("append log: {e}")))
        })
    }

    fn missing(&self, vid: &Id16, key: &[u8; 32], ids: &[Cid]) -> R<Vec<Cid>> {
        let dir = self.with_vault(vid, |v, _| {
            key_check(v, key)?;
            Ok(v.dir.clone())
        })?;
        let mut out = Vec::new();
        for id in ids {
            match chunk_path(&dir, &hex(id)).try_exists() {
                Ok(true) => {}
                Ok(false) => out.push(*id),
                Err(e) => return Err(SErr::Internal(format!("stat chunk: {e}"))),
            }
        }
        Ok(out)
    }

    fn put_chunk(&self, vid: &Id16, key: &[u8; 32], cid: &Cid, data: &[u8]) -> R<()> {
        let (dir, slot) = {
            let slot = self.slot(vid, false)?.ok_or(SErr::NoVault)?;
            let dir = self.with_vault(vid, |v, _| {
                key_check(v, key)?;
                Ok(v.dir.clone())
            })?;
            (dir, slot)
        };
        let path = chunk_path(&dir, &hex(cid));
        let ierr = |what: &str, e: io::Error| SErr::Internal(format!("{what}: {e}"));
        // Content-addressed and immutable: no vault lock. Existing chunk: refresh its mtime
        // (GC grace) and succeed regardless of quota.
        match OpenOptions::new().write(true).open(&path) {
            Ok(f) => {
                let _ = f.set_modified(SystemTime::now());
                return Ok(());
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(ierr("open chunk", e)),
        }
        let len = data.len() as u64;
        {
            let mut u = lock(&slot.usage);
            if self.quota.is_some_and(|q| u.bytes + len > q) {
                return Err(SErr::Quota);
            }
            u.bytes += len;
            u.chunks += 1;
        }
        let release = || {
            let mut u = lock(&slot.usage);
            u.bytes -= len;
            u.chunks -= 1;
        };
        let sub = path.parent().unwrap();
        let tmp = sub.join(format!(".tmp-{}-{}", hex(cid), unique()));
        let res = (|| -> io::Result<bool> {
            let mut f = OpenOptions::new().write(true).create_new(true).open(&tmp)?;
            f.write_all(data)?;
            f.sync_all()?;
            drop(f);
            // link, not rename: a concurrent PUT of the same chunk must not be counted twice.
            let created = match fs::hard_link(&tmp, &path) {
                Ok(()) => true,
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => false,
                Err(e) => return Err(e),
            };
            fs::remove_file(&tmp)?;
            fsync_dir(sub)?;
            Ok(created)
        })();
        match res {
            Ok(true) => Ok(()),
            Ok(false) => {
                release();
                Ok(())
            }
            Err(e) => {
                let _ = fs::remove_file(&tmp);
                // The link may have landed; usage is re-derived on next load anyway.
                if !path.exists() {
                    release();
                }
                Err(ierr("write chunk", e))
            }
        }
    }

    fn get_chunk(&self, vid: &Id16, key: &[u8; 32], cid: &Cid) -> R<Vec<u8>> {
        let dir = self.with_vault(vid, |v, _| {
            key_check(v, key)?;
            Ok(v.dir.clone())
        })?;
        match fs::read(chunk_path(&dir, &hex(cid))) {
            Ok(b) => Ok(b),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Err(SErr::NoChunk),
            Err(e) => Err(SErr::Internal(format!("read chunk: {e}"))),
        }
    }

    /// Phase 1 (lock): rewrite log, collect live refs R. Phase 2 (no lock): scan chunks not
    /// in R and older than grace. Phase 3 (lock): add refs of records appended since phase 1,
    /// re-stat, delete. A commit checks refs and appends under the same lock, so it either
    /// lands before phase 3 (its refs are seen) or after (a deleted ref is reported missing).
    fn prune(&self, vid: &Id16, key: &[u8; 32], items: &[(Id16, u64)]) -> R<PruneResp> {
        let (records, live, h1, dir) = self.with_vault(vid, |v, _| {
            key_check(v, key)?;
            let mut below = HashMap::new();
            for (entry, b) in items {
                let Some(&(cur, _)) = v.entries.get(entry) else {
                    continue;
                };
                if *b > cur {
                    return Err(SErr::Bad("below exceeds current rev".into()).into());
                }
                let e = below.entry(*entry).or_insert(0);
                *e = (*e).max(*b);
            }
            let (n, live) = v.rewrite_pruned(&below)?;
            Ok((n, live, v.head(), v.dir.clone()))
        })?;
        let cands = self.gc_candidates(&dir, &live)?;
        let cutoff = SystemTime::now().checked_sub(self.grace).unwrap_or(UNIX_EPOCH);
        let (chunks, bytes) = self.with_vault(vid, |v, slot| {
            let mut late = HashSet::new();
            for seq in h1 + 1..=v.head() {
                let r = v.read(seq).map_err(|e| Fail::Fatal(format!("read log: {e}")))?;
                late.extend(r.refs);
            }
            let (mut n, mut b) = (0u64, 0u64);
            let mut dirs = HashSet::new();
            for c in cands.iter().filter(|c| !late.contains(&c.cid)) {
                let md = match fs::metadata(&c.path) {
                    Ok(m) => m,
                    Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
                    Err(e) => return Err(SErr::Internal(format!("stat chunk: {e}")).into()),
                };
                if md.modified().map_or(true, |m| m > cutoff) {
                    continue; // re-uploaded meanwhile
                }
                match fs::remove_file(&c.path) {
                    Ok(()) => {}
                    Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
                    Err(e) => return Err(SErr::Internal(format!("delete chunk: {e}")).into()),
                }
                n += 1;
                b += md.len();
                dirs.insert(c.path.parent().unwrap().to_owned());
            }
            {
                let mut u = lock(&slot.usage);
                u.bytes = u.bytes.saturating_sub(b);
                u.chunks = u.chunks.saturating_sub(n);
            }
            for d in dirs {
                fsync_dir(&d).map_err(|e| SErr::Internal(format!("fsync chunk dir: {e}")))?;
            }
            Ok((n, b))
        })?;
        Ok(PruneResp { records, chunks, bytes })
    }

    fn usage(&self, vid: &Id16, key: &[u8; 32]) -> R<UsageResp> {
        self.with_vault(vid, |v, slot| {
            key_check(v, key)?;
            let u = *lock(&slot.usage);
            Ok(UsageResp {
                bytes: u.bytes,
                chunks: u.chunks,
                records: v.head(),
                quota: self.quota,
            })
        })
    }

    fn edit_invites(&self, vid: &Id16, key: Option<&[u8; 32]>, f: &mut dyn FnMut(&mut Vec<InviteRec>) -> R<InviteOut>) -> R<InviteOut> {
        self.with_vault(vid, |v, _| {
            if let Some(k) = key {
                key_check(v, k)?;
            }
            let mut list = v.meta.invites.clone();
            let out = f(&mut list)?;
            if list != v.meta.invites {
                let mut meta = v.meta.clone();
                meta.invites = list;
                v.set_meta(meta).map_err(|e| Fail::Fatal(format!("write meta: {e}")))?;
            }
            Ok(out)
        })
    }

    fn invite_claim_key(&self, vid: &Id16, iid: &str, _fresh: bool) -> R<Option<[u8; 32]>> {
        self.with_vault(vid, |v, _| Ok(invites::claim_key(&v.meta.invites, iid).ok()))
    }

    fn sweep_invites(&self, vid: &Id16) -> R<()> {
        self.with_vault(vid, |v, _| {
            let now = now_ms();
            if !invites::stale(&v.meta.invites, now) {
                return Ok(());
            }
            let mut meta = v.meta.clone();
            invites::tidy(&mut meta.invites, now);
            v.set_meta(meta).map_err(|e| Fail::Fatal(format!("write meta: {e}")))
        })
    }
}
