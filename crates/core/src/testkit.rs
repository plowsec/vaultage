//! Test support: in-memory server, fault-injecting network, multi-device worlds, convergence fuzzer.
//! Compiled for tests and with the `testing` feature (the server crate reuses it over real HTTP).

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::Path;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};

use crate::error::{Error, Result};
use crate::model::*;
use crate::remote::{CommitOutcome, Record, Remote};
use crate::sync::{sync_once, SyncReport};
use crate::vault::Vault;

/// Same semantics as the real server, in memory.
#[derive(Default)]
pub struct MemRemote {
    pub log: Mutex<Vec<Record>>,
    pub chunks: Mutex<HashMap<ChunkId, Vec<u8>>>,
    /// Chunk references per record seq.
    pub refs: Mutex<HashMap<u64, Vec<ChunkId>>>,
}

impl Remote for MemRemote {
    fn pull(&self, after: u64, limit: u32) -> Result<(u64, Vec<Record>)> {
        let log = self.log.lock().unwrap();
        Ok((log.len() as u64, log.iter().filter(|r| r.seq > after).take(limit as usize).cloned().collect()))
    }
    fn commit(&self, entry: &EntryId, base_rev: u64, rev: u64, blob: &[u8], refs: &[ChunkId]) -> Result<CommitOutcome> {
        let mut log = self.log.lock().unwrap();
        let current = log.iter().filter(|r| r.entry == *entry).map(|r| r.rev).max().unwrap_or(0);
        if current != base_rev {
            return Ok(CommitOutcome::Conflict(current));
        }
        let chunks = self.chunks.lock().unwrap();
        let missing: Vec<ChunkId> = refs.iter().filter(|r| !chunks.contains_key(r)).cloned().collect();
        if !missing.is_empty() {
            return Ok(CommitOutcome::MissingRefs(missing));
        }
        let seq = log.len() as u64 + 1;
        log.push(Record { seq, entry: *entry, rev, blob: blob.to_vec() });
        self.refs.lock().unwrap().insert(seq, refs.to_vec());
        Ok(CommitOutcome::Committed(seq))
    }
    fn missing(&self, ids: &[ChunkId]) -> Result<Vec<ChunkId>> {
        let chunks = self.chunks.lock().unwrap();
        Ok(ids.iter().filter(|r| !chunks.contains_key(r)).cloned().collect())
    }
    fn put_chunk(&self, id: &ChunkId, data: &[u8]) -> Result<()> {
        if blake3::hash(data).as_bytes() != &id.0 {
            return Err(Error::Server(400, "hash mismatch".into()));
        }
        self.chunks.lock().unwrap().insert(*id, data.to_vec());
        Ok(())
    }
    fn get_chunk(&self, id: &ChunkId) -> Result<Vec<u8>> {
        self.chunks.lock().unwrap().get(id).cloned().ok_or_else(|| Error::NotFound("chunk".into()))
    }
    fn prune(&self, items: &[(EntryId, u64)]) -> Result<()> {
        let mut log = self.log.lock().unwrap();
        let mut refs = self.refs.lock().unwrap();
        for (entry, below) in items {
            let current = log.iter().filter(|r| r.entry == *entry).map(|r| r.rev).max().unwrap_or(0);
            if *below > current {
                return Err(Error::Server(400, "cannot prune the newest revision".into()));
            }
            for r in log.iter_mut().filter(|r| r.entry == *entry && r.rev < *below) {
                r.blob.clear();
                refs.remove(&r.seq);
            }
        }
        let live: std::collections::HashSet<ChunkId> = refs.values().flatten().cloned().collect();
        self.chunks.lock().unwrap().retain(|id, _| live.contains(id));
        Ok(())
    }
}

pub struct Rng(pub u64);
impl Rng {
    pub fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    pub fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
}

/// Unreliable network: each call may be lost before reaching the server, or its reply may be lost
/// after the server acted on it.
pub struct Flaky {
    pub inner: Arc<dyn Remote>,
    /// Percent of calls that fail (half before, half after the server acts). 0 = reliable.
    pub rate: AtomicU32,
    /// Fail the reply of the next N commits (server applies them; client sees an error).
    pub drop_commit_acks: AtomicU32,
    rng: Mutex<Rng>,
}

impl Flaky {
    pub fn new(inner: Arc<dyn Remote>, seed: u64) -> Arc<Flaky> {
        Arc::new(Flaky { inner, rate: AtomicU32::new(0), drop_commit_acks: AtomicU32::new(0), rng: Mutex::new(Rng(seed | 1)) })
    }
    fn run<T>(&self, f: impl FnOnce() -> Result<T>) -> Result<T> {
        let rate = self.rate.load(Ordering::Relaxed) as u64;
        let roll = self.rng.lock().unwrap().below(100);
        if roll < rate / 2 {
            return Err(Error::Net("request lost".into()));
        }
        let out = f();
        if roll < rate {
            return Err(Error::Net("reply lost".into()));
        }
        out
    }
}

impl Remote for Flaky {
    fn pull(&self, after: u64, limit: u32) -> Result<(u64, Vec<Record>)> {
        self.run(|| self.inner.pull(after, limit))
    }
    fn commit(&self, entry: &EntryId, base_rev: u64, rev: u64, blob: &[u8], refs: &[ChunkId]) -> Result<CommitOutcome> {
        let out = self.run(|| self.inner.commit(entry, base_rev, rev, blob, refs));
        if out.is_ok() && self.drop_commit_acks.load(Ordering::Relaxed) > 0 {
            self.drop_commit_acks.fetch_sub(1, Ordering::Relaxed);
            return Err(Error::Net("reply lost".into()));
        }
        out
    }
    fn missing(&self, ids: &[ChunkId]) -> Result<Vec<ChunkId>> {
        self.run(|| self.inner.missing(ids))
    }
    fn put_chunk(&self, id: &ChunkId, data: &[u8]) -> Result<()> {
        self.run(|| self.inner.put_chunk(id, data))
    }
    fn get_chunk(&self, id: &ChunkId) -> Result<Vec<u8>> {
        self.run(|| self.inner.get_chunk(id))
    }
    fn prune(&self, items: &[(EntryId, u64)]) -> Result<()> {
        self.run(|| self.inner.prune(items))
    }
}

pub struct Client {
    pub vault: Mutex<Vault>,
    pub net: Arc<Flaky>,
}

impl Client {
    pub fn v(&self) -> std::sync::MutexGuard<'_, Vault> {
        self.vault.lock().unwrap()
    }
    pub fn sync(&self) -> Result<SyncReport> {
        sync_once(&self.vault, &*self.net)
    }
    pub fn put(&self, path: &str, data: &[u8]) -> EntryId {
        self.v().put_bytes(path, data, 1).unwrap()
    }
    pub fn read(&self, path: &str) -> Vec<u8> {
        let r = { let v = self.v(); let id = v.find(path).unwrap_or_else(|| panic!("no file at {path}")).id; v.reader(&id, None).unwrap() };
        r.read_all(Some(&*self.net)).unwrap()
    }
    /// Live tree: path -> content hash (None for folders).
    pub fn tree(&self) -> BTreeMap<String, Option<String>> {
        self.v().live().map(|m| (m.path.clone(), m.hash().map(|h| h.hex()))).collect()
    }
    pub fn paths(&self) -> Vec<String> {
        self.tree().into_keys().collect()
    }
}

/// Several devices sharing one vault through one server.
pub struct World {
    pub clients: Vec<Client>,
    _dir: tempfile::TempDir,
}

impl World {
    /// `connect` gets each device's vault and returns its link to the (shared) server.
    pub fn new(n: usize, connect: &dyn Fn(&Vault) -> Arc<dyn Remote>) -> World {
        crate::store::SKIP_FSYNC.store(true, Ordering::Relaxed);
        let dir = tempfile::tempdir().unwrap();
        let mut clients: Vec<Client> = Vec::new();
        for i in 0..n {
            let path = dir.path().join(format!("device{i}"));
            let device = Device::new(&format!("dev{i}"));
            let vault = if i == 0 {
                Vault::create(&path, Some("test://".into()), &device).unwrap().0
            } else {
                let first = clients[0].v();
                Vault::init(&path, &first.portable_header(), Some("test://".into())).unwrap();
                Vault::open(&path, first.keys().vmk.clone(), &device).unwrap()
            };
            let mut vault = vault;
            vault.gc_min_age = std::time::Duration::ZERO;
            let net = Flaky::new(connect(&vault), 0x9E3779B97F4A7C15 ^ (i as u64 + 1));
            clients.push(Client { vault: Mutex::new(vault), net });
        }
        World { clients, _dir: dir }
    }

    pub fn mem(n: usize) -> (World, Arc<MemRemote>) {
        let server = Arc::new(MemRemote::default());
        let s = server.clone();
        (World::new(n, &move |_| s.clone() as Arc<dyn Remote>), server)
    }

    /// Sync everyone until nothing moves. Panics on any error.
    pub fn settle(&self) {
        for c in &self.clients {
            c.net.rate.store(0, Ordering::Relaxed);
        }
        for _ in 0..6 {
            let mut moved = 0;
            for c in &self.clients {
                let r = c.sync().unwrap();
                assert!(r.errors.is_empty(), "{:?}", r.errors);
                moved += r.pulled + r.pushed + r.downloaded;
            }
            if moved == 0 {
                break;
            }
        }
        for c in &self.clients {
            assert_eq!(c.v().pending_count(), 0, "pending changes left after settling");
        }
    }

    /// All devices show the same tree, with unique paths and no file/folder clashes.
    pub fn assert_converged(&self) {
        let t0 = self.clients[0].tree();
        for (i, c) in self.clients.iter().enumerate() {
            let v = c.v();
            let paths: Vec<&str> = v.live().map(|m| m.path.as_str()).collect();
            let unique: BTreeSet<&str> = paths.iter().cloned().collect();
            assert_eq!(paths.len(), unique.len(), "device {i} has duplicate paths: {paths:?}");
            for m in v.live().filter(|m| m.kind == Kind::File) {
                assert!(!v.live().any(|o| o.path != m.path && is_under(&o.path, &m.path)), "file {} is also a folder", m.path);
            }
            drop(v);
            assert_eq!(c.tree(), t0, "device {i} diverged from device 0");
        }
    }
}

fn content_hashes(v: &Vault, pending_only: bool) -> BTreeSet<Hash32> {
    let mut out = BTreeSet::new();
    for e in v.state.entries.values() {
        if let Some(h) = e.pending.as_ref().and_then(|m| m.hash()) {
            out.insert(h);
        }
        if !pending_only {
            out.extend(e.history.iter().filter_map(|r| r.meta.hash()));
        }
    }
    out
}

/// Random offline edits on several devices over a lossy network, then: everyone converges, and
/// every version that was ever synced is still readable, byte-exact, on every device.
pub fn fuzz(seed: u64, devices: usize, steps: usize, connect: &dyn Fn(&Vault) -> Arc<dyn Remote>) {
    fuzz_opts(seed, devices, steps, false, connect)
}

/// `purges`: devices also empty their trash and drop old versions at random. Then the promise is
/// weaker by design (purged versions are gone), but everything still converges and every version
/// that remains in anyone's history must still be readable (no chunk collected too early).
pub fn fuzz_opts(seed: u64, devices: usize, steps: usize, purges: bool, connect: &dyn Fn(&Vault) -> Arc<dyn Remote>) {
    let w = World::new(devices, connect);
    let mut rng = Rng(seed.wrapping_mul(0x2545F4914F6CDD1D) | 1);
    let names = ["a.txt", "b.txt", "d/c.txt", "d/e/f.bin", "d/g", "h/i.txt"];
    let dirs = ["d", "d/e", "h", "z"];
    let mut must_survive: BTreeSet<Hash32> = BTreeSet::new();
    let mut counter = 0u64;

    for _ in 0..steps {
        let c = &w.clients[rng.below(devices as u64) as usize];
        c.net.rate.store([0, 0, 30, 60][rng.below(4) as usize], Ordering::Relaxed);
        match rng.below(if purges { 12 } else { 10 }) {
            10 => {
                let _ = c.v().empty_trash();
            }
            11 => {
                let id = c.v().find(names[rng.below(names.len() as u64) as usize]).map(|m| m.id);
                if let Some(id) = id {
                    let _ = c.v().prune_versions(&id);
                }
            }
            0..=3 => {
                counter += 1;
                let mut data = format!("v{counter} seed{seed} ").into_bytes();
                data.resize(data.len() + rng.below(3000) as usize, (counter % 251) as u8);
                let _ = c.v().put_bytes(names[rng.below(names.len() as u64) as usize], &data, counter as i64);
            }
            4 => {
                let _ = c.v().delete(names[rng.below(names.len() as u64) as usize]);
            }
            5 => {
                let _ = c.v().rename(names[rng.below(names.len() as u64) as usize], names[rng.below(names.len() as u64) as usize]);
            }
            6 => {
                let (a, b) = (dirs[rng.below(dirs.len() as u64) as usize], dirs[rng.below(dirs.len() as u64) as usize]);
                let _ = if rng.below(2) == 0 { c.v().rename(a, b).map(|_| ()) } else { c.v().mkdir(a) };
            }
            _ => {
                let pending = content_hashes(&c.v(), true);
                match c.sync() {
                    Ok(r) if r.errors.is_empty() => {
                        assert_eq!(c.v().pending_count(), 0);
                        must_survive.extend(pending);
                    }
                    Ok(_) => {}
                    Err(Error::Net(_)) => {}
                    Err(e) => panic!("seed {seed}: sync failed with a non-network error: {e}"),
                }
            }
        }
    }
    // Whatever is pending when the dust settles must survive too.
    for c in &w.clients {
        must_survive.extend(content_hashes(&c.v(), true));
    }
    w.settle();
    w.assert_converged();
    for (i, c) in w.clients.iter().enumerate() {
        let have = content_hashes(&c.v(), false);
        for h in must_survive.iter().filter(|_| !purges) {
            assert!(have.contains(h), "seed {seed}: device {i} lost version {}", h.hex());
        }
        // Every revision in history decrypts and matches its hash.
        let revs: Vec<(EntryId, u64)> = c.v().state.entries.iter().flat_map(|(id, e)| e.history.iter().filter(|r| r.meta.content.is_some()).map(|r| (*id, r.meta.rev)).collect::<Vec<_>>()).collect();
        for (id, rev) in revs {
            let reader = c.v().reader(&id, Some(rev)).unwrap();
            reader.read_all(Some(&*c.net)).unwrap_or_else(|e| panic!("seed {seed}: device {i} cannot read a committed version: {e}"));
        }
    }
}

/// Reopen a device's vault from disk, as after a crash or restart.
pub fn reopen(c: &mut Client) {
    let (dir, vmk, device): (std::path::PathBuf, _, _) = { let v = c.v(); (v.dir.clone(), v.keys().vmk.clone(), v.device.clone()) };
    // Release the directory lock before reopening.
    let placeholder = Path::new(&dir).to_path_buf();
    let old = std::mem::replace(&mut c.vault, Mutex::new(unsafe_placeholder(&placeholder, &vmk, &device)));
    drop(old);
    *c.vault.lock().unwrap() = Vault::open(&dir, vmk, &device).unwrap();
}

fn unsafe_placeholder(dir: &Path, _vmk: &crate::crypto::Key, device: &Device) -> Vault {
    // A throwaway vault in a sibling directory, only to keep the Mutex populated during the swap.
    let side = dir.with_extension(format!("swap{}", crate::hexutil::encode(&crate::crypto::random::<4>())));
    Vault::create(&side, None, device).unwrap().0
}
