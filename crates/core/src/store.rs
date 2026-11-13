//! On-disk pieces of a vault: content-addressed chunk store and the encrypted, append-only journal.

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use serde::{de::DeserializeOwned, Serialize};

use crate::crypto::{self, Key};
use crate::error::{Error, Result};
use crate::hexutil;
use crate::model::ChunkId;

/// Tests only: skip physical flushes (F_FULLFSYNC makes thousands of tiny writes very slow).
/// Nothing outside `testkit` sets this.
pub static SKIP_FSYNC: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

fn fsync(f: &File) -> std::io::Result<()> {
    if SKIP_FSYNC.load(std::sync::atomic::Ordering::Relaxed) {
        return Ok(());
    }
    f.sync_all()
}

fn sync_dir(dir: &Path) {
    if let Ok(d) = File::open(dir) {
        let _ = fsync(&d);
    }
}

/// Write-temp, fsync, rename, fsync dir. Readers see the old or the new file, never a partial one.
pub fn atomic_write(path: &Path, data: &[u8]) -> Result<()> {
    let dir = path.parent().ok_or_else(|| Error::Invalid("path has no parent".into()))?;
    fs::create_dir_all(dir)?;
    let tmp = dir.join(format!(".tmp-{}", hexutil::encode(&crypto::random::<8>())));
    let res = (|| -> Result<()> {
        let mut f = OpenOptions::new().write(true).create_new(true).open(&tmp)?;
        f.write_all(data)?;
        fsync(&f)?;
        fs::rename(&tmp, path)?;
        Ok(())
    })();
    if res.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    sync_dir(dir);
    res
}

/// Immutable encrypted chunks, named by the BLAKE3 of their ciphertext.
#[derive(Clone)]
pub struct ChunkStore {
    dir: PathBuf,
}

impl ChunkStore {
    pub fn new(dir: PathBuf) -> Result<Self> {
        fs::create_dir_all(&dir)?;
        Ok(ChunkStore { dir })
    }
    fn path(&self, id: &ChunkId) -> PathBuf {
        let h = id.hex();
        self.dir.join(&h[..2]).join(h)
    }
    pub fn has(&self, id: &ChunkId) -> bool {
        self.path(id).is_file()
    }
    pub fn put(&self, data: &[u8]) -> Result<ChunkId> {
        let id = ChunkId(*blake3::hash(data).as_bytes());
        if !self.has(&id) {
            atomic_write(&self.path(&id), data)?;
        }
        Ok(id)
    }
    /// Store data received from elsewhere; rejects anything that does not hash to `id`.
    pub fn put_verified(&self, id: &ChunkId, data: &[u8]) -> Result<()> {
        if blake3::hash(data).as_bytes() != &id.0 {
            return Err(Error::Integrity(format!("chunk {} does not match its hash", id.hex())));
        }
        self.put(data).map(|_| ())
    }
    pub fn get(&self, id: &ChunkId) -> Result<Vec<u8>> {
        let data = fs::read(self.path(id)).map_err(|e| match e.kind() {
            std::io::ErrorKind::NotFound => Error::NotFound(format!("chunk {}", id.hex())),
            _ => Error::Io(e),
        })?;
        if blake3::hash(&data).as_bytes() != &id.0 {
            return Err(Error::Integrity(format!("chunk {} is corrupt on disk", id.hex())));
        }
        Ok(data)
    }
    /// Delete chunks that are not in `keep` and older than `min_age`. Returns (count, bytes).
    pub fn sweep(&self, keep: &std::collections::BTreeSet<ChunkId>, min_age: std::time::Duration) -> Result<(u64, u64)> {
        let (mut n, mut bytes) = (0, 0);
        let old_enough = |md: &fs::Metadata| md.modified().ok().and_then(|t| t.elapsed().ok()).map(|age| age >= min_age).unwrap_or(false);
        for sub in fs::read_dir(&self.dir)?.flatten() {
            if !sub.path().is_dir() {
                continue;
            }
            for f in fs::read_dir(sub.path())?.flatten() {
                let name = f.file_name().to_string_lossy().into_owned();
                let Ok(md) = f.metadata() else { continue };
                let dead = match ChunkId::parse(&name) {
                    Ok(id) => !keep.contains(&id) && old_enough(&md),
                    // Leftover temp file from a crashed write.
                    Err(_) => name.starts_with(".tmp-") && md.modified().ok().and_then(|t| t.elapsed().ok()).map(|a| a.as_secs() > 3600).unwrap_or(false),
                };
                if dead && fs::remove_file(f.path()).is_ok() {
                    n += 1;
                    bytes += md.len();
                }
            }
        }
        Ok((n, bytes))
    }

    /// Drop a corrupt local copy so it can be re-fetched.
    pub fn discard(&self, id: &ChunkId) {
        let _ = fs::remove_file(self.path(id));
    }
}

/// Append-only log of encrypted events. Frame: u32 LE length | seal(key, event JSON).
pub struct Journal {
    file: File,
    key: Key,
    aad: Vec<u8>,
}

impl Journal {
    /// Open and replay. A torn final frame (crash mid-append) is cut off; damage anywhere else is
    /// a hard error, never silently dropped.
    pub fn open<E: DeserializeOwned>(path: &Path, key: Key, vault: &[u8; 16]) -> Result<(Journal, Vec<E>)> {
        let mut aad = b"coffer/journal/v1".to_vec();
        aad.extend_from_slice(vault);
        let mut file = OpenOptions::new().read(true).write(true).create(true).truncate(false).open(path)?;
        let mut buf = Vec::new();
        file.read_to_end(&mut buf)?;
        let (mut off, mut events) = (0usize, Vec::new());
        while off < buf.len() {
            let frame = (|| {
                let len = u32::from_le_bytes(buf.get(off..off + 4)?.try_into().ok()?) as usize;
                let body = buf.get(off + 4..off + 4 + len)?;
                Some((len, crypto::open(&key, &aad, body).ok()?))
            })();
            match frame {
                Some((len, pt)) => {
                    events.push(serde_json::from_slice(&pt)?);
                    off += 4 + len;
                }
                None => {
                    // Torn append = incomplete frame or zero-filled tail. A complete frame that
                    // fails authentication is corruption and is never discarded.
                    let declared = buf.get(off..off + 4).map(|b| u32::from_le_bytes(b.try_into().unwrap()) as usize);
                    let incomplete = declared.map(|l| off + 4 + l > buf.len()).unwrap_or(true);
                    if !incomplete && buf[off..].iter().any(|b| *b != 0) {
                        return Err(Error::Integrity(format!("journal damaged at byte {off}; refusing to continue")));
                    }
                    file.set_len(off as u64)?;
                    file.sync_all()?;
                    break;
                }
            }
        }
        file.seek(SeekFrom::End(0))?;
        Ok((Journal { file, key, aad }, events))
    }

    /// Replace the journal with exactly `events` (compaction: purged data is gone from the file).
    /// Atomic: a crash leaves the old or the new journal.
    pub fn rewrite<E: Serialize>(path: &Path, key: Key, vault: &[u8; 16], events: &[E]) -> Result<Journal> {
        let mut aad = b"coffer/journal/v1".to_vec();
        aad.extend_from_slice(vault);
        let mut out = Vec::new();
        for e in events {
            let sealed = crypto::seal(&key, &aad, &serde_json::to_vec(e)?);
            out.extend_from_slice(&(sealed.len() as u32).to_le_bytes());
            out.extend_from_slice(&sealed);
        }
        atomic_write(path, &out)?;
        let mut file = OpenOptions::new().read(true).write(true).open(path)?;
        file.seek(SeekFrom::End(0))?;
        Ok(Journal { file, key, aad })
    }

    /// Durable once this returns (one fsync for the whole batch).
    pub fn append<E: Serialize>(&mut self, events: &[E]) -> Result<()> {
        if events.is_empty() {
            return Ok(());
        }
        let mut out = Vec::new();
        for e in events {
            let sealed = crypto::seal(&self.key, &self.aad, &serde_json::to_vec(e)?);
            out.extend_from_slice(&(sealed.len() as u32).to_le_bytes());
            out.extend_from_slice(&sealed);
        }
        let before = self.file.metadata()?.len();
        if let Err(e) = self.file.write_all(&out).and_then(|_| fsync(&self.file)) {
            // Leave no half-written frame behind for the next append to bury.
            let _ = self.file.set_len(before);
            let _ = self.file.seek(SeekFrom::End(0));
            return Err(e.into());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn journal_replay_torn_tail_and_corruption() {
        let dir = tempfile::tempdir().unwrap();
        let (p, key, v) = (dir.path().join("journal"), Key::random(), [1u8; 16]);
        {
            let (mut j, ev) = Journal::open::<String>(&p, key.clone(), &v).unwrap();
            assert!(ev.is_empty());
            j.append(&["a".to_string(), "b".to_string()]).unwrap();
            j.append(&["c".to_string()]).unwrap();
        }
        let good = fs::read(&p).unwrap();
        // Torn tail: half a frame appended.
        let mut torn = good.clone();
        torn.extend_from_slice(&[200, 0, 0, 0, 1, 2, 3]);
        fs::write(&p, &torn).unwrap();
        let (mut j, ev) = Journal::open::<String>(&p, key.clone(), &v).unwrap();
        assert_eq!(ev, ["a", "b", "c"]);
        j.append(&["d".to_string()]).unwrap();
        drop(j);
        let (_, ev) = Journal::open::<String>(&p, key.clone(), &v).unwrap();
        assert_eq!(ev, ["a", "b", "c", "d"]);
        // Damage in the middle is fatal, not truncated.
        let mut bad = fs::read(&p).unwrap();
        bad[10] ^= 0xff;
        fs::write(&p, &bad).unwrap();
        assert!(matches!(Journal::open::<String>(&p, key.clone(), &v), Err(Error::Integrity(_))));
        // A single damaged frame at the very end is still not truncated.
        let mut bad = good.clone();
        let n = bad.len();
        bad[n - 1] ^= 1;
        fs::write(&p, &bad).unwrap();
        assert!(matches!(Journal::open::<String>(&p, key.clone(), &v), Err(Error::Integrity(_))));
        // Wrong key reads nothing and must not destroy data.
        fs::write(&p, &good).unwrap();
        assert!(Journal::open::<String>(&p, Key::random(), &v).is_err());
        assert_eq!(fs::read(&p).unwrap(), good);
    }

    #[test]
    fn chunks_verify() {
        let dir = tempfile::tempdir().unwrap();
        let s = ChunkStore::new(dir.path().join("c")).unwrap();
        let id = s.put(b"hello").unwrap();
        assert_eq!(s.get(&id).unwrap(), b"hello");
        assert!(s.put_verified(&id, b"other").is_err());
        fs::write(s.path(&id), b"evil").unwrap();
        assert!(matches!(s.get(&id), Err(Error::Integrity(_))));
        assert!(matches!(s.get(&ChunkId([0; 32])), Err(Error::NotFound(_))));
    }
}
