//! Sync: pull the server log, merge, push pending changes with per-entry compare-and-swap.
//!
//! No-loss rules:
//! - A change is pushed only after every chunk it references is on the server.
//! - The server accepts a revision only if it builds on the entry's current one; otherwise we
//!   pull, merge and retry. Nothing is ever overwritten blindly.
//! - Concurrent edits of one file keep both versions (the local one becomes a "conflict" copy).
//! - An edit beats a delete. Deletes are tombstones; old revisions stay restorable.
//! - The server log must be gapless and append-only from our point of view, or we stop.

use std::collections::BTreeSet;
use std::sync::Mutex;

use serde::Serialize;

use crate::error::{Error, Result};
use crate::model::*;
use crate::remote::{CommitOutcome, Record, Remote};
use crate::vault::{Event, Vault};

enum Merge {
    /// Remote state stands; the local change is redundant or loses.
    Drop,
    /// Re-apply this on top of the remote revision.
    Rebase(Meta),
    /// Keep the remote revision and save this as a separate file.
    Fork(Meta),
}

/// Three-way merge of one entry: `base` is what both sides started from.
fn merge(base: Option<&Meta>, local: &Meta, remote: &Meta, my_origin: &str) -> Merge {
    if local.same_state(remote) {
        // Same visible state; only a local purge request still needs to go out.
        return if local.purge && !remote.purge { Merge::Rebase(local.clone()) } else { Merge::Drop };
    }
    if !remote.origin.is_empty() && remote.origin == my_origin {
        // Our own earlier push whose acknowledgement was lost; the pending change came after it.
        return Merge::Rebase(local.clone());
    }
    if local.deleted {
        return Merge::Drop; // someone still works on it: never let a delete win
    }
    if remote.deleted {
        return Merge::Rebase(local.clone()); // local edit resurrects the file
    }
    if local.kind != remote.kind {
        return Merge::Fork(local.clone());
    }
    if local.kind == Kind::Dir {
        return Merge::Drop;
    }
    let changed = |m: &Meta| base.map(|b| b.deleted || b.hash() != m.hash()).unwrap_or(true);
    let remote_moved = base.map(|b| b.path != remote.path).unwrap_or(true);
    match (changed(local), changed(remote)) {
        // Local only moved it.
        (false, _) if remote_moved => Merge::Drop,
        (false, _) => Merge::Rebase(Meta { path: local.path.clone(), purge: false, ..remote.clone() }),
        // Local edited, remote only moved it: keep the edit, follow the move.
        (true, false) => Merge::Rebase(Meta { path: remote.path.clone(), ..local.clone() }),
        (true, true) if local.hash() == remote.hash() => Merge::Drop,
        (true, true) => Merge::Fork(local.clone()),
    }
}

pub struct PushJob {
    pub meta: Meta,
    pub blob: Vec<u8>,
    pub refs: Vec<ChunkId>,
}

impl Vault {
    /// Apply a batch of server records (must continue exactly at our cursor).
    pub fn apply_remote(&mut self, head: u64, records: Vec<Record>) -> Result<usize> {
        if head < self.state.cursor {
            return Err(Error::Integrity("server log went backwards (rollback)".into()));
        }
        let n = records.len();
        let res = records.into_iter().try_for_each(|r| self.apply_record(r));
        self.flush()?;
        res?;
        if self.state.cursor >= head {
            // Placeholders are only legitimate below a purge that an authentic record announces.
            if self.state.entries.values().any(|e| e.pruned_through > 0 && e.pruned_through >= e.floor) {
                return Err(Error::Integrity("server withheld revisions that were never purged".into()));
            }
        }
        Ok(n)
    }

    fn apply_record(&mut self, r: Record) -> Result<()> {
        if r.seq != self.state.cursor + 1 {
            return Err(Error::Integrity(format!("server log gap: expected seq {}, got {}", self.state.cursor + 1, r.seq)));
        }
        let st = self.state.entries.get(&r.entry);
        let last = st.map(|e| e.base_rev()).unwrap_or(0);
        let floor = st.map(|e| e.floor).unwrap_or(0);
        if r.blob.is_empty() {
            // Purged on the server. Fine if we already moved past it; otherwise note it and
            // check at the end of the pull that a purge really covers it.
            if r.rev > last + 1 {
                return Err(Error::Integrity(format!("server skipped revision {} of an entry", last + 1)));
            }
            if r.rev == last + 1 {
                self.stage(Event::Pruned { entry: r.entry, rev: r.rev });
            }
            self.stage(Event::Cursor { seq: r.seq });
            return Ok(());
        }
        let m = self.keys.open_meta(&self.id, &r.entry, r.rev, &r.blob)
            .map_err(|e| Error::Integrity(format!("server record {} is not authentic: {e}", r.seq)))?;
        if r.rev <= last {
            // Already known (our own push). It must be identical, or history was rewritten.
            let same = r.rev < floor || st.and_then(|e| e.history.iter().find(|h| h.meta.rev == r.rev)).map(|h| h.meta == m).unwrap_or(false);
            if !same {
                return Err(Error::Integrity("server changed an already-committed revision".into()));
            }
            self.stage(Event::Cursor { seq: r.seq });
            return Ok(());
        }
        if r.rev != last + 1 {
            return Err(Error::Integrity(format!("server skipped revision {} of an entry", last + 1)));
        }
        let base = st.and_then(|e| e.base().cloned());
        let pending = st.and_then(|e| e.pending.clone());
        self.stage(Event::Base { seq: r.seq, meta: m.clone() });
        if let Some(local) = pending {
            match merge(base.as_ref(), &local, &m, &self.device.id) {
                Merge::Drop => self.stage(Event::Unpend { id: r.entry }),
                Merge::Rebase(mut n) => {
                    n.rev = m.rev + 1;
                    n.prune_below = n.prune_below.max(m.floor());
                    self.stage(Event::Pending { meta: n });
                }
                Merge::Fork(mut n) => {
                    self.stage(Event::Unpend { id: r.entry });
                    let wanted = tagged_path(&n.path, &format!("conflict {} {}", n.device, stamp(n.ts)));
                    let mut path = wanted.clone();
                    let mut i = 2;
                    while self.live().any(|x| is_under(&x.path, &path)) {
                        path = tagged_path(&wanted, &i.to_string());
                        i += 1;
                    }
                    self.conflicts.push(format!(
                        "'{}' was changed here and on {}. Both kept: your version is '{}'.",
                        local.path,
                        if m.device.is_empty() { "another device" } else { &m.device },
                        basename(&path)
                    ));
                    n.id = EntryId::random();
                    n.rev = 1;
                    n.purge = false;
                    n.prune_below = 0;
                    n.path = path;
                    self.stage(Event::Pending { meta: n });
                }
            }
        }
        self.stage(Event::Cursor { seq: r.seq });
        Ok(())
    }

    /// Oldest pending change not in `skip`.
    pub fn next_pending(&self, skip: &BTreeSet<EntryId>) -> Option<PushJob> {
        let meta = self
            .state
            .entries
            .iter()
            .filter(|(id, _)| !skip.contains(id))
            .filter_map(|(_, e)| e.pending.as_ref())
            .min_by_key(|m| (m.ts, m.id))?
            .clone();
        Some(PushJob { blob: self.keys.seal_meta(&self.id, &meta), refs: meta.refs(), meta })
    }

    pub fn pending_count(&self) -> usize {
        self.state.entries.values().filter(|e| e.pending.is_some()).count()
    }

    /// The server accepted `pushed` as `seq`.
    pub fn ack_push(&mut self, pushed: &Meta, seq: u64) -> Result<()> {
        let pending = self.state.entries.get(&pushed.id).and_then(|e| e.pending.clone());
        let mut events = vec![Event::Base { seq, meta: pushed.clone() }];
        if pushed.purge {
            events.push(Event::PruneTodo { entry: pushed.id, below: pushed.rev });
        }
        match pending {
            Some(p) if p == *pushed => events.push(Event::Unpend { id: pushed.id }),
            // Edited again while the push was in flight: keep that edit, on top of what we pushed.
            Some(p) => events.push(Event::Pending { meta: Meta { rev: pushed.rev + 1, ..p } }),
            None => {}
        }
        self.log(events)
    }

    /// Purges the server has not been told about yet.
    pub fn prune_todo(&self) -> Vec<(EntryId, u64)> {
        self.state.prune_todo.iter().map(|(e, b)| (*e, *b)).collect()
    }

    pub fn prune_sent(&mut self, items: &[(EntryId, u64)]) -> Result<()> {
        self.log(items.iter().map(|(entry, _)| Event::PruneDone { entry: *entry }).collect())
    }

    /// Chunks of live files that are not stored locally yet.
    pub fn missing_chunks(&self) -> Vec<ChunkId> {
        let mut ids: BTreeSet<ChunkId> = BTreeSet::new();
        for m in self.live() {
            ids.extend(m.refs());
        }
        ids.into_iter().filter(|id| !self.chunks.has(id)).collect()
    }
}

#[derive(Serialize, Default, Debug, Clone)]
pub struct SyncReport {
    pub pulled: usize,
    pub pushed: usize,
    pub downloaded: usize,
    /// Non-fatal problems (the rest of the sync still ran).
    pub errors: Vec<String>,
}

/// One full sync. Takes the vault lock only for short, local steps; network I/O runs unlocked.
/// Safe to interrupt anywhere and to repeat any number of times.
pub fn sync_once(vault: &Mutex<Vault>, remote: &dyn Remote) -> Result<SyncReport> {
    let mut rep = SyncReport::default();
    let mut skip = BTreeSet::new();
    let lock = || vault.lock().unwrap_or_else(|p| p.into_inner());
    let chunks = lock().chunks.clone();

    for _round in 0..32 {
        loop {
            let cursor = lock().cursor();
            let (head, records) = remote.pull(cursor, 500)?;
            let n = records.len();
            let mut v = lock();
            rep.pulled += v.apply_remote(head, records)?;
            if n == 0 || v.cursor() >= head {
                break;
            }
        }
        lock().resolve_collisions()?;

        let mut conflict = false;
        'push: loop {
            let Some(job) = lock().next_pending(&skip) else { break };
            for attempt in 0..2 {
                let missing = if attempt == 0 { remote.missing(&job.refs)? } else { job.refs.clone() };
                let mut unreadable = None;
                for id in &missing {
                    match chunks.get(id) {
                        Ok(data) => remote.put_chunk(id, &data)?,
                        Err(e) => {
                            unreadable = Some(e);
                            break;
                        }
                    }
                }
                if let Some(e) = unreadable {
                    rep.errors.push(format!("cannot upload '{}': {e}", job.meta.path));
                    skip.insert(job.meta.id);
                    continue 'push;
                }
                match remote.commit(&job.meta.id, job.meta.rev - 1, job.meta.rev, &job.blob, &job.refs)? {
                    CommitOutcome::Committed(seq) => {
                        lock().ack_push(&job.meta, seq)?;
                        rep.pushed += 1;
                        continue 'push;
                    }
                    CommitOutcome::Conflict(_) => {
                        conflict = true;
                        break 'push;
                    }
                    CommitOutcome::MissingRefs(_) if attempt == 0 => continue, // re-upload everything once
                    CommitOutcome::MissingRefs(_) => {
                        rep.errors.push(format!("server keeps losing chunks of '{}'", job.meta.path));
                        skip.insert(job.meta.id);
                        continue 'push;
                    }
                }
            }
        }
        if !conflict {
            break;
        }
    }

    // Purges: have the server erase the old revisions and their chunks; then clean up locally.
    let todo = lock().prune_todo();
    if !todo.is_empty() {
        match remote.prune(&todo) {
            Ok(()) => lock().prune_sent(&todo)?,
            Err(e @ Error::Net(_)) => return Err(e),
            Err(e) => rep.errors.push(format!("server could not purge: {e}")),
        }
    }
    lock().maintain()?;

    // Full local replica: fetch content we do not have yet. Failures here are retried next time.
    let wanted = lock().missing_chunks();
    for id in wanted {
        match remote.get_chunk(&id).and_then(|d| chunks.put_verified(&id, &d)) {
            Ok(()) => rep.downloaded += 1,
            Err(e @ Error::Net(_)) => {
                rep.errors.push(e.to_string());
                break;
            }
            Err(e) => rep.errors.push(e.to_string()),
        }
    }
    if rep.downloaded > 0 {
        lock().generation += 1;
    }
    Ok(rep)
}
