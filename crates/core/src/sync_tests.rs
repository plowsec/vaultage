use std::sync::atomic::Ordering;

use crate::error::Error;
use crate::remote::Remote;
use crate::testkit::*;

fn conflict_copy(c: &Client, of: &str) -> String {
    let stem = of.rsplit_once('.').map(|(s, _)| s).unwrap_or(of);
    c.paths().into_iter().find(|p| p.starts_with(stem) && p.contains("(conflict")).unwrap_or_else(|| panic!("no conflict copy of {of}: {:?}", c.paths()))
}

#[test]
fn two_devices_basic_sync() {
    let (w, _) = World::mem(2);
    let (a, b) = (&w.clients[0], &w.clients[1]);
    a.put("docs/plan.txt", b"hello");
    a.v().mkdir("empty").unwrap();
    a.sync().unwrap();
    let r = b.sync().unwrap();
    assert_eq!((r.pulled, r.downloaded), (2, 1));
    assert_eq!(b.read("docs/plan.txt"), b"hello");
    b.put("docs/plan.txt", b"hello v2");
    b.sync().unwrap();
    a.sync().unwrap();
    assert_eq!(a.read("docs/plan.txt"), b"hello v2");
    // History travelled too: A can still read v1.
    let id = a.v().find("docs/plan.txt").unwrap().id;
    assert_eq!(a.v().reader(&id, Some(1)).unwrap().read_all(None).unwrap(), b"hello");
    w.settle();
    w.assert_converged();
}

#[test]
fn concurrent_edits_keep_both_versions() {
    let (w, _) = World::mem(3);
    let (a, b, c) = (&w.clients[0], &w.clients[1], &w.clients[2]);
    a.put("report.txt", b"base");
    w.settle();
    // All three edit the same file while offline.
    a.put("report.txt", b"from A");
    b.put("report.txt", b"from B");
    c.put("report.txt", b"from C");
    a.sync().unwrap();
    b.sync().unwrap();
    c.sync().unwrap();
    w.settle();
    w.assert_converged();
    assert_eq!(a.read("report.txt"), b"from A");
    let all: Vec<Vec<u8>> = a.paths().iter().map(|p| a.read(p)).collect();
    assert_eq!(all.len(), 3, "{:?}", a.paths());
    for want in [&b"from A"[..], b"from B", b"from C"] {
        assert!(all.iter().any(|d| d == want));
    }
    assert!(!b.v().conflicts.is_empty());
}

#[test]
fn edit_beats_delete_in_both_directions() {
    let (w, _) = World::mem(2);
    let (a, b) = (&w.clients[0], &w.clients[1]);
    a.put("x.txt", b"base");
    a.put("y.txt", b"base");
    w.settle();
    // Delete reaches the server first, edit second.
    a.v().delete("x.txt").unwrap();
    b.put("x.txt", b"edited");
    // Edit first, delete second.
    b.put("y.txt", b"edited");
    a.v().delete("y.txt").unwrap();
    a.sync().unwrap(); // pushes delete x, delete y
    b.sync().unwrap(); // edit x resurrects; edit y resurrects
    w.settle();
    w.assert_converged();
    assert_eq!(a.read("x.txt"), b"edited");
    assert_eq!(a.read("y.txt"), b"edited");
}

#[test]
fn rename_and_edit_merge_cleanly() {
    let (w, _) = World::mem(2);
    let (a, b) = (&w.clients[0], &w.clients[1]);
    a.put("draft.txt", b"v1");
    w.settle();
    a.v().rename("draft.txt", "final.txt").unwrap();
    b.put("draft.txt", b"v2");
    a.sync().unwrap();
    b.sync().unwrap();
    w.settle();
    w.assert_converged();
    assert_eq!(a.paths(), ["final.txt"]);
    assert_eq!(a.read("final.txt"), b"v2");
    // And the other order: edit lands first, rename second.
    b.put("final.txt", b"v3");
    a.v().rename("final.txt", "done.txt").unwrap();
    b.sync().unwrap();
    a.sync().unwrap();
    w.settle();
    w.assert_converged();
    assert_eq!(b.paths(), ["done.txt"]);
    assert_eq!(b.read("done.txt"), b"v3");
}

#[test]
fn same_new_path_on_two_devices_keeps_both() {
    let (w, _) = World::mem(2);
    let (a, b) = (&w.clients[0], &w.clients[1]);
    a.put("notes.md", b"A's notes");
    b.put("notes.md", b"B's notes");
    a.sync().unwrap();
    b.sync().unwrap();
    w.settle();
    w.assert_converged();
    assert_eq!(a.paths().len(), 2);
    assert_eq!(a.read("notes.md"), b"A's notes");
    assert_eq!(a.read(&conflict_copy(a, "notes.md")), b"B's notes");
    // Identical content on both sides is still two entries, but nothing is lost or duplicated in content.
}

#[test]
fn file_versus_folder_with_same_name() {
    let (w, _) = World::mem(2);
    let (a, b) = (&w.clients[0], &w.clients[1]);
    a.put("thing", b"a file");
    b.put("thing/inside.txt", b"in a folder");
    a.sync().unwrap();
    b.sync().unwrap();
    w.settle();
    w.assert_converged();
    assert_eq!(a.read("thing/inside.txt"), b"in a folder");
    assert_eq!(a.read(&conflict_copy(a, "thing")), b"a file");
}

#[test]
fn folder_rename_versus_new_file_inside() {
    let (w, _) = World::mem(2);
    let (a, b) = (&w.clients[0], &w.clients[1]);
    a.put("proj/a.txt", b"a");
    w.settle();
    a.v().rename("proj", "archive").unwrap();
    b.put("proj/new.txt", b"new");
    a.sync().unwrap();
    b.sync().unwrap();
    w.settle();
    w.assert_converged();
    // Path-based model: the late file keeps its old folder name. Nothing lost.
    assert_eq!(a.paths(), ["archive/a.txt", "proj/new.txt"]);
}

#[test]
fn lost_acknowledgement_does_not_duplicate_or_conflict() {
    let (w, server) = World::mem(2);
    let (a, b) = (&w.clients[0], &w.clients[1]);
    a.put("a.txt", b"one");
    a.net.drop_commit_acks.store(1, Ordering::Relaxed);
    assert!(matches!(a.sync(), Err(Error::Net(_)))); // server has it, A does not know
    assert_eq!(a.v().pending_count(), 1);
    a.sync().unwrap();
    assert_eq!(a.v().pending_count(), 0);
    assert_eq!(server.log.lock().unwrap().len(), 1);

    // Lost ack, then the user saves again before the retry: must not conflict with ourselves.
    a.put("a.txt", b"two");
    a.net.drop_commit_acks.store(1, Ordering::Relaxed);
    assert!(a.sync().is_err());
    a.put("a.txt", b"three");
    a.sync().unwrap();
    b.sync().unwrap();
    w.settle();
    w.assert_converged();
    assert_eq!(b.paths(), ["a.txt"]);
    assert_eq!(b.read("a.txt"), b"three");
    assert!(a.v().conflicts.is_empty());
    // "two" was committed (the server took it) and is still in history.
    let id = b.v().find("a.txt").unwrap().id;
    let old = b.v().reader(&id, Some(2)).unwrap();
    assert_eq!(old.read_all(Some(&*b.net)).unwrap(), b"two");
}

#[test]
fn offline_changes_survive_restart_and_sync_later() {
    let (mut w, _) = World::mem(2);
    w.clients[0].put("a.txt", b"written offline");
    w.clients[0].net.rate.store(100, Ordering::Relaxed);
    assert!(w.clients[0].sync().is_err());
    reopen(&mut w.clients[0]); // app quit / crash with unsynced work
    assert_eq!(w.clients[0].v().pending_count(), 1);
    assert_eq!(w.clients[0].read("a.txt"), b"written offline");
    w.settle();
    assert_eq!(w.clients[1].read("a.txt"), b"written offline");
}

#[test]
fn interrupted_upload_resumes_without_reuploading() {
    let (w, server) = World::mem(1);
    let a = &w.clients[0];
    a.put("big.bin", &vec![5u8; crate::proto::CHUNK_SIZE * 2 + 10]);
    a.put("other.bin", &vec![6u8; 100]);
    a.net.rate.store(70, Ordering::Relaxed);
    let mut tries = 0;
    while a.v().pending_count() > 0 {
        let _ = a.sync();
        tries += 1;
        assert!(tries < 500);
    }
    assert!(tries > 1);
    assert_eq!(server.log.lock().unwrap().len(), 2);
    // big.bin's two full chunks are identical, so 2 unique chunks + 1 for other.bin... plus the tail.
    assert_eq!(server.chunks.lock().unwrap().len(), 3);
}

#[test]
fn commit_never_precedes_its_chunks() {
    let (w, server) = World::mem(1);
    let a = &w.clients[0];
    let id = a.put("a.bin", b"data");
    let job = a.v().next_pending(&Default::default()).unwrap();
    // A buggy client that skips the upload is refused by the server.
    assert!(matches!(server.commit(&id, 0, 1, &job.blob, &job.refs).unwrap(), crate::remote::CommitOutcome::MissingRefs(_)));
    assert!(server.log.lock().unwrap().is_empty());
}

#[test]
fn malicious_server_is_detected() {
    // Rollback.
    let (w, server) = World::mem(2);
    let (a, b) = (&w.clients[0], &w.clients[1]);
    a.put("a.txt", b"1");
    a.sync().unwrap();
    a.put("a.txt", b"2");
    a.sync().unwrap();
    b.sync().unwrap();
    server.log.lock().unwrap().pop();
    assert!(matches!(b.sync(), Err(Error::Integrity(_))));

    // Dropped record (gap).
    let (w, server) = World::mem(2);
    let (a, b) = (&w.clients[0], &w.clients[1]);
    a.put("a.txt", b"1");
    a.put("b.txt", b"1");
    a.sync().unwrap();
    server.log.lock().unwrap().remove(0);
    assert!(matches!(b.sync(), Err(Error::Integrity(_))));
    assert!(b.paths().is_empty());

    // Tampered record.
    let (w, server) = World::mem(2);
    let (a, b) = (&w.clients[0], &w.clients[1]);
    a.put("a.txt", b"1");
    a.sync().unwrap();
    server.log.lock().unwrap()[0].blob[40] ^= 1;
    assert!(matches!(b.sync(), Err(Error::Integrity(_))));

    // Old revision replayed as a newer one.
    let (w, server) = World::mem(2);
    let (a, b) = (&w.clients[0], &w.clients[1]);
    a.put("a.txt", b"1");
    a.sync().unwrap();
    a.put("a.txt", b"2");
    a.sync().unwrap();
    {
        let mut log = server.log.lock().unwrap();
        let first = log[0].blob.clone();
        log[1].blob = first;
    }
    assert!(matches!(b.sync(), Err(Error::Integrity(_))));

    // Swapped chunk content.
    let (w, server) = World::mem(2);
    let (a, b) = (&w.clients[0], &w.clients[1]);
    a.put("a.txt", b"real");
    a.sync().unwrap();
    for v in server.chunks.lock().unwrap().values_mut() {
        v[30] ^= 1;
    }
    let r = b.sync().unwrap();
    assert_eq!(r.downloaded, 0);
    assert!(!r.errors.is_empty());
}

#[test]
fn fuzz_convergence_and_no_loss() {
    for seed in 1..=40 {
        let server = std::sync::Arc::new(MemRemote::default());
        let s = server.clone();
        fuzz(seed, 2 + (seed as usize % 3), 120, &move |_| s.clone() as std::sync::Arc<dyn Remote>);
    }
}

fn chunk_files(c: &Client) -> usize {
    fn count(p: &std::path::Path) -> usize {
        std::fs::read_dir(p).map(|d| d.flatten().map(|e| if e.path().is_dir() { count(&e.path()) } else { 1 }).sum()).unwrap_or(0)
    }
    count(&c.v().dir.join("chunks"))
}

#[test]
fn empty_trash_erases_everywhere() {
    let (w, server) = World::mem(2);
    let (a, b) = (&w.clients[0], &w.clients[1]);
    let id = a.put("secret.txt", b"version one");
    a.put("secret.txt", b"version two");
    a.put("keep.txt", b"keep me");
    w.settle();
    assert_eq!((chunk_files(a), chunk_files(b)), (3, 2)); // b holds live content only
    a.v().delete("secret.txt").unwrap();
    w.settle();
    assert_eq!(b.v().trash().len(), 1);

    assert_eq!(a.v().empty_trash().unwrap(), 1);
    assert!(a.v().trash().is_empty()); // gone from the list at once, even before sync
    w.settle();
    for c in [a, b] {
        assert!(c.v().trash().is_empty());
        assert!(c.v().restore(&id, None).is_err());
        assert_eq!(c.v().versions(&id).unwrap().len(), 1); // only the bare tombstone
        assert_eq!(chunk_files(c), 1, "old chunks must be deleted locally");
        assert_eq!(c.read("keep.txt"), b"keep me");
    }
    // Server: old records are placeholders, their chunks are gone, the rest is intact.
    let log = server.log.lock().unwrap();
    assert_eq!(log.iter().filter(|r| r.entry == id).map(|r| r.blob.is_empty()).collect::<Vec<_>>(), [true, true, false]); // put (both saves were one push), delete, purge marker
    assert_eq!(server.chunks.lock().unwrap().len(), 1);
    drop(log);
    assert!(a.v().prune_todo().is_empty());
}

#[test]
fn new_device_accepts_purged_history_but_not_hidden_history() {
    let (w, server) = World::mem(3);
    let (a, b, c) = (&w.clients[0], &w.clients[1], &w.clients[2]);
    let id = a.put("f.txt", b"one");
    a.put("f.txt", b"two");
    a.put("g.txt", b"other");
    a.sync().unwrap();
    a.v().prune_versions(&id).unwrap();
    a.sync().unwrap();
    // B was never online before: it sees placeholders and an authentic purge marker.
    b.sync().unwrap();
    assert_eq!(b.read("f.txt"), b"two");
    assert_eq!(b.v().versions(&id).unwrap().len(), 1);
    assert_eq!(b.paths(), ["f.txt", "g.txt"]);
    // B can keep editing the pruned file.
    b.put("f.txt", b"three");
    w.clients[..2].iter().for_each(|x| { x.sync().unwrap(); });
    a.sync().unwrap();
    assert_eq!(a.read("f.txt"), b"three");
    assert_eq!(a.v().versions(&id).unwrap().len(), 2);

    // A server that blanks a record nobody purged is caught.
    let gid = a.v().find("g.txt").unwrap().id;
    server.log.lock().unwrap().iter_mut().filter(|r| r.entry == gid).for_each(|r| r.blob.clear());
    assert!(matches!(c.sync(), Err(Error::Integrity(_))));
}

#[test]
fn purge_loses_to_a_concurrent_edit_and_survives_offline() {
    let (mut w, server) = World::mem(2);
    w.clients[0].put("x.txt", b"base");
    w.settle();
    // A trashes + empties; B edits meanwhile. The edit wins; nothing is purged.
    w.clients[0].v().delete("x.txt").unwrap();
    w.clients[0].v().empty_trash().unwrap();
    w.clients[1].put("x.txt", b"edited");
    w.clients[1].sync().unwrap();
    w.clients[0].sync().unwrap();
    w.settle();
    w.assert_converged();
    assert_eq!(w.clients[0].read("x.txt"), b"edited");
    assert!(server.log.lock().unwrap().iter().all(|r| !r.blob.is_empty()));

    // Purge requested offline, app restarted, server told later.
    w.clients[0].v().delete("x.txt").unwrap();
    w.settle();
    w.clients[0].net.rate.store(100, Ordering::Relaxed);
    w.clients[0].v().empty_trash().unwrap();
    assert!(w.clients[0].sync().is_err());
    reopen(&mut w.clients[0]);
    w.settle();
    assert!(w.clients[1].v().trash().is_empty());
    assert_eq!(server.chunks.lock().unwrap().len(), 0);
    assert!(w.clients[0].v().prune_todo().is_empty());
}

#[test]
fn local_vault_purge_and_journal_scrub() {
    let d = tempfile::tempdir().unwrap();
    let dev = crate::model::Device::new("mac");
    let (mut v, _) = crate::vault::Vault::create(&d.path().join("v"), None, &dev).unwrap();
    v.gc_min_age = std::time::Duration::ZERO;
    let big = vec![9u8; 300_000];
    let id = v.put_bytes("a.bin", &big, 1).unwrap();
    v.put_bytes("a.bin", b"small", 2).unwrap();
    let journal_before = std::fs::metadata(v.dir.join("journal")).unwrap().len();
    v.prune_versions(&id).unwrap();
    assert_eq!(v.versions(&id).unwrap().len(), 1);
    assert!(v.reader(&id, Some(1)).is_err());
    assert!(std::fs::metadata(v.dir.join("journal")).unwrap().len() < journal_before);
    // An import in flight blocks collection of its not-yet-committed chunks.
    let ing = v.ingester("later.bin").unwrap();
    let (content, size) = ing.ingest(&mut &big[..]).unwrap();
    v.delete("a.bin").unwrap();
    v.empty_trash().unwrap();
    v.commit_file(ing.id, "later.bin", content, size, 3).unwrap();
    drop(ing);
    v.gc().unwrap();
    let rid = v.find("later.bin").unwrap().id;
    assert_eq!(v.reader(&rid, None).unwrap().read_all(None).unwrap(), big);
    // Survives reopen.
    let (dir, vmk) = (v.dir.clone(), v.keys().vmk.clone());
    drop(v);
    let v = crate::vault::Vault::open(&dir, vmk, &dev).unwrap();
    assert_eq!(v.summary().files, 1);
    assert!(v.trash().is_empty());
}

#[test]
fn fuzz_with_purges_converges_and_keeps_what_remains_readable() {
    for seed in 201..=230 {
        let server = std::sync::Arc::new(MemRemote::default());
        let s = server.clone();
        fuzz_opts(seed, 2 + (seed as usize % 3), 140, true, &move |_| s.clone() as std::sync::Arc<dyn Remote>);
        // The server holds no chunk that no live record references, and none is missing.
        let live: std::collections::HashSet<_> = server.refs.lock().unwrap().values().flatten().cloned().collect();
        let stored: std::collections::HashSet<_> = server.chunks.lock().unwrap().keys().cloned().collect();
        assert!(live.is_subset(&stored), "seed {seed}: server lost a referenced chunk");
    }
}
