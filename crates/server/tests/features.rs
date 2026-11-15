//! Purge, key rotation, invites, local->synced and header sync, through the real client stack
//! against the real server.

use std::fs;
use std::path::Path;

use coffer_core::crypto::KdfParams;
use coffer_core::header::SlotKind;
use coffer_core::manager::Manager;
use coffer_core::Error;
use coffer_server::{spawn, Config, ServerHandle};
use serde_json::Value;

const TOKEN: &str = "enroll-token-for-tests";

fn server(data: &Path) -> (ServerHandle, String) {
    let cfg = Config { data_dir: data.to_path_buf(), enroll_token: Some(TOKEN.into()), gc_grace_secs: 0, ..Default::default() };
    let h = spawn(cfg, "127.0.0.1:0").unwrap();
    let url = format!("http://{}", h.addr());
    (h, url)
}

fn weak() -> Option<KdfParams> {
    Some(KdfParams::weak_for_tests())
}

fn put(m: &Manager, id: &str, path: &str, data: &[u8]) {
    m.get(id).unwrap().v().put_bytes(path, data, 1).unwrap();
}

fn read(m: &Manager, id: &str, path: &str) -> Vec<u8> {
    let entry = m.get(id).unwrap().v().find(path).unwrap_or_else(|| panic!("no {path}")).id;
    m.read(id, &entry, None, 1 << 24).unwrap()
}

fn sync(m: &Manager, id: &str) {
    let ov = m.get(id).unwrap();
    ov.v().gc_min_age = std::time::Duration::ZERO;
    let r = ov.sync_blocking().unwrap();
    assert!(r.errors.is_empty(), "{:?}", r.errors);
}

fn all_bytes(p: &Path) -> Vec<u8> {
    let mut out = Vec::new();
    fn walk(p: &Path, out: &mut Vec<u8>) {
        for e in fs::read_dir(p).unwrap() {
            let e = e.unwrap().path();
            if e.is_dir() { walk(&e, out) } else { out.extend(fs::read(&e).unwrap()) }
        }
    }
    walk(p, &mut out);
    out
}

fn chunk_count(p: &Path) -> usize {
    fn walk(p: &Path, n: &mut usize) {
        for e in fs::read_dir(p).unwrap() {
            let e = e.unwrap().path();
            if e.is_dir() {
                walk(&e, n)
            } else if e.file_name().unwrap().len() == 64 {
                *n += 1
            }
        }
    }
    let mut n = 0;
    walk(p, &mut n);
    n
}

#[test]
fn empty_trash_reclaims_server_storage() {
    let tmp = tempfile::tempdir().unwrap();
    let (_h, url) = server(&tmp.path().join("server"));
    let a = Manager::new(tmp.path().join("homeA"), false).unwrap();
    let b = Manager::new(tmp.path().join("homeB"), false).unwrap();
    let (id, recovery) = a.create("Docs", Some((&url, TOKEN))).unwrap();
    put(&a, &id, "big.bin", &vec![7u8; 600_000]);
    put(&a, &id, "keep.txt", b"keep");
    sync(&a, &id);
    b.join("Docs", &url, &id, SlotKind::Recovery, recovery.as_bytes()).unwrap();
    sync(&b, &id);
    let before = a.usage(&id).unwrap();
    assert_eq!(before.chunks, 2);
    assert_eq!(chunk_count(&tmp.path().join("server")), 2);

    a.get(&id).unwrap().v().delete("big.bin").unwrap();
    sync(&a, &id);
    assert_eq!(a.get(&id).unwrap().v().empty_trash().unwrap(), 1);
    sync(&a, &id);
    sync(&b, &id);

    let after = a.usage(&id).unwrap();
    assert_eq!(after.chunks, 1);
    assert!(after.bytes < before.bytes / 100);
    assert_eq!(chunk_count(&tmp.path().join("server")), 1);
    for (m, home) in [(&a, "homeA"), (&b, "homeB")] {
        assert!(m.get(&id).unwrap().v().trash().is_empty());
        assert_eq!(chunk_count(&tmp.path().join(home)), 1, "{home} still holds purged chunks");
        assert_eq!(read(m, &id, "keep.txt"), b"keep");
    }
    // A third device joining now gets placeholders and is fine with them.
    let c = Manager::new(tmp.path().join("homeC"), false).unwrap();
    c.join("Docs", &url, &id, SlotKind::Recovery, recovery.as_bytes()).unwrap();
    sync(&c, &id);
    assert_eq!(read(&c, &id, "keep.txt"), b"keep");
    assert!(c.get(&id).unwrap().v().trash().is_empty());
}

#[test]
fn local_vault_becomes_synced() {
    let tmp = tempfile::tempdir().unwrap();
    let (_h, url) = server(&tmp.path().join("server"));
    let a = Manager::new(tmp.path().join("homeA"), false).unwrap();
    let (id, recovery) = a.create("Private", None).unwrap();
    put(&a, &id, "notes/a.txt", b"v1");
    put(&a, &id, "notes/a.txt", b"v2");
    put(&a, &id, "old.txt", b"purge me");
    put(&a, &id, "b.bin", &vec![3u8; 100_000]);
    {
        let ov = a.get(&id).unwrap();
        let mut v = ov.v();
        v.gc_min_age = std::time::Duration::ZERO;
        v.delete("old.txt").unwrap();
        v.empty_trash().unwrap();
        v.rename("b.bin", "c.bin").unwrap();
    }
    assert!(matches!(a.attach(&id, &url, "wrong"), Err(Error::Server(403, _))));
    put(&a, &id, "still-local.txt", b"writes work again after a failed connect");
    a.attach(&id, &url, TOKEN).unwrap();
    assert_eq!(a.list()[0].remote.as_deref(), Some(url.as_str()));
    sync(&a, &id);
    put(&a, &id, "after.txt", b"written after connecting");
    sync(&a, &id);

    let b = Manager::new(tmp.path().join("homeB"), false).unwrap();
    b.join("Private", &url, &id, SlotKind::Recovery, recovery.as_bytes()).unwrap();
    sync(&b, &id);
    assert_eq!(read(&b, &id, "notes/a.txt"), b"v2");
    assert_eq!(read(&b, &id, "c.bin"), vec![3u8; 100_000]);
    assert_eq!(read(&b, &id, "after.txt"), b"written after connecting");
    // History came along; the purged file did not.
    let e = b.get(&id).unwrap().v().find("notes/a.txt").unwrap().id;
    assert_eq!(b.read(&id, &e, Some(1), 1 << 20).unwrap(), b"v1");
    assert!(b.get(&id).unwrap().v().trash().is_empty());
    let server_bytes = all_bytes(&tmp.path().join("server"));
    assert!(!server_bytes.windows(8).any(|w| w == b"purge me"));
    // Survives a restart of A as a synced vault with nothing pending.
    a.lock(&id);
    a.unlock(&id, SlotKind::Recovery, None, recovery.as_bytes()).unwrap();
    sync(&a, &id);
    assert_eq!(a.get(&id).unwrap().v().summary().pending, 0);
    assert!(a.attach(&id, &url, TOKEN).is_err());
}

#[test]
fn rotation_revokes_other_devices_until_they_adopt() {
    let tmp = tempfile::tempdir().unwrap();
    let (_h, url) = server(&tmp.path().join("server"));
    let a = Manager::new(tmp.path().join("homeA"), false).unwrap();
    let b = Manager::new(tmp.path().join("homeB"), false).unwrap();
    let thief = Manager::new(tmp.path().join("homeT"), false).unwrap();
    let (id, recovery) = a.create("Docs", Some((&url, TOKEN))).unwrap();
    a.add_slot(&id, SlotKind::Passphrase, "pw", b"old passphrase", Value::Null, weak()).unwrap();
    put(&a, &id, "a.txt", b"before");
    sync(&a, &id);
    for m in [&b, &thief] {
        m.join("Docs", &url, &id, SlotKind::Passphrase, b"old passphrase").unwrap();
        sync(m, &id);
    }
    put(&b, &id, "offline-on-b.txt", b"written by B before it knew");

    let new_recovery = a.rotate_prepare(&id, Some(b"new passphrase"), weak()).unwrap();
    a.rotate_commit(&id).unwrap();
    put(&a, &id, "a.txt", b"after rotation");
    put(&a, &id, "new.txt", b"only for the new keys");
    sync(&a, &id);

    // The old key no longer talks to the server; the client says why.
    for m in [&b, &thief] {
        assert!(matches!(m.get(&id).unwrap().sync_blocking(), Err(Error::Server(401, _))));
        assert_eq!(m.get(&id).unwrap().status().state, "rekeyed");
    }
    // Old secrets cannot adopt, and cannot join afresh.
    assert!(thief.adopt_rekey(&id, SlotKind::Passphrase, b"old passphrase").is_err());
    assert!(thief.adopt_rekey(&id, SlotKind::Recovery, recovery.as_bytes()).is_err());
    let fresh = Manager::new(tmp.path().join("homeF"), false).unwrap();
    assert!(fresh.join("Docs", &url, &id, SlotKind::Passphrase, b"old passphrase").is_err());
    assert_eq!(read(&thief, &id, "a.txt"), b"before"); // keeps what it already had, gets nothing new

    // B adopts with the new passphrase, keeps its unsynced work, and catches up.
    b.adopt_rekey(&id, SlotKind::Passphrase, b"new passphrase").unwrap();
    sync(&b, &id);
    sync(&a, &id);
    assert_eq!(read(&b, &id, "a.txt"), b"after rotation");
    assert_eq!(read(&b, &id, "new.txt"), b"only for the new keys");
    assert_eq!(read(&a, &id, "offline-on-b.txt"), b"written by B before it knew");
    let e = b.get(&id).unwrap().v().find("a.txt").unwrap().id;
    assert_eq!(b.read(&id, &e, Some(1), 1 << 20).unwrap(), b"before"); // old epoch still readable
    // B restarts: only the new secrets open it.
    b.lock(&id);
    assert!(b.unlock(&id, SlotKind::Passphrase, None, b"old passphrase").is_err());
    b.unlock(&id, SlotKind::Recovery, None, new_recovery.as_bytes()).unwrap();
    sync(&b, &id);
    // A locked device can adopt too.
    let c = Manager::new(tmp.path().join("homeC"), false).unwrap();
    c.join("Docs", &url, &id, SlotKind::Passphrase, b"new passphrase").unwrap();
    sync(&c, &id);
    c.lock(&id);
    let r2 = a.rotate_prepare(&id, None, None).unwrap();
    a.rotate_commit(&id).unwrap();
    sync(&a, &id);
    c.adopt_rekey(&id, SlotKind::Recovery, r2.as_bytes()).unwrap();
    sync(&c, &id);
    assert_eq!(c.get(&id).unwrap().v().header.epoch(), 2);
    assert_eq!(read(&c, &id, "new.txt"), b"only for the new keys");
}

fn gone(r: Result<(String, Option<String>), Error>, why: &str) {
    match r {
        Err(Error::Server(410, m)) => assert!(m.contains(why), "{m}"),
        other => panic!("expected 410 '{why}', got {other:?}"),
    }
}

#[test]
fn invites_work_once_and_slot_changes_travel() {
    let tmp = tempfile::tempdir().unwrap();
    let (_h, url) = server(&tmp.path().join("server"));
    let a = Manager::new(tmp.path().join("homeA"), false).unwrap();
    let friend = Manager::new(tmp.path().join("homeFriend"), false).unwrap();
    let snoop = Manager::new(tmp.path().join("homeSnoop"), false).unwrap();
    let (id, a_key) = a.create("Shared", Some((&url, TOKEN))).unwrap();
    put(&a, &id, "plan.txt", b"shared plan");
    sync(&a, &id);

    let code = a.invite(&id, "Sam", None).unwrap();
    assert_eq!(code.split('#').count(), 3);
    // Not a key slot: nothing in the public header opens with it.
    assert!(!a.list()[0].slots.iter().any(|s| s.label.starts_with("Invite")));
    assert!(snoop.join("X", &url, &id, SlotKind::Recovery, code.rsplit('#').next().unwrap().as_bytes()).is_err());
    assert!(friend.join_invite("Shared", "garbage").is_err());

    let (fid, sam_key) = friend.join_invite("Shared", &code).unwrap();
    assert_eq!(fid, id);
    let sam_key = sam_key.expect("one-time invite gives the joiner a recovery key");
    sync(&friend, &id);
    assert_eq!(read(&friend, &id, "plan.txt"), b"shared plan");

    // Used up: the same line, read later from a chat, gets nothing.
    gone(snoop.join_invite("X", &code), "used");
    assert!(snoop.list().is_empty());

    // Sam's own slots reach A's header through the server.
    friend.add_slot(&id, SlotKind::Passphrase, "Sam's passphrase", b"sams passphrase", Value::Null, weak()).unwrap();
    put(&friend, &id, "from-sam.txt", b"hi");
    sync(&friend, &id);
    a.lock(&id); // the server header is read once per unlock
    a.unlock(&id, SlotKind::Recovery, None, a_key.as_bytes()).unwrap();
    sync(&a, &id);
    assert_eq!(read(&a, &id, "from-sam.txt"), b"hi");
    let labels: Vec<String> = a.list()[0].slots.iter().map(|s| s.label.clone()).collect();
    assert!(labels.contains(&"Sam's passphrase".into()) && labels.contains(&"Recovery key (Sam)".into()), "{labels:?}");
    // Sam's recovery key is a real way in (new device).
    let sam2 = Manager::new(tmp.path().join("homeSam2"), false).unwrap();
    sam2.join("Shared", &url, &id, SlotKind::Recovery, sam_key.as_bytes()).unwrap();

    let list = a.invites(&id).unwrap();
    assert_eq!(list.len(), 1);
    assert_eq!((list[0].state.as_str(), list[0].label.as_str()), ("used", "Sam"));
    assert!(list[0].claimed.is_some());

    // Revoked before use.
    let wrong = a.invite(&id, "Wrong person", None).unwrap();
    let iid = a.invites(&id).unwrap().into_iter().find(|i| i.state == "waiting").unwrap().id;
    a.revoke_invite(&id, &iid).unwrap();
    gone(snoop.join_invite("X", &wrong), "revoked");
    // Expired.
    let short = a.invite(&id, "", Some(300)).unwrap();
    std::thread::sleep(std::time::Duration::from_millis(400));
    gone(snoop.join_invite("X", &short), "expired");
    assert!(a.invite(&id, "", Some(8 * 24 * 3600 * 1000)).is_err());
    let states: Vec<String> = a.invites(&id).unwrap().into_iter().map(|i| i.state).collect();
    assert_eq!(states, ["expired", "revoked", "used"]);

    // Old-style invite (a recovery slot in the header) still joins, and keeps working.
    let old_key = coffer_core::crypto::random::<32>();
    a.get(&id).unwrap().v().edit_header(|h, vmk| h.add_slot(vmk, SlotKind::Recovery, "Invite: Old", &old_key, None, Value::Null)).unwrap();
    sync(&a, &id);
    let old_line = format!("{url}#{id}#{}", coffer_core::crypto::recovery_encode(&old_key));
    let oldie = Manager::new(tmp.path().join("homeOld"), false).unwrap();
    assert_eq!(oldie.join_invite("Shared", &old_line).unwrap(), (id.clone(), None));

    // Rotation drops open invites and cuts Sam off.
    let later = a.invite(&id, "Later", None).unwrap();
    a.rotate_prepare(&id, None, None).unwrap();
    a.rotate_commit(&id).unwrap();
    sync(&a, &id);
    assert!(a.invites(&id).unwrap().is_empty());
    assert!(matches!(snoop.join_invite("X", &later), Err(Error::NotFound(_))));
    assert!(friend.get(&id).unwrap().sync_blocking().is_err());
    assert!(friend.adopt_rekey(&id, SlotKind::Passphrase, b"sams passphrase").is_err());
    assert!(friend.adopt_rekey(&id, SlotKind::Recovery, sam_key.as_bytes()).is_err());
}

#[test]
fn fuzz_with_purges_over_http() {
    use coffer_core::http::{create_vault, HttpRemote};
    use coffer_core::remote::Remote;
    use std::sync::atomic::{AtomicBool, Ordering};
    for seed in 301..=304 {
        let data = tempfile::tempdir().unwrap();
        let (_h, url) = server(data.path());
        let registered = AtomicBool::new(false);
        coffer_core::testkit::fuzz_opts(seed, 3, 100, true, &|v: &coffer_core::vault::Vault| {
            if !registered.swap(true, Ordering::SeqCst) {
                create_vault(&url, TOKEN, &v.keys(), &v.portable_header()).unwrap();
            }
            std::sync::Arc::new(HttpRemote::new(&url, &v.id_hex(), v.keys()).unwrap()) as std::sync::Arc<dyn Remote>
        });
    }
}

/// Is a sealed invite payload at rest in the server's data directory?
fn payload_at_rest(data: &Path) -> bool {
    all_bytes(data).windows(6).any(|w| w == b"\"blob\"")
}

#[test]
fn invite_payload_is_erased_and_junk_claims_block_nobody() {
    let tmp = tempfile::tempdir().unwrap();
    let data = tmp.path().join("server");
    let (_h, url) = server(&data);
    let a = Manager::new(tmp.path().join("homeA"), false).unwrap();
    let friend = Manager::new(tmp.path().join("homeFriend"), false).unwrap();
    let snoop = Manager::new(tmp.path().join("homeSnoop"), false).unwrap();
    let (id, _) = a.create("Shared", Some((&url, TOKEN))).unwrap();
    sync(&a, &id);
    let wait = || std::thread::sleep(std::time::Duration::from_millis(400));

    // Expired, then claimed with the line: refused, and the refusal erases the payload.
    let line = a.invite(&id, "", Some(300)).unwrap();
    assert!(payload_at_rest(&data));
    wait();
    gone(snoop.join_invite("X", &line), "expired");
    assert!(!payload_at_rest(&data), "a refused claim must erase the payload");

    // Expired, nobody claims: the next request from a member erases it.
    a.invite(&id, "", Some(300)).unwrap();
    wait();
    assert!(payload_at_rest(&data));
    sync(&a, &id);
    assert!(!payload_at_rest(&data), "a member's request must erase stale payloads");

    // Junk claims use up the vault's auth-failure budget; the invite's holder still gets in.
    let real = a.invite(&id, "Real", None).unwrap();
    let junk = |i: u32| {
        let u = format!("{url}/v1/vaults/{id}/invites/{i:032x}/claim");
        ureq::post(&u).header("Content-Type", "application/json").send(&br#"{"nonce":"00000000000000000000000000000000"}"#[..]).map(|_| ())
    };
    for i in 0..20 {
        assert!(matches!(junk(i), Err(ureq::Error::StatusCode(404))));
    }
    assert!(matches!(junk(99), Err(ureq::Error::StatusCode(429))), "junk is rate-limited");
    let (fid, key) = friend.join_invite("Shared", &real).unwrap();
    assert!(fid == id && key.is_some());
    gone(snoop.join_invite("X", &real), "used");
}

#[test]
fn a_join_that_fails_does_not_burn_the_invite() {
    use coffer_core::invite::{parse_line, InviteKeys};
    let tmp = tempfile::tempdir().unwrap();
    let (_h, url) = server(&tmp.path().join("server"));
    let a = Manager::new(tmp.path().join("homeA"), false).unwrap();
    let home = tmp.path().join("homeFriend");
    let friend = Manager::new(home.clone(), false).unwrap();
    let snoop = Manager::new(tmp.path().join("homeSnoop"), false).unwrap();
    let (id, _) = a.create("Shared", Some((&url, TOKEN))).unwrap();
    put(&a, &id, "plan.txt", b"shared plan");
    sync(&a, &id);
    let state = || a.invites(&id).unwrap()[0].state.clone();
    let line = a.invite(&id, "Sam", None).unwrap();

    // A leftover folder is in the way: the join stops before the claim, the invite stays open.
    let (dir, junk) = (home.join("vaults").join(&id), home.join("vaults").join(&id).join("leftover"));
    fs::create_dir_all(&dir).unwrap();
    fs::write(&junk, b"x").unwrap();
    assert!(matches!(friend.join_invite("Shared", &line), Err(Error::Exists(_))));
    assert_eq!(state(), "waiting");

    // The claim lands but the join does not finish (crash, full disk): simulated by claiming with
    // the nonce the failed attempt saved. The same device can still join; nobody else can.
    let claims: Value = serde_json::from_slice(&fs::read(home.join("claims.json")).unwrap()).unwrap();
    let ik = InviteKeys::from_secret(&coffer_core::crypto::recovery_decode(&parse_line(&line).unwrap().secret).unwrap());
    let nonce = claims[&ik.id]["nonce"].as_str().unwrap().to_string();
    coffer_core::http::claim_invite(&url, &id, &ik, &nonce).unwrap();
    assert_eq!(state(), "used");
    gone(snoop.join_invite("X", &line), "used");
    fs::remove_file(&junk).unwrap();
    fs::remove_dir(&dir).unwrap();
    let (fid, key) = friend.join_invite("Shared", &line).unwrap();
    assert!(fid == id && key.is_some());
    sync(&friend, &id);
    assert_eq!(read(&friend, &id, "plan.txt"), b"shared plan");
    // Joined: the saved nonce is gone.
    let claims: Value = serde_json::from_slice(&fs::read(home.join("claims.json")).unwrap()).unwrap();
    assert!(claims.as_object().unwrap().is_empty());
}
