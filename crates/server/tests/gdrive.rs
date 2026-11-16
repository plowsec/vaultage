//! GCS store with chunk bytes in Google Drive (both fakes): placement, lost replies, races,
//! orphans, outages, quota, token refresh, bucket-held chunks from before, the login flow.

mod common;

use std::sync::atomic::Ordering;

use vaultage_server::gdrive_login::{login, Opts};
use vaultage_server::StoreKind;
use common::fake_drive::{self, decode, GOOD_CODE};
use common::*;

fn drive_off(c: &mut vaultage_server::Config) {
    if let StoreKind::Gcs(g) = &mut c.store {
        g.drive = None;
    }
}

/// Chunk data whose id starts with `shard` (hex char).
fn data_in_shard(shard: char, tag: &str) -> Vec<u8> {
    (0..)
        .map(|i| format!("{tag}-{i}").into_bytes())
        .find(|d| blake3::hash(d).to_hex().starts_with(shard))
        .unwrap()
}

fn cid_of(d: &[u8]) -> String {
    blake3::hash(d).to_hex().to_string()
}

#[test]
fn chunk_bytes_live_in_drive_only() {
    let (env, _h, c) = setup(Kind::GcsDrive, "place");
    let data = b"opaque ciphertext ".repeat(200);
    let (cid, r) = c.put_chunk(&data);
    assert_eq!(r.status, 200);

    let ids = env.pointed_files(&c.vid);
    assert_eq!(ids.len(), 1);
    let blobs = env.drive().blobs();
    let f = &blobs[&ids[0]];
    assert_eq!((f.data.as_slice(), f.name.as_str()), (data.as_slice(), cid.as_str()));
    assert!(!contains(&env.fake().all_bytes(), &data), "bytes leaked into the bucket");
    {
        // <root>/<vault id>/<first hex char>/<cid>
        let files = env.drive().state.files.lock().unwrap();
        let shard = &files[f.parent.as_ref().unwrap()];
        assert_eq!(shard.name, cid[..1]);
        let vf = &files[shard.parent.as_ref().unwrap()];
        assert_eq!(vf.name, c.vid);
        assert_eq!(vf.parent.as_deref(), Some(fake_drive::ROOT));
    }

    let g = c.get_chunk(&cid);
    assert_eq!((g.status, &g.body), (200, &data));
    // Re-upload: no second file.
    assert_eq!(c.put_chunk(&data).1.status, 200);
    assert_eq!(env.drive().blobs().len(), 1);
    let u = c.usage();
    assert_eq!((u["bytes"].as_u64(), u["chunks"].as_u64()), (Some(data.len() as u64), Some(1)));
}

#[test]
fn lost_upload_reply_leaves_an_orphan_that_prune_sweeps_later() {
    let (env, _h, c) = setup(Kind::GcsDrive, "orphan");
    let x = b"first chunk".to_vec();
    assert_eq!(c.put_chunk(&x).1.status, 200); // folders exist from here on
    let y = data_in_shard(cid_of(&x).chars().next().unwrap(), "same-shard");
    env.drive().state.drop_after_apply.store(1, Ordering::SeqCst);
    assert_eq!(c.put_chunk(&y).1.status, 200, "retried after a lost reply");
    assert_eq!(env.drive().blobs().len(), 3, "x, y, and y's first copy");
    let e = id_hex("e", 16);
    let r = c.commit(&e, 0, 1, b"rec", &[&cid_of(&x), &cid_of(&y)]);
    assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));

    assert_eq!(c.prune(&[]).status, 200);
    assert_eq!(env.drive().blobs().len(), 3, "young orphan kept (upload may await its pointer)");
    env.drive().age(3600);
    assert_eq!(c.prune(&[]).status, 200);
    assert_eq!(env.drive().blobs().len(), 2, "old orphan swept");
    assert_eq!(env.chunk_count(&c.vid), 2);
    for d in [&x, &y] {
        assert_eq!(c.get_chunk(&cid_of(d)).body, *d);
    }
}

#[test]
fn lost_pointer_reply_is_recognized() {
    let (env, _h, c) = setup(Kind::GcsDrive, "lostptr");
    let x = b"warm up".to_vec();
    assert_eq!(c.put_chunk(&x).1.status, 200);
    let y = data_in_shard(cid_of(&x).chars().next().unwrap(), "ptr");
    // Next bucket write is the pointer insert: applied, reply lost; the retry sees ours.
    env.fake().state.drop_after_apply.store(1, Ordering::SeqCst);
    assert_eq!(c.put_chunk(&y).1.status, 200);
    assert_eq!(env.drive().blobs().len(), 2, "our file kept: the pointer names it");
    assert_eq!(c.get_chunk(&cid_of(&y)).body, y);
}

#[test]
fn two_instances_race_for_chunks_and_folders() {
    let env = Env::new(Kind::GcsDrive);
    let (ha, hb) = (env.start(), env.start());
    let c = Client::new(ha.addr(), "race");
    assert_eq!(c.create().status, 201);
    let n = 24;
    for i in 0..n {
        let data = format!("contended chunk {i}").into_bytes();
        std::thread::scope(|s| {
            for addr in [ha.addr(), hb.addr()] {
                let (c, data) = (c.at(addr), &data);
                s.spawn(move || assert_eq!(c.put_chunk(data).1.status, 200));
            }
        });
    }
    assert_eq!(env.chunk_count(&c.vid), n);
    assert_eq!(env.drive().blobs().len(), n, "every loser deleted its copy");
    // One vault folder, at most 16 shards, all under it.
    let files = env.drive().state.files.lock().unwrap();
    let vaults: Vec<_> = files.iter().filter(|(_, f)| f.parent.as_deref() == Some(fake_drive::ROOT)).collect();
    assert_eq!(vaults.len(), 1, "duplicate vault folder left behind");
    let vf = vaults[0].0.clone();
    let shards = files.iter().filter(|(_, f)| f.parent.as_deref() == Some(&vf)).count();
    assert!(shards <= 16, "{shards} shard folders");
    for f in files.values().filter(|f| f.mime != fake_drive::FOLDER) {
        assert_eq!(files[f.parent.as_ref().unwrap()].parent.as_deref(), Some(vf.as_str()));
    }
    drop(files);
    for i in 0..n {
        let data = format!("contended chunk {i}").into_bytes();
        assert_eq!(c.at(hb.addr()).get_chunk(&cid_of(&data)).body, data);
    }
}

#[test]
fn drive_outage_rate_limits_and_quota() {
    let (env, _h, c) = setup(Kind::GcsDrive, "outage");
    let st = &env.drive().state;

    st.rate_limit_403.store(2, Ordering::SeqCst);
    assert_eq!(c.put_chunk(b"through rate limits").1.status, 200);

    st.fail_503.store(1000, Ordering::SeqCst);
    let r = c.put_chunk(b"during outage").1;
    assert_eq!((r.status, r.retry_after.as_deref()), (503, Some("1")));
    assert_eq!(c.get_chunk(&cid_of(b"through rate limits")).status, 503);
    st.fail_503.store(0, Ordering::SeqCst);
    assert_eq!(c.put_chunk(b"during outage").1.status, 200);
    assert_eq!(c.get_chunk(&cid_of(b"during outage")).body, b"during outage");

    st.quota_full.store(true, Ordering::SeqCst);
    assert_eq!(c.put_chunk(b"drive full").1.status, 507);
    st.quota_full.store(false, Ordering::SeqCst);
    assert_eq!(c.put_chunk(b"drive full").1.status, 200);
    assert_eq!(env.chunk_count(&c.vid), 3);
}

#[test]
fn access_token_refresh() {
    let (env, _h, c) = setup(Kind::GcsDrive, "tok");
    assert_eq!(c.put_chunk(b"one").1.status, 200);
    let st = &env.drive().state;
    assert_eq!(st.refreshes.load(Ordering::SeqCst), 1, "one token for many calls");
    env.drive().revoke_access();
    assert_eq!(c.get_chunk(&cid_of(b"one")).body, b"one", "401 → new token → retry");
    assert_eq!(st.refreshes.load(Ordering::SeqCst), 2);
}

#[test]
fn rejected_refresh_token_is_503_not_a_crash() {
    let env = Env::new(Kind::GcsDrive);
    let h = env.start_with(|cfg| {
        if let StoreKind::Gcs(g) = &mut cfg.store {
            g.drive.as_mut().unwrap().refresh_token = Some("revoked".into());
        }
    });
    let c = Client::new(h.addr(), "badtok");
    assert_eq!(c.create().status, 201, "the bucket side still works");
    assert_eq!(c.put_chunk(b"x").1.status, 503);
}

#[test]
fn missing_or_wrong_folder_refuses_to_start() {
    let env = Env::new(Kind::GcsDrive);
    let mut cfg = env.config(Some(TOKEN));
    if let StoreKind::Gcs(g) = &mut cfg.store {
        g.drive.as_mut().unwrap().folder = "noSuchFolder".into();
    }
    let Err(e) = vaultage_server::router(cfg) else { panic!("must refuse") };
    assert!(e.to_string().contains("not found"), "{e}");
}

#[test]
fn bucket_chunks_from_before_stay_readable_and_collectable() {
    let env = Env::new(Kind::GcsDrive);
    let h = env.start_with(drive_off);
    let c = Client::new(h.addr(), "mixed");
    assert_eq!(c.create().status, 201);
    let old = b"stored in the bucket".to_vec();
    assert_eq!(c.put_chunk(&old).1.status, 200);
    let e = id_hex("e", 16);
    assert_eq!(c.commit(&e, 0, 1, b"r1", &[&cid_of(&old)]).status, 200);
    h.shutdown();

    let h = env.start();
    let c = c.at(h.addr());
    assert_eq!(c.get_chunk(&cid_of(&old)).body, old);
    let new = b"stored in Drive".to_vec();
    assert_eq!(c.put_chunk(&new).1.status, 200);
    assert_eq!(env.drive().blobs().len(), 1);
    let u = c.usage();
    assert_eq!(u["bytes"].as_u64(), Some((old.len() + new.len()) as u64));
    assert_eq!(c.commit(&e, 1, 2, b"r2", &[&cid_of(&new)]).status, 200);
    let r = c.prune(&[(&e, 2)]);
    assert_eq!(r.status, 200);
    assert_eq!(r.json()["bytes"].as_u64(), Some(old.len() as u64));
    assert_eq!(c.get_chunk(&cid_of(&old)).status, 404);
    assert_eq!(c.get_chunk(&cid_of(&new)).body, new);
}

#[test]
fn gc_deletes_drive_files_and_stale_ids_recover() {
    let env = Env::new(Kind::GcsDrive);
    let (ha, hb) = (env.start(), env.start());
    let c = Client::new(ha.addr(), "stale");
    assert_eq!(c.create().status, 201);
    let x = b"collected then re-uploaded".to_vec();
    assert_eq!(c.put_chunk(&x).1.status, 200);
    assert_eq!(c.get_chunk(&cid_of(&x)).body, x); // A caches the file id
    let cb = c.at(hb.addr());
    assert_eq!(cb.prune(&[]).status, 200); // unreferenced, grace 0: collected
    assert!(env.drive().blobs().is_empty(), "Drive file deleted with its pointer");
    assert_eq!(c.get_chunk(&cid_of(&x)).status, 404);
    assert_eq!(cb.put_chunk(&x).1.status, 200); // new file id
    assert_eq!(c.get_chunk(&cid_of(&x)).body, x, "A re-reads the pointer");
}

#[test]
fn drive_file_deleted_out_of_band_is_an_error_not_a_miss() {
    let (env, _h, c) = setup(Kind::GcsDrive, "oob");
    assert_eq!(c.put_chunk(b"precious").1.status, 200);
    let id = env.pointed_files(&c.vid).remove(0);
    env.drive().state.files.lock().unwrap().remove(&id);
    let r = c.get_chunk(&cid_of(b"precious"));
    assert_eq!(r.status, 500);
}

#[test]
fn drive_holds_no_plaintext_names() {
    let (env, _h, c) = setup(Kind::GcsDrive, "names");
    assert_eq!(c.put_chunk(b"x").1.status, 200);
    let files = env.drive().state.files.lock().unwrap();
    for f in files.values() {
        let n = &f.name;
        let ok = n == "Vaultage" || n == &c.vid || (n.len() == 1 && n.chars().all(|c| c.is_ascii_hexdigit())) || (n.len() == 64 && n.chars().all(|c| c.is_ascii_hexdigit()));
        assert!(ok, "unexpected Drive name {n:?}");
    }
}

// ---- gdrive-login ----

fn param(url: &str, key: &str) -> String {
    let q = url.split_once('?').unwrap().1;
    q.split('&')
        .find_map(|kv| kv.strip_prefix(&format!("{key}=")))
        .map(decode)
        .unwrap_or_else(|| panic!("no {key} in {url}"))
}

fn opts(d: &FakeDrive) -> Opts {
    Opts {
        client_id: fake_drive::CLIENT_ID.into(),
        client_secret: fake_drive::CLIENT_SECRET.into(),
        folder_name: Some("My Vaultage".into()),
        auth_url: Some(format!("{}/auth", d.endpoint())),
        token_url: Some(format!("{}/token", d.endpoint())),
        drive_endpoint: Some(d.endpoint()),
    }
}

/// Plays the browser: follows the consent URL's redirect with `code` and `state`.
fn browser(url: &str, state: Option<&str>, code: &str) -> std::thread::JoinHandle<u16> {
    assert_eq!(param(url, "scope"), "https://www.googleapis.com/auth/drive.file");
    assert_eq!(param(url, "access_type"), "offline");
    let redirect = param(url, "redirect_uri");
    let state = state.map_or_else(|| param(url, "state"), str::to_owned);
    let target = format!("{redirect}/favicon.ico");
    let cb = format!("{redirect}/?state={state}&code={}", code.replace('/', "%2F"));
    std::thread::spawn(move || {
        assert_eq!(send(&agent(), "GET", &target, &[], b"").status, 404);
        send(&agent(), "GET", &cb, &[], b"").status
    })
}

#[test]
fn login_creates_the_folder_and_returns_a_refresh_token() {
    let d = FakeDrive::start();
    let mut t = None;
    let out = login(&opts(&d), |url| t = Some(browser(url, None, GOOD_CODE))).unwrap();
    assert_eq!(t.unwrap().join().unwrap(), 200);
    assert_eq!(out.refresh_token, fake_drive::REFRESH);
    let files = d.state.files.lock().unwrap();
    let f = &files[out.folder_id.as_ref().unwrap()];
    assert_eq!((f.name.as_str(), f.mime.as_str(), f.parent.as_deref()), ("My Vaultage", fake_drive::FOLDER, None));
    drop(files);

    // New token for the existing folder: nothing created.
    let mut t = None;
    let o2 = Opts { folder_name: None, ..opts(&d) };
    let out = login(&o2, |url| t = Some(browser(url, None, GOOD_CODE))).unwrap();
    assert_eq!(t.unwrap().join().unwrap(), 200);
    assert_eq!((out.refresh_token.as_str(), out.folder_id), (fake_drive::REFRESH, None));
    assert_eq!(d.folders(), 2);
}

#[test]
fn login_refuses_a_forged_redirect_and_a_bad_code() {
    let d = FakeDrive::start();
    let mut t = None;
    let e = login(&opts(&d), |url| t = Some(browser(url, Some("forged"), GOOD_CODE))).err().unwrap();
    assert_eq!(t.unwrap().join().unwrap(), 400);
    assert!(e.contains("state mismatch"), "{e}");

    let mut t = None;
    let e = login(&opts(&d), |url| t = Some(browser(url, None, "4/wrong"))).err().unwrap();
    assert_eq!(t.unwrap().join().unwrap(), 200);
    assert!(e.contains("invalid_grant"), "{e}");
    assert_eq!(d.folders(), 1, "only the fake's own root folder");
}
