//! GCS backend only (against the in-process fake): multiple instances, lost replies, outages.

mod common;

use std::sync::atomic::Ordering;
use std::time::Duration;

use common::*;
use ed25519_dalek::SigningKey;
use serde_json::json;

fn two(env: &Env, grace: u64) -> (vaultage_server::ServerHandle, vaultage_server::ServerHandle) {
    let a = env.start_with(|c| c.gc_grace_secs = grace);
    let b = env.start_with(|c| c.gc_grace_secs = grace);
    (a, b)
}

fn assert_gapless_chains(recs: &[serde_json::Value]) {
    let mut revs = std::collections::HashMap::new();
    for (i, r) in recs.iter().enumerate() {
        assert_eq!(r["seq"].as_u64(), Some(i as u64 + 1), "gapless seq");
        let e = r["entry"].as_str().unwrap().to_owned();
        let prev = revs.insert(e, r["rev"].as_u64().unwrap()).unwrap_or(0);
        assert_eq!(r["rev"].as_u64(), Some(prev + 1), "rev chain at seq {}", i + 1);
    }
}

#[test]
fn two_instances_race_one_entry() {
    let env = Env::new(Kind::Gcs);
    let (ha, hb) = two(&env, 0);
    let c = Client::new(ha.addr(), "race2");
    assert_eq!(c.create().status, 201);
    let e = id_hex("contended", 16);
    let n = 20u64;
    let wins: Vec<u64> = std::thread::scope(|s| {
        [ha.addr(), hb.addr()]
            .into_iter()
            .enumerate()
            .map(|(t, addr)| {
                let c = c.at(addr);
                let e = e.clone();
                s.spawn(move || {
                    let (mut base, mut wins, mut attempt) = (0u64, 0u64, 0u64);
                    while wins < n {
                        attempt += 1;
                        let r = c.commit(&e, base, base + 1, format!("i{t}-a{attempt}").as_bytes(), &[]);
                        match r.status {
                            200 => {
                                wins += 1;
                                base += 1;
                            }
                            409 => base = r.json()["current_rev"].as_u64().unwrap(),
                            s => panic!("unexpected {s}"),
                        }
                    }
                    wins
                })
            })
            .collect::<Vec<_>>()
            .into_iter()
            .map(|h| h.join().unwrap())
            .collect()
    });
    assert_eq!(wins, vec![n, n]);
    for addr in [ha.addr(), hb.addr()] {
        let (head, recs) = c.at(addr).full_log();
        assert_eq!((head, recs.len() as u64), (2 * n, 2 * n));
        assert_gapless_chains(&recs);
    }
    // Each instance sees the other's commits.
    let r = c.at(hb.addr()).commit(&e, 2 * n - 1, 2 * n, b"late", &[]);
    assert_eq!((r.status, r.json()), (409, json!({"current_rev": 2 * n})));
}

#[test]
fn two_instances_race_distinct_entries() {
    let env = Env::new(Kind::Gcs);
    let (ha, hb) = two(&env, 0);
    let c = Client::new(ha.addr(), "race3");
    assert_eq!(c.create().status, 201);
    let n = 25u64;
    std::thread::scope(|s| {
        for (t, addr) in [ha.addr(), hb.addr(), ha.addr(), hb.addr()].into_iter().enumerate() {
            let c = c.at(addr);
            s.spawn(move || {
                let e = id_hex(&format!("own-{t}"), 16);
                let mut rev = 0;
                while rev < n {
                    let r = c.commit(&e, rev, rev + 1, format!("t{t}r{rev}").as_bytes(), &[]);
                    match r.status {
                        200 => rev += 1,
                        503 => {} // contention: client retries
                        s => panic!("unexpected {s}: {}", String::from_utf8_lossy(&r.body)),
                    }
                }
            });
        }
    });
    let (head, recs) = c.at(hb.addr()).full_log();
    assert_eq!(head, 4 * n);
    assert_gapless_chains(&recs);
}

#[test]
fn lost_replies_are_recognized() {
    let env = Env::new(Kind::Gcs);
    let h = env.start();
    let st = &env.fake().state;
    let c = Client::new(h.addr(), "lost");
    let drop_next = || st.drop_after_apply.store(1, Ordering::SeqCst);

    drop_next();
    assert_eq!(c.create().status, 201, "create applied, reply lost");
    assert_eq!(c.create().status, 409);

    let e = id_hex("e", 16);
    drop_next();
    let (cid, r) = c.put_chunk(b"chunk");
    assert_eq!(r.status, 200);
    drop_next();
    assert_eq!(c.commit(&e, 0, 1, b"one", &[&cid]).json(), json!({"seq": 1}));
    assert_eq!(c.log("").json()["head"], 1, "no duplicate append");
    drop_next();
    assert_eq!(c.commit(&e, 1, 2, b"two", &[]).json(), json!({"seq": 2}));

    drop_next();
    assert_eq!(c.signed("PUT", "/header", br#"{"version":2}"#).status, 200);
    assert_eq!(c.get_header().json(), json!({"version": 2}));

    drop_next();
    let r = c.prune(&[(&e, 2)]);
    assert_eq!(r.json()["records"], 1);
    drop_next(); // the chunk delete
    assert_eq!(c.prune(&[]).status, 200);
    assert_eq!(c.get_chunk(&cid).status, 404);

    let new = SigningKey::from_bytes(&[5u8; 32]);
    drop_next();
    assert_eq!(c.rekey(&new, 3).status, 200);
    assert_eq!(c.with_key(new).log("").status, 200);
    assert_eq!(c.log("").status, 401);
    assert_eq!(
        st.drop_after_apply.load(Ordering::SeqCst),
        0,
        "every injected fault was hit"
    );
}

#[test]
fn outage_is_503_and_recovers() {
    let env = Env::new(Kind::Gcs);
    let h = env.start();
    let st = &env.fake().state;
    let c = Client::new(h.addr(), "outage");
    assert_eq!(c.create().status, 201);
    let e = id_hex("e", 16);

    // Short blip: retried inside the server.
    st.fail_503.store(2, Ordering::SeqCst);
    assert_eq!(c.commit(&e, 0, 1, b"one", &[]).status, 200);

    st.fail_503.store(1000, Ordering::SeqCst);
    let r = c.commit(&e, 1, 2, b"two", &[]);
    assert_eq!(r.status, 503);
    assert!(r.retry_after.is_some());
    assert_eq!(c.put_chunk(b"x").1.status, 503);
    assert_eq!(c.prune(&[]).status, 503);
    st.fail_503.store(0, Ordering::SeqCst);

    assert_eq!(c.commit(&e, 1, 2, b"two", &[]).json(), json!({"seq": 2}));
    let (head, recs) = c.full_log();
    assert_eq!(head, 2);
    assert_gapless_chains(&recs);
}

#[test]
fn rekey_seen_by_other_instance() {
    let env = Env::new(Kind::Gcs);
    let (ha, hb) = two(&env, 0);
    let ca = Client::new(ha.addr(), "rk2");
    assert_eq!(ca.create().status, 201);
    let cb = ca.at(hb.addr());
    assert_eq!(cb.log("").status, 200); // B caches the key
    let new = SigningKey::from_bytes(&[8u8; 32]);
    assert_eq!(ca.rekey(&new, 2).status, 200);
    // New key works on B at once (stale cache is re-read on failure).
    assert_eq!(cb.with_key(new.clone()).log("").status, 200);
    // Old key: rejected everywhere once the cache TTL (2 s) has passed.
    std::thread::sleep(Duration::from_millis(2200));
    assert_eq!(cb.log("").status, 401);
    assert_eq!(ca.log("").status, 401);
    assert_eq!(cb.get_header().json()["version"], 2);
    // Concurrent rekeys from both instances with the same version: exactly one wins.
    let (k3, k4) = (SigningKey::from_bytes(&[3u8; 32]), SigningKey::from_bytes(&[4u8; 32]));
    let (a, b) = (ca.with_key(new.clone()), cb.with_key(new.clone()));
    let (ra, rb) = std::thread::scope(|s| {
        let x = s.spawn(|| a.rekey(&k3, 3).status);
        let y = s.spawn(|| b.rekey(&k4, 3).status);
        (x.join().unwrap(), y.join().unwrap())
    });
    let mut st = [ra, rb];
    st.sort();
    assert!(st == [200, 409] || st == [200, 401], "{st:?}");
    let winner = if ra == 200 { k3 } else { k4 };
    std::thread::sleep(Duration::from_millis(2200));
    assert_eq!(cb.with_key(winner.clone()).log("").status, 200);
    assert_eq!(ca.with_key(winner).log("").status, 200);
}

#[test]
fn prune_on_one_instance_seen_by_other() {
    let env = Env::new(Kind::Gcs);
    let (ha, hb) = two(&env, 0);
    let ca = Client::new(ha.addr(), "pr2");
    assert_eq!(ca.create().status, 201);
    let cb = ca.at(hb.addr());
    let e = id_hex("e", 16);
    let (x, _) = ca.put_chunk(b"x-data");
    assert_eq!(ca.commit(&e, 0, 1, b"SECRET-one", &[&x]).status, 200);
    assert_eq!(cb.commit(&e, 1, 2, b"two", &[]).status, 200);
    assert_eq!(cb.full_log().1[0]["blob"], vaultage_core::hexutil::encode(b"SECRET-one"));
    assert_eq!(
        ca.prune(&[(&e, 2)]).json(),
        json!({"records": 1, "chunks": 1, "bytes": 6})
    );
    assert_eq!(cb.full_log().1[0]["blob"], "");
    assert!(!contains(&env.all_stored(), b"SECRET-one"));
    let r = cb.commit(&id_hex("f", 16), 0, 1, b"f", &[&x]);
    assert_eq!((r.status, r.json()), (422, json!({"missing": [x]})));
    assert_eq!(cb.prune(&[(&e, 2)]).json()["records"], 0);
}

/// Cross-instance commit vs GC with a grace period: no in-process lock is shared, so only
/// the protect/precondition protocol keeps referenced chunks alive.
#[test]
fn cross_instance_commit_vs_gc() {
    let env = Env::new(Kind::Gcs);
    let (ha, hb) = two(&env, 2);
    let ca = Client::new(ha.addr(), "xgc");
    assert_eq!(ca.create().status, 201);
    let cb = ca.at(hb.addr());
    let (mut won, mut missing) = (Vec::new(), 0);
    let mut span = Duration::from_millis(5);
    for i in 0..40 {
        let (e, f) = (id_hex(&format!("e{i}"), 16), id_hex(&format!("f{i}"), 16));
        let (s, _) = ca.put_chunk(format!("shared-{i}").as_bytes());
        assert_eq!(ca.commit(&e, 0, 1, b"e1", &[&s]).status, 200);
        assert_eq!(ca.commit(&e, 1, 2, b"e2", &[]).status, 200);
        env.age_chunks(&ca.vid, 10); // older than grace: collectable
        let delay = span.mul_f64((i % 12) as f64 / 8.0);
        let barrier = std::sync::Barrier::new(2);
        let (pr, cr) = std::thread::scope(|sc| {
            let p = sc.spawn(|| {
                barrier.wait();
                let t = std::time::Instant::now();
                (ca.prune(&[(&e, 2)]).status, t.elapsed())
            });
            let q = sc.spawn(|| {
                barrier.wait();
                std::thread::sleep(delay);
                cb.commit(&f, 0, 1, b"f1", &[&s])
            });
            (p.join().unwrap(), q.join().unwrap())
        });
        assert_eq!(pr.0, 200);
        span = pr.1;
        match cr.status {
            200 => {
                assert_eq!(
                    ca.get_chunk(&s).status,
                    200,
                    "iter {i}: committed record references a deleted chunk"
                );
                won.push(s);
            }
            422 => {
                missing += 1;
                assert_eq!(ca.get_chunk(&s).status, 404);
            }
            s => panic!("unexpected {s}"),
        }
    }
    eprintln!(
        "cross_instance_commit_vs_gc: {} commits won, {missing} got 422 (prune ~{span:?})",
        won.len()
    );
    // Later GCs on either instance (all chunks old) keep everything still referenced.
    env.age_chunks(&ca.vid, 10);
    assert_eq!(ca.prune(&[]).status, 200);
    assert_eq!(cb.prune(&[]).status, 200);
    for s in &won {
        assert_eq!(cb.get_chunk(s).status, 200);
    }
}

#[test]
fn corrupt_record_object_is_500() {
    let env = Env::new(Kind::Gcs);
    let h = env.start();
    let c = Client::new(h.addr(), "corrupt");
    assert_eq!(c.create().status, 201);
    let e = id_hex("e", 16);
    assert_eq!(c.commit(&e, 0, 1, b"blob", &[]).status, 200);
    let name = format!("{PREFIX}vaults/{}/log/{:020}", c.vid, 1);
    env.fake().with_obj(&name, |o| o.unwrap().data[10] ^= 1);
    assert_eq!(c.log("").status, 500);
}

/// Manual runs: `FAKE_GCS_SECS=60 cargo test -p vaultage-server --test gcs serve_fake -- --ignored --nocapture`,
/// then `STORAGE_EMULATOR_HOST=<printed addr> vaultaged --store gcs://test-bucket/pfx`.
#[test]
#[ignore]
fn serve_fake() {
    let f = FakeGcs::start();
    let secs = std::env::var("FAKE_GCS_SECS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(30);
    println!("fake gcs at {}", f.addr);
    std::thread::sleep(Duration::from_secs(secs));
    println!("objects: {:?}", f.names(""));
}
