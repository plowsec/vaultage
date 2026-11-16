//! Prune/GC, rekey, quota, usage, rate limits — both backends.

mod common;

use std::time::Duration;

use vaultage_core::hexutil;
use common::*;
use ed25519_dalek::SigningKey;
use serde_json::json;

both!(
    prune_placeholders_and_gc,
    prune_validation,
    gc_grace_period,
    commit_vs_gc_race,
    rekey,
    quota,
    usage_counts,
    rate_limit_header,
    rate_limit_auth_failures,
    rate_limit_enroll,
);

fn blob(r: &serde_json::Value) -> &str {
    r["blob"].as_str().unwrap()
}

fn prune_placeholders_and_gc(k: Kind) {
    let (env, h, c) = setup(k, "prune");
    let (a, b) = (id_hex("a", 16), id_hex("b", 16));
    let (only1, _) = c.put_chunk(b"CHUNK-only-in-a1");
    let (only2, _) = c.put_chunk(b"CHUNK-only-in-a2");
    let (shared, _) = c.put_chunk(b"CHUNK-shared-a1-a4");
    let (cb, _) = c.put_chunk(b"CHUNK-of-b1");
    assert_eq!(c.commit(&a, 0, 1, b"SECRET-a1-blob", &[&only1, &shared]).status, 200); // seq 1
    assert_eq!(c.commit(&b, 0, 1, b"SECRET-b1-blob", &[&cb]).status, 200); // seq 2
    assert_eq!(c.commit(&a, 1, 2, b"SECRET-a2-blob", &[&only2]).status, 200); // seq 3
    assert_eq!(c.commit(&a, 2, 3, b"SECRET-a3-blob", &[]).status, 200); // seq 4
    assert_eq!(c.commit(&a, 3, 4, b"SECRET-a4-blob", &[&shared]).status, 200); // seq 5

    let r = c.prune(&[(&a, 3)]);
    assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
    let want_bytes = (b"CHUNK-only-in-a1".len() + b"CHUNK-only-in-a2".len()) as u64;
    assert_eq!(r.json(), json!({"records": 2, "chunks": 2, "bytes": want_bytes}));

    let (head, recs) = c.full_log();
    assert_eq!(head, 5);
    let blobs: Vec<&str> = recs.iter().map(blob).collect();
    assert_eq!(
        blobs,
        [
            "",
            &hexutil::encode(b"SECRET-b1-blob"),
            "",
            &hexutil::encode(b"SECRET-a3-blob"),
            &hexutil::encode(b"SECRET-a4-blob"),
        ]
    );
    assert_eq!(recs[0], json!({"seq": 1, "entry": a, "rev": 1, "blob": ""}));
    assert_eq!(recs[2], json!({"seq": 3, "entry": a, "rev": 2, "blob": ""}));

    // Physically gone from storage.
    let all = env.all_stored();
    for gone in [
        &b"SECRET-a1-blob"[..],
        b"SECRET-a2-blob",
        b"CHUNK-only-in-a1",
        b"CHUNK-only-in-a2",
    ] {
        assert!(!contains(&all, gone), "{} still stored", String::from_utf8_lossy(gone));
    }
    for kept in [
        &b"SECRET-a3-blob"[..],
        b"SECRET-b1-blob",
        b"CHUNK-shared-a1-a4",
        b"CHUNK-of-b1",
    ] {
        assert!(contains(&all, kept), "{} lost", String::from_utf8_lossy(kept));
    }
    assert_eq!(c.get_chunk(&only1).status, 404);
    assert_eq!(c.get_chunk(&shared).status, 200);
    assert_eq!(c.get_chunk(&cb).status, 200);

    // Idempotent; placeholders don't satisfy the commit idempotency rule.
    assert_eq!(
        c.prune(&[(&a, 3)]).json(),
        json!({"records": 0, "chunks": 0, "bytes": 0})
    );
    let r = c.commit(&a, 0, 1, b"SECRET-a1-blob", &[]);
    assert_eq!((r.status, r.json()), (409, json!({"current_rev": 4})));

    // Restart: same log, refs remembered (GC still spares referenced chunks).
    let before = c.full_log();
    h.shutdown();
    let h = env.start();
    let c = c.at(h.addr());
    assert_eq!(c.full_log(), before);
    assert_eq!(
        c.prune(&[(&a, 3)]).json(),
        json!({"records": 0, "chunks": 0, "bytes": 0})
    );
    assert_eq!(c.get_chunk(&shared).status, 200);
    assert_eq!(c.get_chunk(&cb).status, 200);
    assert_eq!(
        c.commit(&a, 4, 5, b"SECRET-a5-blob", &[&shared]).json(),
        json!({"seq": 6})
    );

    // Prune up to the newest rev: everything but a5; `shared` still referenced by a5.
    let r = c.prune(&[(&a, 5), (&b, 1)]).json();
    assert_eq!(r["records"], 2);
    assert_eq!(r["chunks"], 0);
    assert_eq!(c.get_chunk(&shared).status, 200);
    // Freshly uploaded, never committed chunk: grace 0 here, so it's collected.
    let (orphan, _) = c.put_chunk(b"orphan");
    assert_eq!(c.prune(&[]).json()["chunks"], 1);
    assert_eq!(c.get_chunk(&orphan).status, 404);
    // Commit referencing a collected chunk → 422.
    let r = c.commit(&b, 1, 2, b"b2", &[&only1]);
    assert_eq!((r.status, r.json()), (422, json!({"missing": [only1]})));
}

fn prune_validation(k: Kind) {
    let (_env, _h, c) = setup(k, "prunev");
    let a = id_hex("a", 16);
    for rev in 1..=3 {
        assert_eq!(
            c.commit(&a, rev - 1, rev, format!("r{rev}").as_bytes(), &[]).status,
            200
        );
    }
    let r = c.prune(&[(&a, 4)]);
    assert_eq!(r.status, 400, "newest rev is never pruned");
    assert!(r.json()["error"].is_string());
    assert_eq!(
        c.full_log().1.iter().filter(|r| blob(r).is_empty()).count(),
        0,
        "nothing changed"
    );
    // Unknown entry is skipped.
    assert_eq!(c.prune(&[(&id_hex("ghost", 16), 9)]).json()["records"], 0);
    // Mixed: one bad item rejects the whole request.
    assert_eq!(c.prune(&[(&a, 2), (&a, 99)]).status, 400);
    for bad in [
        json!({"items": [{"entry": "XYZ", "below": 1}]}),
        json!({"items": [{"entry": a.to_uppercase(), "below": 1}]}),
        json!({"items": [{"entry": a, "below": -1}]}),
        json!({"nope": 1}),
    ] {
        let r = c.signed("POST", "/prune", &serde_json::to_vec(&bad).unwrap());
        assert_eq!(r.status, 400, "{bad}");
    }
    assert_eq!(c.signed("POST", "/prune", b"{").status, 400);
    // below 0/1: nothing to do.
    assert_eq!(c.prune(&[(&a, 1)]).json()["records"], 0);
    assert_eq!(c.prune(&[(&a, 3)]).json()["records"], 2);
    let (_, recs) = c.full_log();
    assert_eq!(recs[2]["blob"], hexutil::encode(b"r3"));
}

fn gc_grace_period(k: Kind) {
    let env = Env::new(k);
    let h = env.start_with(|c| c.gc_grace_secs = 3600);
    let c = Client::new(h.addr(), "grace");
    assert_eq!(c.create().status, 201);
    let a = id_hex("a", 16);
    let (x, _) = c.put_chunk(b"x-referenced-by-a1");
    let (y, _) = c.put_chunk(b"y-uploaded-never-committed");
    let (z, _) = c.put_chunk(b"z-reuploaded-later");
    assert_eq!(c.commit(&a, 0, 1, b"a1", &[&x, &z]).status, 200);
    assert_eq!(c.commit(&a, 1, 2, b"a2", &[]).status, 200);
    // x, y, z unreferenced after this, but young.
    let r = c.prune(&[(&a, 2)]).json();
    assert_eq!((r["records"].as_u64(), r["chunks"].as_u64()), (Some(1), Some(0)));
    for id in [&x, &y, &z] {
        assert!(env.chunk_exists(&c.vid, id));
    }
    // Age them; re-PUT of z makes it young again.
    env.age_chunks(&c.vid, 7200);
    assert_eq!(c.put_chunk(b"z-reuploaded-later").1.status, 200);
    let r = c.prune(&[]).json();
    assert_eq!((r["records"].as_u64(), r["chunks"].as_u64()), (Some(0), Some(2)));
    assert!(!env.chunk_exists(&c.vid, &x));
    assert!(!env.chunk_exists(&c.vid, &y));
    assert!(env.chunk_exists(&c.vid, &z));
}

/// A commit referencing a chunk that a concurrent prune makes unreferenced (grace 0) must
/// either fail with 422 or leave the chunk in place.
fn commit_vs_gc_race(k: Kind) {
    let (_env, h, c) = setup(k, "gcrace");
    let iters = if k == Kind::Gcs { 60 } else { 200 };
    // Sweep the commit's start across the (previous) prune's duration.
    let t0 = std::time::Instant::now();
    c.prune(&[]);
    let mut span = t0.elapsed();
    let (mut ok, mut missing) = (0, 0);
    for i in 0..iters {
        let (e, f) = (id_hex(&format!("e{i}"), 16), id_hex(&format!("f{i}"), 16));
        let (s, _) = c.put_chunk(format!("shared-{i}").as_bytes());
        assert_eq!(c.commit(&e, 0, 1, b"e1", &[&s]).status, 200);
        assert_eq!(c.commit(&e, 1, 2, b"e2", &[]).status, 200);
        let delay = span.mul_f64((i % 12) as f64 / 8.0);
        let barrier = std::sync::Barrier::new(2);
        let (pr, cr) = std::thread::scope(|sc| {
            let p = sc.spawn(|| {
                let c = c.at(h.addr());
                barrier.wait();
                let t = std::time::Instant::now();
                (c.prune(&[(&e, 2)]).status, t.elapsed())
            });
            let q = sc.spawn(|| {
                let c = c.at(h.addr());
                barrier.wait();
                std::thread::sleep(delay);
                c.commit(&f, 0, 1, b"f1", &[&s])
            });
            (p.join().unwrap(), q.join().unwrap())
        });
        assert_eq!(pr.0, 200);
        span = pr.1;
        match cr.status {
            200 => {
                ok += 1;
                assert_eq!(
                    c.get_chunk(&s).status,
                    200,
                    "iter {i}: committed record references a deleted chunk"
                );
                // And it stays: a later GC sees the reference.
                c.prune(&[]);
                assert_eq!(
                    c.get_chunk(&s).status,
                    200,
                    "iter {i}: later GC deleted a referenced chunk"
                );
            }
            422 => {
                missing += 1;
                assert_eq!(c.get_chunk(&s).status, 404);
            }
            s => panic!("unexpected {s}"),
        }
    }
    eprintln!("commit_vs_gc_race({k:?}): {ok} commits won, {missing} got 422 (prune ~{span:?})");
}

fn rekey(k: Kind) {
    let (env, h, c) = setup(k, "rekey");
    let new = SigningKey::from_bytes(&[9u8; 32]);
    let cn = c.with_key(new.clone());
    assert_eq!(cn.log("").status, 401);

    // Validation.
    let bad = |body: serde_json::Value| c.signed("POST", "/rekey", &serde_json::to_vec(&body).unwrap()).status;
    assert_eq!(bad(json!({"auth_pub": "zz", "header": {"version": 2}})), 400);
    assert_eq!(
        bad(json!({"auth_pub": hexutil::encode(&[1u8; 32]), "header": {"no": 1}})),
        400
    );
    assert_eq!(c.rekey(&new, 1).status, 409, "version must increase");
    assert_eq!(cn.rekey(&new, 2).status, 401, "signed by a non-current key");

    assert_eq!(c.rekey(&new, 2).status, 200);
    assert_eq!(c.log("").status, 401, "old key");
    assert_eq!(c.signed("PUT", "/header", br#"{"version":9}"#).status, 401);
    assert_eq!(cn.log("").status, 200, "new key");
    assert_eq!(c.get_header().json(), json!({"version": 2, "slots": ["rekeyed"]}));
    assert_eq!(cn.rekey(&new, 2).status, 409);

    h.shutdown();
    let h = env.start();
    let (c, cn) = (c.at(h.addr()), cn.at(h.addr()));
    assert_eq!(c.log("").status, 401);
    assert_eq!(cn.log("").status, 200);
    assert_eq!(c.get_header().json()["version"], 2);
    // Rotate back.
    assert_eq!(cn.rekey(&c.key, 3).status, 200);
    assert_eq!(c.log("").status, 200);
    assert_eq!(cn.log("").status, 401);
}

fn quota(k: Kind) {
    let env = Env::new(k);
    let h = env.start_with(|c| c.vault_quota_bytes = Some(100));
    let c = Client::new(h.addr(), "quota");
    assert_eq!(c.create().status, 201);
    let a = id_hex("a", 16);
    let (c1, r) = c.put_chunk(&[1u8; 60]);
    assert_eq!(r.status, 200);
    let (c2, r) = c.put_chunk(&[2u8; 60]);
    assert_eq!(r.status, 507);
    assert!(r.json()["error"].is_string());
    assert_eq!(c.get_chunk(&c2).status, 404);
    assert_eq!(c.put_chunk(&[1u8; 60]).1.status, 200, "re-put of existing");
    assert_eq!(c.put_chunk(&[3u8; 40]).1.status, 200, "exactly at quota");
    assert_eq!(c.put_chunk(&[4u8; 1]).1.status, 507);
    let u = c.usage();
    assert_eq!((u["bytes"].as_u64(), u["quota"].as_u64()), (Some(100), Some(100)));

    assert_eq!(c.commit(&a, 0, 1, b"a1", &[&c1]).status, 200);
    assert_eq!(c.commit(&a, 1, 2, b"a2", &[]).status, 200);
    h.shutdown();

    // Lower quota: existing chunks still re-PUT fine; pruning frees space.
    let h = env.start_with(|c| c.vault_quota_bytes = Some(70));
    let c = c.at(h.addr());
    assert_eq!(c.put_chunk(&[1u8; 60]).1.status, 200);
    assert_eq!(c.put_chunk(&[2u8; 60]).1.status, 507);
    // c1 (60) freed, and the uncommitted 40-byte chunk too (grace 0).
    assert_eq!(
        c.prune(&[(&a, 2)]).json(),
        json!({"records": 1, "chunks": 2, "bytes": 100})
    );
    assert_eq!(c.put_chunk(&[2u8; 60]).1.status, 200);
    assert_eq!(c.usage()["bytes"], 60);
}

fn usage_counts(k: Kind) {
    let (env, h, c) = setup(k, "usage");
    assert_eq!(c.usage(), json!({"bytes": 0, "chunks": 0, "records": 0, "quota": null}));
    let (x, _) = c.put_chunk(&[1u8; 10]);
    c.put_chunk(&[2u8; 20]);
    c.put_chunk(&[2u8; 20]);
    let a = id_hex("a", 16);
    assert_eq!(c.commit(&a, 0, 1, b"1", &[&x]).status, 200);
    assert_eq!(c.commit(&a, 1, 2, b"2", &[&x]).status, 200);
    assert_eq!(c.commit(&a, 2, 3, b"3", &[]).status, 200);
    assert_eq!(
        c.usage(),
        json!({"bytes": 30, "chunks": 2, "records": 3, "quota": null})
    );
    assert_eq!(c.prune(&[(&a, 3)]).json()["chunks"], 2);
    let u = json!({"bytes": 0, "chunks": 0, "records": 3, "quota": null});
    assert_eq!(c.usage(), u, "placeholders still count as records");
    c.put_chunk(&[5u8; 7]);
    h.shutdown();
    let h = env.start();
    let c = c.at(h.addr());
    assert_eq!(c.usage(), json!({"bytes": 7, "chunks": 1, "records": 3, "quota": null}));
    assert_eq!(env.chunk_count(&c.vid), 1);
}

const WINDOW: u64 = 2;

fn rate_limit_header(k: Kind) {
    let env = Env::new(k);
    let h = env.start_with(|c| {
        c.rate_header_reads = 3;
        c.rate_window_secs = WINDOW;
    });
    let c = Client::new(h.addr(), "rlh");
    assert_eq!(c.create().status, 201);
    let other = Client::new(h.addr(), "rlh-other");
    assert_eq!(other.create().status, 201);
    for _ in 0..3 {
        assert_eq!(c.get_header().status, 200);
    }
    let r = c.get_header();
    assert_eq!(r.status, 429);
    let ra: u64 = r.retry_after.expect("Retry-After").parse().unwrap();
    assert!((1..=WINDOW).contains(&ra), "{ra}");
    assert_eq!(other.get_header().status, 200, "per vault id");
    assert_eq!(c.log("").status, 200, "signed routes unaffected");
    std::thread::sleep(Duration::from_millis(WINDOW * 1000 + 200));
    assert_eq!(c.get_header().status, 200, "window over");
}

fn rate_limit_auth_failures(k: Kind) {
    let env = Env::new(k);
    let h = env.start_with(|c| {
        c.rate_auth_failures = 3;
        c.rate_window_secs = WINDOW;
    });
    let c = Client::new(h.addr(), "rla");
    assert_eq!(c.create().status, 201);
    let other = Client::new(h.addr(), "rla-other");
    assert_eq!(other.create().status, 201);
    let attacker = c.with_key(SigningKey::from_bytes(&[66u8; 32]));
    for _ in 0..3 {
        assert_eq!(attacker.log("").status, 401);
    }
    let r = attacker.log("");
    assert_eq!(r.status, 429);
    assert!(r.retry_after.is_some());
    assert_eq!(attacker.commit(&id_hex("e", 16), 0, 1, b"x", &[]).status, 429);
    // Valid signatures are never locked out.
    assert_eq!(c.log("").status, 200);
    assert_eq!(c.commit(&id_hex("e", 16), 0, 1, b"x", &[]).status, 200);
    // Other vaults unaffected.
    assert_eq!(other.with_key(SigningKey::from_bytes(&[66u8; 32])).log("").status, 401);
    assert_eq!(other.log("").status, 200);
    std::thread::sleep(Duration::from_millis(WINDOW * 1000 + 200));
    assert_eq!(attacker.log("").status, 401, "window over");
}

fn rate_limit_enroll(k: Kind) {
    let env = Env::new(k);
    let h = env.start_with(|c| {
        c.rate_enroll_failures = 2;
        c.rate_window_secs = WINDOW;
    });
    let c = Client::new(h.addr(), "rle");
    let url = format!("{}/v1/vaults", c.base);
    let bad = || {
        send(
            &c.agent,
            "POST",
            &url,
            &[("X-Coffer-Enroll", "wrong".into())],
            &c.create_req(1),
        )
    };
    assert_eq!(bad().status, 403);
    assert_eq!(send(&c.agent, "POST", &url, &[], &c.create_req(1)).status, 403);
    let r = bad();
    assert_eq!(r.status, 429);
    assert!(r.retry_after.is_some());
    // The right token still works.
    assert_eq!(c.create().status, 201);
    std::thread::sleep(Duration::from_millis(WINDOW * 1000 + 200));
    assert_eq!(bad().status, 403, "window over");
}
