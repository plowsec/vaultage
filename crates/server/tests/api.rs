//! HTTP API tests, run against both backends (FS and GCS-on-fake) unless noted.

mod common;

use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::PathBuf;
use std::time::Duration;

use vaultage_core::hexutil;
use vaultage_core::proto::{sign_request, ENROLL_HEADER, MAX_CHUNK_BODY};
use common::*;
use ed25519_dalek::SigningKey;
use serde_json::json;

both!(
    healthz,
    enrollment,
    signature_checks,
    chunks,
    commits,
    same_rev_different_blob_conflicts,
    log_pagination,
    header_cas,
    concurrent_commit_race,
    restart_preserves_state,
    path_traversal_rejected,
);

fn healthz(k: Kind) {
    let env = Env::new(k);
    let h = env.start_with(|c| c.enroll_token = None);
    let r = send(&agent(), "GET", &format!("http://{}/healthz", h.addr()), &[], b"");
    assert_eq!((r.status, r.body.as_slice()), (200, &b"ok"[..]));
}

fn enrollment(k: Kind) {
    let env = Env::new(k);
    // No token configured: always 403.
    let h = env.start_with(|c| c.enroll_token = None);
    let c = Client::new(h.addr(), "enroll");
    assert_eq!(c.create().status, 403);
    h.shutdown();

    let h = env.start();
    let c = c.at(h.addr());
    let url = format!("{}/v1/vaults", c.base);
    let body = c.create_req(1);
    assert_eq!(send(&c.agent, "POST", &url, &[], &body).status, 403);
    assert_eq!(
        send(&c.agent, "POST", &url, &[(ENROLL_HEADER, "wrong".into())], &body).status,
        403
    );
    assert_eq!(
        send(&c.agent, "POST", &url, &[(ENROLL_HEADER, format!("{TOKEN}x"))], &body).status,
        403
    );
    assert_eq!(
        send(&c.agent, "POST", &url, &[(ENROLL_HEADER, TOKEN.into())], &body).status,
        201
    );
    assert_eq!(c.create().status, 409, "duplicate vault");

    let tok = [(ENROLL_HEADER, TOKEN.to_string())];
    let pubhex = hexutil::encode(&c.key.verifying_key().to_bytes());
    for bad in [
        json!({"vault_id": "abc", "auth_pub": pubhex, "header": {"version": 1}}),
        json!({"vault_id": c.vid.to_uppercase(), "auth_pub": pubhex, "header": {"version": 1}}),
        json!({"vault_id": "../../../../../../tmp/xx", "auth_pub": pubhex, "header": {"version": 1}}),
        json!({"vault_id": id_hex("other", 16), "auth_pub": "zz", "header": {"version": 1}}),
        json!({"vault_id": id_hex("other", 16), "auth_pub": pubhex, "header": {"no": "version"}}),
    ] {
        let r = send(&c.agent, "POST", &url, &tok, &serde_json::to_vec(&bad).unwrap());
        assert_eq!(r.status, 400, "{bad}");
        assert!(r.json()["error"].is_string());
    }
    assert_eq!(send(&c.agent, "POST", &url, &tok, b"not json").status, 400);
}

fn signature_checks(k: Kind) {
    let (_env, h, c) = setup(k, "auth");
    assert_eq!(c.log("").status, 200);
    let pq = c.vpath("/log");
    let other = SigningKey::from_bytes(&[7u8; 32]);
    assert_eq!(c.signed_ts(&other, "GET", &pq, b"", now_ms()).status, 401, "wrong key");
    assert_eq!(
        c.signed_ts(&c.key, "GET", &pq, b"", now_ms() - 10 * 60 * 1000).status,
        401,
        "stale ts"
    );
    assert_eq!(
        c.signed_ts(&c.key, "GET", &pq, b"", now_ms() + 10 * 60 * 1000).status,
        401,
        "future ts"
    );
    // Signed for one query, sent with another.
    let auth = sign_request(&c.key, "GET", &format!("{pq}?after=0"), now_ms(), b"");
    let r = send(
        &c.agent,
        "GET",
        &format!("{}{pq}?after=1", c.base),
        &[("Authorization", auth)],
        b"",
    );
    assert_eq!(r.status, 401);
    // Signed for one body, sent with another.
    let auth = sign_request(&c.key, "POST", &c.vpath("/missing"), now_ms(), br#"{"ids":[]}"#);
    let r = send(
        &c.agent,
        "POST",
        &format!("{}{}", c.base, c.vpath("/missing")),
        &[("Authorization", auth)],
        br#"{"ids": []}"#,
    );
    assert_eq!(r.status, 401);
    let r = send(&c.agent, "GET", &format!("{}{pq}", c.base), &[], b"");
    assert_eq!(r.status, 401, "no auth header");
    assert_eq!(r.json()["error"], "bad signature");
    let r = send(
        &c.agent,
        "GET",
        &format!("{}{pq}", c.base),
        &[("Authorization", "Coffer ts=1,sig=zz".into())],
        b"",
    );
    assert_eq!(r.status, 401);
    // New routes are signed too.
    for (m, rest) in [("POST", "/prune"), ("POST", "/rekey"), ("GET", "/usage")] {
        let r = c.signed_ts(&other, m, &c.vpath(rest), b"{}", now_ms());
        assert_eq!(r.status, 401, "{rest}");
    }

    // Unknown vault: 404 before signature check.
    let ghost = Client {
        vid: id_hex("ghost", 16),
        ..c.at(h.addr())
    };
    assert_eq!(ghost.log("").status, 404);
    assert_eq!(ghost.get_header().status, 404);
}

fn chunks(k: Kind) {
    let (_env, h, c) = setup(k, "chunks");
    let data = b"ciphertext bytes".to_vec();
    let (cid, r) = c.put_chunk(&data);
    assert_eq!(r.status, 200);
    let (_, r) = c.put_chunk(&data);
    assert_eq!(r.status, 200, "idempotent re-put");
    let r = c.get_chunk(&cid);
    assert_eq!((r.status, &r.body), (200, &data));

    let absent = id_hex("absent", 32);
    assert_eq!(c.get_chunk(&absent).status, 404);
    let r = c.signed("PUT", &format!("/chunks/{absent}"), b"not matching");
    assert_eq!(r.status, 400, "hash mismatch");
    assert_eq!(c.get_chunk(&absent).status, 404, "mismatch not stored");

    // Unsigned put rejected.
    let r = send(
        &c.agent,
        "PUT",
        &format!(
            "{}{}",
            c.base,
            c.vpath(&format!("/chunks/{}", blake3::hash(b"x").to_hex()))
        ),
        &[],
        b"x",
    );
    assert_eq!(r.status, 401);

    // Max size accepted, one byte more rejected.
    let big = vec![0xabu8; MAX_CHUNK_BODY];
    assert_eq!(c.put_chunk(&big).1.status, 200);
    let big_cid = blake3::hash(&[0u8; 1]).to_hex();
    let status = raw_status(
        h.addr(),
        &format!(
            "PUT {} HTTP/1.1\r\nHost: x\r\nContent-Length: {}\r\nAuthorization: Coffer ts=0,sig=00\r\n\r\n",
            c.vpath(&format!("/chunks/{big_cid}")),
            MAX_CHUNK_BODY + 1
        ),
    );
    assert_eq!(status, 413, "oversize");
    // No Content-Length: limit enforced while streaming.
    let mut s = TcpStream::connect(h.addr()).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    let head = format!(
        "PUT {} HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n{:x}\r\n",
        c.vpath(&format!("/chunks/{big_cid}")),
        MAX_CHUNK_BODY + 1
    );
    let _ = s.write_all(head.as_bytes());
    let _ = s.write_all(&vec![0u8; MAX_CHUNK_BODY + 1]);
    let _ = s.write_all(b"\r\n0\r\n\r\n");
    let mut resp = [0u8; 12];
    s.read_exact(&mut resp).unwrap();
    assert_eq!(&resp[9..12], b"413", "oversize chunked");

    let ids = json!({"ids": [cid, absent, absent]});
    let r = c.signed("POST", "/missing", &serde_json::to_vec(&ids).unwrap());
    assert_eq!(r.status, 200);
    assert_eq!(r.json()["missing"], json!([absent]));
    let r = c.signed("POST", "/missing", br#"{"ids":["../meta.json"]}"#);
    assert_eq!(r.status, 400);
}

fn commits(k: Kind) {
    let (_env, _h, c) = setup(k, "commits");
    let e = id_hex("entry-a", 16);
    let (cid, _) = c.put_chunk(b"chunk-1");

    let r = c.commit(&e, 0, 1, b"blob-1", &[&cid]);
    assert_eq!(r.status, 200);
    assert_eq!(r.json()["seq"], 1);

    // Stale base.
    let r = c.commit(&e, 0, 1, b"blob-other", &[]);
    assert_eq!(r.status, 409);
    assert_eq!(r.json(), json!({"current_rev": 1}));

    // Identical retry: same seq, nothing appended.
    let r = c.commit(&e, 0, 1, b"blob-1", &[&cid]);
    assert_eq!((r.status, r.json()["seq"].as_u64()), (200, Some(1)));
    assert_eq!(c.log("").json()["head"], 1);

    let r = c.commit(&e, 1, 2, b"blob-2", &[]);
    assert_eq!((r.status, r.json()["seq"].as_u64()), (200, Some(2)));
    // Base far behind.
    let r = c.commit(&e, 0, 1, b"blob-1", &[]);
    assert_eq!((r.status, r.json()), (409, json!({"current_rev": 2})));
    // Base ahead.
    let r = c.commit(&e, 5, 6, b"x", &[]);
    assert_eq!((r.status, r.json()), (409, json!({"current_rev": 2})));

    // Missing refs.
    let m1 = id_hex("m1", 32);
    let r = c.commit(&e, 2, 3, b"blob-3", &[&cid, &m1, &m1]);
    assert_eq!(r.status, 422);
    assert_eq!(r.json(), json!({"missing": [m1]}));
    let (m1_real, _) = c.put_chunk(b"m1 data");
    let r = c.commit(&e, 2, 3, b"blob-3", &[&cid, &m1_real]);
    assert_eq!((r.status, r.json()["seq"].as_u64()), (200, Some(3)));

    // Validation.
    for (entry, base, rev, blob, refs) in [
        (e.as_str(), 3, 5, "aa", vec![]),
        ("short", 3, 4, "aa", vec![]),
        (e.as_str(), 3, 4, "", vec![]),
        (e.as_str(), 3, 4, "zz", vec![]),
        (e.as_str(), 3, 4, "aa", vec!["../../meta.json"]),
    ] {
        let body =
            serde_json::to_vec(&json!({"entry": entry, "base_rev": base, "rev": rev, "blob": blob, "refs": refs}))
                .unwrap();
        assert_eq!(c.signed("POST", "/commit", &body).status, 400, "{entry} {rev} {blob}");
    }
    let body =
        serde_json::to_vec(&json!({"entry": e, "base_rev": u64::MAX, "rev": 0, "blob": "aa", "refs": []})).unwrap();
    assert_eq!(c.signed("POST", "/commit", &body).status, 400);
    assert_eq!(c.signed("POST", "/commit", b"{").status, 400);

    let (head, recs) = c.full_log();
    assert_eq!(head, 3);
    assert_eq!(
        recs[2],
        json!({"seq": 3, "entry": e, "rev": 3, "blob": hexutil::encode(b"blob-3")})
    );
}

fn same_rev_different_blob_conflicts(k: Kind) {
    let (_env, _h, c) = setup(k, "samerev");
    let e = id_hex("e", 16);
    assert_eq!(c.commit(&e, 0, 1, b"mine", &[]).status, 200);
    let r = c.commit(&e, 0, 1, b"theirs", &[]);
    assert_eq!((r.status, r.json()), (409, json!({"current_rev": 1})));
}

fn log_pagination(k: Kind) {
    let (_env, _h, c) = setup(k, "log");
    let (a, b) = (id_hex("a", 16), id_hex("b", 16));
    for i in 0..7u64 {
        let (e, rev) = if i % 2 == 0 { (&a, i / 2 + 1) } else { (&b, i / 2 + 1) };
        assert_eq!(
            c.commit(e, rev - 1, rev, format!("blob{i}").as_bytes(), &[]).status,
            200
        );
    }
    let seqs = |q: &str| -> (u64, Vec<u64>) {
        let v = c.log(q).json();
        let s = v["records"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| r["seq"].as_u64().unwrap())
            .collect();
        (v["head"].as_u64().unwrap(), s)
    };
    assert_eq!(seqs(""), (7, vec![1, 2, 3, 4, 5, 6, 7]));
    assert_eq!(seqs("?after=0&limit=3"), (7, vec![1, 2, 3]));
    assert_eq!(seqs("?after=3&limit=3"), (7, vec![4, 5, 6]));
    assert_eq!(seqs("?limit=2&after=6"), (7, vec![7]));
    assert_eq!(seqs("?after=7"), (7, vec![]));
    assert_eq!(seqs("?after=100"), (7, vec![]));
    assert_eq!(seqs("?after=2&limit=5000"), (7, vec![3, 4, 5, 6, 7]));
    assert_eq!(c.log("?after=x").status, 400);
    assert_eq!(c.log("?limit=-1").status, 400);

    let v = c.log("?after=4&limit=1").json();
    assert_eq!(
        v["records"][0],
        json!({"seq": 5, "entry": a, "rev": 3, "blob": hexutil::encode(b"blob4")})
    );
}

fn header_cas(k: Kind) {
    let (_env, _h, c) = setup(k, "header");
    let r = c.get_header();
    assert_eq!(r.status, 200);
    assert_eq!(r.json(), json!({"version": 1, "slots": ["opaque"]}));

    let put = |v: serde_json::Value| c.signed("PUT", "/header", &serde_json::to_vec(&v).unwrap()).status;
    assert_eq!(put(json!({"version": 1, "x": 1})), 409);
    assert_eq!(put(json!({"version": 0})), 409);
    assert_eq!(put(json!({"x": 1})), 400);
    assert_eq!(put(json!({"version": "2"})), 400);
    assert_eq!(put(json!({"version": 2, "slots": ["new"]})), 200);
    assert_eq!(put(json!({"version": 2, "slots": ["again"]})), 409);
    let url = format!("{}{}", c.base, c.vpath("/header"));
    assert_eq!(send(&c.agent, "PUT", &url, &[], br#"{"version":9}"#).status, 401);
    assert_eq!(c.get_header().json(), json!({"version": 2, "slots": ["new"]}));
}

fn concurrent_commit_race(k: Kind) {
    let (_env, h, c) = setup(k, "race");
    let e = id_hex("contended", 16);
    let n = if k != Kind::Fs { 25 } else { 50 };
    let wins: Vec<u64> = std::thread::scope(|s| {
        let hs: Vec<_> = (0..2)
            .map(|t| {
                let c = c.at(h.addr());
                let e = e.clone();
                s.spawn(move || {
                    let (mut base, mut wins, mut attempt) = (0u64, 0u64, 0u64);
                    while wins < n {
                        attempt += 1;
                        let r = c.commit(&e, base, base + 1, format!("t{t}-a{attempt}").as_bytes(), &[]);
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
            .collect();
        hs.into_iter().map(|h| h.join().unwrap()).collect()
    });
    assert_eq!(wins, vec![n, n]);
    let (head, recs) = c.full_log();
    assert_eq!(head, 2 * n);
    assert_eq!(recs.len() as u64, 2 * n);
    for (i, r) in recs.iter().enumerate() {
        assert_eq!(r["seq"].as_u64(), Some(i as u64 + 1), "contiguous seq");
        assert_eq!(r["rev"].as_u64(), Some(i as u64 + 1), "one winner per rev");
        assert_eq!(r["entry"], e);
    }
    let r = c.commit(&e, 2 * n - 1, 2 * n, b"late", &[]);
    assert_eq!((r.status, r.json()), (409, json!({"current_rev": 2 * n})));
}

fn restart_preserves_state(k: Kind) {
    let env = Env::new(k);
    let h = env.start();
    let c = Client::new(h.addr(), "restart");
    assert_eq!(c.create().status, 201);
    let (cid, _) = c.put_chunk(b"persisted chunk");
    let (a, b) = (id_hex("a", 16), id_hex("b", 16));
    assert_eq!(c.commit(&a, 0, 1, b"a1", &[&cid]).status, 200);
    assert_eq!(c.commit(&a, 1, 2, b"a2", &[&cid]).status, 200);
    assert_eq!(c.commit(&b, 0, 1, b"b1", &[]).status, 200);
    assert_eq!(c.signed("PUT", "/header", br#"{"version":5}"#).status, 200);
    let before = c.full_log();
    h.shutdown();

    let h = env.start();
    let c = c.at(h.addr());
    assert_eq!(c.full_log(), before);
    assert_eq!(c.create().status, 409, "vault persists");
    let r = c.get_chunk(&cid);
    assert_eq!((r.status, r.body.as_slice()), (200, &b"persisted chunk"[..]));
    // Revs reloaded: stale base conflicts, idempotent retry returns original seq.
    assert_eq!(c.commit(&a, 1, 2, b"other", &[]).json(), json!({"current_rev": 2}));
    assert_eq!(c.commit(&a, 1, 2, b"a2", &[&cid]).json(), json!({"seq": 2}));
    assert_eq!(c.commit(&b, 1, 2, b"b2", &[]).json(), json!({"seq": 4}));
    assert_eq!(
        c.signed("PUT", "/header", br#"{"version":5}"#).status,
        409,
        "header version persisted"
    );
    assert_eq!(c.get_header().json(), json!({"version": 5}));
    drop(h); // Drop also stops the server.

    let h = env.start();
    assert_eq!(c.at(h.addr()).full_log().0, 4);
}

fn path_traversal_rejected(k: Kind) {
    let (env, h, c) = setup(k, "traversal");
    let cid = blake3::hash(b"x").to_hex().to_string();
    let bad_vids = [
        "..",
        "..%2F..%2F..%2Fetc",
        "%2e%2e",
        &c.vid.to_uppercase(),
        &format!("{}0", c.vid),
        "x",
    ];
    for vid in bad_vids {
        for (m, rest) in [
            ("GET", "/header"),
            ("GET", "/log"),
            ("POST", "/commit"),
            ("POST", "/prune"),
            ("GET", "/usage"),
            ("GET", &format!("/chunks/{cid}")),
        ] {
            let pq = format!("/v1/vaults/{vid}{rest}");
            let s = raw_status(
                h.addr(),
                &format!("{m} {pq} HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\n\r\n"),
            );
            assert!(s == 400 || s == 404, "{m} {pq} -> {s}");
        }
    }
    for cid in ["..%2F..%2Fmeta.json", "..", &cid.to_uppercase(), "%2e%2e%2fmeta.json"] {
        let pq = c.vpath(&format!("/chunks/{cid}"));
        let s = c.signed_ts(&c.key, "GET", &pq, b"", now_ms()).status;
        assert!(s == 400 || s == 404, "{pq} -> {s}");
        let s = raw_status(
            h.addr(),
            &format!("PUT {pq} HTTP/1.1\r\nHost: x\r\nContent-Length: 1\r\n\r\nx"),
        );
        assert!(s == 400 || s == 404, "{pq} -> {s}");
    }
    for p in [
        "/v1/vaults/../../etc/passwd",
        "/v1/vaults/%2e%2e/%2e%2e/meta.json",
        "/../vaults",
    ] {
        let s = raw_status(h.addr(), &format!("GET {p} HTTP/1.1\r\nHost: x\r\n\r\n"));
        assert!(s == 400 || s == 404, "{p} -> {s}");
    }
    // Only our vault exists.
    match k {
        Kind::Fs => {
            let names: Vec<_> = std::fs::read_dir(env.dir.path().join("vaults"))
                .unwrap()
                .map(|e| e.unwrap().file_name())
                .collect();
            assert_eq!(names, vec![std::ffi::OsString::from(&c.vid)]);
        }
        Kind::Gcs | Kind::GcsDrive => {
            let names = env.fake().names("");
            assert!(!names.is_empty());
            let ours = format!("{PREFIX}vaults/{}/", c.vid);
            assert!(names.iter().all(|n| n.starts_with(&ours)), "{names:?}");
        }
    }
}

// ---- FS only ----

fn log_file(env: &Env, c: &Client) -> PathBuf {
    env.vault_dir(&c.vid).join("log")
}

#[test]
fn torn_tail_recovers() {
    let env = Env::new(Kind::Fs);
    let h = env.start();
    let c = Client::new(h.addr(), "torn");
    assert_eq!(c.create().status, 201);
    let e = id_hex("e", 16);
    for rev in 1..=3 {
        assert_eq!(
            c.commit(&e, rev - 1, rev, format!("r{rev}").as_bytes(), &[]).status,
            200
        );
    }
    let before = c.full_log();
    h.shutdown();
    let path = log_file(&env, &c);
    let good_len = std::fs::metadata(&path).unwrap().len();

    // Garbage, then a plausible-but-truncated frame header.
    for tail in [&b"garbage!garbage!"[..], &[0x40, 0, 0, 0, 1, 2, 3][..], &[0, 0][..]] {
        std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap()
            .write_all(tail)
            .unwrap();
        let h = env.start();
        let c = c.at(h.addr());
        assert_eq!(c.full_log(), before);
        h.shutdown();
        assert_eq!(std::fs::metadata(&path).unwrap().len(), good_len, "tail truncated");
    }

    // Final frame with a bad checksum (a torn write of the last record).
    let mut bytes = std::fs::read(&path).unwrap();
    let last = bytes.len() - 1;
    bytes[last] ^= 0xff;
    std::fs::write(&path, &bytes).unwrap();
    let h = env.start();
    let c = c.at(h.addr());
    let (head, recs) = c.full_log();
    assert_eq!((head, recs.len()), (2, 2));
    assert_eq!(recs[..], before.1[..2]);
    // Appending continues from the recovered head.
    assert_eq!(c.commit(&e, 2, 3, b"r3-again", &[]).json(), json!({"seq": 3}));
}

#[test]
fn mid_log_corruption_is_hard_error() {
    let env = Env::new(Kind::Fs);
    let h = env.start();
    let c = Client::new(h.addr(), "corrupt");
    assert_eq!(c.create().status, 201);
    let e = id_hex("e", 16);
    for rev in 1..=3 {
        assert_eq!(c.commit(&e, rev - 1, rev, b"some blob", &[]).status, 200);
    }
    h.shutdown();
    let path = log_file(&env, &c);
    let mut bytes = std::fs::read(&path).unwrap();
    bytes[30] ^= 1; // inside the first frame's payload
    std::fs::write(&path, &bytes).unwrap();

    let h = env.start();
    let c = c.at(h.addr());
    assert_eq!(c.log("").status, 500);
    assert_eq!(c.commit(&e, 3, 4, b"x", &[]).status, 500);
    assert_eq!(std::fs::read(&path).unwrap(), bytes, "never silently truncated");
}

#[test]
fn stray_temp_files_removed_on_load() {
    let env = Env::new(Kind::Fs);
    let h = env.start();
    let c = Client::new(h.addr(), "tmps");
    assert_eq!(c.create().status, 201);
    h.shutdown();
    let dir = env.vault_dir(&c.vid);
    std::fs::write(dir.join(".tmp-log-crashed"), b"pruned secret").unwrap();
    std::fs::write(dir.join("chunks/ab/.tmp-abc-1"), b"partial upload").unwrap();
    let h = env.start();
    let c = c.at(h.addr());
    assert_eq!(c.log("").status, 200);
    assert!(!dir.join(".tmp-log-crashed").exists());
    assert!(!dir.join("chunks/ab/.tmp-abc-1").exists());
}
