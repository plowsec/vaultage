//! Shared test helpers: HTTP client, signed requests, per-backend environments.
#![allow(dead_code)]

pub mod fake_gcs;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use vaultage_core::hexutil;
use vaultage_core::proto::{sign_request, ENROLL_HEADER};
use vaultage_server::{spawn, Config, GcsConfig, ServerHandle, StoreKind};
use ed25519_dalek::SigningKey;
use serde_json::{json, Value};

pub use fake_gcs::FakeGcs;

pub const TOKEN: &str = "test-enroll-token";
pub const PREFIX: &str = "pfx/";

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Kind {
    Fs,
    Gcs,
}

/// Generates `mod fs` and `mod gcs`, each with a #[test] per listed `fn name(Kind)`.
#[macro_export]
macro_rules! both {
    ($($name:ident),* $(,)?) => {
        mod fs { $( #[test] fn $name() { super::$name($crate::common::Kind::Fs) } )* }
        mod gcs { $( #[test] fn $name() { super::$name($crate::common::Kind::Gcs) } )* }
    };
}

pub fn now_ms() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as i64
}

/// One backend's storage, outliving server restarts.
pub struct Env {
    pub kind: Kind,
    pub dir: tempfile::TempDir,
    pub fake: Option<FakeGcs>,
}

impl Env {
    pub fn new(kind: Kind) -> Env {
        Env {
            kind,
            dir: tempfile::tempdir().unwrap(),
            fake: (kind == Kind::Gcs).then(FakeGcs::start),
        }
    }

    pub fn fake(&self) -> &FakeGcs {
        self.fake.as_ref().expect("gcs env")
    }

    pub fn config(&self, token: Option<&str>) -> Config {
        Config {
            data_dir: self.dir.path().to_owned(),
            enroll_token: token.map(str::to_owned),
            store: match &self.fake {
                None => StoreKind::Fs,
                Some(f) => StoreKind::Gcs(GcsConfig {
                    bucket: "test-bucket".into(),
                    prefix: PREFIX.into(),
                    endpoint: Some(f.endpoint()),
                    token: None,
                }),
            },
            gc_grace_secs: 0,
            ..Default::default()
        }
    }

    pub fn start(&self) -> ServerHandle {
        self.start_with(|_| {})
    }

    pub fn start_with(&self, f: impl FnOnce(&mut Config)) -> ServerHandle {
        let mut c = self.config(Some(TOKEN));
        f(&mut c);
        spawn(c, "127.0.0.1:0").unwrap()
    }

    pub fn vault_dir(&self, vid: &str) -> PathBuf {
        self.dir.path().join("vaults").join(vid)
    }

    pub fn chunk_exists(&self, vid: &str, cid: &str) -> bool {
        match self.kind {
            Kind::Fs => self.vault_dir(vid).join("chunks").join(&cid[..2]).join(cid).exists(),
            Kind::Gcs => !self
                .fake()
                .names(&format!("{PREFIX}vaults/{vid}/chunks/{cid}"))
                .is_empty(),
        }
    }

    pub fn chunk_count(&self, vid: &str) -> usize {
        match self.kind {
            Kind::Fs => (0..=255u8)
                .map(|i| {
                    std::fs::read_dir(self.vault_dir(vid).join("chunks").join(hexutil::encode(&[i])))
                        .unwrap()
                        .filter(|e| !e.as_ref().unwrap().file_name().to_string_lossy().starts_with('.'))
                        .count()
                })
                .sum(),
            Kind::Gcs => self.fake().names(&format!("{PREFIX}vaults/{vid}/chunks/")).len(),
        }
    }

    /// Make every chunk of the vault look `secs` old (GC grace tests).
    pub fn age_chunks(&self, vid: &str, secs: u64) {
        match self.kind {
            Kind::Fs => {
                let t = SystemTime::now() - Duration::from_secs(secs);
                for i in 0..=255u8 {
                    let sub = self.vault_dir(vid).join("chunks").join(hexutil::encode(&[i]));
                    for e in std::fs::read_dir(sub).unwrap() {
                        let f = std::fs::File::options().write(true).open(e.unwrap().path()).unwrap();
                        f.set_modified(t).unwrap();
                    }
                }
            }
            Kind::Gcs => {
                let objs = &mut *self.fake().state.objs.lock().unwrap();
                let p = format!("{PREFIX}vaults/{vid}/chunks/");
                for (k, o) in objs.iter_mut() {
                    if k.split_once('/').is_some_and(|(_, n)| n.starts_with(&p)) {
                        o.updated_ms -= secs as i64 * 1000;
                        o.created_ms -= secs as i64 * 1000;
                    }
                }
            }
        }
    }

    /// Everything the backend stores (all files / all live objects), concatenated.
    pub fn all_stored(&self) -> Vec<u8> {
        fn walk(p: &Path, out: &mut Vec<u8>) {
            for e in std::fs::read_dir(p).unwrap() {
                let e = e.unwrap().path();
                if e.is_dir() {
                    walk(&e, out)
                } else {
                    out.extend(std::fs::read(&e).unwrap())
                }
            }
        }
        match self.kind {
            Kind::Fs => {
                let mut v = Vec::new();
                walk(self.dir.path(), &mut v);
                v
            }
            Kind::Gcs => self.fake().all_bytes(),
        }
    }
}

pub fn contains(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|w| w == needle)
}

pub fn agent() -> ureq::Agent {
    ureq::Agent::config_builder().http_status_as_error(false).build().into()
}

pub struct Resp {
    pub status: u16,
    pub body: Vec<u8>,
    pub retry_after: Option<String>,
}

impl Resp {
    pub fn json(&self) -> Value {
        serde_json::from_slice(&self.body)
            .unwrap_or_else(|_| panic!("not json: {:?}", String::from_utf8_lossy(&self.body)))
    }
}

pub fn send(agent: &ureq::Agent, method: &str, url: &str, headers: &[(&str, String)], body: &[u8]) -> Resp {
    let r = match method {
        "GET" => {
            let mut b = agent.get(url);
            for (k, v) in headers {
                b = b.header(*k, v);
            }
            b.call()
        }
        "PUT" | "POST" => {
            let mut b = if method == "PUT" {
                agent.put(url)
            } else {
                agent.post(url)
            };
            for (k, v) in headers {
                b = b.header(*k, v);
            }
            b.send(body)
        }
        _ => unreachable!(),
    };
    let mut r = r.unwrap_or_else(|e| panic!("{method} {url}: {e}"));
    let status = r.status().as_u16();
    let retry_after = r.headers().get("retry-after").map(|v| v.to_str().unwrap().to_owned());
    let body = r.body_mut().with_config().limit(64 << 20).read_to_vec().unwrap();
    Resp {
        status,
        body,
        retry_after,
    }
}

pub fn id_hex(seed: &str, bytes: usize) -> String {
    hexutil::encode(&blake3::hash(seed.as_bytes()).as_bytes()[..bytes])
}

pub fn key_for(name: &str) -> SigningKey {
    SigningKey::from_bytes(blake3::hash(format!("key-{name}").as_bytes()).as_bytes())
}

pub struct Client {
    pub agent: ureq::Agent,
    pub base: String,
    pub vid: String,
    pub key: SigningKey,
}

impl Client {
    pub fn new(addr: SocketAddr, name: &str) -> Self {
        Client {
            agent: agent(),
            base: format!("http://{addr}"),
            vid: id_hex(&format!("vid-{name}"), 16),
            key: key_for(name),
        }
    }

    pub fn at(&self, addr: SocketAddr) -> Self {
        Client {
            agent: agent(),
            base: format!("http://{addr}"),
            vid: self.vid.clone(),
            key: self.key.clone(),
        }
    }

    pub fn with_key(&self, key: SigningKey) -> Self {
        Client {
            agent: agent(),
            base: self.base.clone(),
            vid: self.vid.clone(),
            key,
        }
    }

    pub fn create_req(&self, version: u64) -> Vec<u8> {
        serde_json::to_vec(&json!({
            "vault_id": self.vid,
            "auth_pub": hexutil::encode(&self.key.verifying_key().to_bytes()),
            "header": {"version": version, "slots": ["opaque"]},
        }))
        .unwrap()
    }

    pub fn create(&self) -> Resp {
        send(
            &self.agent,
            "POST",
            &format!("{}/v1/vaults", self.base),
            &[(ENROLL_HEADER, TOKEN.into())],
            &self.create_req(1),
        )
    }

    pub fn vpath(&self, rest: &str) -> String {
        format!("/v1/vaults/{}{rest}", self.vid)
    }

    pub fn get_header(&self) -> Resp {
        send(
            &self.agent,
            "GET",
            &format!("{}{}", self.base, self.vpath("/header")),
            &[],
            b"",
        )
    }

    pub fn signed_ts(&self, key: &SigningKey, method: &str, pq: &str, body: &[u8], ts: i64) -> Resp {
        let auth = sign_request(key, method, pq, ts, body);
        send(
            &self.agent,
            method,
            &format!("{}{pq}", self.base),
            &[("Authorization", auth)],
            body,
        )
    }

    pub fn signed(&self, method: &str, rest: &str, body: &[u8]) -> Resp {
        self.signed_ts(&self.key, method, &self.vpath(rest), body, now_ms())
    }

    pub fn put_chunk(&self, data: &[u8]) -> (String, Resp) {
        let cid = blake3::hash(data).to_hex().to_string();
        let r = self.signed("PUT", &format!("/chunks/{cid}"), data);
        (cid, r)
    }

    pub fn get_chunk(&self, cid: &str) -> Resp {
        self.signed("GET", &format!("/chunks/{cid}"), b"")
    }

    pub fn commit(&self, entry: &str, base_rev: u64, rev: u64, blob: &[u8], refs: &[&str]) -> Resp {
        let body = serde_json::to_vec(&json!({
            "entry": entry, "base_rev": base_rev, "rev": rev,
            "blob": hexutil::encode(blob), "refs": refs,
        }))
        .unwrap();
        self.signed("POST", "/commit", &body)
    }

    pub fn prune(&self, items: &[(&str, u64)]) -> Resp {
        let items: Vec<Value> = items.iter().map(|(e, b)| json!({"entry": e, "below": b})).collect();
        self.signed(
            "POST",
            "/prune",
            &serde_json::to_vec(&json!({ "items": items })).unwrap(),
        )
    }

    pub fn rekey(&self, new: &SigningKey, version: u64) -> Resp {
        let body = json!({
            "auth_pub": hexutil::encode(&new.verifying_key().to_bytes()),
            "header": {"version": version, "slots": ["rekeyed"]},
        });
        self.signed("POST", "/rekey", &serde_json::to_vec(&body).unwrap())
    }

    pub fn usage(&self) -> Value {
        let r = self.signed("GET", "/usage", b"");
        assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
        r.json()
    }

    pub fn log(&self, query: &str) -> Resp {
        self.signed("GET", &format!("/log{query}"), b"")
    }

    /// All records via pagination.
    pub fn full_log(&self) -> (u64, Vec<Value>) {
        let (mut after, mut all) = (0u64, Vec::new());
        loop {
            let r = self.log(&format!("?after={after}&limit=7"));
            assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
            let v = r.json();
            let recs = v["records"].as_array().unwrap().clone();
            if recs.is_empty() {
                return (v["head"].as_u64().unwrap(), all);
            }
            after = recs.last().unwrap()["seq"].as_u64().unwrap();
            all.extend(recs);
        }
    }
}

/// Env + running server + created vault.
pub fn setup(kind: Kind, name: &str) -> (Env, ServerHandle, Client) {
    let env = Env::new(kind);
    let h = env.start();
    let c = Client::new(h.addr(), name);
    assert_eq!(c.create().status, 201);
    (env, h, c)
}

/// Raw HTTP/1.1 exchange; returns the status code.
pub fn raw_status(addr: SocketAddr, req: &str) -> u16 {
    let mut s = TcpStream::connect(addr).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    s.write_all(req.as_bytes()).unwrap();
    let mut buf = Vec::new();
    let mut tmp = [0u8; 1024];
    while !buf.windows(2).any(|w| w == b"\r\n") {
        let n = s.read(&mut tmp).unwrap();
        assert!(n > 0, "connection closed without response");
        buf.extend_from_slice(&tmp[..n]);
    }
    let line = String::from_utf8_lossy(&buf);
    line.split(' ').nth(1).unwrap().parse().unwrap()
}
