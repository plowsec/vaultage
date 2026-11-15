//! Google Cloud Storage backend (JSON API via blocking ureq).
//!
//! TESTED ONLY AGAINST THE IN-PROCESS FAKE in tests/common/fake_gcs.rs, not real GCS.
//!
//! Layout under `<prefix>vaults/<vid>/`: `meta.json` (auth key + header, one object),
//! `log/<seq %020>` (one record frame per object, custom metadata e=entry r=rev p=1 if
//! placeholder), `chunks/<cid>`.
//!
//! Correctness across instances comes from object preconditions, not the in-process locks:
//! - append: insert `log/<head+1>` with ifGenerationMatch=0; on 412 re-list, re-check, retry.
//! - meta (header PUT, rekey): rewrite with ifGenerationMatch=<generation read>.
//! - prune: rewrite each record with ifGenerationMatch=<generation listed>.
//! - GC vs a concurrent commit on another instance: a commit "protects" each ref (metadata
//!   PATCH bumps `updated` and metageneration, unless updated within grace/4) and appends only
//!   if that happened less than grace/2 ago. GC (1) lists chunks (metageneration, updated),
//!   keeps those updated within grace, (2) re-lists the log and keeps every chunk referenced
//!   by a record appended since its reference scan, (3) deletes with ifMetagenerationMatch.
//!   A commit landing after (2) protected its refs < grace/2 before landing, so after (1)
//!   (metageneration changed → 412) or less than grace before (1) (kept as young).
//!   Residual: clock skew or a stalled instance exceeding grace/2. With grace 0 only the
//!   in-process lock protects, i.e. safe only with a single instance.

use std::collections::{HashMap, HashSet};
use std::io;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use coffer_core::proto::{PruneResp, UsageResp};

use super::*;
use crate::GcsConfig;

/// How long a cached auth key is trusted (rekey on another instance is seen within this).
const AUTH_TTL: Duration = Duration::from_secs(2);
const USAGE_TTL: Duration = Duration::from_secs(300);
const ATTEMPTS: u32 = 5;
const PAR: usize = 8;
const MAX_BODY: u64 = 64 << 20;
const DEFAULT_ENDPOINT: &str = "https://storage.googleapis.com";
const METADATA_TOKEN_URL: &str =
    "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token";

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

// ---------------------------------------------------------------- HTTP client

#[derive(Debug)]
enum GErr {
    NotFound,
    Precondition,
    /// Retries exhausted / transport failure.
    Unavailable(String),
    Other(String),
}

impl From<GErr> for SErr {
    fn from(e: GErr) -> SErr {
        match e {
            GErr::Unavailable(m) => SErr::Unavailable(m),
            GErr::NotFound => SErr::Internal("gcs: unexpected 404".into()),
            GErr::Precondition => SErr::Internal("gcs: unexpected 412".into()),
            GErr::Other(m) => SErr::Internal(m),
        }
    }
}

type G<T> = Result<T, GErr>;

#[derive(Clone, Debug)]
struct Obj {
    name: String,
    gen: i64,
    metagen: i64,
    size: u64,
    updated_ms: i64,
    metadata: HashMap<String, String>,
}

enum Auth {
    None,
    Static(String),
    Metadata(Mutex<Option<(String, Instant)>>),
}

struct Client {
    agent: ureq::Agent,
    base: String,
    bucket: String,
    auth: Auth,
}

/// Percent-encode everything but unreserved chars (object names contain '/').
fn enc(s: &str) -> String {
    let mut o = String::with_capacity(s.len() * 3);
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || b"-._~".contains(&b) {
            o.push(b as char);
        } else {
            o.push_str(&format!("%{b:02X}"));
        }
    }
    o
}

fn jitter_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos() as u64 % 100)
        .unwrap_or(0)
}

/// RFC 3339 (`2026-01-02T03:04:05.678Z` or with ±hh:mm) → unix ms.
fn parse_rfc3339(s: &str) -> Option<i64> {
    let b = s.as_bytes();
    if b.len() < 20 || b[4] != b'-' || b[7] != b'-' || !matches!(b[10], b'T' | b't') || b[13] != b':' || b[16] != b':' {
        return None;
    }
    let num = |r: std::ops::Range<usize>| s.get(r)?.parse::<i64>().ok();
    let (y, mo, d, h, mi, se) = (
        num(0..4)?,
        num(5..7)?,
        num(8..10)?,
        num(11..13)?,
        num(14..16)?,
        num(17..19)?,
    );
    let mut i = 19;
    let mut ms = 0i64;
    if b.get(i) == Some(&b'.') {
        i += 1;
        let st = i;
        while i < b.len() && b[i].is_ascii_digit() {
            i += 1;
        }
        let frac = &s[st..i];
        let f3: String = frac.chars().chain("000".chars()).take(3).collect();
        ms = f3.parse().ok()?;
    }
    let off_min = match b.get(i)? {
        b'Z' | b'z' => 0,
        c @ (b'+' | b'-') => {
            let oh = num(i + 1..i + 3)?;
            let om = num(i + 4..i + 6)?;
            let v = oh * 60 + om;
            if *c == b'-' {
                -v
            } else {
                v
            }
        }
        _ => return None,
    };
    // days from civil (Howard Hinnant)
    let y2 = if mo <= 2 { y - 1 } else { y };
    let era = y2.div_euclid(400);
    let yoe = y2 - era * 400;
    let mp = (mo + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    Some(((days * 86_400 + h * 3600 + mi * 60 + se - off_min * 60) * 1000) + ms)
}

fn parse_obj(v: &serde_json::Value) -> G<Obj> {
    let bad = || GErr::Other("gcs: malformed object resource".into());
    let num = |k: &str| -> G<i64> {
        match &v[k] {
            serde_json::Value::String(s) => s.parse().map_err(|_| bad()),
            serde_json::Value::Number(n) => n.as_i64().ok_or_else(bad),
            _ => Err(bad()),
        }
    };
    let metadata = match v["metadata"].as_object() {
        Some(m) => m
            .iter()
            .filter_map(|(k, v)| Some((k.clone(), v.as_str()?.to_owned())))
            .collect(),
        None => HashMap::new(),
    };
    Ok(Obj {
        name: v["name"].as_str().ok_or_else(bad)?.to_owned(),
        gen: num("generation")?,
        metagen: num("metageneration")?,
        size: num("size")? as u64,
        updated_ms: v["updated"].as_str().and_then(parse_rfc3339).ok_or_else(bad)?,
        metadata,
    })
}

struct Resp {
    status: u16,
    body: Vec<u8>,
    gen: Option<i64>,
}

impl Client {
    fn token(&self) -> G<Option<String>> {
        match &self.auth {
            Auth::None => Ok(None),
            Auth::Static(t) => Ok(Some(t.clone())),
            Auth::Metadata(cache) => {
                let mut c = lock(cache);
                if let Some((t, exp)) = &*c {
                    if Instant::now() < *exp {
                        return Ok(Some(t.clone()));
                    }
                }
                let r = self
                    .agent
                    .get(METADATA_TOKEN_URL)
                    .header("Metadata-Flavor", "Google")
                    .call()
                    .map_err(|e| GErr::Unavailable(format!("metadata token: {e}")))?;
                let status = r.status().as_u16();
                let mut r = r;
                let body = r
                    .body_mut()
                    .with_config()
                    .limit(1 << 20)
                    .read_to_vec()
                    .map_err(|e| GErr::Unavailable(format!("metadata token: {e}")))?;
                if status != 200 {
                    return Err(GErr::Unavailable(format!("metadata token: HTTP {status}")));
                }
                let v: serde_json::Value =
                    serde_json::from_slice(&body).map_err(|_| GErr::Unavailable("metadata token: bad json".into()))?;
                let t = v["access_token"]
                    .as_str()
                    .ok_or_else(|| GErr::Unavailable("metadata token: no access_token".into()))?
                    .to_owned();
                let ttl = v["expires_in"].as_u64().unwrap_or(300);
                let exp = Instant::now() + Duration::from_secs(ttl.saturating_sub(60).max(10));
                *c = Some((t.clone(), exp));
                Ok(Some(t))
            }
        }
    }

    /// Run with retries on transport errors, 408, 429, 5xx. Every call site is idempotent
    /// or conditional; callers handle "applied, reply lost" (412/404 on the retry).
    fn exec(
        &self,
        what: &str,
        f: impl Fn(Option<&str>) -> Result<ureq::http::Response<ureq::Body>, ureq::Error>,
    ) -> G<Resp> {
        let mut last = String::new();
        for attempt in 0..ATTEMPTS {
            if attempt > 0 {
                let ms = (100u64 << (attempt - 1)).min(2000) + jitter_ms();
                std::thread::sleep(Duration::from_millis(ms));
            }
            let tok = match self.token() {
                Ok(t) => t,
                Err(e) => {
                    last = format!("{e:?}");
                    continue;
                }
            };
            let bearer = tok.map(|t| format!("Bearer {t}"));
            let mut r = match f(bearer.as_deref()) {
                Ok(r) => r,
                Err(e) => {
                    last = format!("{what}: {e}");
                    continue;
                }
            };
            let status = r.status().as_u16();
            let gen = r
                .headers()
                .get("x-goog-generation")
                .and_then(|v| v.to_str().ok()?.parse().ok());
            let body = match r.body_mut().with_config().limit(MAX_BODY).read_to_vec() {
                Ok(b) => b,
                Err(e) => {
                    last = format!("{what}: read body: {e}");
                    continue;
                }
            };
            if status == 408 || status == 429 || status >= 500 {
                last = format!("{what}: HTTP {status}");
                continue;
            }
            if status == 401 {
                // Drop a cached token the server no longer accepts.
                if let Auth::Metadata(c) = &self.auth {
                    *lock(c) = None;
                }
            }
            return Ok(Resp { status, body, gen });
        }
        Err(GErr::Unavailable(last))
    }

    fn obj_url(&self, name: &str) -> String {
        format!("{}/storage/v1/b/{}/o/{}", self.base, enc(&self.bucket), enc(name))
    }

    fn fail(what: &str, r: &Resp) -> GErr {
        match r.status {
            404 => GErr::NotFound,
            412 => GErr::Precondition,
            s => {
                let msg = String::from_utf8_lossy(&r.body[..r.body.len().min(300)]).into_owned();
                GErr::Other(format!("gcs {what}: HTTP {s}: {msg}"))
            }
        }
    }

    /// Object bytes (+ generation if the server sent x-goog-generation).
    fn get(&self, name: &str, if_gen: Option<i64>) -> G<Option<(Vec<u8>, Option<i64>)>> {
        let mut url = format!("{}?alt=media", self.obj_url(name));
        if let Some(g) = if_gen {
            url.push_str(&format!("&ifGenerationMatch={g}"));
        }
        let r = self.exec("get", |b| {
            let mut q = self.agent.get(&url);
            if let Some(b) = b {
                q = q.header("Authorization", b);
            }
            q.call()
        })?;
        match r.status {
            200 => Ok(Some((r.body, r.gen))),
            404 => Ok(None),
            _ => Err(Self::fail("get", &r)),
        }
    }

    /// Bytes + generation, consistent with each other.
    fn get_gen(&self, name: &str) -> G<Option<(Vec<u8>, i64)>> {
        for _ in 0..5 {
            match self.get(name, None)? {
                None => return Ok(None),
                Some((b, Some(g))) => return Ok(Some((b, g))),
                Some((_, None)) => {}
            }
            let Some(o) = self.stat(name)? else { return Ok(None) };
            match self.get(name, Some(o.gen)) {
                Ok(Some((b, _))) => return Ok(Some((b, o.gen))),
                Ok(None) => return Ok(None),
                Err(GErr::Precondition) => continue,
                Err(e) => return Err(e),
            }
        }
        Err(GErr::Unavailable(format!("{name}: changing too fast")))
    }

    fn stat(&self, name: &str) -> G<Option<Obj>> {
        let url = self.obj_url(name);
        let r = self.exec("stat", |b| {
            let mut q = self.agent.get(&url);
            if let Some(b) = b {
                q = q.header("Authorization", b);
            }
            q.call()
        })?;
        match r.status {
            200 => Ok(Some(parse_obj(&json(&r.body)?)?)),
            404 => Ok(None),
            _ => Err(Self::fail("stat", &r)),
        }
    }

    /// Upload; `if_gen` 0 = must not exist. 412 → `Precondition`.
    fn insert(&self, name: &str, data: &[u8], if_gen: i64, meta: &[(&str, String)]) -> G<Obj> {
        let (url, ctype, body) = if meta.is_empty() {
            (
                format!(
                    "{}/upload/storage/v1/b/{}/o?uploadType=media&name={}&ifGenerationMatch={if_gen}",
                    self.base,
                    enc(&self.bucket),
                    enc(name)
                ),
                "application/octet-stream".to_owned(),
                data.to_vec(),
            )
        } else {
            let md: serde_json::Map<String, serde_json::Value> =
                meta.iter().map(|(k, v)| (k.to_string(), v.clone().into())).collect();
            let doc = serde_json::json!({"name": name, "metadata": md, "contentType": "application/octet-stream"});
            // The data can't contain its own hash.
            let boundary = format!("coffer{}", &blake3::hash(data).to_hex()[..32]);
            let mut b = Vec::with_capacity(data.len() + 512);
            b.extend_from_slice(
                format!("--{boundary}\r\nContent-Type: application/json; charset=UTF-8\r\n\r\n").as_bytes(),
            );
            b.extend_from_slice(doc.to_string().as_bytes());
            b.extend_from_slice(
                format!("\r\n--{boundary}\r\nContent-Type: application/octet-stream\r\n\r\n").as_bytes(),
            );
            b.extend_from_slice(data);
            b.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
            (
                format!(
                    "{}/upload/storage/v1/b/{}/o?uploadType=multipart&ifGenerationMatch={if_gen}",
                    self.base,
                    enc(&self.bucket)
                ),
                format!("multipart/related; boundary={boundary}"),
                b,
            )
        };
        let r = self.exec("insert", |b| {
            let mut q = self.agent.post(&url).header("Content-Type", &ctype);
            if let Some(b) = b {
                q = q.header("Authorization", b);
            }
            q.send(&body[..])
        })?;
        match r.status {
            200 => parse_obj(&json(&r.body)?),
            _ => Err(Self::fail("insert", &r)),
        }
    }

    /// Merge custom metadata (bumps metageneration and `updated`). None on 404.
    fn patch_meta(&self, name: &str, meta: &[(&str, String)]) -> G<Option<Obj>> {
        let md: serde_json::Map<String, serde_json::Value> =
            meta.iter().map(|(k, v)| (k.to_string(), v.clone().into())).collect();
        let body = serde_json::json!({ "metadata": md }).to_string();
        let url = self.obj_url(name);
        let r = self.exec("patch", |b| {
            let mut q = self.agent.patch(&url).header("Content-Type", "application/json");
            if let Some(b) = b {
                q = q.header("Authorization", b);
            }
            q.send(body.as_bytes())
        })?;
        match r.status {
            200 => Ok(Some(parse_obj(&json(&r.body)?)?)),
            404 => Ok(None),
            _ => Err(Self::fail("patch", &r)),
        }
    }

    /// false on 404 (gone already, possibly by our own retried request).
    fn delete(&self, name: &str, if_metagen: Option<i64>) -> G<bool> {
        let mut url = self.obj_url(name);
        if let Some(m) = if_metagen {
            url.push_str(&format!("?ifMetagenerationMatch={m}"));
        }
        let r = self.exec("delete", |b| {
            let mut q = self.agent.delete(&url);
            if let Some(b) = b {
                q = q.header("Authorization", b);
            }
            q.call()
        })?;
        match r.status {
            200 | 204 => Ok(true),
            404 => Ok(false),
            _ => Err(Self::fail("delete", &r)),
        }
    }

    /// All objects under `prefix` with name >= `start`, ascending.
    fn list(&self, prefix: &str, start: Option<&str>) -> G<Vec<Obj>> {
        let mut out = Vec::new();
        let mut page: Option<String> = None;
        loop {
            let mut url = format!(
                "{}/storage/v1/b/{}/o?prefix={}&maxResults=1000",
                self.base,
                enc(&self.bucket),
                enc(prefix)
            );
            if let Some(s) = start {
                url.push_str(&format!("&startOffset={}", enc(s)));
            }
            if let Some(p) = &page {
                url.push_str(&format!("&pageToken={}", enc(p)));
            }
            let r = self.exec("list", |b| {
                let mut q = self.agent.get(&url);
                if let Some(b) = b {
                    q = q.header("Authorization", b);
                }
                q.call()
            })?;
            if r.status != 200 {
                return Err(Self::fail("list", &r));
            }
            let v = json(&r.body)?;
            if let Some(items) = v["items"].as_array() {
                for it in items {
                    out.push(parse_obj(it)?);
                }
            }
            match v["nextPageToken"].as_str() {
                Some(p) if !p.is_empty() => page = Some(p.to_owned()),
                _ => return Ok(out),
            }
        }
    }
}

fn json(b: &[u8]) -> G<serde_json::Value> {
    serde_json::from_slice(b).map_err(|_| GErr::Other("gcs: bad json".into()))
}

/// Order-preserving parallel map (scoped threads).
fn par_map<T: Sync, U: Send>(items: &[T], f: impl Fn(&T) -> U + Sync) -> Vec<U> {
    if items.len() <= 1 {
        return items.iter().map(f).collect();
    }
    let per = items.len().div_ceil(PAR);
    let f = &f;
    std::thread::scope(|s| {
        let hs: Vec<_> = items
            .chunks(per)
            .map(|part| s.spawn(move || part.iter().map(f).collect::<Vec<U>>()))
            .collect();
        hs.into_iter()
            .flat_map(|h| h.join().unwrap_or_else(|e| std::panic::resume_unwind(e)))
            .collect()
    })
}

// ---------------------------------------------------------------- store

#[derive(Clone)]
struct MetaCache {
    at: Instant,
    gen: i64,
    meta: Meta,
    p: MetaParsed,
}

struct RecIdx {
    entry: Id16,
    rev: u64,
    gen: i64,
    placeholder: bool,
    /// Refs as of generation .0.
    refs: Option<(i64, Vec<Cid>)>,
}

#[derive(Default)]
struct LogState {
    recs: Vec<RecIdx>,
    entries: HashMap<Id16, (u64, u64)>,
}

impl LogState {
    fn head(&self) -> u64 {
        self.recs.len() as u64
    }
}

struct Usage {
    at: Instant,
    bytes: u64,
    chunks: u64,
}

struct GVault {
    /// In-process serialization of log ops (an optimization; preconditions decide).
    st: Mutex<LogState>,
    meta: Mutex<MetaCache>,
    usage: Mutex<Option<Usage>>,
}

pub struct GcsStore {
    c: Client,
    prefix: String,
    grace: Duration,
    quota: Option<u64>,
    vaults: Mutex<HashMap<Id16, Arc<GVault>>>,
}

fn rec_meta(entry: &Id16, rev: u64, placeholder: bool) -> Vec<(&'static str, String)> {
    let mut m = vec![("e", hex(entry)), ("r", rev.to_string())];
    if placeholder {
        m.push(("p", "1".into()));
    }
    m
}

impl GcsStore {
    pub fn new(cfg: &GcsConfig, grace: Duration, quota: Option<u64>) -> io::Result<GcsStore> {
        if cfg.bucket.is_empty() {
            return Err(io::Error::other("gcs: empty bucket name"));
        }
        let base = match &cfg.endpoint {
            Some(e) if e.contains("://") => e.trim_end_matches('/').to_owned(),
            Some(e) => format!("http://{}", e.trim_end_matches('/')),
            None => DEFAULT_ENDPOINT.to_owned(),
        };
        let auth = match (&cfg.token, &cfg.endpoint) {
            (Some(t), _) => Auth::Static(t.clone()),
            (None, Some(_)) => Auth::None,
            (None, None) => Auth::Metadata(Mutex::new(None)),
        };
        let agent: ureq::Agent = ureq::Agent::config_builder()
            .http_status_as_error(false)
            .timeout_connect(Some(Duration::from_secs(10)))
            .timeout_global(Some(Duration::from_secs(120)))
            .build()
            .into();
        Ok(GcsStore {
            c: Client {
                agent,
                base,
                bucket: cfg.bucket.clone(),
                auth,
            },
            prefix: cfg.prefix.clone(),
            grace,
            quota,
            vaults: Mutex::new(HashMap::new()),
        })
    }

    fn vbase(&self, vid: &Id16) -> String {
        format!("{}vaults/{}/", self.prefix, hex(vid))
    }
    fn meta_name(&self, vid: &Id16) -> String {
        format!("{}meta.json", self.vbase(vid))
    }
    fn log_prefix(&self, vid: &Id16) -> String {
        format!("{}log/", self.vbase(vid))
    }
    fn log_name(&self, vid: &Id16, seq: u64) -> String {
        format!("{}log/{seq:020}", self.vbase(vid))
    }
    fn chunk_prefix(&self, vid: &Id16) -> String {
        format!("{}chunks/", self.vbase(vid))
    }
    fn chunk_name(&self, vid: &Id16, cid: &Cid) -> String {
        format!("{}chunks/{}", self.vbase(vid), hex(cid))
    }

    fn load_meta(&self, vid: &Id16) -> R<Option<MetaCache>> {
        let Some((b, gen)) = self.c.get_gen(&self.meta_name(vid))? else {
            return Ok(None);
        };
        let (meta, p) = Meta::decode(&b).map_err(SErr::Internal)?;
        Ok(Some(MetaCache {
            at: Instant::now(),
            gen,
            meta,
            p,
        }))
    }

    /// Vault handle; only existing vaults are cached (probes can't grow the map).
    fn vault(&self, vid: &Id16) -> R<Arc<GVault>> {
        if let Some(v) = lock(&self.vaults).get(vid) {
            return Ok(v.clone());
        }
        let m = self.load_meta(vid)?.ok_or(SErr::NoVault)?;
        let v = Arc::new(GVault {
            st: Mutex::new(LogState::default()),
            meta: Mutex::new(m),
            usage: Mutex::new(None),
        });
        Ok(lock(&self.vaults).entry(*vid).or_insert(v).clone())
    }

    fn meta(&self, vid: &Id16, v: &GVault, fresh: bool) -> R<MetaCache> {
        {
            let m = lock(&v.meta);
            if !fresh && m.at.elapsed() < AUTH_TTL {
                return Ok(m.clone());
            }
        }
        let m = self
            .load_meta(vid)?
            .ok_or_else(|| SErr::Internal("meta.json disappeared".into()))?;
        let mut g = lock(&v.meta);
        // Keep the newer one if a concurrent writer updated the cache.
        if m.gen >= g.gen {
            *g = m;
        }
        Ok(g.clone())
    }

    fn check_key(&self, vid: &Id16, v: &GVault, key: &[u8; 32]) -> R<()> {
        if self.meta(vid, v, false)?.p.auth_pub == *key {
            Ok(())
        } else {
            Err(SErr::BadSig)
        }
    }

    fn update_meta(
        &self,
        vid: &Id16,
        key: &[u8; 32],
        new_pub: Option<&[u8; 32]>,
        header: &[u8],
        version: u64,
    ) -> R<()> {
        let v = self.vault(vid)?;
        let name = self.meta_name(vid);
        for _ in 0..8 {
            let m = self.meta(vid, &v, true)?;
            if m.p.auth_pub != *key {
                return Err(SErr::BadSig);
            }
            if version <= m.p.version {
                return Err(SErr::StaleHeader);
            }
            let mut new = Meta::new(
                new_pub.unwrap_or(&m.p.auth_pub),
                header,
                m.meta.created_ms,
                Some(&m.meta.create_id),
            )?;
            if new_pub.is_none() {
                new.invites = m.meta.invites.clone(); // rekey drops them: they carry old keys
            }
            let bytes = new.encode();
            let gen = match self.c.insert(&name, &bytes, m.gen, &[]) {
                Ok(o) => o.gen,
                Err(GErr::Precondition) => match self.c.get_gen(&name)? {
                    // Our write landed and its reply was lost.
                    Some((b, g)) if b == bytes => g,
                    _ => continue,
                },
                Err(e) => return Err(e.into()),
            };
            let (meta, p) = Meta::decode(&bytes).map_err(SErr::Internal)?;
            let mut g = lock(&v.meta);
            if gen >= g.gen {
                *g = MetaCache {
                    at: Instant::now(),
                    gen,
                    meta,
                    p,
                };
            }
            return Ok(());
        }
        Err(SErr::Unavailable("meta update contention".into()))
    }

    /// Catch up with records appended by anyone. `full` re-lists everything (prune).
    fn sync(&self, vid: &Id16, st: &mut LogState, full: bool) -> R<()> {
        let from = if full { 1 } else { st.head() + 1 };
        let objs = self.c.list(&self.log_prefix(vid), Some(&self.log_name(vid, from)))?;
        let pfx = self.log_prefix(vid);
        for o in objs {
            let corrupt = |m: &str| SErr::Internal(format!("vault {} log {}: {m}", hex(vid), o.name));
            let seq: u64 = o
                .name
                .strip_prefix(&pfx)
                .and_then(|s| s.parse().ok())
                .ok_or_else(|| corrupt("bad name"))?;
            let entry = o
                .metadata
                .get("e")
                .and_then(|e| {
                    is_hex(e, 32)
                        .then(|| coffer_core::hexutil::decode_array::<16>(e))
                        .flatten()
                })
                .ok_or_else(|| corrupt("no entry metadata"))?;
            let rev: u64 = o
                .metadata
                .get("r")
                .and_then(|r| r.parse().ok())
                .ok_or_else(|| corrupt("no rev metadata"))?;
            let placeholder = o.metadata.get("p").is_some_and(|p| p == "1");
            if seq <= st.head() {
                let r = &mut st.recs[seq as usize - 1];
                if r.entry != entry || r.rev != rev {
                    return Err(corrupt("record changed identity"));
                }
                r.gen = o.gen;
                r.placeholder = placeholder;
                continue;
            }
            if seq != st.head() + 1 {
                return Err(corrupt(&format!("gap after seq {}", st.head())));
            }
            let prev = st.entries.get(&entry).map_or(0, |e| e.0);
            if rev != prev + 1 {
                return Err(corrupt(&format!("rev {rev} after rev {prev}")));
            }
            st.recs.push(RecIdx {
                entry,
                rev,
                gen: o.gen,
                placeholder,
                refs: None,
            });
            st.entries.insert(entry, (rev, seq));
        }
        Ok(())
    }

    fn read_rec(&self, vid: &Id16, seq: u64, if_gen: Option<i64>) -> G<Option<Rec>> {
        let Some((b, _)) = self.c.get(&self.log_name(vid, seq), if_gen)? else {
            return Ok(None);
        };
        let r = decode_frame(&b).map_err(|e| GErr::Other(format!("log {seq}: {e}")))?;
        if r.seq != seq {
            return Err(GErr::Other(format!("log {seq}: holds seq {}", r.seq)));
        }
        Ok(Some(r))
    }

    /// Make `cid` young for GC (see module doc). Some(age ms at check) if present.
    fn protect(&self, vid: &Id16, cid: &Cid) -> G<Option<i64>> {
        let name = self.chunk_name(vid, cid);
        let Some(o) = self.c.stat(&name)? else { return Ok(None) };
        let grace = self.grace.as_millis() as i64;
        if grace == 0 {
            return Ok(Some(0));
        }
        let age = (now_ms() - o.updated_ms).max(0);
        if age < grace / 4 {
            return Ok(Some(age));
        }
        Ok(self.c.patch_meta(&name, &[("t", now_ms().to_string())])?.map(|_| 0))
    }

    fn usage_of(&self, vid: &Id16, v: &GVault) -> R<(u64, u64)> {
        if let Some(u) = &*lock(&v.usage) {
            if u.at.elapsed() < USAGE_TTL {
                return Ok((u.bytes, u.chunks));
            }
        }
        let objs = self.c.list(&self.chunk_prefix(vid), None)?;
        let (bytes, chunks) = (objs.iter().map(|o| o.size).sum(), objs.len() as u64);
        *lock(&v.usage) = Some(Usage {
            at: Instant::now(),
            bytes,
            chunks,
        });
        Ok((bytes, chunks))
    }

    fn usage_add(&self, v: &GVault, bytes: i64, chunks: i64) {
        if let Some(u) = &mut *lock(&v.usage) {
            u.bytes = u.bytes.saturating_add_signed(bytes);
            u.chunks = u.chunks.saturating_add_signed(chunks);
        }
    }

    /// Refs of unpruned records `seqs` (cached per generation). Records that turned into
    /// placeholders meanwhile contribute nothing.
    fn refs_of(&self, vid: &Id16, st: &mut LogState, seqs: &[u64], out: &mut HashSet<Cid>) -> R<()> {
        let need: Vec<(u64, i64)> = seqs
            .iter()
            .filter_map(|&s| {
                let r = &st.recs[s as usize - 1];
                (!r.placeholder && r.refs.as_ref().is_none_or(|(g, _)| *g != r.gen)).then_some((s, r.gen))
            })
            .collect();
        let got = par_map(&need, |&(seq, gen)| self.read_rec(vid, seq, Some(gen)));
        for ((seq, gen), res) in need.into_iter().zip(got) {
            let r = &mut st.recs[seq as usize - 1];
            match res {
                Ok(Some(rec)) => r.refs = Some((gen, rec.refs)),
                Ok(None) => return Err(SErr::Internal(format!("log {seq} vanished"))),
                Err(GErr::Precondition) => {
                    // Rewritten since listed: only prune does that.
                    match self.c.stat(&self.log_name(vid, seq))? {
                        Some(o) if o.metadata.get("p").is_some_and(|p| p == "1") => {
                            r.placeholder = true;
                            r.gen = o.gen;
                        }
                        _ => return Err(SErr::Unavailable(format!("log {seq} changing"))),
                    }
                }
                Err(e) => return Err(e.into()),
            }
        }
        for &s in seqs {
            let r = &st.recs[s as usize - 1];
            if let (false, Some((g, refs))) = (r.placeholder, &r.refs) {
                if *g == r.gen {
                    out.extend(refs.iter().copied());
                }
            }
        }
        Ok(())
    }
}

impl Store for GcsStore {
    fn create(&self, vid: &Id16, auth_pub: &[u8; 32], header: &[u8]) -> R<()> {
        let bytes = Meta::new(auth_pub, header, now_ms(), None)?.encode();
        let name = self.meta_name(vid);
        match self.c.insert(&name, &bytes, 0, &[]) {
            Ok(_) => Ok(()),
            Err(GErr::Precondition) => match self.c.get(&name, None)? {
                Some((b, _)) if b == bytes => Ok(()),
                _ => Err(SErr::Exists),
            },
            Err(e) => Err(e.into()),
        }
    }

    fn auth_key(&self, vid: &Id16, fresh: bool) -> R<[u8; 32]> {
        let v = self.vault(vid)?;
        Ok(self.meta(vid, &v, fresh)?.p.auth_pub)
    }

    fn header(&self, vid: &Id16) -> R<Vec<u8>> {
        let v = self.vault(vid)?;
        Ok(self.meta(vid, &v, false)?.p.header)
    }

    fn put_header(&self, vid: &Id16, key: &[u8; 32], header: &[u8], version: u64) -> R<()> {
        self.update_meta(vid, key, None, header, version)
    }

    fn rekey(&self, vid: &Id16, key: &[u8; 32], new_pub: &[u8; 32], header: &[u8], version: u64) -> R<()> {
        self.update_meta(vid, key, Some(new_pub), header, version)
    }

    fn log(&self, vid: &Id16, key: &[u8; 32], after: u64, limit: usize, max_bytes: usize) -> R<(u64, Vec<Rec>)> {
        let v = self.vault(vid)?;
        self.check_key(vid, &v, key)?;
        let head = {
            let mut st = lock(&v.st);
            self.sync(vid, &mut st, false)?;
            st.head()
        };
        let end = after.saturating_add(limit as u64).min(head);
        let seqs: Vec<u64> = (after.saturating_add(1)..=end).collect();
        let mut out = Vec::with_capacity(seqs.len());
        let mut bytes = 0usize;
        // Batches, so the byte budget stops further downloads.
        for batch in seqs.chunks(PAR * 4) {
            let got = par_map(batch, |&s| self.read_rec(vid, s, None));
            for (s, r) in batch.iter().zip(got) {
                let rec = r?.ok_or_else(|| SErr::Internal(format!("log {s} missing")))?;
                if !out.is_empty() && bytes + rec.blob.len() > max_bytes {
                    return Ok((head, out));
                }
                bytes += rec.blob.len();
                out.push(rec);
            }
        }
        Ok((head, out))
    }

    fn commit(&self, vid: &Id16, key: &[u8; 32], c: &CommitIn) -> R<u64> {
        let v = self.vault(vid)?;
        self.check_key(vid, &v, key)?;
        let mut st = lock(&v.st);
        for _ in 0..16 {
            self.sync(vid, &mut st, false)?;
            let (cur, cur_seq) = st.entries.get(&c.entry).copied().unwrap_or((0, 0));
            if cur != c.base_rev {
                if cur == c.rev {
                    let stored = self
                        .read_rec(vid, cur_seq, None)?
                        .ok_or_else(|| SErr::Internal("current record missing".into()))?;
                    // Placeholders have an empty blob: never a match.
                    if stored.blob == c.blob {
                        return Ok(cur_seq);
                    }
                }
                return Err(SErr::Conflict(cur));
            }
            let t0 = Instant::now();
            let checked = par_map(&c.refs, |cid| self.protect(vid, cid));
            let mut missing = Vec::new();
            let mut oldest = 0i64;
            for (cid, r) in c.refs.iter().zip(checked) {
                match r? {
                    None => missing.push(*cid),
                    Some(age) => oldest = oldest.max(age),
                }
            }
            if !missing.is_empty() {
                return Err(SErr::Missing(missing));
            }
            let seq = st.head() + 1;
            let frame = encode_frame(seq, &c.entry, c.rev, &c.refs, &c.blob);
            if !self.grace.is_zero() && t0.elapsed().as_millis() as i64 + oldest >= self.grace.as_millis() as i64 / 2 {
                return Err(SErr::Unavailable("commit too slow for GC grace".into()));
            }
            let name = self.log_name(vid, seq);
            match self.c.insert(&name, &frame, 0, &rec_meta(&c.entry, c.rev, false)) {
                Ok(o) => {
                    st.recs.push(RecIdx {
                        entry: c.entry,
                        rev: c.rev,
                        gen: o.gen,
                        placeholder: false,
                        refs: Some((o.gen, c.refs.clone())),
                    });
                    st.entries.insert(c.entry, (c.rev, seq));
                    return Ok(seq);
                }
                Err(GErr::Precondition) => {
                    if let Some((b, _)) = self.c.get(&name, None)? {
                        if b == frame {
                            // Ours (reply lost) or an identical commit: same outcome.
                            return Ok(seq);
                        }
                    }
                    // Someone else took this seq: re-sync and re-check.
                }
                Err(e) => return Err(e.into()),
            }
        }
        Err(SErr::Unavailable("commit contention".into()))
    }

    fn missing(&self, vid: &Id16, key: &[u8; 32], ids: &[Cid]) -> R<Vec<Cid>> {
        let v = self.vault(vid)?;
        self.check_key(vid, &v, key)?;
        let got = par_map(ids, |cid| self.c.stat(&self.chunk_name(vid, cid)));
        let mut out = Vec::new();
        for (cid, r) in ids.iter().zip(got) {
            if r?.is_none() {
                out.push(*cid);
            }
        }
        Ok(out)
    }

    fn put_chunk(&self, vid: &Id16, key: &[u8; 32], cid: &Cid, data: &[u8]) -> R<()> {
        let v = self.vault(vid)?;
        self.check_key(vid, &v, key)?;
        let name = self.chunk_name(vid, cid);
        // Existing: refresh for GC grace like the FS mtime touch; never fails on quota.
        if self.protect(vid, cid)?.is_some() {
            return Ok(());
        }
        let len = data.len() as i64;
        if let Some(q) = self.quota {
            let (bytes, _) = self.usage_of(vid, &v)?;
            // Per-instance counter: with several instances the quota is approximate.
            if bytes + data.len() as u64 > q {
                return Err(SErr::Quota);
            }
        }
        self.usage_add(&v, len, 1);
        match self.c.insert(&name, data, 0, &[]) {
            Ok(_) => Ok(()),
            Err(GErr::Precondition) => {
                // Exists (concurrent upload, or ours with a lost reply).
                self.usage_add(&v, -len, -1);
                Ok(())
            }
            Err(e) => {
                self.usage_add(&v, -len, -1);
                Err(e.into())
            }
        }
    }

    fn get_chunk(&self, vid: &Id16, key: &[u8; 32], cid: &Cid) -> R<Vec<u8>> {
        let v = self.vault(vid)?;
        self.check_key(vid, &v, key)?;
        match self.c.get(&self.chunk_name(vid, cid), None)? {
            Some((b, _)) => Ok(b),
            None => Err(SErr::NoChunk),
        }
    }

    fn prune(&self, vid: &Id16, key: &[u8; 32], items: &[(Id16, u64)]) -> R<PruneResp> {
        let v = self.vault(vid)?;
        self.check_key(vid, &v, key)?;

        // Phase 1 (lock): placeholders, live refs.
        let (records, live, h1) = {
            let mut st = lock(&v.st);
            self.sync(vid, &mut st, true)?;
            let mut below: HashMap<Id16, u64> = HashMap::new();
            for (entry, b) in items {
                let Some(&(cur, _)) = st.entries.get(entry) else {
                    continue;
                };
                if *b > cur {
                    return Err(SErr::Bad("below exceeds current rev".into()));
                }
                let e = below.entry(*entry).or_insert(0);
                *e = (*e).max(*b);
            }
            let targets: Vec<(u64, Id16, u64, i64)> = st
                .recs
                .iter()
                .enumerate()
                .filter(|(_, r)| !r.placeholder && below.get(&r.entry).is_some_and(|b| r.rev < *b))
                .map(|(i, r)| (i as u64 + 1, r.entry, r.rev, r.gen))
                .collect();
            let done = par_map(&targets, |&(seq, entry, rev, gen)| -> R<i64> {
                let name = self.log_name(vid, seq);
                match self.c.insert(
                    &name,
                    &placeholder_frame(seq, &entry, rev),
                    gen,
                    &rec_meta(&entry, rev, true),
                ) {
                    Ok(o) => Ok(o.gen),
                    Err(GErr::Precondition) => match self.c.stat(&name)? {
                        // Lost reply, or another instance pruned it.
                        Some(o) if o.metadata.get("p").is_some_and(|p| p == "1") => Ok(o.gen),
                        _ => Err(SErr::Unavailable(format!("log {seq} changed during prune"))),
                    },
                    Err(e) => Err(e.into()),
                }
            });
            let mut n = 0u64;
            let mut first_err = None;
            for (t, r) in targets.iter().zip(done) {
                match r {
                    Ok(gen) => {
                        let rec = &mut st.recs[t.0 as usize - 1];
                        rec.placeholder = true;
                        rec.gen = gen;
                        rec.refs = None;
                        n += 1;
                    }
                    Err(e) => {
                        first_err.get_or_insert(e);
                    }
                }
            }
            if let Some(e) = first_err {
                // Done ones are durable; re-running prune finishes the rest.
                return Err(e);
            }
            let seqs: Vec<u64> = (1..=st.head()).collect();
            let mut live = HashSet::new();
            self.refs_of(vid, &mut st, &seqs, &mut live)?;
            (n, live, st.head())
        };

        // Phase 2 (no lock): candidates by listing (records metageneration + updated).
        let grace = self.grace.as_millis() as i64;
        let pfx = self.chunk_prefix(vid);
        let now = now_ms();
        let cands: Vec<(Cid, Obj)> = self
            .c
            .list(&pfx, None)?
            .into_iter()
            .filter_map(|o| {
                let h = o.name.strip_prefix(&pfx)?;
                let cid = is_hex(h, 64)
                    .then(|| coffer_core::hexutil::decode_array::<32>(h))
                    .flatten()?;
                (!live.contains(&cid) && now - o.updated_ms >= grace).then_some((cid, o))
            })
            .collect();

        // Phase 3 (lock): re-list the log, spare refs of later records, conditional delete.
        let (chunks, bytes) = {
            let mut st = lock(&v.st);
            self.sync(vid, &mut st, false)?;
            let mut late = HashSet::new();
            let seqs: Vec<u64> = (h1 + 1..=st.head()).collect();
            self.refs_of(vid, &mut st, &seqs, &mut late)?;
            let del: Vec<&(Cid, Obj)> = cands.iter().filter(|(c, _)| !late.contains(c)).collect();
            let res = par_map(&del, |(_, o)| self.c.delete(&o.name, Some(o.metagen)));
            let (mut n, mut b) = (0u64, 0u64);
            for ((_, o), r) in del.iter().zip(res) {
                match r {
                    Ok(true) => {
                        n += 1;
                        b += o.size;
                    }
                    Ok(false) | Err(GErr::Precondition) => {} // gone, or touched since listing
                    Err(e) => return Err(e.into()),
                }
            }
            (n, b)
        };
        self.usage_add(&v, -(bytes as i64), -(chunks as i64));
        Ok(PruneResp { records, chunks, bytes })
    }

    fn usage(&self, vid: &Id16, key: &[u8; 32]) -> R<UsageResp> {
        let v = self.vault(vid)?;
        self.check_key(vid, &v, key)?;
        let records = {
            let mut st = lock(&v.st);
            self.sync(vid, &mut st, false)?;
            st.head()
        };
        let (bytes, chunks) = self.usage_of(vid, &v)?;
        Ok(UsageResp {
            bytes,
            chunks,
            records,
            quota: self.quota,
        })
    }

    fn edit_invites(&self, vid: &Id16, key: Option<&[u8; 32]>, f: &mut dyn FnMut(&mut Vec<InviteRec>) -> R<InviteOut>) -> R<InviteOut> {
        let v = self.vault(vid)?;
        let name = self.meta_name(vid);
        for _ in 0..8 {
            let m = self.meta(vid, &v, true)?;
            if key.is_some_and(|k| m.p.auth_pub != *k) {
                return Err(SErr::BadSig);
            }
            let mut list = m.meta.invites.clone();
            let out = f(&mut list)?;
            if list == m.meta.invites {
                return Ok(out);
            }
            let mut new = m.meta.clone();
            new.invites = list;
            let bytes = new.encode();
            let gen = match self.c.insert(&name, &bytes, m.gen, &[]) {
                Ok(o) => o.gen,
                Err(GErr::Precondition) => match self.c.get_gen(&name)? {
                    Some((b, g)) if b == bytes => g,
                    _ => continue,
                },
                Err(e) => return Err(e.into()),
            };
            let (meta, p) = Meta::decode(&bytes).map_err(SErr::Internal)?;
            let mut g = lock(&v.meta);
            if gen >= g.gen {
                *g = MetaCache { at: Instant::now(), gen, meta, p };
            }
            return Ok(out);
        }
        Err(SErr::Unavailable("meta update contention".into()))
    }

    fn invite_claim_key(&self, vid: &Id16, iid: &str, fresh: bool) -> R<Option<[u8; 32]>> {
        let v = self.vault(vid)?;
        Ok(invites::claim_key(&self.meta(vid, &v, fresh)?.meta.invites, iid).ok())
    }

    fn sweep_invites(&self, vid: &Id16) -> R<()> {
        let v = self.vault(vid)?;
        // Cached meta: at worst the erase waits for the next request after the cache refreshes.
        if !invites::stale(&self.meta(vid, &v, false)?.meta.invites, now_ms()) {
            return Ok(());
        }
        self.edit_invites(vid, None, &mut |l| {
            invites::tidy(l, now_ms());
            Ok(InviteOut::None)
        })
        .map(|_| ())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc3339() {
        assert_eq!(parse_rfc3339("1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(parse_rfc3339("1970-01-01T00:00:01.5Z"), Some(1500));
        assert_eq!(parse_rfc3339("2000-03-01T00:00:00.000Z"), Some(951_868_800_000));
        assert_eq!(parse_rfc3339("2000-03-01T01:00:00+01:00"), Some(951_868_800_000));
        assert_eq!(parse_rfc3339("garbage"), None);
    }

    #[test]
    fn encode_names() {
        assert_eq!(enc("a/b c~"), "a%2Fb%20c~");
    }
}
