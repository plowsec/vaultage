// Handlers return `Response` as the error type; boxing it buys nothing here.
#![allow(clippy::result_large_err)]

use std::collections::HashSet;
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::body::Bytes;
use axum::extract::rejection::BytesRejection;
use axum::extract::{DefaultBodyLimit, Path, Request, State};
use axum::http::{header, HeaderMap, Method, StatusCode, Uri};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use coffer_core::hexutil;
use coffer_core::proto::{
    verify_request, CommitReq, CommitResp, ConflictResp, CreateVaultReq, ErrorResp, InviteClaimReq, InviteClaimResp,
    InviteCreateReq, InvitesResp, LogResp, MissingReq, MissingResp, PruneReq, RekeyReq, WireRecord, ENROLL_HEADER,
    MAX_CHUNK_BODY, MAX_JSON_BODY,
};

use crate::ratelimit::Limiter;
use crate::store::invites::{self, InviteOut};
use crate::store::{self, hex, is_hex, Cid, CommitIn, Id16, SErr, Store};
use crate::{Config, StoreKind};

const LOG_DEFAULT_LIMIT: usize = 500;
const LOG_MAX_LIMIT: usize = 1000;
const LOG_MAX_BLOB_BYTES: usize = 8 * 1024 * 1024;

struct App {
    store: Box<dyn Store>,
    enroll: Option<String>,
    header_rl: Limiter<Id16>,
    authfail_rl: Limiter<Id16>,
    enroll_rl: Limiter<()>,
}

type St = State<Arc<App>>;

fn err(code: StatusCode, msg: &str) -> Response {
    (code, Json(ErrorResp { error: msg.to_owned() })).into_response()
}

fn too_many(retry_after: u64) -> Response {
    let mut r = err(StatusCode::TOO_MANY_REQUESTS, "rate limited");
    r.headers_mut().insert(header::RETRY_AFTER, retry_after.into());
    r
}

fn internal(ctx: &str, e: impl std::fmt::Display) -> Response {
    eprintln!("cofferd: {ctx}: {e}");
    err(StatusCode::INTERNAL_SERVER_ERROR, "internal error")
}

fn ok_empty(code: StatusCode) -> Response {
    (code, Json(serde_json::json!({}))).into_response()
}

fn serr(e: SErr) -> Response {
    match e {
        SErr::NoVault => err(StatusCode::NOT_FOUND, "no such vault"),
        SErr::Exists => err(StatusCode::CONFLICT, "vault exists"),
        SErr::BadSig => err(StatusCode::UNAUTHORIZED, "bad signature"),
        SErr::Conflict(current_rev) => (StatusCode::CONFLICT, Json(ConflictResp { current_rev })).into_response(),
        SErr::StaleHeader => err(StatusCode::CONFLICT, "stale header version"),
        SErr::Missing(ids) => (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(MissingResp {
                missing: ids.iter().map(|c| hex(c)).collect(),
            }),
        )
            .into_response(),
        SErr::Bad(m) => err(StatusCode::BAD_REQUEST, &m),
        SErr::Quota => err(StatusCode::INSUFFICIENT_STORAGE, "vault quota exceeded"),
        SErr::NoChunk => err(StatusCode::NOT_FOUND, "no such chunk"),
        SErr::NoInvite => err(StatusCode::NOT_FOUND, "no such invite"),
        SErr::Gone(m) => err(StatusCode::GONE, &m),
        SErr::Unavailable(m) => {
            eprintln!("cofferd: storage unavailable: {m}");
            let mut r = err(StatusCode::SERVICE_UNAVAILABLE, "storage temporarily unavailable");
            r.headers_mut().insert(header::RETRY_AFTER, 1u64.into());
            r
        }
        SErr::Internal(m) => internal("storage", m),
    }
}

fn bad(m: &str) -> SErr {
    SErr::Bad(m.to_owned())
}

fn parse_id16(s: &str) -> Option<Id16> {
    if is_hex(s, 32) {
        hexutil::decode_array(s)
    } else {
        None
    }
}

fn parse_cid(s: &str) -> Option<Cid> {
    if is_hex(s, 64) {
        hexutil::decode_array(s)
    } else {
        None
    }
}

fn bad_vid() -> Response {
    err(StatusCode::BAD_REQUEST, "bad vault id")
}

fn body_or_reject(b: Result<Bytes, BytesRejection>) -> Result<Bytes, Response> {
    b.map_err(|r| {
        let code = r.status();
        let msg = if code == StatusCode::PAYLOAD_TOO_LARGE {
            "body too large"
        } else {
            "bad body"
        };
        err(code, msg)
    })
}

fn parse_json<T: serde::de::DeserializeOwned>(b: &[u8]) -> Result<T, SErr> {
    serde_json::from_slice(b).map_err(|_| bad("bad json"))
}

/// Header JSON must be an object with a numeric version. Returns (bytes to store, version).
fn check_header(v: &serde_json::Value) -> Result<(Vec<u8>, u64), SErr> {
    let version = store::header_version(v).ok_or_else(|| bad("header must be an object with a numeric version"))?;
    Ok((
        serde_json::to_vec(v).map_err(|e| SErr::Internal(e.to_string()))?,
        version,
    ))
}

fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    // blake3::Hash equality is constant-time.
    blake3::hash(a) == blake3::hash(b)
}

/// Run blocking storage work off the async runtime.
async fn blocking(f: impl FnOnce() -> Response + Send + 'static) -> Response {
    tokio::task::spawn_blocking(f)
        .await
        .unwrap_or_else(|e| internal("blocking task", e))
}

struct Signed {
    authz: Option<String>,
    method: String,
    pq: String,
}

impl Signed {
    fn new(method: &Method, uri: &Uri, headers: &HeaderMap) -> Self {
        Signed {
            authz: headers
                .get(header::AUTHORIZATION)
                .and_then(|v| v.to_str().ok())
                .map(str::to_owned),
            method: method.as_str().to_owned(),
            pq: uri
                .path_and_query()
                .map_or_else(|| uri.path().to_owned(), |p| p.as_str().to_owned()),
        }
    }

    fn ok(&self, key: &[u8; 32], body: &[u8]) -> bool {
        self.authz
            .as_deref()
            .is_some_and(|a| verify_request(key, a, &self.method, &self.pq, body, store::now_ms()))
    }
}

impl App {
    /// Verify the signature; returns the key it verified against. Only failures are
    /// rate-limited, so garbage from others never locks out a valid signer.
    fn authenticate(&self, vid: &Id16, sig: &Signed, body: &[u8]) -> Result<[u8; 32], Response> {
        let key = self.store.auth_key(vid, false).map_err(serr)?;
        if sig.ok(&key, body) {
            return Ok(key);
        }
        // Cached key may be stale (rekey on another instance). Re-read, unless locked out.
        if !self.authfail_rl.blocked(vid) {
            if let Ok(k2) = self.store.auth_key(vid, true) {
                if k2 != key && sig.ok(&k2, body) {
                    return Ok(k2);
                }
            }
        }
        Err(match self.authfail_rl.hit(vid) {
            Ok(()) => serr(SErr::BadSig),
            Err(ra) => too_many(ra),
        })
    }

    /// Same for a claim, against the invite's own key: only failures (bad signature, unknown id)
    /// are rate-limited, so junk claims never lock out the invite's holder.
    fn authenticate_claim(&self, vid: &Id16, iid: &str, sig: &Signed, body: &[u8]) -> Result<(), Response> {
        let mut found = self.store.invite_claim_key(vid, iid, false).map_err(serr)?;
        if found.is_some_and(|k| sig.ok(&k, body)) {
            return Ok(());
        }
        // The cache may predate the invite (created on another instance). Re-read, unless locked out.
        if !self.authfail_rl.blocked(vid) {
            if let Ok(k2) = self.store.invite_claim_key(vid, iid, true) {
                if k2.is_some_and(|k| sig.ok(&k, body)) {
                    return Ok(());
                }
                found = k2;
            }
        }
        Err(match self.authfail_rl.hit(vid) {
            Ok(()) => serr(if found.is_some() { SErr::BadSig } else { SErr::NoInvite }),
            Err(ra) => too_many(ra),
        })
    }
}

/// Common shape of a signed vault route: authenticate, then run `op` (blocking).
async fn signed_op<T: IntoResponse>(
    app: Arc<App>,
    vid: String,
    sig: Signed,
    body: Bytes,
    op: impl FnOnce(&dyn Store, &Id16, &[u8; 32], &[u8]) -> Result<T, SErr> + Send + 'static,
) -> Response {
    let Some(vid) = parse_id16(&vid) else { return bad_vid() };
    blocking(move || {
        let key = match app.authenticate(&vid, &sig, &body) {
            Ok(k) => k,
            Err(r) => return r,
        };
        // A member is here: erase invite payloads past their time (best effort).
        if let Err(SErr::Unavailable(m) | SErr::Internal(m)) = app.store.sweep_invites(&vid) {
            eprintln!("cofferd: invite sweep: {m}");
        }
        match op(&*app.store, &vid, &key, &body) {
            Ok(r) => r.into_response(),
            Err(SErr::BadSig) => match app.authfail_rl.hit(&vid) {
                Ok(()) => serr(SErr::BadSig),
                Err(ra) => too_many(ra),
            },
            Err(e) => serr(e),
        }
    })
    .await
}

pub fn router(cfg: Config) -> std::io::Result<Router> {
    let grace = Duration::from_secs(cfg.gc_grace_secs);
    let store: Box<dyn Store> = match &cfg.store {
        StoreKind::Fs => Box::new(store::fs::FsStore::new(&cfg.data_dir, grace, cfg.vault_quota_bytes)?),
        StoreKind::Gcs(g) => Box::new(store::gcs::GcsStore::new(g, grace, cfg.vault_quota_bytes)?),
    };
    let window = Duration::from_secs(cfg.rate_window_secs);
    let app = Arc::new(App {
        store,
        enroll: cfg.enroll_token.filter(|t| !t.is_empty()),
        header_rl: Limiter::new(cfg.rate_header_reads, window),
        authfail_rl: Limiter::new(cfg.rate_auth_failures, window),
        enroll_rl: Limiter::new(cfg.rate_enroll_failures, window),
    });
    Ok(Router::new()
        .route("/healthz", get(|| async { "ok" }))
        .route("/v1/vaults", post(create_vault))
        .route("/v1/vaults/{vid}/header", get(get_header).put(put_header))
        .route("/v1/vaults/{vid}/log", get(get_log))
        .route("/v1/vaults/{vid}/commit", post(commit))
        .route("/v1/vaults/{vid}/missing", post(missing))
        .route("/v1/vaults/{vid}/prune", post(prune))
        .route("/v1/vaults/{vid}/rekey", post(rekey))
        .route("/v1/vaults/{vid}/usage", get(usage))
        .route("/v1/vaults/{vid}/invites", get(list_invites).post(create_invite))
        .route("/v1/vaults/{vid}/invites/{iid}/revoke", post(revoke_invite))
        .route("/v1/vaults/{vid}/invites/{iid}/claim", post(claim_invite))
        .route(
            "/v1/vaults/{vid}/chunks/{cid}",
            get(get_chunk)
                .put(put_chunk)
                .layer(DefaultBodyLimit::max(MAX_CHUNK_BODY))
                .layer(middleware::from_fn(|r, n| cap_len(MAX_CHUNK_BODY, r, n))),
        )
        .fallback(|| async { err(StatusCode::NOT_FOUND, "not found") })
        .layer(DefaultBodyLimit::max(MAX_JSON_BODY))
        .layer(middleware::from_fn(|r, n| cap_len(MAX_JSON_BODY, r, n)))
        .layer(middleware::from_fn(log_request))
        .with_state(app))
}

/// Refuse a declared oversize body before reading it (DefaultBodyLimit covers chunked bodies).
async fn cap_len(limit: usize, req: Request, next: Next) -> Response {
    let len = req
        .headers()
        .get(header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok()?.parse::<u64>().ok());
    if len.is_some_and(|n| n > limit as u64) {
        return err(StatusCode::PAYLOAD_TOO_LARGE, "body too large");
    }
    next.run(req).await
}

/// Vault ids grant header reads: log only an 8-char prefix (of invite ids too).
fn redact_path(path: &str) -> String {
    match path.strip_prefix("/v1/vaults/") {
        Some(rest) => {
            let (vid, tail) = rest.split_at(rest.find('/').unwrap_or(rest.len()));
            let tail = match tail.strip_prefix("/invites/") {
                Some(t) => {
                    let (iid, more) = t.split_at(t.find('/').unwrap_or(t.len()));
                    match iid.get(..8) {
                        Some(p) if iid.len() > 8 => format!("/invites/{p}…{more}"),
                        _ => tail.to_owned(),
                    }
                }
                None => tail.to_owned(),
            };
            match vid.get(..8) {
                Some(p) if vid.len() > 8 => format!("/v1/vaults/{p}…{tail}"),
                _ => format!("/v1/vaults/{vid}{tail}"),
            }
        }
        None => path.to_owned(),
    }
}

/// One line per request. Never logs bodies, query strings or headers.
async fn log_request(req: Request, next: Next) -> Response {
    let method = req.method().clone();
    let path = redact_path(req.uri().path());
    let t = Instant::now();
    let resp = next.run(req).await;
    eprintln!(
        "{method} {path} {} {}ms",
        resp.status().as_u16(),
        t.elapsed().as_millis()
    );
    resp
}

async fn create_vault(State(app): St, headers: HeaderMap, body: Result<Bytes, BytesRejection>) -> Response {
    let given = headers.get(ENROLL_HEADER).map(|v| v.as_bytes()).unwrap_or_default();
    let good = app.enroll.as_deref().is_some_and(|t| ct_eq(given, t.as_bytes()));
    if !good {
        if let Err(ra) = app.enroll_rl.hit(&()) {
            return too_many(ra);
        }
        return err(
            StatusCode::FORBIDDEN,
            if app.enroll.is_none() {
                "enrollment disabled"
            } else {
                "bad enrollment token"
            },
        );
    }
    let body = match body_or_reject(body) {
        Ok(b) => b,
        Err(r) => return r,
    };
    let parsed = (|| {
        let req: CreateVaultReq = parse_json(&body)?;
        let vid = parse_id16(&req.vault_id).ok_or_else(|| bad("bad vault id"))?;
        let auth_pub = parse_auth_pub(&req.auth_pub)?;
        let (header, _) = check_header(&req.header)?;
        Ok((vid, auth_pub, header))
    })();
    let (vid, auth_pub, header) = match parsed {
        Ok(x) => x,
        Err(e) => return serr(e),
    };
    blocking(move || match app.store.create(&vid, &auth_pub, &header) {
        Ok(()) => ok_empty(StatusCode::CREATED),
        Err(e) => serr(e),
    })
    .await
}

fn parse_auth_pub(s: &str) -> Result<[u8; 32], SErr> {
    if !is_hex(s, 64) {
        return Err(bad("bad auth_pub"));
    }
    hexutil::decode_array(s).ok_or_else(|| bad("bad auth_pub"))
}

async fn get_header(State(app): St, Path(vid): Path<String>) -> Response {
    let Some(vid) = parse_id16(&vid) else { return bad_vid() };
    if let Err(ra) = app.header_rl.hit(&vid) {
        return too_many(ra);
    }
    blocking(move || match app.store.header(&vid) {
        Ok(b) => ([(header::CONTENT_TYPE, "application/json")], b).into_response(),
        Err(e) => serr(e),
    })
    .await
}

macro_rules! body {
    ($b:expr) => {
        match body_or_reject($b) {
            Ok(b) => b,
            Err(r) => return r,
        }
    };
}

async fn put_header(
    State(app): St,
    Path(vid): Path<String>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> Response {
    let body = body!(body);
    let sig = Signed::new(&method, &uri, &headers);
    signed_op(app, vid, sig, body, |s, vid, key, body| {
        let val: serde_json::Value = parse_json(body)?;
        let (_, version) = check_header(&val)?;
        // Stored verbatim.
        s.put_header(vid, key, body, version)?;
        Ok(ok_empty(StatusCode::OK))
    })
    .await
}

async fn rekey(
    State(app): St,
    Path(vid): Path<String>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> Response {
    let body = body!(body);
    let sig = Signed::new(&method, &uri, &headers);
    signed_op(app, vid, sig, body, |s, vid, key, body| {
        let req: RekeyReq = parse_json(body)?;
        let new_pub = parse_auth_pub(&req.auth_pub)?;
        let (header, version) = check_header(&req.header)?;
        s.rekey(vid, key, &new_pub, &header, version)?;
        Ok(ok_empty(StatusCode::OK))
    })
    .await
}

fn parse_log_query(q: Option<&str>) -> Option<(u64, usize)> {
    let (mut after, mut limit) = (0u64, LOG_DEFAULT_LIMIT);
    for kv in q.unwrap_or("").split('&').filter(|s| !s.is_empty()) {
        let (k, val) = kv.split_once('=').unwrap_or((kv, ""));
        match k {
            "after" => after = val.parse().ok()?,
            "limit" => limit = val.parse().ok()?,
            _ => {}
        }
    }
    Some((after, limit.clamp(1, LOG_MAX_LIMIT)))
}

async fn get_log(State(app): St, Path(vid): Path<String>, method: Method, uri: Uri, headers: HeaderMap) -> Response {
    if parse_id16(&vid).is_none() {
        return bad_vid();
    }
    let Some((after, limit)) = parse_log_query(uri.query()) else {
        return err(StatusCode::BAD_REQUEST, "bad query");
    };
    let sig = Signed::new(&method, &uri, &headers);
    signed_op(app, vid, sig, Bytes::new(), move |s, vid, key, _| {
        let (head, recs) = s.log(vid, key, after, limit, LOG_MAX_BLOB_BYTES)?;
        let records = recs
            .into_iter()
            .map(|r| WireRecord {
                seq: r.seq,
                entry: hex(&r.entry),
                rev: r.rev,
                blob: hex(&r.blob),
            })
            .collect();
        Ok(Json(LogResp { head, records }))
    })
    .await
}

fn parse_cids(ids: &[String], what: &str) -> Result<Vec<Cid>, SErr> {
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for id in ids {
        let c = parse_cid(id).ok_or_else(|| bad(what))?;
        if seen.insert(c) {
            out.push(c);
        }
    }
    Ok(out)
}

async fn commit(
    State(app): St,
    Path(vid): Path<String>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> Response {
    let body = body!(body);
    let sig = Signed::new(&method, &uri, &headers);
    signed_op(app, vid, sig, body, |s, vid, key, body| {
        let req: CommitReq = parse_json(body)?;
        if req.base_rev.checked_add(1) != Some(req.rev) {
            return Err(bad("rev must be base_rev + 1"));
        }
        let entry = parse_id16(&req.entry).ok_or_else(|| bad("bad entry id"))?;
        let blob = hexutil::decode(&req.blob)
            .filter(|b| !b.is_empty())
            .ok_or_else(|| bad("bad blob"))?;
        let refs = parse_cids(&req.refs, "bad chunk id in refs")?;
        if store::payload_len(refs.len(), blob.len()) > store::MAX_PAYLOAD {
            return Err(bad("blob too large"));
        }
        let c = CommitIn {
            entry,
            base_rev: req.base_rev,
            rev: req.rev,
            blob,
            refs,
        };
        let seq = s.commit(vid, key, &c)?;
        Ok(Json(CommitResp { seq }))
    })
    .await
}

async fn missing(
    State(app): St,
    Path(vid): Path<String>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> Response {
    let body = body!(body);
    let sig = Signed::new(&method, &uri, &headers);
    signed_op(app, vid, sig, body, |s, vid, key, body| {
        let req: MissingReq = parse_json(body)?;
        let ids = parse_cids(&req.ids, "bad chunk id")?;
        let missing = s.missing(vid, key, &ids)?;
        Ok(Json(MissingResp {
            missing: missing.iter().map(|c| hex(c)).collect(),
        }))
    })
    .await
}

async fn prune(
    State(app): St,
    Path(vid): Path<String>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> Response {
    let body = body!(body);
    let sig = Signed::new(&method, &uri, &headers);
    signed_op(app, vid, sig, body, |s, vid, key, body| {
        let req: PruneReq = parse_json(body)?;
        let items = req
            .items
            .iter()
            .map(|it| Ok((parse_id16(&it.entry).ok_or_else(|| bad("bad entry id"))?, it.below)))
            .collect::<Result<Vec<_>, SErr>>()?;
        Ok(Json(s.prune(vid, key, &items)?))
    })
    .await
}

async fn usage(State(app): St, Path(vid): Path<String>, method: Method, uri: Uri, headers: HeaderMap) -> Response {
    let sig = Signed::new(&method, &uri, &headers);
    signed_op(app, vid, sig, Bytes::new(), |s, vid, key, _| {
        Ok(Json(s.usage(vid, key)?))
    })
    .await
}

async fn put_chunk(
    State(app): St,
    Path((vid, cid)): Path<(String, String)>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> Response {
    if parse_id16(&vid).is_none() {
        return bad_vid();
    }
    let Some(cid) = parse_cid(&cid) else {
        return err(StatusCode::BAD_REQUEST, "bad chunk id");
    };
    let body = body!(body);
    let sig = Signed::new(&method, &uri, &headers);
    signed_op(app, vid, sig, body, move |s, vid, key, body| {
        if blake3::hash(body).as_bytes() != &cid {
            return Err(bad("chunk hash mismatch"));
        }
        s.put_chunk(vid, key, &cid, body)?;
        Ok(ok_empty(StatusCode::OK))
    })
    .await
}

async fn get_chunk(
    State(app): St,
    Path((vid, cid)): Path<(String, String)>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
) -> Response {
    if parse_id16(&vid).is_none() {
        return bad_vid();
    }
    let Some(cid) = parse_cid(&cid) else {
        return err(StatusCode::BAD_REQUEST, "bad chunk id");
    };
    let sig = Signed::new(&method, &uri, &headers);
    signed_op(app, vid, sig, Bytes::new(), move |s, vid, key, _| {
        let b = s.get_chunk(vid, key, &cid)?;
        Ok(([(header::CONTENT_TYPE, "application/octet-stream")], b))
    })
    .await
}

async fn create_invite(
    State(app): St,
    Path(vid): Path<String>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> Response {
    let body = body!(body);
    let sig = Signed::new(&method, &uri, &headers);
    signed_op(app, vid, sig, body, |s, vid, key, body| {
        let req: InviteCreateReq = parse_json(body)?;
        invites::validate(&req, store::now_ms())?;
        s.edit_invites(vid, Some(key), &mut |l| invites::create(l, &req, store::now_ms()))?;
        Ok(ok_empty(StatusCode::CREATED))
    })
    .await
}

async fn list_invites(State(app): St, Path(vid): Path<String>, method: Method, uri: Uri, headers: HeaderMap) -> Response {
    let sig = Signed::new(&method, &uri, &headers);
    signed_op(app, vid, sig, Bytes::new(), |s, vid, key, _| {
        match s.edit_invites(vid, Some(key), &mut |l| invites::list_all(l, store::now_ms()))? {
            InviteOut::List(invites) => Ok(Json(InvitesResp { invites })),
            _ => Err(SErr::Internal("invite list".into())),
        }
    })
    .await
}

async fn revoke_invite(
    State(app): St,
    Path((vid, iid)): Path<(String, String)>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> Response {
    if !is_hex(&iid, 32) {
        return err(StatusCode::BAD_REQUEST, "bad invite id");
    }
    let body = body!(body);
    let sig = Signed::new(&method, &uri, &headers);
    signed_op(app, vid, sig, body, move |s, vid, key, _| {
        s.edit_invites(vid, Some(key), &mut |l| invites::revoke(l, &iid, store::now_ms()))?;
        Ok(ok_empty(StatusCode::OK))
    })
    .await
}

/// Signed with the invite's own claim key, not the vault key. Failed signatures and unknown ids
/// count as auth failures (rate-limited per vault); a valid claim is never refused for them.
async fn claim_invite(
    State(app): St,
    Path((vid, iid)): Path<(String, String)>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> Response {
    let Some(vid) = parse_id16(&vid) else { return bad_vid() };
    if !is_hex(&iid, 32) {
        return err(StatusCode::BAD_REQUEST, "bad invite id");
    }
    let body = body!(body);
    let sig = Signed::new(&method, &uri, &headers);
    blocking(move || {
        if let Err(r) = app.authenticate_claim(&vid, &iid, &sig, &body) {
            return r;
        }
        let req: InviteClaimReq = match parse_json(&body) {
            Ok(r) => r,
            Err(e) => return serr(e),
        };
        let res = app.store.edit_invites(&vid, None, &mut |l| {
            let k = invites::claim_key(l, &iid)?;
            if !sig.ok(&k, &body) {
                return Err(SErr::BadSig);
            }
            invites::claim(l, &iid, &req.nonce, store::now_ms())
        });
        match res {
            Ok(InviteOut::Blob(blob)) => Json(InviteClaimResp { blob }).into_response(),
            Ok(InviteOut::Gone(m)) => serr(SErr::Gone(m)),
            Ok(_) => serr(SErr::Internal("invite claim".into())),
            Err(e @ (SErr::BadSig | SErr::NoInvite)) => match app.authfail_rl.hit(&vid) {
                Ok(()) => serr(e),
                Err(ra) => too_many(ra),
            },
            Err(e) => serr(e),
        }
    })
    .await
}
