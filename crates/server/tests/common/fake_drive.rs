//! In-memory fake of the Drive v3 subset vaultaged uses (folder create, multipart upload,
//! download, metadata get, delete, list by parent with pagination) plus the OAuth token
//! endpoint (refresh and authorization-code grants). Every Drive call needs the current access
//! token. Fault injection: 503s, rate-limit 403s, lost replies, full storage.
#![allow(clippy::result_large_err)]

use std::collections::{BTreeMap, HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::body::Bytes;
use axum::extract::{Path, Query, Request, State};
use axum::http::{header, HeaderMap, Method, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde_json::{json, Value};

use super::fake_gcs::{parse_multipart, rfc3339};

pub const ROOT: &str = "rootFolder0";
pub const FOLDER: &str = "application/vnd.google-apps.folder";
pub const CLIENT_ID: &str = "test-client";
pub const CLIENT_SECRET: &str = "test-secret";
pub const REFRESH: &str = "test-refresh-token";
pub const GOOD_CODE: &str = "4/good-code";

#[derive(Clone)]
pub struct DFile {
    pub name: String,
    pub parent: Option<String>,
    pub mime: String,
    pub data: Vec<u8>,
    pub created_ms: i64,
}

#[derive(Default)]
pub struct DriveState {
    pub files: Mutex<BTreeMap<String, DFile>>,
    next: AtomicI64,
    /// Valid access tokens (every issued one, until `revoke_access`).
    pub access: Mutex<HashSet<String>>,
    pub refreshes: AtomicU32,
    pub fail_503: AtomicU32,
    pub rate_limit_403: AtomicU32,
    /// Next N mutating Drive requests: applied, then answered 503 (lost reply).
    pub drop_after_apply: AtomicU32,
    pub quota_full: AtomicBool,
    pub page_size: usize,
}

fn now_ms() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as i64
}

fn derr(code: StatusCode, reason: &str) -> Response {
    (
        code,
        Json(json!({"error": {"code": code.as_u16(), "message": reason, "errors": [{"reason": reason}]}})),
    )
        .into_response()
}

type St = State<Arc<DriveState>>;

impl DriveState {
    fn add(&self, f: DFile) -> String {
        let id = format!("f{:06}x", self.next.fetch_add(1, Ordering::SeqCst));
        self.files.lock().unwrap().insert(id.clone(), f);
        id
    }

    fn parent_ok(&self, p: Option<&str>) -> bool {
        p.is_none_or(|p| self.files.lock().unwrap().get(p).is_some_and(|f| f.mime == FOLDER))
    }
}

fn form_get(body: &[u8], key: &str) -> Option<String> {
    let s = String::from_utf8_lossy(body);
    s.split('&').find_map(|kv| {
        let (k, v) = kv.split_once('=')?;
        (k == key).then(|| decode(v))
    })
}

pub fn decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            out.push(u8::from_str_radix(&s[i + 1..i + 3], 16).unwrap());
            i += 3;
        } else {
            out.push(if b[i] == b'+' { b' ' } else { b[i] });
            i += 1;
        }
    }
    String::from_utf8(out).unwrap()
}

async fn token(State(s): St, body: Bytes) -> Response {
    let ok = |s: &DriveState, with_refresh: bool| {
        s.refreshes.fetch_add(1, Ordering::SeqCst);
        let t = format!("at-{}", s.refreshes.load(Ordering::SeqCst));
        s.access.lock().unwrap().insert(t.clone());
        let mut v = json!({"access_token": t, "expires_in": 3599, "token_type": "Bearer"});
        if with_refresh {
            v["refresh_token"] = REFRESH.into();
        }
        Json(v).into_response()
    };
    let bad = || (StatusCode::BAD_REQUEST, Json(json!({"error": "invalid_grant"}))).into_response();
    if form_get(&body, "client_id").as_deref() != Some(CLIENT_ID)
        || form_get(&body, "client_secret").as_deref() != Some(CLIENT_SECRET)
    {
        return (StatusCode::UNAUTHORIZED, Json(json!({"error": "invalid_client"}))).into_response();
    }
    match form_get(&body, "grant_type").as_deref() {
        Some("refresh_token") if form_get(&body, "refresh_token").as_deref() == Some(REFRESH) => ok(&s, false),
        Some("authorization_code")
            if form_get(&body, "code").as_deref() == Some(GOOD_CODE)
                && form_get(&body, "redirect_uri").is_some_and(|r| r.starts_with("http://127.0.0.1:")) =>
        {
            ok(&s, true)
        }
        _ => bad(),
    }
}

async fn create(State(s): St, body: Bytes) -> Response {
    let Ok(v) = serde_json::from_slice::<Value>(&body) else {
        return derr(StatusCode::BAD_REQUEST, "badRequest");
    };
    let parent = v["parents"][0].as_str().map(str::to_owned);
    if !s.parent_ok(parent.as_deref()) {
        return derr(StatusCode::NOT_FOUND, "notFound");
    }
    let id = s.add(DFile {
        name: v["name"].as_str().unwrap_or("Untitled").to_owned(),
        parent,
        mime: v["mimeType"].as_str().unwrap_or("application/octet-stream").to_owned(),
        data: vec![],
        created_ms: now_ms(),
    });
    Json(json!({ "id": id })).into_response()
}

async fn upload(State(s): St, Query(q): Query<HashMap<String, String>>, headers: HeaderMap, body: Bytes) -> Response {
    if q.get("uploadType").map(String::as_str) != Some("multipart") {
        return derr(StatusCode::BAD_REQUEST, "badRequest");
    }
    let ctype = headers.get(header::CONTENT_TYPE).and_then(|v| v.to_str().ok()).unwrap_or("");
    let Some((meta, data)) = parse_multipart(ctype, &body) else {
        return derr(StatusCode::BAD_REQUEST, "badMultipart");
    };
    if data.len() > 5 << 20 {
        return derr(StatusCode::PAYLOAD_TOO_LARGE, "uploadTooLarge");
    }
    if s.quota_full.load(Ordering::SeqCst) {
        return derr(StatusCode::FORBIDDEN, "storageQuotaExceeded");
    }
    let parent = meta["parents"][0].as_str().map(str::to_owned);
    if !s.parent_ok(parent.as_deref()) {
        return derr(StatusCode::NOT_FOUND, "notFound");
    }
    let id = s.add(DFile {
        name: meta["name"].as_str().unwrap_or("Untitled").to_owned(),
        parent,
        mime: "application/octet-stream".into(),
        data,
        created_ms: now_ms(),
    });
    Json(json!({ "id": id })).into_response()
}

async fn get_file(State(s): St, Path(id): Path<String>, Query(q): Query<HashMap<String, String>>) -> Response {
    let files = s.files.lock().unwrap();
    let Some(f) = files.get(&id) else {
        return derr(StatusCode::NOT_FOUND, "notFound");
    };
    if q.get("alt").map(String::as_str) == Some("media") {
        if f.mime == FOLDER {
            return derr(StatusCode::FORBIDDEN, "fileNotDownloadable");
        }
        return ([(header::CONTENT_TYPE, "application/octet-stream")], f.data.clone()).into_response();
    }
    Json(json!({"id": id, "name": f.name, "mimeType": f.mime, "trashed": false})).into_response()
}

async fn delete_file(State(s): St, Path(id): Path<String>) -> Response {
    let mut files = s.files.lock().unwrap();
    if files.remove(&id).is_none() {
        return derr(StatusCode::NOT_FOUND, "notFound");
    }
    // Like Drive: a folder's contents go with it.
    let mut gone = vec![id];
    while let Some(p) = gone.pop() {
        let kids: Vec<String> = files
            .iter()
            .filter(|(_, f)| f.parent.as_deref() == Some(&p))
            .map(|(k, _)| k.clone())
            .collect();
        for k in kids {
            files.remove(&k);
            gone.push(k);
        }
    }
    StatusCode::NO_CONTENT.into_response()
}

async fn list(State(s): St, Query(q): Query<HashMap<String, String>>) -> Response {
    // Only the shape vaultaged sends: "'<id>' in parents and trashed = false".
    let query = q.get("q").cloned().unwrap_or_default();
    let Some(parent) = query
        .strip_prefix('\'')
        .and_then(|r| r.split_once("' in parents and trashed = false"))
        .map(|(p, _)| p.to_owned())
    else {
        return derr(StatusCode::BAD_REQUEST, "invalidQuery");
    };
    let max = q
        .get("pageSize")
        .and_then(|m| m.parse::<usize>().ok())
        .unwrap_or(100)
        .min(s.page_size.max(1));
    let after = q.get("pageToken").cloned();
    let files = s.files.lock().unwrap();
    let mut out = Vec::new();
    let mut next = None;
    for (id, f) in files.iter() {
        if f.parent.as_deref() != Some(&parent) || after.as_ref().is_some_and(|a| id <= a) {
            continue;
        }
        if out.len() == max {
            next = Some(out.last().map(|(i, _): &(String, Value)| i.clone()).unwrap());
            break;
        }
        out.push((
            id.clone(),
            json!({"id": id, "name": f.name, "createdTime": rfc3339(f.created_ms)}),
        ));
    }
    let mut v = json!({"files": out.into_iter().map(|(_, v)| v).collect::<Vec<_>>()});
    if let Some(n) = next {
        v["nextPageToken"] = n.into();
    }
    Json(v).into_response()
}

async fn gate(State(s): St, req: Request, next: Next) -> Response {
    let path = req.uri().path().to_owned();
    if path == "/token" {
        return next.run(req).await;
    }
    let dec = |a: &AtomicU32| a.try_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1)).is_ok();
    let got = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok()?.strip_prefix("Bearer "))
        .map(str::to_owned);
    if !got.is_some_and(|t| s.access.lock().unwrap().contains(&t)) {
        return derr(StatusCode::UNAUTHORIZED, "authError");
    }
    if dec(&s.fail_503) {
        return derr(StatusCode::SERVICE_UNAVAILABLE, "backendError");
    }
    if dec(&s.rate_limit_403) {
        return derr(StatusCode::FORBIDDEN, "userRateLimitExceeded");
    }
    let mutating = matches!(*req.method(), Method::POST | Method::PATCH | Method::DELETE);
    let resp = next.run(req).await;
    if mutating && resp.status().is_success() && dec(&s.drop_after_apply) {
        return derr(StatusCode::SERVICE_UNAVAILABLE, "backendError");
    }
    resp
}

pub struct FakeDrive {
    pub addr: SocketAddr,
    pub state: Arc<DriveState>,
    stop: Option<tokio::sync::oneshot::Sender<()>>,
    thread: Option<JoinHandle<()>>,
}

impl FakeDrive {
    /// With the root folder `ROOT` (as `vaultaged gdrive-login` would have made it).
    pub fn start() -> FakeDrive {
        let state = Arc::new(DriveState {
            page_size: 5,
            ..Default::default()
        });
        state.files.lock().unwrap().insert(
            ROOT.into(),
            DFile {
                name: "Vaultage".into(),
                parent: None,
                mime: FOLDER.into(),
                data: vec![],
                created_ms: now_ms(),
            },
        );
        let app = Router::new()
            .route("/token", post(token))
            .route("/drive/v3/files", post(create).get(list))
            .route("/drive/v3/files/{id}", get(get_file).delete(delete_file))
            .route("/upload/drive/v3/files", post(upload))
            .layer(axum::extract::DefaultBodyLimit::max(16 << 20))
            .layer(middleware::from_fn_with_state(state.clone(), gate))
            .with_state(state.clone());
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let addr = listener.local_addr().unwrap();
        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        let thread = std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_all()
                .build()
                .unwrap();
            rt.block_on(async move {
                let l = tokio::net::TcpListener::from_std(listener).unwrap();
                axum::serve(l, app)
                    .with_graceful_shutdown(async {
                        let _ = rx.await;
                    })
                    .await
                    .unwrap();
            });
        });
        FakeDrive {
            addr,
            state,
            stop: Some(tx),
            thread: Some(thread),
        }
    }

    pub fn endpoint(&self) -> String {
        format!("http://{}", self.addr)
    }

    /// Non-folder files: id → file.
    pub fn blobs(&self) -> BTreeMap<String, DFile> {
        self.state
            .files
            .lock()
            .unwrap()
            .iter()
            .filter(|(_, f)| f.mime != FOLDER)
            .map(|(k, f)| (k.clone(), f.clone()))
            .collect()
    }

    pub fn folders(&self) -> usize {
        self.state.files.lock().unwrap().values().filter(|f| f.mime == FOLDER).count()
    }

    pub fn exists(&self, id: &str) -> bool {
        self.state.files.lock().unwrap().contains_key(id)
    }

    /// Make every file look `secs` old.
    pub fn age(&self, secs: u64) {
        for f in self.state.files.lock().unwrap().values_mut() {
            f.created_ms -= secs as i64 * 1000;
        }
    }

    /// Invalidate every issued access token (as if they expired early).
    pub fn revoke_access(&self) {
        self.state.access.lock().unwrap().clear();
    }

    pub fn all_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        for (id, f) in self.state.files.lock().unwrap().iter() {
            out.extend_from_slice(id.as_bytes());
            out.extend_from_slice(f.name.as_bytes());
            out.extend_from_slice(&f.data);
        }
        out
    }
}

impl Drop for FakeDrive {
    fn drop(&mut self) {
        if let Some(tx) = self.stop.take() {
            let _ = tx.send(());
        }
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}
