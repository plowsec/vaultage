//! In-memory fake of the GCS JSON API subset vaultaged uses: media/multipart insert, get
//! (media + metadata), metadata patch, delete, list (prefix, startOffset, pagination), with
//! generation/metageneration preconditions (412) and fault injection.
#![allow(clippy::result_large_err)]

use std::collections::{BTreeMap, HashMap};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicI64, AtomicU32, Ordering};
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

#[derive(Clone)]
pub struct FObj {
    pub data: Vec<u8>,
    pub gen: i64,
    pub metagen: i64,
    pub created_ms: i64,
    pub updated_ms: i64,
    pub metadata: BTreeMap<String, String>,
}

#[derive(Default)]
pub struct FakeState {
    /// key: "<bucket>/<name>"
    pub objs: Mutex<BTreeMap<String, FObj>>,
    next_gen: AtomicI64,
    /// Next N requests: 503 without applying.
    pub fail_503: AtomicU32,
    /// Next N mutating requests (POST/PATCH/DELETE): applied, then answered 503 (lost reply).
    pub drop_after_apply: AtomicU32,
    /// Max items per list page (exercises pagination).
    pub page_size: usize,
}

fn now_ms() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as i64
}

pub fn rfc3339(ms: i64) -> String {
    let (secs, milli) = (ms.div_euclid(1000), ms.rem_euclid(1000));
    let (days, sod) = (secs.div_euclid(86_400), secs.rem_euclid(86_400));
    // civil from days (Howard Hinnant)
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}.{milli:03}Z",
        sod / 3600,
        sod % 3600 / 60,
        sod % 60
    )
}

fn resource(bucket: &str, name: &str, o: &FObj) -> Value {
    let mut v = json!({
        "kind": "storage#object",
        "bucket": bucket,
        "name": name,
        "generation": o.gen.to_string(),
        "metageneration": o.metagen.to_string(),
        "size": o.data.len().to_string(),
        "timeCreated": rfc3339(o.created_ms),
        "updated": rfc3339(o.updated_ms),
        "contentType": "application/octet-stream",
    });
    if !o.metadata.is_empty() {
        v["metadata"] = json!(o.metadata);
    }
    v
}

fn gerr(code: StatusCode, msg: &str) -> Response {
    (code, Json(json!({"error": {"code": code.as_u16(), "message": msg}}))).into_response()
}

fn q_i64(q: &HashMap<String, String>, k: &str) -> Result<Option<i64>, Response> {
    match q.get(k) {
        None => Ok(None),
        Some(v) => v
            .parse()
            .map(Some)
            .map_err(|_| gerr(StatusCode::BAD_REQUEST, "bad number")),
    }
}

/// Generation/metageneration preconditions against the current object (None = absent).
fn check_pre(q: &HashMap<String, String>, cur: Option<&FObj>) -> Result<(), Response> {
    if let Some(g) = q_i64(q, "ifGenerationMatch")? {
        let ok = match cur {
            None => g == 0,
            Some(o) => o.gen == g,
        };
        if !ok {
            return Err(gerr(StatusCode::PRECONDITION_FAILED, "generation mismatch"));
        }
    }
    if let Some(m) = q_i64(q, "ifMetagenerationMatch")? {
        if cur.is_none_or(|o| o.metagen != m) {
            return Err(gerr(StatusCode::PRECONDITION_FAILED, "metageneration mismatch"));
        }
    }
    Ok(())
}

type St = State<Arc<FakeState>>;

fn find(hay: &[u8], needle: &[u8], from: usize) -> Option<usize> {
    hay.get(from..)?
        .windows(needle.len())
        .position(|w| w == needle)
        .map(|p| p + from)
}

/// multipart/related: JSON metadata part, then media part.
pub fn parse_multipart(ctype: &str, body: &[u8]) -> Option<(Value, Vec<u8>)> {
    let b = ctype.split("boundary=").nth(1)?.trim_matches('"');
    let delim = format!("--{b}");
    let p1 = find(body, delim.as_bytes(), 0)?;
    let h1 = find(body, b"\r\n\r\n", p1)? + 4;
    let e1 = find(body, format!("\r\n{delim}").as_bytes(), h1)?;
    let meta: Value = serde_json::from_slice(&body[h1..e1]).ok()?;
    let h2 = find(body, b"\r\n\r\n", e1 + 2)? + 4;
    let close = format!("\r\n{delim}--");
    let e2 = body.windows(close.len()).rposition(|w| w == close.as_bytes())?;
    (e2 >= h2).then(|| (meta, body[h2..e2].to_vec()))
}

async fn insert(
    State(s): St,
    Path(bucket): Path<String>,
    Query(q): Query<HashMap<String, String>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let ctype = headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let (name, metadata, data) = match q.get("uploadType").map(String::as_str) {
        Some("media") => match q.get("name") {
            Some(n) => (n.clone(), BTreeMap::new(), body.to_vec()),
            None => return gerr(StatusCode::BAD_REQUEST, "name required"),
        },
        Some("multipart") => {
            let Some((meta, data)) = parse_multipart(ctype, &body) else {
                return gerr(StatusCode::BAD_REQUEST, "bad multipart");
            };
            let Some(name) = meta["name"]
                .as_str()
                .map(str::to_owned)
                .or_else(|| q.get("name").cloned())
            else {
                return gerr(StatusCode::BAD_REQUEST, "name required");
            };
            let md = meta["metadata"]
                .as_object()
                .map(|m| {
                    m.iter()
                        .filter_map(|(k, v)| Some((k.clone(), v.as_str()?.to_owned())))
                        .collect()
                })
                .unwrap_or_default();
            (name, md, data)
        }
        _ => return gerr(StatusCode::BAD_REQUEST, "unsupported uploadType"),
    };
    let key = format!("{bucket}/{name}");
    let mut objs = s.objs.lock().unwrap();
    if let Err(r) = check_pre(&q, objs.get(&key)) {
        return r;
    }
    let now = now_ms();
    let o = FObj {
        data,
        gen: s.next_gen.fetch_add(1, Ordering::SeqCst) + 1_000_000,
        metagen: 1,
        created_ms: now,
        updated_ms: now,
        metadata,
    };
    let v = resource(&bucket, &name, &o);
    objs.insert(key, o);
    Json(v).into_response()
}

async fn get_obj(
    State(s): St,
    Path((bucket, name)): Path<(String, String)>,
    Query(q): Query<HashMap<String, String>>,
) -> Response {
    let objs = s.objs.lock().unwrap();
    let Some(o) = objs.get(&format!("{bucket}/{name}")) else {
        return gerr(StatusCode::NOT_FOUND, "no such object");
    };
    if let Err(r) = check_pre(&q, Some(o)) {
        return r;
    }
    if q.get("alt").map(String::as_str) == Some("media") {
        return (
            [
                (header::CONTENT_TYPE, "application/octet-stream".to_owned()),
                (header::HeaderName::from_static("x-goog-generation"), o.gen.to_string()),
            ],
            o.data.clone(),
        )
            .into_response();
    }
    Json(resource(&bucket, &name, o)).into_response()
}

async fn patch_obj(
    State(s): St,
    Path((bucket, name)): Path<(String, String)>,
    Query(q): Query<HashMap<String, String>>,
    body: Bytes,
) -> Response {
    let Ok(v) = serde_json::from_slice::<Value>(&body) else {
        return gerr(StatusCode::BAD_REQUEST, "bad json");
    };
    let mut objs = s.objs.lock().unwrap();
    let Some(o) = objs.get_mut(&format!("{bucket}/{name}")) else {
        return gerr(StatusCode::NOT_FOUND, "no such object");
    };
    if let Err(r) = check_pre(&q, Some(o)) {
        return r;
    }
    if let Some(m) = v["metadata"].as_object() {
        for (k, val) in m {
            match val.as_str() {
                Some(sv) => {
                    o.metadata.insert(k.clone(), sv.to_owned());
                }
                None => {
                    o.metadata.remove(k);
                }
            }
        }
    }
    o.metagen += 1;
    o.updated_ms = now_ms();
    Json(resource(&bucket, &name, o)).into_response()
}

async fn delete_obj(
    State(s): St,
    Path((bucket, name)): Path<(String, String)>,
    Query(q): Query<HashMap<String, String>>,
) -> Response {
    let key = format!("{bucket}/{name}");
    let mut objs = s.objs.lock().unwrap();
    let Some(o) = objs.get(&key) else {
        return gerr(StatusCode::NOT_FOUND, "no such object");
    };
    if let Err(r) = check_pre(&q, Some(o)) {
        return r;
    }
    objs.remove(&key);
    StatusCode::NO_CONTENT.into_response()
}

async fn list(State(s): St, Path(bucket): Path<String>, Query(q): Query<HashMap<String, String>>) -> Response {
    let prefix = q.get("prefix").cloned().unwrap_or_default();
    let max = q
        .get("maxResults")
        .and_then(|m| m.parse::<usize>().ok())
        .unwrap_or(1000)
        .min(s.page_size.max(1));
    let bp = format!("{bucket}/");
    let mut from = format!("{bp}{prefix}");
    if let Some(so) = q.get("startOffset") {
        from = from.max(format!("{bp}{so}"));
    }
    // Page token = last name returned; continue strictly after it.
    let after = q.get("pageToken").map(|t| format!("{bp}{t}"));
    let objs = s.objs.lock().unwrap();
    let mut items = Vec::new();
    let mut next = None;
    for (k, o) in objs.range(from..) {
        if !k.starts_with(&format!("{bp}{prefix}")) {
            break;
        }
        if after.as_ref().is_some_and(|a| k <= a) {
            continue;
        }
        if items.len() == max {
            next = Some(items.last().map(|(n, _): &(String, Value)| n.clone()).unwrap());
            break;
        }
        let name = k[bp.len()..].to_owned();
        items.push((name.clone(), resource(&bucket, &name, o)));
    }
    let mut v = json!({"kind": "storage#objects"});
    if !items.is_empty() {
        v["items"] = Value::Array(items.into_iter().map(|(_, r)| r).collect());
    }
    if let Some(n) = next {
        v["nextPageToken"] = n.into();
    }
    Json(v).into_response()
}

async fn faults(State(s): St, req: Request, next: Next) -> Response {
    let dec = |a: &AtomicU32| {
        a.try_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1))
            .is_ok()
    };
    if dec(&s.fail_503) {
        return gerr(StatusCode::SERVICE_UNAVAILABLE, "injected");
    }
    let mutating = matches!(*req.method(), Method::POST | Method::PATCH | Method::DELETE);
    let resp = next.run(req).await;
    if mutating && resp.status().is_success() && dec(&s.drop_after_apply) {
        return gerr(StatusCode::SERVICE_UNAVAILABLE, "injected after apply");
    }
    resp
}

pub struct FakeGcs {
    pub addr: SocketAddr,
    pub state: Arc<FakeState>,
    stop: Option<tokio::sync::oneshot::Sender<()>>,
    thread: Option<JoinHandle<()>>,
}

impl FakeGcs {
    pub fn start() -> FakeGcs {
        let state = Arc::new(FakeState {
            page_size: 7,
            ..Default::default()
        });
        let app = Router::new()
            .route("/upload/storage/v1/b/{bucket}/o", post(insert))
            .route("/storage/v1/b/{bucket}/o", get(list))
            .route(
                "/storage/v1/b/{bucket}/o/{name}",
                get(get_obj).patch(patch_obj).delete(delete_obj),
            )
            .layer(axum::extract::DefaultBodyLimit::max(128 << 20))
            .layer(middleware::from_fn_with_state(state.clone(), faults))
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
        FakeGcs {
            addr,
            state,
            stop: Some(tx),
            thread: Some(thread),
        }
    }

    pub fn endpoint(&self) -> String {
        format!("http://{}", self.addr)
    }

    /// Names (without bucket) starting with `prefix`.
    pub fn names(&self, prefix: &str) -> Vec<String> {
        self.state
            .objs
            .lock()
            .unwrap()
            .keys()
            .filter_map(|k| k.split_once('/').map(|(_, n)| n.to_owned()))
            .filter(|n| n.starts_with(prefix))
            .collect()
    }

    pub fn with_obj<T>(&self, name: &str, f: impl FnOnce(Option<&mut FObj>) -> T) -> T {
        let mut objs = self.state.objs.lock().unwrap();
        let key = objs
            .keys()
            .find(|k| k.split_once('/').is_some_and(|(_, n)| n == name))
            .cloned();
        f(key.and_then(|k| objs.get_mut(&k)))
    }

    /// Every live object's data and metadata, concatenated.
    pub fn all_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        for (k, o) in self.state.objs.lock().unwrap().iter() {
            out.extend_from_slice(k.as_bytes());
            out.extend_from_slice(&o.data);
            for (a, b) in &o.metadata {
                out.extend_from_slice(a.as_bytes());
                out.extend_from_slice(b.as_bytes());
            }
        }
        out
    }
}

impl Drop for FakeGcs {
    fn drop(&mut self) {
        if let Some(tx) = self.stop.take() {
            let _ = tx.send(());
        }
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}
