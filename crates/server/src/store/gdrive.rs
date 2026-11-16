//! Google Drive API v3 client: chunk bytes for the GCS store (see gcs.rs, "Drive chunks").
//!
//! TESTED ONLY AGAINST THE IN-PROCESS FAKE in tests/common/fake_drive.rs, not real Drive.
//!
//! Drive has no conditional writes and file names are not unique, so Drive decides nothing:
//! each file is written once, never changed, and found by the id a GCS object records.
//! A retried upload whose first reply was lost leaves an unreferenced file; prune sweeps those.

use std::collections::HashMap;
use std::io;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use super::gcs::{enc, jitter_ms, lock, parse_rfc3339};
use super::{Cid, Id16};
use crate::DriveConfig;

const DEFAULT_ENDPOINT: &str = "https://www.googleapis.com";
pub const DEFAULT_TOKEN_URL: &str = "https://oauth2.googleapis.com/token";
pub const SCOPE: &str = "https://www.googleapis.com/auth/drive.file";
pub const FOLDER_MIME: &str = "application/vnd.google-apps.folder";
const ATTEMPTS: u32 = 6;
const MAX_BODY: u64 = 64 << 20;
/// Bound on the (vault, chunk) → file id cache.
const MAX_IDS: usize = 200_000;

#[derive(Debug)]
pub enum DErr {
    /// Retries exhausted / transport / auth failure.
    Unavailable(String),
    /// The Drive owner's storage is full.
    Quota,
    Other(String),
}

pub type D<T> = Result<T, DErr>;

pub struct DFile {
    pub id: String,
    pub created_ms: i64,
}

enum Auth {
    None,
    Static(String),
    Refresh {
        client_id: String,
        client_secret: String,
        refresh_token: String,
        cache: Mutex<Option<(String, Instant)>>,
    },
}

pub struct Drive {
    agent: ureq::Agent,
    base: String,
    token_url: String,
    auth: Auth,
}

struct Resp {
    status: u16,
    body: Vec<u8>,
}

/// Drive ids are `[A-Za-z0-9_-]`; anything else could break out of a query string.
pub fn id_ok(id: &str) -> bool {
    !id.is_empty() && id.len() <= 200 && id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

fn json(b: &[u8]) -> D<serde_json::Value> {
    serde_json::from_slice(b).map_err(|_| DErr::Other("gdrive: bad json".into()))
}

fn snippet(b: &[u8]) -> String {
    String::from_utf8_lossy(&b[..b.len().min(300)]).into_owned()
}

fn rate_limited(r: &Resp) -> bool {
    r.status == 403 && String::from_utf8_lossy(&r.body).contains("ateLimitExceeded")
}

/// `application/x-www-form-urlencoded` body.
pub fn form(pairs: &[(&str, &str)]) -> String {
    pairs.iter().map(|(k, v)| format!("{}={}", enc(k), enc(v))).collect::<Vec<_>>().join("&")
}

pub fn agent() -> ureq::Agent {
    ureq::Agent::config_builder()
        .http_status_as_error(false)
        .timeout_connect(Some(Duration::from_secs(10)))
        .timeout_global(Some(Duration::from_secs(120)))
        .build()
        .into()
}

/// Exchange a refresh token (or, with `code`, an authorization code) at the token endpoint.
/// Returns the parsed JSON on 200.
pub fn token_request(agent: &ureq::Agent, url: &str, body: &str) -> Result<serde_json::Value, String> {
    let mut r = agent
        .post(url)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .send(body.as_bytes())
        .map_err(|e| format!("token endpoint: {e}"))?;
    let status = r.status().as_u16();
    let b = r
        .body_mut()
        .with_config()
        .limit(1 << 20)
        .read_to_vec()
        .map_err(|e| format!("token endpoint: {e}"))?;
    let v: serde_json::Value = serde_json::from_slice(&b).unwrap_or(serde_json::Value::Null);
    if status != 200 {
        let code = v["error"].as_str().unwrap_or("");
        return Err(format!("token endpoint: HTTP {status} {code}"));
    }
    Ok(v)
}

impl Drive {
    pub fn new(cfg: &DriveConfig) -> io::Result<Drive> {
        if !id_ok(&cfg.folder) {
            return Err(io::Error::other(format!("gdrive: bad folder id {:?}", cfg.folder)));
        }
        let base = match &cfg.endpoint {
            Some(e) if e.contains("://") => e.trim_end_matches('/').to_owned(),
            Some(e) => format!("http://{}", e.trim_end_matches('/')),
            None => DEFAULT_ENDPOINT.to_owned(),
        };
        let auth = match (&cfg.token, &cfg.client_id, &cfg.client_secret, &cfg.refresh_token) {
            (Some(t), ..) => Auth::Static(t.clone()),
            (None, Some(id), Some(secret), Some(rt)) => Auth::Refresh {
                client_id: id.clone(),
                client_secret: secret.clone(),
                refresh_token: rt.clone(),
                cache: Mutex::new(None),
            },
            (None, None, None, None) if cfg.endpoint.is_some() => Auth::None,
            _ => {
                return Err(io::Error::other(
                    "gdrive: need VAULTAGE_GDRIVE_CLIENT_ID, VAULTAGE_GDRIVE_CLIENT_SECRET and VAULTAGE_GDRIVE_REFRESH_TOKEN",
                ))
            }
        };
        Ok(Drive {
            agent: agent(),
            base,
            token_url: cfg.token_url.clone().unwrap_or_else(|| DEFAULT_TOKEN_URL.to_owned()),
            auth,
        })
    }

    fn token(&self) -> D<Option<String>> {
        let (client_id, client_secret, refresh_token, cache) = match &self.auth {
            Auth::None => return Ok(None),
            Auth::Static(t) => return Ok(Some(t.clone())),
            Auth::Refresh {
                client_id,
                client_secret,
                refresh_token,
                cache,
            } => (client_id, client_secret, refresh_token, cache),
        };
        let mut c = lock(cache);
        if let Some((t, exp)) = &*c {
            if Instant::now() < *exp {
                return Ok(Some(t.clone()));
            }
        }
        let body = form(&[
            ("client_id", client_id),
            ("client_secret", client_secret),
            ("refresh_token", refresh_token),
            ("grant_type", "refresh_token"),
        ]);
        let v = token_request(&self.agent, &self.token_url, &body).map_err(|e| {
            let hint = if e.contains("invalid_grant") {
                " (refresh token revoked or expired: run `vaultaged gdrive-login` again)"
            } else {
                ""
            };
            DErr::Unavailable(format!("gdrive {e}{hint}"))
        })?;
        let t = v["access_token"]
            .as_str()
            .ok_or_else(|| DErr::Unavailable("gdrive token: no access_token".into()))?
            .to_owned();
        let ttl = v["expires_in"].as_u64().unwrap_or(300);
        *c = Some((t.clone(), Instant::now() + Duration::from_secs(ttl.saturating_sub(60).max(10))));
        Ok(Some(t))
    }

    fn drop_token(&self) {
        if let Auth::Refresh { cache, .. } = &self.auth {
            *lock(cache) = None;
        }
    }

    /// Run with retries on transport errors, 401 (fresh token), 408, 429, 5xx and 403 rate
    /// limits. Uploads are not idempotent: a retry after a lost reply makes a second file.
    fn exec(
        &self,
        what: &str,
        f: impl Fn(Option<&str>) -> Result<ureq::http::Response<ureq::Body>, ureq::Error>,
    ) -> D<Resp> {
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
                    last = format!("gdrive {what}: {e}");
                    continue;
                }
            };
            let status = r.status().as_u16();
            let body = match r.body_mut().with_config().limit(MAX_BODY).read_to_vec() {
                Ok(b) => b,
                Err(e) => {
                    last = format!("gdrive {what}: read body: {e}");
                    continue;
                }
            };
            let resp = Resp { status, body };
            if status == 401 && !matches!(self.auth, Auth::None) {
                self.drop_token();
                last = format!("gdrive {what}: HTTP 401");
                continue;
            }
            if status == 408 || status == 429 || status >= 500 || rate_limited(&resp) {
                last = format!("gdrive {what}: HTTP {status}");
                continue;
            }
            return Ok(resp);
        }
        Err(DErr::Unavailable(last))
    }

    fn fail(what: &str, r: &Resp) -> DErr {
        let msg = snippet(&r.body);
        if r.status == 403 && msg.contains("storageQuotaExceeded") {
            return DErr::Quota;
        }
        DErr::Other(format!("gdrive {what}: HTTP {}: {msg}", r.status))
    }

    fn file_url(&self, id: &str) -> String {
        format!("{}/drive/v3/files/{}", self.base, enc(id))
    }

    /// The folder exists, is a folder, is not trashed and is visible to this client.
    pub fn check_folder(&self, id: &str) -> D<()> {
        let url = format!("{}?fields={}", self.file_url(id), enc("id,mimeType,trashed"));
        let r = self.exec("check folder", |b| {
            let mut q = self.agent.get(&url);
            if let Some(b) = b {
                q = q.header("Authorization", b);
            }
            q.call()
        })?;
        if r.status == 404 {
            return Err(DErr::Other(format!(
                "gdrive: folder {id} not found (it must be created by this OAuth client: `vaultaged gdrive-login`)"
            )));
        }
        if r.status != 200 {
            return Err(Self::fail("check folder", &r));
        }
        let v = json(&r.body)?;
        if v["mimeType"].as_str() != Some(FOLDER_MIME) || v["trashed"].as_bool() == Some(true) {
            return Err(DErr::Other(format!("gdrive: {id} is not a live folder")));
        }
        Ok(())
    }

    /// New folder; returns its id.
    pub fn create_folder(&self, name: &str, parent: Option<&str>) -> D<String> {
        let mut doc = serde_json::json!({ "name": name, "mimeType": FOLDER_MIME });
        if let Some(p) = parent {
            doc["parents"] = serde_json::json!([p]);
        }
        let body = doc.to_string();
        let url = format!("{}/drive/v3/files?fields=id", self.base);
        let r = self.exec("create folder", |b| {
            let mut q = self.agent.post(&url).header("Content-Type", "application/json");
            if let Some(b) = b {
                q = q.header("Authorization", b);
            }
            q.send(body.as_bytes())
        })?;
        if r.status != 200 {
            return Err(Self::fail("create folder", &r));
        }
        Self::id_of(&r)
    }

    fn id_of(r: &Resp) -> D<String> {
        let v = json(&r.body)?;
        match v["id"].as_str() {
            Some(id) if id_ok(id) => Ok(id.to_owned()),
            _ => Err(DErr::Other("gdrive: reply without a valid id".into())),
        }
    }

    /// New file with `data` (≤ 5 MB, multipart upload); returns its id.
    pub fn upload(&self, name: &str, parent: &str, data: &[u8]) -> D<String> {
        let doc = serde_json::json!({ "name": name, "parents": [parent] });
        let boundary = format!("coffer{}", &blake3::hash(data).to_hex()[..32]);
        let mut body = Vec::with_capacity(data.len() + 512);
        body.extend_from_slice(format!("--{boundary}\r\nContent-Type: application/json; charset=UTF-8\r\n\r\n").as_bytes());
        body.extend_from_slice(doc.to_string().as_bytes());
        body.extend_from_slice(format!("\r\n--{boundary}\r\nContent-Type: application/octet-stream\r\n\r\n").as_bytes());
        body.extend_from_slice(data);
        body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
        let ctype = format!("multipart/related; boundary={boundary}");
        let url = format!("{}/upload/drive/v3/files?uploadType=multipart&fields=id", self.base);
        let r = self.exec("upload", |b| {
            let mut q = self.agent.post(&url).header("Content-Type", &ctype);
            if let Some(b) = b {
                q = q.header("Authorization", b);
            }
            q.send(&body[..])
        })?;
        if r.status != 200 {
            return Err(Self::fail("upload", &r));
        }
        Self::id_of(&r)
    }

    /// File bytes; None on 404.
    pub fn download(&self, id: &str) -> D<Option<Vec<u8>>> {
        let url = format!("{}?alt=media", self.file_url(id));
        let r = self.exec("download", |b| {
            let mut q = self.agent.get(&url);
            if let Some(b) = b {
                q = q.header("Authorization", b);
            }
            q.call()
        })?;
        match r.status {
            200 => Ok(Some(r.body)),
            404 => Ok(None),
            _ => Err(Self::fail("download", &r)),
        }
    }

    /// Permanent delete (no trash). false on 404.
    pub fn delete(&self, id: &str) -> D<bool> {
        let url = self.file_url(id);
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

    /// Children of a folder (not trashed). Drive's listing may lag recent writes: use it only
    /// to find candidates, never to decide whether something exists.
    pub fn list_children(&self, parent: &str) -> D<Vec<DFile>> {
        if !id_ok(parent) {
            return Err(DErr::Other(format!("gdrive: bad folder id {parent:?}")));
        }
        let q = format!("'{parent}' in parents and trashed = false");
        let mut out = Vec::new();
        let mut page: Option<String> = None;
        loop {
            let mut url = format!(
                "{}/drive/v3/files?q={}&pageSize=1000&fields={}",
                self.base,
                enc(&q),
                enc("nextPageToken,files(id,createdTime)")
            );
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
            for f in v["files"].as_array().map(Vec::as_slice).unwrap_or_default() {
                let bad = || DErr::Other("gdrive: malformed file resource".into());
                let id = f["id"].as_str().filter(|i| id_ok(i)).ok_or_else(bad)?;
                out.push(DFile {
                    id: id.to_owned(),
                    created_ms: f["createdTime"].as_str().and_then(parse_rfc3339).ok_or_else(bad)?,
                });
            }
            match v["nextPageToken"].as_str() {
                Some(p) if !p.is_empty() => page = Some(p.to_owned()),
                _ => return Ok(out),
            }
        }
    }
}

/// Drive side of the GCS store: client, root folder, caches.
pub struct DriveChunks {
    pub d: Drive,
    pub root: String,
    /// (vault, registry name) → folder id. Registry names: "vault", "0".."f".
    folders: Mutex<HashMap<(Id16, String), String>>,
    /// (vault, chunk) → file id. A stale entry shows up as a 404 and is re-read.
    ids: Mutex<HashMap<(Id16, Cid), String>>,
}

impl DriveChunks {
    pub fn new(cfg: &DriveConfig) -> io::Result<DriveChunks> {
        let d = Drive::new(cfg)?;
        match d.check_folder(&cfg.folder) {
            Ok(()) => {}
            Err(DErr::Unavailable(m)) => eprintln!("vaultaged: gdrive: could not check the folder now: {m}"),
            Err(DErr::Quota) => {}
            Err(DErr::Other(m)) => return Err(io::Error::other(m)),
        }
        Ok(DriveChunks {
            d,
            root: cfg.folder.clone(),
            folders: Mutex::new(HashMap::new()),
            ids: Mutex::new(HashMap::new()),
        })
    }

    pub fn folder(&self, vid: &Id16, name: &str) -> Option<String> {
        lock(&self.folders).get(&(*vid, name.to_owned())).cloned()
    }

    pub fn set_folder(&self, vid: &Id16, name: &str, id: &str) {
        lock(&self.folders).insert((*vid, name.to_owned()), id.to_owned());
    }

    pub fn id(&self, vid: &Id16, cid: &Cid) -> Option<String> {
        lock(&self.ids).get(&(*vid, *cid)).cloned()
    }

    pub fn set_id(&self, vid: &Id16, cid: &Cid, id: &str) {
        let mut m = lock(&self.ids);
        if m.len() >= MAX_IDS {
            m.clear();
        }
        m.insert((*vid, *cid), id.to_owned());
    }

    pub fn forget_id(&self, vid: &Id16, cid: &Cid) {
        lock(&self.ids).remove(&(*vid, *cid));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids() {
        assert!(id_ok("1AbC-d_9"));
        assert!(!id_ok(""));
        assert!(!id_ok("x' or '1"));
        assert!(!id_ok("a/b"));
    }

    #[test]
    fn form_encoding() {
        assert_eq!(form(&[("a", "x y"), ("b", "1/2")]), "a=x%20y&b=1%2F2");
    }
}
