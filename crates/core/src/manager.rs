//! Several vaults (local-only and synced), their lock state and background sync.

use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, RwLock};
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::crypto::{self, KdfParams, Key};
use crate::error::{Error, Result};
use crate::header::{Header, SlotKind};
use crate::http::{self, HttpRemote};
use crate::model::*;
use crate::proto::UsageResp;
use crate::remote::{CommitOutcome, Remote};
use crate::store::atomic_write;
use crate::sync::{sync_once, SyncReport};
use crate::vault::{Keys, Vault};

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct VaultRef {
    pub id: String,
    pub name: String,
    pub path: PathBuf,
    /// Sync server URL; None = local-only.
    pub remote: Option<String>,
}

#[derive(Serialize, Deserialize, Default)]
struct Registry {
    device: Option<Device>,
    vaults: Vec<VaultRef>,
}

#[derive(Serialize, Clone, Debug)]
pub struct SlotInfo {
    pub id: String,
    pub kind: SlotKind,
    pub label: String,
    pub created: i64,
    pub public: serde_json::Value,
}

#[derive(Serialize, Clone, Debug)]
pub struct VaultInfo {
    pub id: String,
    pub name: String,
    pub path: String,
    pub remote: Option<String>,
    pub unlocked: bool,
    /// Vault folder is gone or unreadable.
    pub missing: bool,
    pub slots: Vec<SlotInfo>,
}

#[derive(Serialize, Clone, Debug, Default)]
pub struct SyncStatus {
    /// local | idle | syncing | offline | paused | error | rekeyed (keys were rotated on another device)
    pub state: String,
    pub last_ok_ms: i64,
    pub error: Option<String>,
    pub last: SyncReport,
}

#[derive(Serialize, Clone, Debug, Default)]
pub struct Activity {
    pub label: String,
    pub done: u64,
    pub total: u64,
}

#[derive(Serialize, Clone, Debug, Default)]
pub struct ImportReport {
    pub files: u64,
    pub bytes: u64,
    pub skipped: Vec<String>,
    pub sources_deleted: u64,
}

pub struct OpenVault {
    pub vault: Mutex<Vault>,
    http: RwLock<Option<Arc<HttpRemote>>>,
    header_checked: AtomicBool,
    status: Mutex<SyncStatus>,
    activity: Mutex<Option<Activity>>,
    wake: (Mutex<bool>, Condvar),
    stop: AtomicBool,
    /// Background sync is on hold (metered network, user choice). Local work continues.
    paused: AtomicBool,
    syncing: Mutex<()>,
    thread: Mutex<Option<std::thread::JoinHandle<()>>>,
}

impl OpenVault {
    pub fn v(&self) -> MutexGuard<'_, Vault> {
        self.vault.lock().unwrap_or_else(|p| p.into_inner())
    }
    pub fn http(&self) -> Option<Arc<HttpRemote>> {
        self.http.read().unwrap().clone()
    }
    /// Run `f` with the server link, if this vault has one.
    pub fn with_remote<T>(&self, f: impl FnOnce(Option<&dyn Remote>) -> T) -> T {
        let http = self.http();
        f(http.as_deref().map(|h| h as &dyn Remote))
    }

    /// Keep the server's portable key slots and ours in step (needed to join from a new device,
    /// and so a passphrase changed on one device works on the others).
    fn sync_header(&self, http: &HttpRemote) -> Result<()> {
        let (version, pushed, portable) = { let v = self.v(); (v.header.version, v.config.header_pushed, v.portable_header()) };
        let unpushed = pushed < version;
        if !unpushed && self.header_checked.swap(true, Ordering::Relaxed) {
            return Ok(()); // nothing to upload; the server's header was looked at once since unlock
        }
        if !(unpushed && http.put_header(&portable)?) {
            // Not uploaded: the server has the same or a newer header. Look at it.
            let server = http::fetch_header(http.url(), http.vault_id())?;
            let mut v = self.v();
            let mut merged = v.header.clone();
            let vmk = v.keys().vmk.clone();
            if merged.merge_portable(&server, &vmk, unpushed)? {
                v.replace_header(merged)?;
            }
            let (now, portable) = (v.header.version, v.portable_header());
            drop(v);
            if now > server.version {
                http.put_header(&portable)?;
            }
        }
        self.header_checked.store(true, Ordering::Relaxed);
        let mut v = self.v();
        let version = v.header.version;
        v.set_header_pushed(version)
    }
    pub fn status(&self) -> SyncStatus {
        self.status.lock().unwrap().clone()
    }
    pub fn activity(&self) -> Option<Activity> {
        self.activity.lock().unwrap().clone()
    }
    fn set_activity(&self, a: Option<Activity>) {
        *self.activity.lock().unwrap() = a;
    }
    /// Ask the background sync to run now (after a local change).
    pub fn wake(&self) {
        *self.wake.0.lock().unwrap() = true;
        self.wake.1.notify_all();
    }

    /// One sync round, on the calling thread.
    pub fn sync_blocking(&self) -> Result<SyncReport> {
        let Some(http) = self.http() else { return Ok(SyncReport::default()) };
        let _one = self.syncing.lock().unwrap_or_else(|p| p.into_inner());
        self.status.lock().unwrap().state = "syncing".into();
        let res = sync_once(&self.vault, &*http).and_then(|rep| {
            self.sync_header(&http)?;
            Ok(rep)
        });
        // Signature refused: were the keys rotated on another device?
        let rotated = matches!(&res, Err(Error::Server(401, _)))
            && http::fetch_header(http.url(), http.vault_id()).map(|h| h.epoch() > self.v().header.epoch()).unwrap_or(false);
        let mut st = self.status.lock().unwrap();
        match &res {
            Ok(rep) => {
                st.state = "idle".into();
                st.error = rep.errors.first().cloned();
                st.last_ok_ms = now_ms();
                st.last = rep.clone();
            }
            Err(Error::Net(e)) => {
                st.state = "offline".into();
                st.error = Some(e.clone());
            }
            Err(_) if rotated => {
                st.state = "rekeyed".into();
                st.error = Some("This vault's keys were rotated on another device. Enter the new recovery key or passphrase to keep syncing.".into());
            }
            Err(e) => {
                st.state = "error".into();
                st.error = Some(e.to_string());
            }
        }
        res
    }

    /// Hold or resume background sync. Resuming syncs at once.
    pub fn set_paused(&self, on: bool) {
        self.paused.store(on, Ordering::Relaxed);
        self.wake();
    }

    fn sync_loop(self: Arc<Self>) {
        let mut failures = 0u32;
        while !self.stop.load(Ordering::Relaxed) {
            let paused = self.paused.load(Ordering::Relaxed);
            if paused {
                let mut st = self.status.lock().unwrap();
                st.state = "paused".into();
                st.error = None;
            } else {
                failures = if self.sync_blocking().is_ok() { 0 } else { (failures + 1).min(6) };
            }
            let wait = if failures == 0 || paused { Duration::from_secs(5) } else { Duration::from_secs(1 << failures) };
            let mut woken = self.wake.0.lock().unwrap();
            if !*woken {
                woken = self.wake.1.wait_timeout(woken, wait).unwrap().0;
            }
            *woken = false;
        }
    }

    fn shutdown(&self) {
        self.stop.store(true, Ordering::Relaxed);
        self.wake();
        if let Some(t) = self.thread.lock().unwrap().take() {
            let _ = t.join();
        }
    }
}

pub struct Manager {
    home: PathBuf,
    registry: Mutex<Registry>,
    /// Pinned certificates per server origin (PEM), mirrored in `trust.json`.
    trust: Mutex<BTreeMap<String, String>>,
    open: Mutex<HashMap<String, Arc<OpenVault>>>,
    /// Start a background sync thread on unlock (apps: yes; one-shot CLI: no).
    pub background_sync: bool,
    /// Background sync held for every vault, open now or later (see `set_sync_paused`).
    sync_paused: AtomicBool,
}

pub fn default_home() -> PathBuf {
    if let Some(h) = std::env::var_os("COFFER_HOME") {
        return PathBuf::from(h);
    }
    let home = PathBuf::from(std::env::var_os("HOME").unwrap_or_default());
    if cfg!(target_os = "macos") {
        home.join("Library/Application Support/Coffer")
    } else {
        std::env::var_os("XDG_DATA_HOME").map(PathBuf::from).unwrap_or_else(|| home.join(".local/share")).join("coffer")
    }
}

fn hostname() -> String {
    let mut buf = [0u8; 256];
    #[cfg(unix)]
    unsafe {
        libc::gethostname(buf.as_mut_ptr() as *mut libc::c_char, buf.len() - 1);
    }
    let end = buf.iter().position(|b| *b == 0).unwrap_or(0);
    let name = String::from_utf8_lossy(&buf[..end]).trim_end_matches(".local").to_string();
    if name.is_empty() { "device".into() } else { name }
}

fn unique_dest(dir: &Path, name: &str) -> PathBuf {
    let mut p = dir.join(name);
    let mut n = 2;
    while p.exists() {
        p = dir.join(basename(&tagged_path(name, &n.to_string())));
        n += 1;
    }
    p
}

impl Manager {
    pub fn new(home: PathBuf, background_sync: bool) -> Result<Manager> {
        fs::create_dir_all(home.join("vaults"))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(&home, fs::Permissions::from_mode(0o700));
        }
        let path = home.join("registry.json");
        let mut registry: Registry = match fs::read(&path) {
            Ok(b) => serde_json::from_slice(&b)?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Registry::default(),
            Err(e) => return Err(e.into()),
        };
        // The state dir can move (iOS gives an app a new container path on every update): a
        // vault that is gone from its recorded path but present under this home is the same vault.
        let mut moved = false;
        for v in registry.vaults.iter_mut() {
            let here = home.join("vaults").join(&v.id);
            if v.path != here && !v.path.join("header.json").exists() && here.join("header.json").exists() {
                v.path = here;
                moved = true;
            }
        }
        let fresh = registry.device.is_none() || moved;
        // Phones have no useful hostname; the app names the device.
        let device_name = std::env::var("COFFER_DEVICE_NAME").ok().filter(|n| !n.trim().is_empty()).unwrap_or_else(hostname);
        registry.device.get_or_insert_with(|| Device::new(device_name.trim()));
        let trust: BTreeMap<String, String> = match fs::read(home.join("trust.json")) {
            Ok(b) => serde_json::from_slice(&b)?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => BTreeMap::new(),
            Err(e) => return Err(e.into()),
        };
        for (url, pem) in &trust {
            // A pin that no longer parses must not silently fall back to the public roots.
            http::set_pin(url, Some(pem)).map_err(|e| Error::Format(format!("trust.json, {url}: {e}")))?;
        }
        let m = Manager { home, registry: Mutex::new(registry), trust: Mutex::new(trust), open: Mutex::new(HashMap::new()), background_sync, sync_paused: AtomicBool::new(false) };
        if fresh {
            m.save()?;
        }
        Ok(m)
    }

    fn save(&self) -> Result<()> {
        atomic_write(&self.home.join("registry.json"), &serde_json::to_vec_pretty(&*self.registry.lock().unwrap())?)
    }

    pub fn device(&self) -> Device {
        self.registry.lock().unwrap().device.clone().unwrap()
    }

    /// Hold or resume background sync for all vaults (e.g. on a metered connection).
    pub fn set_sync_paused(&self, on: bool) {
        self.sync_paused.store(on, Ordering::Relaxed);
        let open: Vec<Arc<OpenVault>> = self.open.lock().unwrap().values().cloned().collect();
        open.iter().for_each(|ov| ov.set_paused(on));
    }

    /// Pinned certificates (PEM) per server origin.
    pub fn trust(&self) -> BTreeMap<String, String> {
        self.trust.lock().unwrap().clone()
    }

    /// Pin a server to the certificates in `pem` (None = trust the built-in public roots again).
    /// Takes effect at once, also for unlocked vaults on that server.
    pub fn set_trust(&self, url: &str, pem: Option<&str>) -> Result<()> {
        let pem = pem.map(str::trim).filter(|p| !p.is_empty());
        let origin = http::set_pin(url, pem)?;
        {
            let mut t = self.trust.lock().unwrap();
            match pem {
                Some(p) => t.insert(origin.clone(), p.to_string()),
                None => t.remove(&origin),
            };
            atomic_write(&self.home.join("trust.json"), &serde_json::to_vec_pretty(&*t)?)?;
        }
        let refs: Vec<VaultRef> = self.registry.lock().unwrap().vaults.iter().filter(|v| v.remote.as_deref() == Some(origin.as_str())).cloned().collect();
        for r in refs {
            let ov = self.open.lock().unwrap().get(&r.id).cloned();
            if let Some(ov) = ov {
                self.rewire(&ov, &r)?;
            }
        }
        Ok(())
    }

    fn vref(&self, id: &str) -> Result<VaultRef> {
        self.registry.lock().unwrap().vaults.iter().find(|v| v.id == id).cloned().ok_or_else(|| Error::NotFound(format!("vault {id}")))
    }

    pub fn list(&self) -> Vec<VaultInfo> {
        let refs = self.registry.lock().unwrap().vaults.clone();
        let open = self.open.lock().unwrap();
        refs.into_iter()
            .map(|r| {
                // Prefer the live header (slots may have changed since unlock).
                let header = match open.get(&r.id) {
                    Some(ov) => Ok(ov.v().header.clone()),
                    None => Header::load(&r.path.join("header.json")),
                };
                let slots = header.as_ref().map(|h| h.slots.iter().map(|s| SlotInfo { id: s.id.clone(), kind: s.kind, label: s.label.clone(), created: s.created, public: s.public.clone() }).collect()).unwrap_or_default();
                VaultInfo { unlocked: open.contains_key(&r.id), missing: header.is_err(), slots, path: r.path.display().to_string(), id: r.id, name: r.name, remote: r.remote }
            })
            .collect()
    }

    fn register(&self, r: VaultRef) -> Result<()> {
        self.registry.lock().unwrap().vaults.push(r);
        self.save()
    }

    fn install(&self, r: &VaultRef, vault: Vault) -> Result<Arc<OpenVault>> {
        let ov = Arc::new(OpenVault {
            vault: Mutex::new(vault),
            http: RwLock::new(None),
            header_checked: AtomicBool::new(false),
            status: Mutex::new(SyncStatus { state: "local".into(), ..Default::default() }),
            activity: Mutex::new(None),
            wake: (Mutex::new(false), Condvar::new()),
            stop: AtomicBool::new(false),
            paused: AtomicBool::new(self.sync_paused.load(Ordering::Relaxed)),
            syncing: Mutex::new(()),
            thread: Mutex::new(None),
        });
        self.rewire(&ov, r)?;
        self.open.lock().unwrap().insert(r.id.clone(), ov.clone());
        Ok(ov)
    }

    /// (Re)build the server link from the vault's current keys and start background sync if due.
    fn rewire(&self, ov: &Arc<OpenVault>, r: &VaultRef) -> Result<()> {
        let http = match &r.remote {
            Some(url) => Some(Arc::new(HttpRemote::new(url, &r.id, ov.v().keys())?)),
            None => None,
        };
        let synced = http.is_some();
        *ov.http.write().unwrap() = http;
        ov.header_checked.store(false, Ordering::Relaxed);
        {
            let mut st = ov.status.lock().unwrap();
            st.state = if synced { "idle" } else { "local" }.into();
            st.error = None;
        }
        let mut thread = ov.thread.lock().unwrap();
        if self.background_sync && synced && thread.is_none() {
            let t = ov.clone();
            *thread = Some(std::thread::Builder::new().name("coffer-sync".into()).spawn(move || t.sync_loop())?);
        }
        drop(thread);
        ov.wake();
        Ok(())
    }

    /// Create a vault and leave it unlocked. `remote` = (server URL, enrollment token).
    /// Returns (vault id, recovery key). The recovery key is shown once and stored nowhere.
    pub fn create(&self, name: &str, remote: Option<(&str, &str)>) -> Result<(String, String)> {
        let name = name.trim();
        if name.is_empty() {
            return Err(Error::Invalid("vault needs a name".into()));
        }
        let url = remote.map(|(u, _)| http::check_url(u)).transpose()?;
        let (header, vmk, recovery) = Header::create();
        let id = header.vault_id.clone();
        let path = self.home.join("vaults").join(&id);
        Vault::init(&path, &header, url.clone())?;
        let vault = Vault::open(&path, vmk, &self.device())?;
        if let Some((u, token)) = remote {
            // Register first: a vault the server does not know must not look "synced".
            if let Err(e) = http::create_vault(u, token, &vault.keys(), &vault.portable_header()) {
                drop(vault);
                let _ = fs::remove_dir_all(&path);
                return Err(e);
            }
        }
        let r = VaultRef { id: id.clone(), name: name.to_string(), path, remote: url };
        self.register(r.clone())?;
        self.install(&r, vault)?;
        Ok((id, recovery))
    }

    /// Add a vault that already exists on a server, using a portable secret (passphrase or recovery key).
    pub fn join(&self, name: &str, url: &str, vault_id: &str, kind: SlotKind, secret: &[u8]) -> Result<String> {
        let url = http::check_url(url)?;
        let vault_id = vault_id.trim().to_lowercase();
        if self.vref(&vault_id).is_ok() {
            return Err(Error::Exists("this vault is already on this device".into()));
        }
        let header = http::fetch_header(&url, &vault_id)?;
        if header.vault_id != vault_id {
            return Err(Error::Integrity("server returned a different vault".into()));
        }
        let vmk = header.unlock_any(kind, secret)?;
        let path = self.home.join("vaults").join(&vault_id);
        Vault::init(&path, &header, Some(url.clone()))?;
        let vault = Vault::open(&path, vmk, &self.device())?;
        let r = VaultRef { id: vault_id.clone(), name: if name.trim().is_empty() { "Vault".into() } else { name.trim().to_string() }, path, remote: Some(url) };
        self.register(r.clone())?;
        self.install(&r, vault)?;
        Ok(vault_id)
    }

    /// Share a synced vault: stores a one-time invite on the server and returns the line
    /// (`server#vault-id#secret`). It works once, until `ttl_ms` (default 24 h) or until revoked.
    /// Whoever claims it gets full read/write access; to cut someone off, rotate keys.
    pub fn invite(&self, id: &str, label: &str, ttl_ms: Option<i64>) -> Result<String> {
        let ov = self.get(id)?;
        let http = ov.http().ok_or_else(|| Error::Invalid("only a synced vault can be shared; connect it to a server first".into()))?;
        let ttl = ttl_ms.unwrap_or(crate::invite::DEFAULT_TTL_MS);
        if ttl <= 0 || ttl > crate::proto::INVITE_MAX_TTL_MS {
            return Err(Error::Invalid("an invite can last at most 7 days".into()));
        }
        let secret = Key::random();
        let ik = crate::invite::InviteKeys::from_secret(&secret);
        let label = label.trim();
        let keys = ov.v().keys();
        let req = crate::proto::InviteCreateReq {
            id: ik.id.clone(),
            claim_pub: ik.claim_pub_hex(),
            blob: crate::hexutil::encode(&ik.seal_payload(id, &keys.vmk, label)),
            info: crate::hexutil::encode(&crate::invite::seal_info(&keys.vmk, id, &ik.id, label)),
            expires_ms: now_ms() + ttl,
        };
        http.create_invite(&req)?;
        Ok(format!("{}#{}#{}", http.url(), id, crypto::recovery_encode(secret.expose())))
    }

    /// This vault's invites on the server (waiting, used, expired, revoked), newest first.
    pub fn invites(&self, id: &str) -> Result<Vec<crate::invite::InviteStatus>> {
        let ov = self.get(id)?;
        let http = ov.http().ok_or_else(|| Error::Invalid("this vault is not synced".into()))?;
        let vmk = ov.v().keys().vmk.clone();
        let now = now_ms();
        let mut out: Vec<_> = http
            .list_invites()?
            .into_iter()
            .map(|i| {
                let label = crate::hexutil::decode(&i.info).and_then(|b| crate::invite::open_info(&vmk, id, &i.id, &b)).unwrap_or_default();
                let state = if i.revoked_ms.is_some() {
                    "revoked"
                } else if i.claimed_ms.is_some() {
                    "used"
                } else if i.expires_ms <= now {
                    "expired"
                } else {
                    "waiting"
                };
                crate::invite::InviteStatus { id: i.id, label, created: i.created_ms, expires: i.expires_ms, claimed: i.claimed_ms, revoked: i.revoked_ms, state: state.into() }
            })
            .collect();
        out.sort_by_key(|i| std::cmp::Reverse(i.created));
        Ok(out)
    }

    pub fn revoke_invite(&self, id: &str, invite_id: &str) -> Result<()> {
        let ov = self.get(id)?;
        let http = ov.http().ok_or_else(|| Error::Invalid("this vault is not synced".into()))?;
        http.revoke_invite(&invite_id.trim().to_lowercase())
    }

    /// Join with an invite line. One-time invite: claims it (the server then deletes it), adds a
    /// new recovery key of this member's own and returns it (show once). An old-style invite
    /// (a key slot in the header) joins as before and returns no recovery key.
    pub fn join_invite(&self, name: &str, code: &str) -> Result<(String, Option<String>)> {
        let line = crate::invite::parse_line(code)?;
        let url = http::check_url(&line.url)?;
        if self.vref(&line.vault).is_ok() {
            return Err(Error::Exists("this vault is already on this device".into()));
        }
        let secret = crypto::recovery_decode(&line.secret).map_err(|_| Error::Invalid("not a valid invite: bad key".into()))?;
        let ik = crate::invite::InviteKeys::from_secret(&secret);
        let blob = match http::claim_invite(&url, &line.vault, &ik) {
            Ok(b) => b,
            Err(Error::NotFound(_)) => {
                // Not a one-time invite: maybe an old-style one (key slot in the header).
                return match self.join(name, &url, &line.vault, SlotKind::Recovery, line.secret.as_bytes()) {
                    Ok(id) => Ok((id, None)),
                    Err(Error::Crypto(_)) | Err(Error::NotFound(_)) => Err(Error::NotFound("this invite doesn't exist on the server: it was never created there, or the vault's keys were rotated".into())),
                    Err(e) => Err(e),
                };
            }
            Err(Error::Server(410, m)) => return Err(Error::Server(410, m)),
            Err(e) => return Err(e),
        };
        let (vmk, label) = ik.open_payload(&line.vault, &blob)?;
        let header = http::fetch_header(&url, &line.vault)?;
        if header.vault_id != line.vault {
            return Err(Error::Integrity("server returned a different vault".into()));
        }
        header.verify(&vmk).map_err(|_| Error::Invalid("the vault's keys were rotated after this invite was made; ask for a new invite".into()))?;
        let path = self.home.join("vaults").join(&line.vault);
        Vault::init(&path, &header, Some(url.clone()))?;
        let mut vault = Vault::open(&path, vmk, &self.device())?;
        // Our own way back in. Pushed to the server by the first sync (header version goes up).
        let recovery = crypto::random::<32>();
        let slot_label = if label.is_empty() { "Recovery key (joined)".to_string() } else { format!("Recovery key ({label})") };
        vault.edit_header(|h, vmk| h.add_slot(vmk, SlotKind::Recovery, &slot_label, &recovery, None, serde_json::Value::Null))?;
        let r = VaultRef { id: line.vault.clone(), name: if name.trim().is_empty() { "Vault".into() } else { name.trim().to_string() }, path, remote: Some(url) };
        self.register(r.clone())?;
        let ov = self.install(&r, vault)?;
        ov.wake();
        Ok((line.vault, Some(crypto::recovery_encode(&recovery))))
    }

    /// Turn a local vault into a synced one: uploads its whole kept history to a server that does
    /// not know it yet. Safe to interrupt and repeat. The vault is read-only while this runs.
    pub fn attach(&self, id: &str, url: &str, token: &str) -> Result<()> {
        let ov = self.get(id)?;
        let url = http::check_url(url)?;
        if ov.http().is_some() {
            return Err(Error::Invalid("this vault already syncs with a server".into()));
        }
        let (plan, keys, header, chunks, vid) = {
            let mut v = ov.v();
            v.frozen = true;
            (v.attach_plan(), v.keys(), v.portable_header(), v.chunks.clone(), v.id)
        };
        let res = (|| -> Result<()> {
            match http::create_vault(&url, token, &keys, &header) {
                Ok(()) | Err(Error::Server(409, _)) => {}
                Err(e) => return Err(e),
            }
            let remote = HttpRemote::new(&url, id, keys.clone())?;
            let differs = || Error::Exists("the server already holds a different history for this vault".into());
            // Resume: whatever the server already has must be a prefix of the plan.
            let mut have = 0usize;
            loop {
                let (head, records) = remote.pull(have as u64, 500)?;
                if records.is_empty() {
                    break;
                }
                for r in records {
                    let want = plan.get(have).ok_or_else(differs)?;
                    let got = keys.open_meta(&vid, &r.entry, r.rev, &r.blob).map_err(|_| differs())?;
                    if got != *want {
                        return Err(differs());
                    }
                    have += 1;
                }
                if have as u64 >= head {
                    break;
                }
            }
            for (i, m) in plan.iter().enumerate().skip(have) {
                ov.set_activity(Some(Activity { label: format!("Uploading {}", basename(&m.path)), done: i as u64, total: plan.len() as u64 }));
                let refs = m.refs();
                for cid in remote.missing(&refs)? {
                    remote.put_chunk(&cid, &chunks.get(&cid)?)?;
                }
                match remote.commit(&m.id, m.rev - 1, m.rev, &keys.seal_meta(&vid, m), &refs)? {
                    CommitOutcome::Committed(seq) if seq == i as u64 + 1 => {}
                    _ => return Err(Error::Invalid("the server's copy changed while connecting; try again".into())),
                }
            }
            ov.v().become_synced(&plan, &url)
        })();
        ov.set_activity(None);
        if let Err(e) = res {
            ov.v().frozen = false;
            return Err(e);
        }
        self.registry.lock().unwrap().vaults.iter_mut().filter(|v| v.id == id).for_each(|v| v.remote = Some(url.clone()));
        self.save()?;
        self.rewire(&ov, &self.vref(id)?)
    }

    // ---- key rotation (revokes every other device, passphrase and invite) ----

    /// Step 1: stage new keys and return the new recovery key so it can be stored first.
    pub fn rotate_prepare(&self, id: &str, passphrase: Option<&[u8]>, kdf: Option<KdfParams>) -> Result<String> {
        let ov = self.get(id)?;
        if passphrase.is_some() && ov.v().rotation_pending() {
            self.rotate_cancel(id)?; // start over with the new passphrase (refused if the server already switched)
        }
        let res = ov.v().rotate_prepare(passphrase, kdf);
        res
    }

    /// Step 2: switch the server (if any) and this device to the staged keys. Afterwards only the
    /// new recovery key / passphrase open the vault; re-enable Touch ID separately.
    pub fn rotate_commit(&self, id: &str) -> Result<()> {
        let ov = self.get(id)?;
        let (mut header, new, _) = ov.v().rotate_staged()?;
        if let Some(http) = ov.http() {
            // Another device may have pushed slot changes we have not seen; the new header must
            // still be the newest. (Those slots die with the old key anyway.)
            if let Ok(server) = http::fetch_header(http.url(), id) {
                if server.epoch() < header.epoch() && server.version >= header.version {
                    header.set_version(server.version + 1, &new);
                }
            }
            let new_keys = Arc::new(Keys::new(header.masters(&new)?));
            if let Err(e) = http.rekey(&new_keys.auth_pub_hex(), &header.portable(&new)) {
                // An earlier attempt may have reached the server before we crashed: then the
                // new key already works there.
                let probe = HttpRemote::new(http.url(), id, new_keys)?;
                if !matches!(e, Error::Server(401, _)) || probe.usage().is_err() {
                    return Err(e);
                }
            }
        }
        let mut v = ov.v();
        v.rotate_finish(&header)?;
        v.reload(new)?;
        let version = v.header.version;
        v.set_header_pushed(version)?;
        drop(v);
        self.rewire(&ov, &self.vref(id)?)
    }

    pub fn rotate_cancel(&self, id: &str) -> Result<()> {
        let ov = self.get(id)?;
        if !ov.v().rotation_pending() {
            return Ok(());
        }
        if let Some(http) = ov.http() {
            // If the server already switched, cancelling would lock this device out.
            if matches!(http.usage(), Err(Error::Server(401, _))) {
                return Err(Error::Invalid("the server already uses the new keys; finish the rotation instead".into()));
            }
        }
        let res = ov.v().rotate_discard();
        res
    }

    /// Keys were rotated on another device: take over the new header from the server using the
    /// new recovery key or passphrase. Refuses a header that does not descend from our vault.
    pub fn adopt_rekey(&self, id: &str, kind: SlotKind, secret: &[u8]) -> Result<()> {
        let r = self.vref(id)?;
        let url = r.remote.clone().ok_or_else(|| Error::Invalid("this is a local vault".into()))?;
        let server = http::fetch_header(&url, id)?;
        let local = Header::load(&r.path.join("header.json"))?;
        if server.vault_id != local.vault_id || server.epoch() <= local.epoch() {
            return Err(Error::Invalid("the server has no newer keys for this vault".into()));
        }
        let new = server.unlock_any(kind, secret)?;
        let masters = server.masters(&new)?;
        local.verify(&masters[local.epoch() as usize]).map_err(|_| Error::Integrity("the server's keys do not descend from this vault's keys".into()))?;
        match self.get(id) {
            Ok(ov) => {
                let mut v = ov.v();
                let version = server.version;
                v.replace_header(server)?;
                v.reload(new)?;
                v.set_header_pushed(version)?;
                drop(v);
                self.rewire(&ov, &r)
            }
            Err(_) => {
                let version = server.version;
                server.save(&r.path.join("header.json"))?;
                let mut vault = Vault::open(&r.path, new, &self.device())?;
                vault.set_header_pushed(version)?;
                self.install(&r, vault).map(|_| ())
            }
        }
    }

    pub fn usage(&self, id: &str) -> Result<UsageResp> {
        self.get(id)?.http().ok_or_else(|| Error::Invalid("this is a local vault".into()))?.usage()
    }

    /// Unlock with a specific slot, or (slot = None) any slot of `kind`.
    /// Secret: passphrase bytes, recovery key text, or the Secure Enclave ECDH output.
    pub fn unlock(&self, id: &str, kind: SlotKind, slot: Option<&str>, secret: &[u8]) -> Result<()> {
        if self.open.lock().unwrap().contains_key(id) {
            return Ok(());
        }
        let r = self.vref(id)?;
        let header = Header::load(&r.path.join("header.json"))?;
        let vmk: Key = match slot {
            Some(s) if kind != SlotKind::Recovery => header.unlock(s, secret)?,
            _ => header.unlock_any(kind, secret)?,
        };
        let vault = Vault::open(&r.path, vmk, &self.device())?;
        self.install(&r, vault)?;
        Ok(())
    }

    /// Drop the keys. Pending changes stay in the encrypted journal and sync after the next unlock.
    pub fn lock(&self, id: &str) {
        let ov = self.open.lock().unwrap().remove(id);
        if let Some(ov) = ov {
            ov.shutdown();
        }
    }

    pub fn lock_all(&self) {
        let ids: Vec<String> = self.open.lock().unwrap().keys().cloned().collect();
        ids.iter().for_each(|id| self.lock(id));
    }

    /// Remove from the list. Files stay on disk; returns their location.
    pub fn forget(&self, id: &str) -> Result<PathBuf> {
        let r = self.vref(id)?;
        self.lock(id);
        self.registry.lock().unwrap().vaults.retain(|v| v.id != id);
        self.save()?;
        Ok(r.path)
    }

    pub fn rename_vault(&self, id: &str, name: &str) -> Result<()> {
        if name.trim().is_empty() {
            return Err(Error::Invalid("vault needs a name".into()));
        }
        self.registry.lock().unwrap().vaults.iter_mut().filter(|v| v.id == id).for_each(|v| v.name = name.trim().to_string());
        self.save()
    }

    pub fn get(&self, id: &str) -> Result<Arc<OpenVault>> {
        self.open.lock().unwrap().get(id).cloned().ok_or(Error::Locked)
    }

    pub fn add_slot(&self, id: &str, kind: SlotKind, label: &str, secret: &[u8], public: serde_json::Value, kdf: Option<KdfParams>) -> Result<String> {
        let ov = self.get(id)?;
        let out = ov.v().edit_header(|h, vmk| h.add_slot(vmk, kind, label, secret, kdf, public))?;
        ov.wake();
        Ok(out)
    }

    pub fn remove_slot(&self, id: &str, slot: &str) -> Result<()> {
        let ov = self.get(id)?;
        ov.v().edit_header(|h, vmk| h.remove_slot(vmk, slot).map(|_| String::new()))?;
        ov.wake();
        Ok(())
    }

    /// Encrypt files/folders from disk into the vault under `dest_dir`.
    /// `delete_source`: after each file is verified readable from the vault, remove the original.
    pub fn import(&self, id: &str, sources: &[PathBuf], dest_dir: &str, delete_source: bool) -> Result<ImportReport> {
        let ov = self.get(id)?;
        let dest_dir = normalize_path(dest_dir)?;
        // (source file or None for an empty folder, vault path)
        let mut plan: Vec<(Option<PathBuf>, String)> = Vec::new();
        let mut rep = ImportReport::default();
        fn walk(src: &Path, vpath: String, plan: &mut Vec<(Option<PathBuf>, String)>, skipped: &mut Vec<String>) {
            let Ok(md) = fs::symlink_metadata(src) else { return skipped.push(format!("{}: unreadable", src.display())) };
            if md.file_type().is_symlink() {
                skipped.push(format!("{}: symbolic link", src.display()));
            } else if md.is_file() {
                plan.push((Some(src.to_path_buf()), vpath));
            } else if md.is_dir() {
                let mut kids: Vec<PathBuf> = fs::read_dir(src).map(|d| d.filter_map(|e| e.ok().map(|e| e.path())).collect()).unwrap_or_default();
                kids.sort();
                kids.retain(|k| k.file_name().map(|n| n != ".DS_Store").unwrap_or(false));
                if kids.is_empty() {
                    plan.push((None, vpath.clone()));
                }
                for k in kids {
                    let name = k.file_name().unwrap().to_string_lossy().into_owned();
                    walk(&k, join(&vpath, &name), plan, skipped);
                }
            } else {
                skipped.push(format!("{}: not a regular file", src.display()));
            }
        }
        for s in sources {
            let name = s.file_name().ok_or_else(|| Error::Invalid(format!("cannot import {}", s.display())))?.to_string_lossy().into_owned();
            walk(s, join(&dest_dir, &name), &mut plan, &mut rep.skipped);
        }
        let total = plan.len() as u64;
        for (i, (src, vpath)) in plan.into_iter().enumerate() {
            ov.set_activity(Some(Activity { label: format!("Encrypting {}", basename(&vpath)), done: i as u64, total }));
            let res = (|| -> Result<u64> {
                let Some(src) = &src else {
                    ov.v().mkdir(&vpath)?;
                    return Ok(0);
                };
                let vpath = normalize_path(&vpath)?;
                let ing = ov.v().ingester(&vpath)?;
                let mut f = fs::File::open(src)?;
                let mtime = f.metadata()?.modified().ok().and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok()).map(|d| d.as_millis() as i64).unwrap_or_else(now_ms);
                let (content, size) = ing.ingest(&mut f)?;
                drop(f);
                let entry = ov.v().commit_file(ing.id, &vpath, content, size, mtime)?;
                if delete_source {
                    // Prove the vault copy decrypts to the same bytes before touching the original.
                    let reader = ov.v().reader(&entry, None)?;
                    reader.write_to(&mut std::io::sink(), None)?;
                    fs::remove_file(src)?;
                    rep.sources_deleted += 1;
                }
                Ok(size)
            })();
            match res {
                Ok(size) => {
                    rep.files += src.is_some() as u64;
                    rep.bytes += size;
                }
                Err(e) => rep.skipped.push(format!("{vpath}: {e}")),
            }
        }
        if delete_source {
            // Remove source folders that are now empty (deepest first); leave anything non-empty.
            for s in sources.iter().filter(|s| s.is_dir()) {
                fn prune(d: &Path) {
                    if let Ok(rd) = fs::read_dir(d) {
                        for e in rd.flatten() {
                            if e.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                                prune(&e.path());
                            } else if e.file_name() == ".DS_Store" {
                                let _ = fs::remove_file(e.path());
                            }
                        }
                    }
                    let _ = fs::remove_dir(d);
                }
                prune(s);
            }
        }
        ov.set_activity(None);
        ov.wake();
        Ok(rep)
    }

    /// Decrypt files/folders to `dest_dir` on disk (outside the vault: plaintext).
    /// `remove`: after everything was written and verified, delete them from the vault ("move out").
    pub fn export(&self, id: &str, paths: &[String], dest_dir: &Path, remove: bool) -> Result<Vec<PathBuf>> {
        let ov = self.get(id)?;
        fs::create_dir_all(dest_dir)?;
        let mut written = Vec::new();
        for p in paths {
            let p = normalize_path(p)?;
            let (files, is_dir) = { let v = ov.v(); (v.files_under(&p), v.is_dir(&p)) };
            if files.is_empty() && !is_dir {
                return Err(Error::NotFound(p));
            }
            let top = unique_dest(dest_dir, basename(&p));
            if is_dir {
                fs::create_dir_all(&top)?;
            }
            let total = files.len() as u64;
            for (i, m) in files.iter().enumerate() {
                ov.set_activity(Some(Activity { label: format!("Decrypting {}", basename(&m.path)), done: i as u64, total }));
                let dest = if is_dir { top.join(&m.path[p.len() + 1..]) } else { top.clone() };
                let reader = ov.v().reader(&m.id, None)?;
                let res = ov.with_remote(|r| reader.export_to(&dest, r));
                if let Err(e) = res {
                    ov.set_activity(None);
                    return Err(e);
                }
            }
            written.push(top);
            if remove {
                ov.v().delete(&p)?;
            }
        }
        ov.set_activity(None);
        if remove {
            ov.wake();
        }
        Ok(written)
    }

    /// Decrypt a file into memory. The caller should wipe the buffer when done.
    pub fn read(&self, id: &str, entry: &EntryId, rev: Option<u64>, max: u64) -> Result<Vec<u8>> {
        let ov = self.get(id)?;
        let reader = ov.v().reader(entry, rev)?;
        if reader.meta.size > max {
            return Err(Error::Invalid(format!("file is too large to open in memory ({} bytes)", reader.meta.size)));
        }
        ov.with_remote(|r| reader.read_all(r))
    }
}

impl Drop for Manager {
    fn drop(&mut self) {
        self.lock_all();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vaults_follow_a_moved_home() {
        crate::store::SKIP_FSYNC.store(true, Ordering::Relaxed);
        let tmp = tempfile::tempdir().unwrap();
        let (old, new) = (tmp.path().join("old"), tmp.path().join("new"));
        let (id, recovery) = {
            let m = Manager::new(old.clone(), false).unwrap();
            let (id, recovery) = m.create("Private", None).unwrap();
            m.get(&id).unwrap().v().put_bytes("a.txt", b"hello", 1).unwrap();
            (id, recovery)
        };
        fs::rename(&old, &new).unwrap();
        let m = Manager::new(new.clone(), false).unwrap();
        let info = m.list();
        assert!(!info[0].missing);
        assert!(info[0].path.starts_with(new.to_str().unwrap()));
        m.unlock(&id, SlotKind::Recovery, None, recovery.as_bytes()).unwrap();
        assert_eq!(m.get(&id).unwrap().v().list("").unwrap().len(), 1);
    }

    #[test]
    fn rotate_keys_on_a_local_vault() {
        crate::store::SKIP_FSYNC.store(true, Ordering::Relaxed);
        let tmp = tempfile::tempdir().unwrap();
        let m = Manager::new(tmp.path().join("home"), false).unwrap();
        let weak = Some(KdfParams::weak_for_tests());
        let (id, recovery) = m.create("Private", None).unwrap();
        m.add_slot(&id, SlotKind::Passphrase, "pw", b"old passphrase", serde_json::Value::Null, weak.clone()).unwrap();
        let entry = m.get(&id).unwrap().v().put_bytes("a.txt", b"before rotation", 1).unwrap();

        // Staging changes nothing and survives a lock; cancel removes it.
        let staged = m.rotate_prepare(&id, Some(b"new passphrase"), weak.clone()).unwrap();
        assert_ne!(staged, recovery);
        m.lock(&id);
        m.unlock(&id, SlotKind::Passphrase, None, b"old passphrase").unwrap();
        assert!(m.get(&id).unwrap().v().rotation_pending());
        assert_eq!(m.rotate_prepare(&id, None, None).unwrap(), staged);
        m.rotate_cancel(&id).unwrap();
        assert!(!m.get(&id).unwrap().v().rotation_pending());
        assert!(m.rotate_commit(&id).is_err());

        let new_recovery = m.rotate_prepare(&id, Some(b"new passphrase"), weak).unwrap();
        m.rotate_commit(&id).unwrap();
        let ov = m.get(&id).unwrap();
        assert_eq!(ov.v().header.epoch(), 1);
        // Old data still readable, new data goes under the new epoch.
        assert_eq!(m.read(&id, &entry, None, 1 << 20).unwrap(), b"before rotation");
        let e2 = ov.v().put_bytes("b.txt", b"after rotation", 2).unwrap();
        ov.v().put_bytes("a.txt", b"edited after rotation", 3).unwrap();
        assert_eq!(ov.v().entry(&e2).unwrap().current().unwrap().content.as_ref().unwrap().epoch, 1);
        assert_eq!(ov.v().entry(&entry).unwrap().current().unwrap().content.as_ref().unwrap().epoch, 1);
        drop(ov);

        // Every old secret is dead; the new ones work; history across epochs reads fine.
        m.lock(&id);
        assert!(m.unlock(&id, SlotKind::Passphrase, None, b"old passphrase").is_err());
        assert!(m.unlock(&id, SlotKind::Recovery, None, recovery.as_bytes()).is_err());
        m.unlock(&id, SlotKind::Recovery, None, new_recovery.as_bytes()).unwrap();
        m.lock(&id);
        m.unlock(&id, SlotKind::Passphrase, None, b"new passphrase").unwrap();
        assert_eq!(m.read(&id, &entry, Some(1), 1 << 20).unwrap(), b"before rotation");
        assert_eq!(m.read(&id, &entry, None, 1 << 20).unwrap(), b"edited after rotation");
        assert_eq!(m.read(&id, &e2, None, 1 << 20).unwrap(), b"after rotation");
    }
}
