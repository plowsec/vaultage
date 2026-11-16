//! Vaultage server: zero-knowledge store for encrypted chunks and an append-only record log.

mod api;
mod ratelimit;
mod store;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::thread::JoinHandle;
use std::time::Duration;

/// Where vault state lives.
#[derive(Clone, Default)]
pub enum StoreKind {
    /// `Config.data_dir` on a POSIX filesystem.
    #[default]
    Fs,
    Gcs(GcsConfig),
}

#[derive(Clone, Default)]
pub struct GcsConfig {
    pub bucket: String,
    /// Object name prefix, "" or ending in '/'.
    pub prefix: String,
    /// API base URL override (emulator/fake). Default https://storage.googleapis.com.
    pub endpoint: Option<String>,
    /// Static bearer token. If unset: none when `endpoint` is set, else the metadata server.
    pub token: Option<String>,
}

impl std::fmt::Debug for GcsConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GcsConfig")
            .field("bucket", &self.bucket)
            .field("prefix", &self.prefix)
            .field("endpoint", &self.endpoint)
            .field("token", &self.token.as_ref().map(|_| "<redacted>"))
            .finish()
    }
}

impl StoreKind {
    /// `fs` or `gcs://<bucket>[/<prefix>]`.
    pub fn parse(s: &str) -> Result<StoreKind, String> {
        if s == "fs" {
            return Ok(StoreKind::Fs);
        }
        let rest = s
            .strip_prefix("gcs://")
            .ok_or(format!("bad store {s:?}: want fs or gcs://bucket[/prefix]"))?;
        let (bucket, prefix) = rest.split_once('/').unwrap_or((rest, ""));
        let ok = |c: char| c.is_ascii_lowercase() || c.is_ascii_digit() || "-_.".contains(c);
        if bucket.is_empty() || !bucket.chars().all(ok) {
            return Err(format!("bad bucket name {bucket:?}"));
        }
        let prefix = prefix.trim_matches('/');
        Ok(StoreKind::Gcs(GcsConfig {
            bucket: bucket.into(),
            prefix: if prefix.is_empty() {
                String::new()
            } else {
                format!("{prefix}/")
            },
            ..Default::default()
        }))
    }
}

pub struct Config {
    /// FS store root (ignored by GCS).
    pub data_dir: PathBuf,
    /// `None` disables enrollment (POST /v1/vaults always 403).
    pub enroll_token: Option<String>,
    pub store: StoreKind,
    /// Unreferenced chunks younger than this survive GC (in-flight uploads).
    pub gc_grace_secs: u64,
    /// Per-vault stored chunk bytes limit.
    pub vault_quota_bytes: Option<u64>,
    /// Rate limits per `rate_window_secs` (0 = unlimited): unauthenticated header reads per vault,
    /// failed signature checks per vault, bad-token vault creations (global).
    pub rate_header_reads: u32,
    pub rate_auth_failures: u32,
    pub rate_enroll_failures: u32,
    pub rate_window_secs: u64,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            data_dir: PathBuf::from("./data"),
            enroll_token: None,
            store: StoreKind::Fs,
            gc_grace_secs: 86_400,
            vault_quota_bytes: None,
            rate_header_reads: 30,
            rate_auth_failures: 20,
            rate_enroll_failures: 10,
            rate_window_secs: 60,
        }
    }
}

pub fn router(cfg: Config) -> std::io::Result<axum::Router> {
    api::router(cfg)
}

pub struct ServerHandle {
    addr: SocketAddr,
    stop: Option<tokio::sync::oneshot::Sender<()>>,
    thread: Option<JoinHandle<()>>,
}

/// Start on a background thread with its own tokio runtime (for tests/embedding). Bind e.g. "127.0.0.1:0".
pub fn spawn(cfg: Config, bind: &str) -> std::io::Result<ServerHandle> {
    let app = router(cfg)?;
    let listener = std::net::TcpListener::bind(bind)?;
    listener.set_nonblocking(true)?;
    let addr = listener.local_addr()?;
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()?;
    let (tx, rx) = tokio::sync::oneshot::channel::<()>();
    let thread = std::thread::Builder::new().name("vaultaged".into()).spawn(move || {
        rt.block_on(async move {
            let l = match tokio::net::TcpListener::from_std(listener) {
                Ok(l) => l,
                Err(e) => return eprintln!("vaultaged: listener: {e}"),
            };
            let shutdown = async {
                let _ = rx.await;
            };
            if let Err(e) = axum::serve(l, app).with_graceful_shutdown(shutdown).await {
                eprintln!("vaultaged: serve: {e}");
            }
        });
        rt.shutdown_timeout(Duration::from_secs(10));
    })?;
    Ok(ServerHandle {
        addr,
        stop: Some(tx),
        thread: Some(thread),
    })
}

impl ServerHandle {
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// Stop accepting, finish in-flight requests, join the server thread.
    pub fn shutdown(mut self) {
        self.stop_and_join();
    }

    fn stop_and_join(&mut self) {
        if let Some(tx) = self.stop.take() {
            let _ = tx.send(());
        }
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

impl Drop for ServerHandle {
    fn drop(&mut self) {
        self.stop_and_join();
    }
}
