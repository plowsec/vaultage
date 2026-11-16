use std::path::PathBuf;
use std::process::ExitCode;

use vaultage_server::{Config, StoreKind};

const USAGE: &str = "usage: vaultaged [options]
  --data <dir>               FS store dir (env VAULTAGE_DATA, default ./data)
  --store <fs|gcs://bucket[/prefix]>
                             storage backend (env VAULTAGE_STORE, default fs)
  --listen <addr>            bind address (env VAULTAGE_LISTEN, default 127.0.0.1:8787)
  --enroll-token-file <path> file holding the enrollment token
                             (env VAULTAGE_ENROLL_TOKEN_FILE, or VAULTAGE_ENROLL_TOKEN for the value)
  --gc-grace-secs <n>        unreferenced chunks younger than this survive prune
                             (env VAULTAGE_GC_GRACE_SECS, default 86400)
  --vault-quota-bytes <n>    per-vault chunk byte limit (env VAULTAGE_VAULT_QUOTA_BYTES, default none)
GCS env: VAULTAGE_GCS_TOKEN (static bearer token), VAULTAGE_GCS_ENDPOINT or STORAGE_EMULATOR_HOST
(API base URL; auth skipped unless VAULTAGE_GCS_TOKEN). Default auth: metadata server.
Old VAULTAGE_* names still work. Without an enrollment token, vault creation is disabled.";

struct Args {
    data: PathBuf,
    listen: String,
    token_file: Option<PathBuf>,
    store: String,
    grace: u64,
    quota: Option<u64>,
}

/// `VAULTAGE_<k>`, else the pre-rename `VAULTAGE_<k>`. Empty counts as unset.
fn env(k: &str) -> Option<String> {
    vaultage_core::env_var(k).filter(|v| !v.is_empty())
}

fn num(name: &str, v: &str) -> Result<u64, String> {
    v.trim().parse().map_err(|_| format!("{name}: not a number: {v:?}"))
}

fn parse_args() -> Result<Args, String> {
    let mut a = Args {
        data: env("DATA").map_or_else(|| PathBuf::from("./data"), PathBuf::from),
        listen: env("LISTEN").unwrap_or_else(|| "127.0.0.1:8787".into()),
        token_file: env("ENROLL_TOKEN_FILE").map(PathBuf::from),
        store: env("STORE").unwrap_or_else(|| "fs".into()),
        grace: env("GC_GRACE_SECS").map_or(Ok(86_400), |v| num("VAULTAGE_GC_GRACE_SECS", &v))?,
        quota: env("VAULT_QUOTA_BYTES")
            .map(|v| num("VAULTAGE_VAULT_QUOTA_BYTES", &v))
            .transpose()?,
    };
    let mut it = std::env::args().skip(1);
    while let Some(flag) = it.next() {
        let (name, inline) = match flag.split_once('=') {
            Some((n, v)) if n.starts_with("--") => (n.to_owned(), Some(v.to_owned())),
            _ => (flag.clone(), None),
        };
        if name == "-h" || name == "--help" {
            println!("{USAGE}");
            std::process::exit(0);
        }
        let mut val = || {
            inline
                .clone()
                .or_else(|| it.next())
                .ok_or(format!("{name} needs a value"))
        };
        match name.as_str() {
            "--data" => a.data = val()?.into(),
            "--listen" => a.listen = val()?,
            "--enroll-token-file" => a.token_file = Some(val()?.into()),
            "--store" => a.store = val()?,
            "--gc-grace-secs" => a.grace = num(&name, &val()?)?,
            "--vault-quota-bytes" => a.quota = Some(num(&name, &val()?)?),
            _ => return Err(format!("unknown argument: {flag}")),
        }
    }
    Ok(a)
}

fn load_token(a: &Args) -> Result<Option<String>, String> {
    let tok = match &a.token_file {
        Some(p) => Some(
            std::fs::read_to_string(p)
                .map_err(|e| format!("read {}: {e}", p.display()))?
                .trim()
                .to_owned(),
        ),
        None => env("ENROLL_TOKEN").map(|t| t.trim().to_owned()),
    };
    Ok(tok.filter(|t| !t.is_empty()))
}

async fn shutdown_signal() {
    use tokio::signal::unix::{signal, SignalKind};
    let mut term = match signal(SignalKind::terminate()) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("vaultaged: SIGTERM handler: {e}");
            let _ = tokio::signal::ctrl_c().await;
            return;
        }
    };
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {}
        _ = term.recv() => {}
    }
    eprintln!("vaultaged: shutting down");
}

#[tokio::main]
async fn main() -> ExitCode {
    let args = match parse_args() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("vaultaged: {e}\n{USAGE}");
            return ExitCode::from(2);
        }
    };
    let mut store = match StoreKind::parse(&args.store) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("vaultaged: {e}");
            return ExitCode::from(2);
        }
    };
    let where_ = match &mut store {
        StoreKind::Fs => format!("data {}", args.data.display()),
        StoreKind::Gcs(g) => {
            g.endpoint = env("GCS_ENDPOINT").or_else(|| std::env::var("STORAGE_EMULATOR_HOST").ok().filter(|v| !v.is_empty()));
            g.token = env("GCS_TOKEN");
            format!(
                "store gcs://{}/{} via {}",
                g.bucket,
                g.prefix,
                g.endpoint.as_deref().unwrap_or("storage.googleapis.com")
            )
        }
    };
    let token = match load_token(&args) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("vaultaged: {e}");
            return ExitCode::FAILURE;
        }
    };
    if token.is_none() {
        eprintln!("vaultaged: no enrollment token: vault creation disabled");
    }
    let app = match vaultage_server::router(Config {
        data_dir: args.data.clone(),
        enroll_token: token,
        store,
        gc_grace_secs: args.grace,
        vault_quota_bytes: args.quota,
        ..Default::default()
    }) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("vaultaged: {where_}: {e}");
            return ExitCode::FAILURE;
        }
    };
    let listener = match tokio::net::TcpListener::bind(&args.listen).await {
        Ok(l) => l,
        Err(e) => {
            eprintln!("vaultaged: bind {}: {e}", args.listen);
            return ExitCode::FAILURE;
        }
    };
    eprintln!("vaultaged: listening on {} ({where_})", args.listen);
    if let Err(e) = axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
    {
        eprintln!("vaultaged: {e}");
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}
