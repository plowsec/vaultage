use std::path::PathBuf;
use std::process::ExitCode;

use vaultage_server::{gdrive_login, Config, DriveConfig, StoreKind};

const USAGE: &str = "usage: vaultaged [options]
       vaultaged gdrive-login [--folder-name <name> | --no-folder]
  --data <dir>               FS store dir (env VAULTAGE_DATA, default ./data)
  --store <fs|gcs://bucket[/prefix]>
                             storage backend (env VAULTAGE_STORE, default fs)
  --listen <addr>            bind address (env VAULTAGE_LISTEN, default 127.0.0.1:8787)
  --enroll-token-file <path> file holding the enrollment token
                             (env VAULTAGE_ENROLL_TOKEN_FILE, or VAULTAGE_ENROLL_TOKEN for the value)
  --gc-grace-secs <n>        unreferenced chunks younger than this survive prune
                             (env VAULTAGE_GC_GRACE_SECS, default 86400)
  --vault-quota-bytes <n>    per-vault chunk byte limit (env VAULTAGE_VAULT_QUOTA_BYTES, default none)
  --chunks <bucket|gdrive://folder-id>
                             where chunk bytes go with a gcs store (env VAULTAGE_CHUNKS, default bucket)
GCS env: VAULTAGE_GCS_TOKEN (static bearer token), VAULTAGE_GCS_ENDPOINT or STORAGE_EMULATOR_HOST
(API base URL; auth skipped unless VAULTAGE_GCS_TOKEN). Default auth: metadata server.
Drive env: VAULTAGE_GDRIVE_CLIENT_ID, VAULTAGE_GDRIVE_CLIENT_SECRET, VAULTAGE_GDRIVE_REFRESH_TOKEN;
VAULTAGE_GDRIVE_ENDPOINT, VAULTAGE_GDRIVE_TOKEN_URL, VAULTAGE_GDRIVE_TOKEN (fakes/tests).
gdrive-login: one-time consent in a browser (needs the client id and secret); creates the folder
(default name Vaultage), prints the refresh token on stdout and the --chunks value on stderr.
Old COFFER_* names still work. Without an enrollment token, vault creation is disabled.";

struct Args {
    data: PathBuf,
    listen: String,
    token_file: Option<PathBuf>,
    store: String,
    grace: u64,
    quota: Option<u64>,
    chunks: String,
}

/// `VAULTAGE_<k>`, else the pre-rename `COFFER_<k>`. Empty counts as unset.
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
        chunks: env("CHUNKS").unwrap_or_else(|| "bucket".into()),
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
            "--chunks" => a.chunks = val()?,
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

/// Trimmed: secrets mounted from files or Secret Manager often end in a newline.
fn secret(k: &str) -> Option<String> {
    env(k).map(|s| s.trim().to_owned()).filter(|s| !s.is_empty())
}

/// `bucket` → None, `gdrive://<folder id>` → Drive config from the environment.
fn parse_chunks(s: &str) -> Result<Option<DriveConfig>, String> {
    if s == "bucket" {
        return Ok(None);
    }
    let folder = s
        .strip_prefix("gdrive://")
        .ok_or(format!("bad --chunks {s:?}: want bucket or gdrive://<folder-id>"))?
        .trim_matches('/');
    Ok(Some(DriveConfig {
        folder: folder.to_owned(),
        endpoint: secret("GDRIVE_ENDPOINT"),
        token_url: secret("GDRIVE_TOKEN_URL"),
        client_id: secret("GDRIVE_CLIENT_ID"),
        client_secret: secret("GDRIVE_CLIENT_SECRET"),
        refresh_token: secret("GDRIVE_REFRESH_TOKEN"),
        token: secret("GDRIVE_TOKEN"),
    }))
}

fn gdrive_login_main(args: &[String]) -> ExitCode {
    let mut name = Some("Vaultage".to_owned());
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "-h" | "--help" => {
                println!("{USAGE}");
                return ExitCode::SUCCESS;
            }
            "--no-folder" => name = None,
            "--folder-name" => match it.next() {
                Some(v) => name = Some(v.clone()),
                None => {
                    eprintln!("vaultaged: --folder-name needs a value");
                    return ExitCode::from(2);
                }
            },
            _ => {
                eprintln!("vaultaged: unknown argument: {a}\n{USAGE}");
                return ExitCode::from(2);
            }
        }
    }
    let (Some(client_id), Some(client_secret)) = (secret("GDRIVE_CLIENT_ID"), secret("GDRIVE_CLIENT_SECRET")) else {
        eprintln!("vaultaged: set VAULTAGE_GDRIVE_CLIENT_ID and VAULTAGE_GDRIVE_CLIENT_SECRET (OAuth client, type Desktop app)");
        return ExitCode::from(2);
    };
    let opts = gdrive_login::Opts {
        client_id,
        client_secret,
        folder_name: name,
        ..Default::default()
    };
    let out = gdrive_login::login(&opts, |url| {
        eprintln!("Open this URL in a browser signed in to the Google account whose Drive will hold the chunks:\n\n{url}\n\nWaiting for the redirect...");
    });
    match out {
        Ok(o) => {
            println!("{}", o.refresh_token);
            eprintln!("\nDone. stdout: the refresh token (store it as VAULTAGE_GDRIVE_REFRESH_TOKEN).");
            if let (Some(id), Some(n)) = (&o.folder_id, &opts.folder_name) {
                eprintln!("Folder {n:?} created: --chunks gdrive://{id}");
            }
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("vaultaged: gdrive-login: {e}");
            ExitCode::FAILURE
        }
    }
}

#[tokio::main]
async fn main() -> ExitCode {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    if argv.first().map(String::as_str) == Some("gdrive-login") {
        return tokio::task::block_in_place(|| gdrive_login_main(&argv[1..]));
    }
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
    let drive = match parse_chunks(&args.chunks) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("vaultaged: {e}");
            return ExitCode::from(2);
        }
    };
    let where_ = match &mut store {
        StoreKind::Fs if drive.is_some() => {
            eprintln!("vaultaged: --chunks gdrive://… needs --store gcs://…");
            return ExitCode::from(2);
        }
        StoreKind::Fs => format!("data {}", args.data.display()),
        StoreKind::Gcs(g) => {
            g.endpoint = env("GCS_ENDPOINT").or_else(|| std::env::var("STORAGE_EMULATOR_HOST").ok().filter(|v| !v.is_empty()));
            g.token = env("GCS_TOKEN");
            let chunks = match &drive {
                Some(d) => format!(", chunks in Drive folder {}", d.folder),
                None => String::new(),
            };
            g.drive = drive.map(Box::new);
            format!(
                "store gcs://{}/{} via {}{chunks}",
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
