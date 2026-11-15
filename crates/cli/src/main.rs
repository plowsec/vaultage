//! `coffer`: command-line client. One-shot: unlocks, acts, syncs, forgets the key.

use std::io::{BufRead, IsTerminal, Write};
use std::path::PathBuf;
use std::process::exit;

use coffer_core::header::SlotKind;
use coffer_core::manager::{default_home, Manager, OpenVault};
use coffer_core::model::{normalize_path, EntryId};
use coffer_core::{harden, Error, Result};
use zeroize::Zeroize;

const USAGE: &str = "\
coffer — encrypted vaults

  coffer vaults                                   list vaults
  coffer new <name> [--server URL --token T|--token-file F] [--passphrase]
  coffer join <name> --server URL --vault ID      (unlock secret as below)
  coffer join <name> --invite                     (prompts for the invite; or COFFER_INVITE)
  coffer forget <vault>                           remove from this machine's list (files stay)
  coffer posture                                  process hardening status
  coffer trust [URL --ca FILE.pem | URL --clear]  pin a server to your own CA / certificate; no args: list

  coffer <vault> ls [path]            coffer <vault> add <src>... [--to DIR] [--move]
  coffer <vault> cat <path>           coffer <vault> get <path>... --out DIR [--move]
  coffer <vault> mv <from> <to>       coffer <vault> rm <path>...
  coffer <vault> mkdir <path>         coffer <vault> versions <path>
  coffer <vault> restore <path|entry-id> [rev]
  coffer <vault> trash                coffer <vault> sync [--watch]
  coffer <vault> passwd               add a passphrase
  coffer <vault> info                 coffer <vault> usage
  coffer <vault> empty-trash          erase trashed files for good, everywhere
  coffer <vault> prune <path>         keep only the current version of a file
  coffer <vault> connect --server URL --token T|--token-file F     local vault -> synced
  coffer <vault> invite [label] [--qr] [--hours N]   one-time invite (full access), default 24 h
  coffer <vault> invites [revoke ID]  list invites (waiting/used/expired/revoked); revoke a waiting one
  coffer <vault> rotate [--passphrase]   new keys; every other device, passphrase, invite is out
  coffer <vault> adopt                after a rotation elsewhere: enter the NEW secret

<vault> is a name or id prefix. Unlock: prompts for the passphrase; --recovery prompts for the
recovery key. Non-interactive: COFFER_PASSPHRASE or COFFER_RECOVERY_KEY. State: $COFFER_HOME.
--move deletes the source after the copy is verified (add) / removes from the vault (get).
rotate: COFFER_NEW_PASSPHRASE, COFFER_YES=1 for scripts.
";

fn die(msg: impl std::fmt::Display) -> ! {
    eprintln!("coffer: {msg}");
    exit(1)
}

/// Read a line without echo.
fn prompt_secret(label: &str) -> Vec<u8> {
    let stdin = std::io::stdin();
    if !stdin.is_terminal() {
        die(format!("{label} needed but stdin is not a terminal (set COFFER_PASSPHRASE or COFFER_RECOVERY_KEY)"));
    }
    eprint!("{label}: ");
    let _ = std::io::stderr().flush();
    let mut line = String::new();
    unsafe {
        let mut t: libc::termios = std::mem::zeroed();
        libc::tcgetattr(0, &mut t);
        let saved = t;
        t.c_lflag &= !libc::ECHO;
        libc::tcsetattr(0, libc::TCSANOW, &t);
        let _ = stdin.lock().read_line(&mut line);
        libc::tcsetattr(0, libc::TCSANOW, &saved);
    }
    eprintln!();
    let out = line.trim_end_matches(['\n', '\r']).as_bytes().to_vec();
    line.zeroize();
    out
}

fn unlock_secret(recovery: bool) -> (SlotKind, Vec<u8>) {
    if let Ok(k) = std::env::var("COFFER_RECOVERY_KEY") {
        return (SlotKind::Recovery, k.into_bytes());
    }
    if recovery {
        return (SlotKind::Recovery, prompt_secret("Recovery key"));
    }
    match std::env::var("COFFER_PASSPHRASE") {
        Ok(p) => (SlotKind::Passphrase, p.into_bytes()),
        Err(_) => (SlotKind::Passphrase, prompt_secret("Passphrase")),
    }
}

fn token_arg(args: &mut Args) -> String {
    match (args.opt("--token"), args.opt("--token-file")) {
        (Some(t), _) => t,
        (None, Some(f)) => std::fs::read_to_string(f).unwrap_or_else(|e| die(e)).trim().to_string(),
        _ => String::new(),
    }
}

/// `reuse_unlock_env`: for a brand-new vault/slot COFFER_PASSPHRASE may supply it; a rotation must
/// not silently reuse the passphrase it is replacing.
fn new_passphrase(reuse_unlock_env: bool) -> Vec<u8> {
    if let Ok(p) = std::env::var("COFFER_NEW_PASSPHRASE") {
        return p.into_bytes();
    }
    if let (true, Ok(p)) = (reuse_unlock_env, std::env::var("COFFER_PASSPHRASE")) {
        return p.into_bytes();
    }
    let a = prompt_secret("New passphrase");
    if a.len() < 8 {
        die("passphrase too short (8+ characters)");
    }
    if a != prompt_secret("Repeat passphrase") {
        die("passphrases differ");
    }
    a
}

struct Args(Vec<String>);
impl Args {
    fn flag(&mut self, name: &str) -> bool {
        let before = self.0.len();
        self.0.retain(|a| a != name);
        before != self.0.len()
    }
    fn opt(&mut self, name: &str) -> Option<String> {
        let i = self.0.iter().position(|a| a == name)?;
        if i + 1 >= self.0.len() {
            die(format!("{name} needs a value"));
        }
        self.0.remove(i);
        Some(self.0.remove(i))
    }
    fn next(&mut self) -> Option<String> {
        if self.0.is_empty() { None } else { Some(self.0.remove(0)) }
    }
    fn need(&mut self, what: &str) -> String {
        self.next().unwrap_or_else(|| die(format!("missing {what}\n\n{USAGE}")))
    }
}

fn human(n: u64) -> String {
    let units = ["B", "KB", "MB", "GB", "TB"];
    let (mut v, mut u) = (n as f64, 0);
    while v >= 1000.0 && u < 4 {
        v /= 1000.0;
        u += 1;
    }
    if u == 0 { format!("{n} B") } else { format!("{v:.1} {}", units[u]) }
}

/// "in 3 h" / "5 min ago".
fn rel(t: i64, now: i64) -> String {
    let d = (t - now).abs() / 60_000;
    let s = match d {
        0 => return "now".into(),
        1..=89 => format!("{d} min"),
        90..=2879 => format!("{} h", (d + 30) / 60),
        _ => format!("{} d", (d + 720) / 1440),
    };
    if t > now { format!("in {s}") } else { format!("{s} ago") }
}

/// QR code for a terminal: two rows per line (half blocks), explicit black on white so it scans
/// on dark and light themes alike.
fn qr_text(text: &str) -> String {
    use qrcodegen::{QrCode, QrCodeEcc};
    let q = QrCode::encode_text(text, QrCodeEcc::Medium).unwrap_or_else(|_| die("invite too long for a QR code"));
    let (n, quiet) = (q.size(), 2);
    let dark = |x: i32, y: i32| (0..n).contains(&x) && (0..n).contains(&y) && q.get_module(x, y);
    let mut out = String::new();
    let mut y = -quiet;
    while y < n + quiet {
        for x in -quiet..n + quiet {
            // Foreground paints the top half, background the bottom half.
            let fg = if dark(x, y) { 30 } else { 97 };
            let bg = if dark(x, y + 1) { 40 } else { 107 };
            out.push_str(&format!("\x1b[{fg};{bg}m▀"));
        }
        out.push_str("\x1b[0m\n");
        y += 2;
    }
    out
}

fn find_vault(m: &Manager, key: &str) -> String {
    let all = m.list();
    let hits: Vec<_> = all.iter().filter(|v| v.name == key || v.id.starts_with(key)).collect();
    match hits.len() {
        1 => hits[0].id.clone(),
        0 => die(format!("no vault named '{key}' (see `coffer vaults`)")),
        _ => die(format!("'{key}' matches several vaults; use the id")),
    }
}

fn sync_and_report(ov: &OpenVault) {
    if !ov.v().synced() {
        return;
    }
    match ov.sync_blocking() {
        Ok(r) => {
            for e in &r.errors {
                eprintln!("coffer: warning: {e}");
            }
            for c in ov.v().conflicts.drain(..) {
                eprintln!("coffer: conflict: {c}");
            }
            eprintln!("synced (↓{} ↑{} chunks↓{})", r.pulled, r.pushed, r.downloaded);
        }
        Err(Error::Net(e)) => eprintln!("coffer: offline ({e}); {} change(s) kept locally, will sync later", ov.v().pending_count()),
        Err(_) if ov.status().state == "rekeyed" => die("this vault's keys were rotated on another device; continue with: coffer <vault> adopt   (enter the NEW recovery key or passphrase)"),
        Err(e) => die(format!("sync stopped: {e}")),
    }
}

fn run() -> Result<()> {
    let mut args = Args(std::env::args().skip(1).collect());
    let recovery = args.flag("--recovery");
    let first = match args.next() {
        Some(a) if a != "-h" && a != "--help" && a != "help" => a,
        _ => {
            print!("{USAGE}");
            return Ok(());
        }
    };
    let m = Manager::new(default_home(), false)?;

    match first.as_str() {
        "posture" => {
            println!("{}", serde_json::to_string_pretty(&harden::harden())?);
            return Ok(());
        }
        "vaults" => {
            for v in m.list() {
                let kinds: Vec<String> = v.slots.iter().map(|s| serde_json::to_value(s.kind).unwrap().as_str().unwrap().to_string()).collect();
                println!("{}  {:<20} {}  [{}]{}", &v.id[..12], v.name, v.remote.as_deref().unwrap_or("local"), kinds.join(", "), if v.missing { "  MISSING" } else { "" });
            }
            return Ok(());
        }
        "new" => {
            let name = args.need("vault name");
            let server = args.opt("--server");
            let token = token_arg(&mut args);
            let pass = args.flag("--passphrase").then(|| new_passphrase(true));
            let (id, recovery_key) = m.create(&name, server.as_deref().map(|s| (s, token.as_str())))?;
            if let Some(mut p) = pass {
                m.add_slot(&id, SlotKind::Passphrase, "Passphrase", &p, serde_json::Value::Null, None)?;
                p.zeroize();
            }
            sync_and_report(&*m.get(&id)?);
            println!("vault id:     {id}");
            println!("recovery key: {recovery_key}");
            eprintln!("\nWrite the recovery key down now. It is not stored anywhere and is the only way in\nif you lose every passphrase and device.");
            return Ok(());
        }
        "join" => {
            let name = args.need("vault name");
            if args.flag("--invite") {
                let mut code = std::env::var("COFFER_INVITE").map(String::into_bytes).unwrap_or_else(|_| prompt_secret("Invite"));
                let res = m.join_invite(&name, std::str::from_utf8(&code).unwrap_or(""));
                code.zeroize();
                let (id, recovery_key) = res?;
                sync_and_report(&*m.get(&id)?);
                println!("joined {id}");
                match recovery_key {
                    Some(k) => {
                        println!("recovery key: {k}");
                        eprintln!("\nThe invite is used up. Write this recovery key down: it is your way in (COFFER_RECOVERY_KEY).\nAdd a passphrase too: coffer {name} passwd");
                    }
                    None => eprintln!("Old-style invite: it keeps working until removed. Add your own passphrase now: coffer {name} passwd\n(unlock with the invite key via COFFER_RECOVERY_KEY)"),
                }
                return Ok(());
            }
            let server = args.opt("--server").unwrap_or_else(|| die("--server URL required"));
            let vault = args.opt("--vault").unwrap_or_else(|| die("--vault ID required"));
            let (kind, mut secret) = unlock_secret(recovery);
            let id = m.join(&name, &server, &vault, kind, &secret)?;
            secret.zeroize();
            sync_and_report(&*m.get(&id)?);
            println!("joined {id}");
            return Ok(());
        }
        "trust" => {
            match args.next() {
                None => {
                    for (url, pem) in m.trust() {
                        println!("{url}  {} certificate(s)", pem.matches("BEGIN CERTIFICATE").count());
                    }
                }
                Some(url) if args.flag("--clear") => {
                    m.set_trust(&url, None)?;
                    println!("{url}: public certificate authorities");
                }
                Some(url) => {
                    let file = args.opt("--ca").unwrap_or_else(|| die("--ca FILE.pem or --clear required"));
                    m.set_trust(&url, Some(&std::fs::read_to_string(&file)?))?;
                    println!("{url}: pinned to {file}");
                }
            }
            return Ok(());
        }
        "forget" => {
            let id = find_vault(&m, &args.need("vault"));
            println!("removed from list; data left at {}", m.forget(&id)?.display());
            return Ok(());
        }
        _ => {}
    }

    let id = find_vault(&m, &first);
    let cmd = args.need("command");
    if cmd == "adopt" {
        // Takes the NEW secret; the old one no longer matters.
        let (kind, mut secret) = unlock_secret(recovery);
        let res = m.adopt_rekey(&id, kind, &secret);
        secret.zeroize();
        res?;
        sync_and_report(&*m.get(&id)?);
        println!("now using the rotated keys");
        return Ok(());
    }
    let (kind, mut secret) = unlock_secret(recovery);
    let res = m.unlock(&id, kind, None, &secret);
    secret.zeroize();
    res?;
    let ov = m.get(&id)?;
    let mut changed = false;

    match cmd.as_str() {
        "ls" => {
            let path = args.next().unwrap_or_default();
            for it in ov.v().list(&path)? {
                let mark = if it.pending { "↑" } else { " " };
                if it.is_dir {
                    println!("{mark} {:>10}  {}/  ({} files)", human(it.size), it.name, it.count);
                } else {
                    println!("{mark} {:>10}  {}", human(it.size), it.name);
                }
            }
        }
        "cat" => {
            let path = normalize_path(&args.need("path"))?;
            let reader = { let v = ov.v(); let e = v.find(&path).ok_or_else(|| Error::NotFound(path.clone()))?.id; v.reader(&e, None)? };
            // Raw fd: std's stdout is line-buffered, which is very slow for binary data.
            use std::os::unix::io::FromRawFd;
            let mut out = std::mem::ManuallyDrop::new(unsafe { std::fs::File::from_raw_fd(1) });
            ov.with_remote(|r| reader.write_to(&mut *out, r))?;
        }
        "add" => {
            let dest = args.opt("--to").unwrap_or_default();
            let mv = args.flag("--move");
            let sources: Vec<PathBuf> = args.0.drain(..).map(PathBuf::from).collect();
            if sources.is_empty() {
                die("nothing to add");
            }
            let rep = m.import(&id, &sources, &dest, mv)?;
            for s in &rep.skipped {
                eprintln!("coffer: skipped {s}");
            }
            println!("encrypted {} file(s), {}{}", rep.files, human(rep.bytes), if mv { format!("; removed {} original(s)", rep.sources_deleted) } else { String::new() });
            changed = true;
            if !rep.skipped.is_empty() {
                sync_and_report(&ov);
                exit(2);
            }
        }
        "get" => {
            let out = PathBuf::from(args.opt("--out").unwrap_or_else(|| die("--out DIR required")));
            let mv = args.flag("--move");
            let paths: Vec<String> = args.0.drain(..).collect();
            for p in m.export(&id, &paths, &out, mv)? {
                println!("{}", p.display());
            }
            changed = mv;
        }
        "mv" => {
            let (from, to) = (args.need("source"), args.need("destination"));
            ov.v().rename(&from, &to)?;
            changed = true;
        }
        "rm" => {
            for p in args.0.drain(..) {
                let n = ov.v().delete(&p)?;
                println!("moved {n} item(s) to trash: {p}");
            }
            changed = true;
        }
        "mkdir" => {
            ov.v().mkdir(&args.need("path"))?;
            changed = true;
        }
        "versions" => {
            let path = normalize_path(&args.need("path"))?;
            let v = ov.v();
            let e = v.find(&path).ok_or_else(|| Error::NotFound(path.clone()))?.id;
            println!("entry {}", e.hex());
            for ver in v.versions(&e)? {
                let tag = if ver.pending { "pending" } else if ver.deleted { "deleted" } else if ver.current { "current" } else { "" };
                println!("rev {:<4} {}  {:>10}  {:<12} {} {}", ver.rev, coffer_core::model::stamp(ver.ts), human(ver.size), ver.device, ver.path, tag);
            }
        }
        "restore" => {
            let what = args.need("path or entry id");
            let rev = args.next().map(|r| r.parse::<u64>().unwrap_or_else(|_| die("rev must be a number")));
            let mut v = ov.v();
            let e = match EntryId::parse(&what) {
                Ok(e) if v.entry(&e).is_some() => e,
                _ => v.find(&normalize_path(&what)?).ok_or_else(|| Error::NotFound(what.clone()))?.id,
            };
            println!("restored to {}", v.restore(&e, rev)?);
            changed = true;
        }
        "trash" => {
            for t in ov.v().trash() {
                println!("{}  {}  {:>10}  {}", t.id, coffer_core::model::stamp(t.deleted_ts), human(t.size), t.path);
            }
        }
        "passwd" => {
            let mut p = new_passphrase(true);
            m.add_slot(&id, SlotKind::Passphrase, "Passphrase", &p, serde_json::Value::Null, None)?;
            p.zeroize();
            println!("passphrase added");
            changed = true;
        }
        "info" => {
            let v = ov.v();
            let s = v.summary();
            println!("id:      {}\nserver:  {}\nfiles:   {} ({})\npending: {}\ntrash:   {}", v.id_hex(), v.config.remote.as_deref().unwrap_or("none (local vault)"), s.files, human(s.bytes), s.pending, s.trashed);
        }
        "usage" => {
            let u = m.usage(&id)?;
            println!("chunks:  {} ({})\nrecords: {}\nquota:   {}", u.chunks, human(u.bytes), u.records, u.quota.map(human).unwrap_or_else(|| "none".into()));
        }
        "empty-trash" => {
            let n = ov.v().empty_trash()?;
            println!("erased {n} trashed item(s) for good");
            changed = true;
        }
        "prune" => {
            let path = normalize_path(&args.need("path"))?;
            let e = ov.v().find(&path).ok_or_else(|| Error::NotFound(path.clone()))?.id;
            ov.v().prune_versions(&e)?;
            println!("older versions of {path} erased");
            changed = true;
        }
        "connect" => {
            let server = args.opt("--server").unwrap_or_else(|| die("--server URL required"));
            let token = token_arg(&mut args);
            m.attach(&id, &server, &token)?;
            println!("vault now syncs with {server}");
            changed = true;
        }
        "invite" => {
            let qr = args.flag("--qr");
            let hours = args.opt("--hours").map(|h| h.parse::<i64>().ok().filter(|h| (1..=168).contains(h)).unwrap_or_else(|| die("--hours must be 1..168")));
            let label = args.next().unwrap_or_default();
            let mut code = m.invite(&id, &label, hours.map(|h| h * 3600 * 1000))?;
            if qr {
                eprint!("{}", qr_text(&code));
            }
            println!("{code}");
            code.zeroize();
            eprintln!("\nWorks once, for {} h. Whoever uses it first gets full access to the vault.\nSee or revoke: coffer {first} invites. To cut off someone who joined: coffer {first} rotate", hours.unwrap_or(24));
        }
        "invites" => {
            let list = m.invites(&id)?;
            if args.next().as_deref() == Some("revoke") {
                let p = args.need("invite id").to_lowercase();
                let hits: Vec<_> = list.iter().filter(|i| i.id.starts_with(&p)).collect();
                let [one] = hits[..] else { die(format!("{} invites match '{p}'", hits.len())) };
                m.revoke_invite(&id, &one.id)?;
                println!("revoked {}", &one.id[..8]);
                return Ok(());
            }
            let now = coffer_core::model::now_ms();
            for i in list {
                let when = match i.state.as_str() {
                    "waiting" => format!("expires {}", rel(i.expires, now)),
                    "used" => format!("used {}", rel(i.claimed.unwrap_or(0), now)),
                    "revoked" => format!("revoked {}", rel(i.revoked.unwrap_or(0), now)),
                    _ => format!("expired {}", rel(i.expires, now)),
                };
                println!("{}  {:<8} {:<18} {}", &i.id[..8], i.state, when, i.label);
            }
        }
        "rotate" => {
            let mut pass = args.flag("--passphrase").then(|| new_passphrase(false));
            let recovery_key = m.rotate_prepare(&id, pass.as_deref(), None)?;
            if let Some(p) = pass.as_mut() {
                p.zeroize();
            }
            println!("new recovery key: {recovery_key}");
            eprintln!("\nStore it now. After this step the old recovery key, passphrases, invites and every other\ndevice stop working. Other devices continue with: coffer {first} adopt");
            if std::env::var("COFFER_YES").is_err() {
                eprint!("Type yes to rotate: ");
                let mut line = String::new();
                let _ = std::io::stdin().lock().read_line(&mut line);
                if line.trim() != "yes" {
                    m.rotate_cancel(&id)?;
                    die("cancelled; nothing changed");
                }
            }
            m.rotate_commit(&id)?;
            println!("keys rotated");
            changed = true;
        }
        "sync" => {
            if !ov.v().synced() {
                die("this is a local vault; nothing to sync");
            }
            if args.flag("--watch") {
                loop {
                    sync_and_report(&ov);
                    std::thread::sleep(std::time::Duration::from_secs(5));
                }
            }
            changed = true;
        }
        other => die(format!("unknown command '{other}'\n\n{USAGE}")),
    }
    if changed {
        sync_and_report(&ov);
    }
    Ok(())
}

fn main() {
    harden::harden();
    if let Err(e) = run() {
        die(e);
    }
}
