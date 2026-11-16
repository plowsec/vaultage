//! `vaultage`: command-line client. One-shot: unlocks, acts, syncs, forgets the key.

use std::io::{BufRead, IsTerminal, Write};
use std::path::PathBuf;
use std::process::exit;

use vaultage_core::header::SlotKind;
use vaultage_core::manager::{default_home, Manager, OpenVault};
use vaultage_core::model::{normalize_path, EntryId};
use vaultage_core::{harden, Error, Result};
use zeroize::Zeroize;

const USAGE: &str = "\
vaultage — encrypted vaults

  vaultage vaults                                   list vaults
  vaultage new <name> [--server URL --token T|--token-file F] [--passphrase]
  vaultage join <name> --server URL --vault ID      (unlock secret as below)
  vaultage join <name> --invite                     (prompts for the invite; or VAULTAGE_INVITE)
  vaultage forget <vault>                           remove from this machine's list (files stay)
  vaultage posture                                  process hardening status
  vaultage trust [URL --ca FILE.pem | URL --clear]  pin a server to your own CA / certificate; no args: list

  vaultage <vault> ls [path]            vaultage <vault> add <src>... [--to DIR] [--move]
  vaultage <vault> cat <path>           vaultage <vault> get <path>... --out DIR [--move]
  vaultage <vault> mv <from> <to>       vaultage <vault> rm <path>...
  vaultage <vault> mkdir <path>         vaultage <vault> versions <path>
  vaultage <vault> restore <path|entry-id> [rev]
  vaultage <vault> trash                vaultage <vault> sync [--watch]
  vaultage <vault> passwd               add a passphrase
  vaultage <vault> info                 vaultage <vault> usage
  vaultage <vault> empty-trash          erase trashed files for good, everywhere
  vaultage <vault> prune <path>         keep only the current version of a file
  vaultage <vault> connect --server URL --token T|--token-file F     local vault -> synced
  vaultage <vault> invite [label] [--qr] [--hours N]   one-time invite (full access), default 24 h
  vaultage <vault> invites [revoke ID]  list invites (waiting/used/expired/revoked); revoke a waiting one
  vaultage <vault> rotate [--passphrase]   new keys; every other device, passphrase, invite is out
  vaultage <vault> adopt                after a rotation elsewhere: enter the NEW secret

Options go anywhere after the command; a name or path starting with '-' goes after --
(vaultage forget -- -old). -h / --help anywhere prints this and changes nothing.
<vault> is a name or id prefix. Unlock: prompts for the passphrase; --recovery prompts for the
recovery key. Non-interactive: VAULTAGE_PASSPHRASE or VAULTAGE_RECOVERY_KEY. State: $VAULTAGE_HOME.
--move deletes the source after the copy is verified (add) / removes from the vault (get).
rotate: VAULTAGE_NEW_PASSPHRASE, VAULTAGE_YES=1 for scripts. Old VAULTAGE_* names still work.
";

fn die(msg: impl std::fmt::Display) -> ! {
    eprintln!("vaultage: {msg}");
    exit(1)
}

/// Read a line without echo.
fn prompt_secret(label: &str) -> Vec<u8> {
    let stdin = std::io::stdin();
    if !stdin.is_terminal() {
        die(format!("{label} needed but stdin is not a terminal (set VAULTAGE_PASSPHRASE or VAULTAGE_RECOVERY_KEY)"));
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
    if let Some(k) = vaultage_core::env_var("RECOVERY_KEY") {
        return (SlotKind::Recovery, k.into_bytes());
    }
    if recovery {
        return (SlotKind::Recovery, prompt_secret("Recovery key"));
    }
    match vaultage_core::env_var("PASSPHRASE") {
        Some(p) => (SlotKind::Passphrase, p.into_bytes()),
        None => (SlotKind::Passphrase, prompt_secret("Passphrase")),
    }
}

fn token_arg(args: &mut Args) -> String {
    match (args.opt("--token").or_die(), args.opt("--token-file").or_die()) {
        (Some(t), _) => t,
        (None, Some(f)) => std::fs::read_to_string(f).unwrap_or_else(|e| die(e)).trim().to_string(),
        _ => String::new(),
    }
}

/// `reuse_unlock_env`: for a brand-new vault/slot VAULTAGE_PASSPHRASE may supply it; a rotation must
/// not silently reuse the passphrase it is replacing.
fn new_passphrase(reuse_unlock_env: bool) -> Vec<u8> {
    if let Some(p) = vaultage_core::env_var("NEW_PASSPHRASE") {
        return p.into_bytes();
    }
    if let (true, Some(p)) = (reuse_unlock_env, vaultage_core::env_var("PASSPHRASE")) {
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

/// Every option the CLI knows. An option's value may not be one of these (`--server --passphrase`).
const OPTIONS: &[&str] = &[
    "--recovery", "--server", "--token", "--token-file", "--passphrase", "--invite", "--vault", "--ca", "--clear", "--to",
    "--move", "--out", "--qr", "--hours", "--watch",
];

fn is_help(a: &str) -> bool {
    a == "-h" || a == "--help"
}

/// Options are taken out first (`flag`, `opt`); what is left are positionals (`next`, `need`,
/// `rest`). A positional that looks like an option is refused, so a typo or `--help` never
/// becomes a vault name or a path. Everything after `--` is positional as written.
#[derive(Debug)]
struct Args {
    v: Vec<String>,
    literal: Vec<String>,
}
impl Args {
    fn parse(mut v: Vec<String>) -> Args {
        let literal = match v.iter().position(|a| a == "--") {
            Some(i) => v.split_off(i).split_off(1),
            None => Vec::new(),
        };
        Args { v, literal }
    }
    fn wants_help(&self) -> bool {
        self.v.iter().any(|a| is_help(a))
    }
    fn flag(&mut self, name: &str) -> bool {
        let before = self.v.len();
        self.v.retain(|a| a != name);
        before != self.v.len()
    }
    fn opt(&mut self, name: &str) -> std::result::Result<Option<String>, String> {
        let Some(i) = self.v.iter().position(|a| a == name) else { return Ok(None) };
        if i + 1 >= self.v.len() || OPTIONS.contains(&self.v[i + 1].as_str()) {
            return Err(format!("{name} needs a value"));
        }
        self.v.remove(i);
        Ok(Some(self.v.remove(i)))
    }
    fn positional(a: String) -> std::result::Result<String, String> {
        if a.len() > 1 && a.starts_with('-') {
            return Err(format!("unknown option '{a}' (for a name or path starting with '-', put it after --)"));
        }
        Ok(a)
    }
    fn next(&mut self) -> std::result::Result<Option<String>, String> {
        if !self.v.is_empty() {
            return Self::positional(self.v.remove(0)).map(Some);
        }
        Ok(if self.literal.is_empty() { None } else { Some(self.literal.remove(0)) })
    }
    fn need(&mut self, what: &str) -> std::result::Result<String, String> {
        self.next()?.ok_or_else(|| format!("missing {what}\n\n{USAGE}"))
    }
    /// All remaining positionals.
    fn rest(&mut self) -> std::result::Result<Vec<String>, String> {
        let mut out = self.v.drain(..).map(Self::positional).collect::<std::result::Result<Vec<_>, _>>()?;
        out.append(&mut self.literal);
        Ok(out)
    }
    /// Refuse options `cmd` does not take, before anything is unlocked or changed. `valued`
    /// options consume the next argument.
    fn only(&self, cmd: &str, flags: &[&str], valued: &[&str]) -> std::result::Result<(), String> {
        let mut it = self.v.iter();
        while let Some(a) = it.next() {
            if valued.contains(&a.as_str()) {
                it.next();
            } else if a.len() > 1 && a.starts_with('-') && !flags.contains(&a.as_str()) {
                return Err(format!("'{cmd}' does not take '{a}' (for a name or path starting with '-', put it after --)"));
            }
        }
        Ok(())
    }
    /// Nothing may be left over: a misspelled option must not be ignored.
    fn done(&mut self) -> std::result::Result<(), String> {
        match self.rest()?.first() {
            Some(a) => Err(format!("unexpected argument '{a}'")),
            None => Ok(()),
        }
    }
}

/// `die` on a bad command line.
trait OrDie<T> {
    fn or_die(self) -> T;
}
impl<T> OrDie<T> for std::result::Result<T, String> {
    fn or_die(self) -> T {
        self.unwrap_or_else(|e| die(e))
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

/// Text another member wrote (an invite label), safe to print: no control characters, so no
/// terminal escape sequences.
fn printable(s: &str) -> String {
    s.chars().map(|c| if c.is_control() { '\u{fffd}' } else { c }).collect()
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
        0 => die(format!("no vault named '{key}' (see `vaultage vaults`)")),
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
                eprintln!("vaultage: warning: {e}");
            }
            for c in ov.v().conflicts.drain(..) {
                eprintln!("vaultage: conflict: {c}");
            }
            eprintln!("synced (↓{} ↑{} chunks↓{})", r.pulled, r.pushed, r.downloaded);
        }
        Err(Error::Net(e)) => eprintln!("vaultage: offline ({e}); {} change(s) kept locally, will sync later", ov.v().pending_count()),
        Err(_) if ov.status().state == "rekeyed" => die("this vault's keys were rotated on another device; continue with: vaultage <vault> adopt   (enter the NEW recovery key or passphrase)"),
        Err(e) => die(format!("sync stopped: {e}")),
    }
}

fn run() -> Result<()> {
    let mut args = Args::parse(std::env::args().skip(1).collect());
    // Before anything touches the vault list: `vaultage new --help` must not create a vault.
    if args.wants_help() || args.v.first().is_some_and(|a| a == "help") {
        print!("{USAGE}");
        return Ok(());
    }
    let recovery = args.flag("--recovery");
    let Some(first) = args.next().or_die() else {
        print!("{USAGE}");
        return Ok(());
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
            let server = args.opt("--server").or_die();
            let token = token_arg(&mut args);
            let want_pass = args.flag("--passphrase");
            let name = args.need("vault name").or_die();
            args.done().or_die();
            let pass = want_pass.then(|| new_passphrase(true));
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
            let invite = args.flag("--invite");
            let server = args.opt("--server").or_die();
            let vault = args.opt("--vault").or_die();
            let name = args.need("vault name").or_die();
            args.done().or_die();
            if invite {
                let mut code = vaultage_core::env_var("INVITE").map(String::into_bytes).unwrap_or_else(|| prompt_secret("Invite"));
                let res = m.join_invite(&name, std::str::from_utf8(&code).unwrap_or(""));
                code.zeroize();
                let (id, recovery_key) = res?;
                sync_and_report(&*m.get(&id)?);
                println!("joined {id}");
                match recovery_key {
                    Some(k) => {
                        println!("recovery key: {k}");
                        eprintln!("\nThe invite is used up. Write this recovery key down: it is your way in (VAULTAGE_RECOVERY_KEY).\nAdd a passphrase too: vaultage {name} passwd");
                    }
                    None => eprintln!("Old-style invite: it keeps working until removed. Add your own passphrase now: vaultage {name} passwd\n(unlock with the invite key via VAULTAGE_RECOVERY_KEY)"),
                }
                return Ok(());
            }
            let server = server.unwrap_or_else(|| die("--server URL required"));
            let vault = vault.unwrap_or_else(|| die("--vault ID required"));
            let (kind, mut secret) = unlock_secret(recovery);
            let id = m.join(&name, &server, &vault, kind, &secret)?;
            secret.zeroize();
            sync_and_report(&*m.get(&id)?);
            println!("joined {id}");
            return Ok(());
        }
        "trust" => {
            let clear = args.flag("--clear");
            let ca = args.opt("--ca").or_die();
            let url = args.next().or_die();
            args.done().or_die();
            match url {
                None => {
                    for (url, pem) in m.trust() {
                        println!("{url}  {} certificate(s)", pem.matches("BEGIN CERTIFICATE").count());
                    }
                }
                Some(url) if clear => {
                    m.set_trust(&url, None)?;
                    println!("{url}: public certificate authorities");
                }
                Some(url) => {
                    let file = ca.unwrap_or_else(|| die("--ca FILE.pem or --clear required"));
                    m.set_trust(&url, Some(&std::fs::read_to_string(&file)?))?;
                    println!("{url}: pinned to {file}");
                }
            }
            return Ok(());
        }
        "forget" => {
            let key = args.need("vault").or_die();
            args.done().or_die();
            let id = find_vault(&m, &key);
            println!("removed from list; data left at {}", m.forget(&id)?.display());
            return Ok(());
        }
        _ => {}
    }

    let id = find_vault(&m, &first);
    let cmd = args.need("command").or_die();
    let (flags, valued): (&[&str], &[&str]) = match cmd.as_str() {
        "add" => (&["--move"], &["--to"]),
        "get" => (&["--move"], &["--out"]),
        "connect" => (&[], &["--server", "--token", "--token-file"]),
        "invite" => (&["--qr"], &["--hours"]),
        "rotate" => (&["--passphrase"], &[]),
        "sync" => (&["--watch"], &[]),
        _ => (&[], &[]),
    };
    args.only(&cmd, flags, valued).or_die();
    if cmd == "adopt" {
        args.done().or_die();
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
            let path = args.next().or_die().unwrap_or_default();
            args.done().or_die();
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
            let path = normalize_path(&args.need("path").or_die())?;
            args.done().or_die();
            let reader = { let v = ov.v(); let e = v.find(&path).ok_or_else(|| Error::NotFound(path.clone()))?.id; v.reader(&e, None)? };
            // Raw fd: std's stdout is line-buffered, which is very slow for binary data.
            use std::os::unix::io::FromRawFd;
            let mut out = std::mem::ManuallyDrop::new(unsafe { std::fs::File::from_raw_fd(1) });
            ov.with_remote(|r| reader.write_to(&mut *out, r))?;
        }
        "add" => {
            let dest = args.opt("--to").or_die().unwrap_or_default();
            let mv = args.flag("--move");
            let sources: Vec<PathBuf> = args.rest().or_die().into_iter().map(PathBuf::from).collect();
            if sources.is_empty() {
                die("nothing to add");
            }
            let rep = m.import(&id, &sources, &dest, mv)?;
            for s in &rep.skipped {
                eprintln!("vaultage: skipped {s}");
            }
            println!("encrypted {} file(s), {}{}", rep.files, human(rep.bytes), if mv { format!("; removed {} original(s)", rep.sources_deleted) } else { String::new() });
            changed = true;
            if !rep.skipped.is_empty() {
                sync_and_report(&ov);
                exit(2);
            }
        }
        "get" => {
            let out = PathBuf::from(args.opt("--out").or_die().unwrap_or_else(|| die("--out DIR required")));
            let mv = args.flag("--move");
            let paths = args.rest().or_die();
            if paths.is_empty() {
                die("nothing to get");
            }
            for p in m.export(&id, &paths, &out, mv)? {
                println!("{}", p.display());
            }
            changed = mv;
        }
        "mv" => {
            let (from, to) = (args.need("source").or_die(), args.need("destination").or_die());
            args.done().or_die();
            ov.v().rename(&from, &to)?;
            changed = true;
        }
        "rm" => {
            let paths = args.rest().or_die();
            if paths.is_empty() {
                die("nothing to remove");
            }
            for p in paths {
                let n = ov.v().delete(&p)?;
                println!("moved {n} item(s) to trash: {p}");
            }
            changed = true;
        }
        "mkdir" => {
            let path = args.need("path").or_die();
            args.done().or_die();
            ov.v().mkdir(&path)?;
            changed = true;
        }
        "versions" => {
            let path = normalize_path(&args.need("path").or_die())?;
            args.done().or_die();
            let v = ov.v();
            let e = v.find(&path).ok_or_else(|| Error::NotFound(path.clone()))?.id;
            println!("entry {}", e.hex());
            for ver in v.versions(&e)? {
                let tag = if ver.pending { "pending" } else if ver.deleted { "deleted" } else if ver.current { "current" } else { "" };
                println!("rev {:<4} {}  {:>10}  {:<12} {} {}", ver.rev, vaultage_core::model::stamp(ver.ts), human(ver.size), ver.device, ver.path, tag);
            }
        }
        "restore" => {
            let what = args.need("path or entry id").or_die();
            let rev = args.next().or_die().map(|r| r.parse::<u64>().unwrap_or_else(|_| die("rev must be a number")));
            args.done().or_die();
            let mut v = ov.v();
            let e = match EntryId::parse(&what) {
                Ok(e) if v.entry(&e).is_some() => e,
                _ => v.find(&normalize_path(&what)?).ok_or_else(|| Error::NotFound(what.clone()))?.id,
            };
            println!("restored to {}", v.restore(&e, rev)?);
            changed = true;
        }
        "trash" => {
            args.done().or_die();
            for t in ov.v().trash() {
                println!("{}  {}  {:>10}  {}", t.id, vaultage_core::model::stamp(t.deleted_ts), human(t.size), t.path);
            }
        }
        "passwd" => {
            args.done().or_die();
            let mut p = new_passphrase(true);
            m.add_slot(&id, SlotKind::Passphrase, "Passphrase", &p, serde_json::Value::Null, None)?;
            p.zeroize();
            println!("passphrase added");
            changed = true;
        }
        "info" => {
            args.done().or_die();
            let v = ov.v();
            let s = v.summary();
            println!("id:      {}\nserver:  {}\nfiles:   {} ({})\npending: {}\ntrash:   {}", v.id_hex(), v.config.remote.as_deref().unwrap_or("none (local vault)"), s.files, human(s.bytes), s.pending, s.trashed);
        }
        "usage" => {
            args.done().or_die();
            let u = m.usage(&id)?;
            println!("chunks:  {} ({})\nrecords: {}\nquota:   {}", u.chunks, human(u.bytes), u.records, u.quota.map(human).unwrap_or_else(|| "none".into()));
        }
        "empty-trash" => {
            args.done().or_die();
            let n = ov.v().empty_trash()?;
            println!("erased {n} trashed item(s) for good");
            changed = true;
        }
        "prune" => {
            let path = normalize_path(&args.need("path").or_die())?;
            args.done().or_die();
            let e = ov.v().find(&path).ok_or_else(|| Error::NotFound(path.clone()))?.id;
            ov.v().prune_versions(&e)?;
            println!("older versions of {path} erased");
            changed = true;
        }
        "connect" => {
            let server = args.opt("--server").or_die().unwrap_or_else(|| die("--server URL required"));
            let token = token_arg(&mut args);
            args.done().or_die();
            m.attach(&id, &server, &token)?;
            println!("vault now syncs with {server}");
            changed = true;
        }
        "invite" => {
            let qr = args.flag("--qr");
            let hours = args.opt("--hours").or_die().map(|h| h.parse::<i64>().ok().filter(|h| (1..=168).contains(h)).unwrap_or_else(|| die("--hours must be 1..168")));
            let label = args.next().or_die().unwrap_or_default();
            args.done().or_die();
            let mut code = m.invite(&id, &label, hours.map(|h| h * 3600 * 1000))?;
            if qr {
                eprint!("{}", qr_text(&code));
            }
            println!("{code}");
            code.zeroize();
            eprintln!("\nWorks once, for {} h. Whoever uses it first gets full access to the vault.\nSee or revoke: vaultage {first} invites. To cut off someone who joined: vaultage {first} rotate", hours.unwrap_or(24));
        }
        "invites" => {
            let revoke = match args.next().or_die().as_deref() {
                None => None,
                Some("revoke") => Some(args.need("invite id").or_die().to_lowercase()),
                Some(other) => die(format!("unknown invites command '{other}' (only: revoke ID)")),
            };
            args.done().or_die();
            let list = m.invites(&id)?;
            if let Some(p) = revoke {
                let hits: Vec<_> = list.iter().filter(|i| i.id.starts_with(&p)).collect();
                let [one] = hits[..] else { die(format!("{} invites match '{p}'", hits.len())) };
                m.revoke_invite(&id, &one.id)?;
                println!("revoked {}", &one.id[..8]);
                return Ok(());
            }
            let now = vaultage_core::model::now_ms();
            for i in list {
                let when = match i.state.as_str() {
                    "waiting" => format!("expires {}", rel(i.expires, now)),
                    "used" => format!("used {}", rel(i.claimed.unwrap_or(0), now)),
                    "revoked" => format!("revoked {}", rel(i.revoked.unwrap_or(0), now)),
                    _ => format!("expired {}", rel(i.expires, now)),
                };
                // Ids are checked by the core (32 hex characters): the slice cannot fail.
                println!("{}  {:<8} {:<18} {}", &i.id[..8], i.state, when, printable(&i.label));
            }
        }
        "rotate" => {
            let want_pass = args.flag("--passphrase");
            args.done().or_die();
            let mut pass = want_pass.then(|| new_passphrase(false));
            let recovery_key = m.rotate_prepare(&id, pass.as_deref(), None)?;
            if let Some(p) = pass.as_mut() {
                p.zeroize();
            }
            println!("new recovery key: {recovery_key}");
            eprintln!("\nStore it now. After this step the old recovery key, passphrases, invites and every other\ndevice stop working. Other devices continue with: vaultage {first} adopt");
            if vaultage_core::env_var_os("YES").is_none() {
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
            let watch = args.flag("--watch");
            args.done().or_die();
            if !ov.v().synced() {
                die("this is a local vault; nothing to sync");
            }
            if watch {
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

#[cfg(test)]
mod tests {
    use super::Args;

    fn args(s: &[&str]) -> Args {
        Args::parse(s.iter().map(|a| a.to_string()).collect())
    }

    #[test]
    fn help_anywhere_but_not_after_double_dash() {
        assert!(args(&["new", "--help"]).wants_help());
        assert!(args(&["new", "Work", "-h"]).wants_help());
        assert!(!args(&["forget", "--", "--help"]).wants_help());
    }

    #[test]
    fn flag_like_positionals_are_refused() {
        let mut a = args(&["--pasphrase", "Work"]);
        assert!(a.need("vault name").unwrap_err().contains("unknown option '--pasphrase'"));
        let mut a = args(&["a", "-r", "b"]);
        assert!(a.rest().is_err());
        // "-" alone is an ordinary argument.
        assert_eq!(args(&["-"]).need("x").unwrap(), "-");
    }

    #[test]
    fn double_dash_makes_the_rest_literal() {
        let mut a = args(&["--", "--help", "-x"]);
        assert_eq!(a.need("vault").unwrap(), "--help");
        assert_eq!(a.rest().unwrap(), ["-x"]);
        let mut a = args(&["a", "--", "-b"]);
        assert_eq!(a.rest().unwrap(), ["a", "-b"]);
    }

    #[test]
    fn options_before_or_after_positionals() {
        let mut a = args(&["--server", "https://s", "Work", "--passphrase"]);
        assert_eq!(a.opt("--server").unwrap().as_deref(), Some("https://s"));
        assert!(a.flag("--passphrase"));
        assert_eq!(a.need("vault name").unwrap(), "Work");
        assert!(a.done().is_ok());
    }

    #[test]
    fn option_value_cannot_be_another_option() {
        assert!(args(&["--server", "--passphrase"]).opt("--server").is_err());
        assert!(args(&["--server"]).opt("--server").is_err());
        // A value that merely starts with '-' (a token) is fine.
        assert_eq!(args(&["--token", "-abc"]).opt("--token").unwrap().as_deref(), Some("-abc"));
    }

    #[test]
    fn leftovers_are_errors() {
        let mut a = args(&["Work", "extra"]);
        a.need("vault").unwrap();
        assert!(a.done().unwrap_err().contains("'extra'"));
    }

    #[test]
    fn only_allows_the_command_options() {
        assert!(args(&["src", "--to", "-dir", "--move"]).only("add", &["--move"], &["--to"]).is_ok());
        assert!(args(&["src", "--mvoe"]).only("add", &["--move"], &["--to"]).unwrap_err().contains("--mvoe"));
        assert!(args(&["--", "-file"]).only("rm", &[], &[]).is_ok());
    }
}
