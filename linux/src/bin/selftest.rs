//! Headless round-trip through the GUI's logic layer (`vaultage_gui::logic`). Never prompts.
//!
//! | Env | Use |
//! |---|---|
//! | `VAULTAGE_HOME` | required: an empty temp dir (this device) |
//! | `VAULTAGE_TEST_URL`, `VAULTAGE_TEST_TOKEN` | a local `vaultaged`: adds synced vault, second device, invite/join, rotate/adopt, attach, directory lock |
//! | `VAULTAGE_TEST_CLI` | path to the `vaultage` CLI (the second device); default `vaultage` on PATH |
//!
//! Exit code 0 = every check passed. Run from a throwaway cwd.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

use vaultage_core::header::SlotKind;
use vaultage_gui::logic::{self, text, Backend, Secret, SortKey};

static FAILS: AtomicU32 = AtomicU32::new(0);

fn check(ok: bool, what: &str) {
    println!("{} {what}", if ok { "ok  " } else { "FAIL" });
    if !ok {
        FAILS.fetch_add(1, Ordering::Relaxed);
    }
}

fn must<T>(r: logic::R<T>, what: &str) -> T {
    match r {
        Ok(v) => v,
        Err(e) => {
            println!("FAIL {what}: {} ({}: {})", e.text(), e.code, e.message);
            println!("{} failure(s)", FAILS.load(Ordering::Relaxed) + 1);
            std::process::exit(1);
        }
    }
}

fn write(dir: &Path, name: &str, data: &[u8]) -> PathBuf {
    let p = dir.join(name);
    std::fs::create_dir_all(p.parent().unwrap()).unwrap();
    std::fs::write(&p, data).unwrap();
    p
}

fn entry(b: &Backend, id: &str, dir: &str, name: &str) -> Option<String> {
    b.list(id, dir).ok()?.0.into_iter().find(|i| i.name == name).and_then(|i| i.id)
}

const PASS: &str = "correct horse battery staple";

fn local(b: &Backend, home: &Path) -> String {
    let created = must(b.create("Test", None, Some(&Secret::new(PASS))), "create local vault with passphrase");
    let id = created.id.clone();
    check(created.recovery.len() > 40 && created.warning.is_none(), "create returns recovery key, passphrase slot added");
    let v = b.vault(&id).unwrap();
    check(v.unlocked && logic::has_passphrase(&v), "new vault unlocked, has passphrase slot");

    // Import: a file and a folder, then a "move in" that deletes the original.
    let src = home.join("src");
    let payload: Vec<u8> = (0..300_000u32).map(|i| (i % 251) as u8).collect();
    let blob = write(&src, "blob.bin", &payload);
    write(&src, "folder/note.txt", b"MARKER-PLAINTEXT-7f3a hello");
    let rep = must(b.import(&id, &[blob.clone(), src.join("folder")], "", false), "import");
    check(rep.files == 2 && rep.skipped.is_empty(), &format!("import 2 files (got {}, skipped {:?})", rep.files, rep.skipped));
    check(logic::import_summary(&rep, false).0.starts_with("Encrypted 2 files"), "import summary text");
    let moved_src = write(&src, "move-me.txt", b"moved in");
    let rep = must(b.import(&id, &[moved_src.clone()], "", true), "import --move");
    check(rep.sources_deleted == 1 && !moved_src.exists(), "move-in deletes the verified original");

    let (mut items, gen) = must(b.list(&id, ""), "list root");
    logic::sort_items(&mut items, SortKey::Name, true);
    let names: Vec<&str> = items.iter().map(|i| i.name.as_str()).collect();
    check(names == ["folder", "blob.bin", "move-me.txt"], &format!("list root, folders first ({names:?})"));
    let blob_id = items.iter().find(|i| i.name == "blob.bin").unwrap().id.clone().unwrap();
    let data = must(b.read(&id, &blob_id, None, 1 << 30), "read");
    check(*data == payload, "read decrypts identical bytes");
    check(b.read(&id, &blob_id, None, 10).is_err(), "read refuses a file over the limit");

    // mkdir / rename / move / search
    let sub = must(b.mkdir(&id, "folder", "sub"), "mkdir");
    check(sub == "folder/sub", "mkdir path");
    check(b.mkdir(&id, "folder", "sub").map_err(|e| e.code).err() == Some("exists"), "mkdir refuses an existing name");
    check(b.mkdir(&id, "", "a/b").is_err(), "mkdir refuses '/' in a name");
    check(must(b.free_folder_name(&id, ""), "free name") == "untitled folder", "free folder name");
    let renamed = must(b.rename(&id, "blob.bin", "blob2.bin"), "rename");
    check(renamed == "blob2.bin", "rename keeps folder");
    let (moved, err) = b.move_to(&id, &["blob2.bin".into(), "folder".into()], "folder/sub");
    check(moved == ["folder/sub/blob2.bin"] && err.is_none(), &format!("move skips a folder into itself ({moved:?})"));
    let found = must(b.search(&id, "BLOB"), "search");
    check(found.len() == 1 && found[0].path == "folder/sub/blob2.bin", "search is case-insensitive");
    check(must(b.folders(&id), "folders") == ["folder", "folder/sub"], "folder list for Move To");
    let st = must(b.status(&id), "status");
    check(st.sync.state == "local" && st.summary.files == 3 && st.generation > gen, "status: local, 3 files, generation moved");
    check(logic::sync_line(&st).text == "Local vault — not synced", "sync line for a local vault");

    // Versions: re-import a same-named file = new revision.
    let edit = write(&home.join("edit"), "note.txt", b"MARKER-PLAINTEXT-7f3a edited");
    must(b.import(&id, &[edit], "folder", false), "re-import");
    let note = entry(b, &id, "folder", "note.txt").unwrap();
    let vs = must(b.versions(&id, &note), "versions");
    check(vs.len() == 2 && vs[0].current, &format!("2 versions, newest first ({})", vs.len()));
    let old = must(b.read(&id, &note, Some(vs[1].rev), 1 << 20), "read old version");
    check(&old[..] == b"MARKER-PLAINTEXT-7f3a hello", "old version readable");
    must(b.restore(&id, &note, Some(vs[1].rev)), "restore old version");
    let now = must(b.read(&id, &note, None, 1 << 20), "read restored");
    check(&now[..] == b"MARKER-PLAINTEXT-7f3a hello", "restore brings old content back as current");
    check(must(b.versions(&id, &note), "versions").len() == 3, "restore adds a revision");
    must(b.prune_versions(&id, &note), "prune versions");
    check(must(b.versions(&id, &note), "versions").len() == 1, "prune keeps only the current version");

    // Trash: delete, restore, purge, empty.
    let n = must(b.delete(&id, &["folder/note.txt".into(), "move-me.txt".into()]), "delete");
    check(n == 2, "delete 2 to trash");
    let trash = must(b.trash(&id), "trash");
    check(trash.len() == 2, "trash lists 2");
    let back = must(b.restore(&id, &note, None), "restore from trash");
    check(back == "folder/note.txt" && entry(b, &id, "folder", "note.txt").is_some(), "restore from trash puts it back");
    let mv = must(b.trash(&id), "trash").into_iter().find(|t| t.path == "move-me.txt").unwrap();
    check(must(b.purge(&id, &[mv.id.clone()]), "purge") == 1, "purge one");
    check(must(b.trash(&id), "trash").is_empty(), "trash empty after purge");
    must(b.delete(&id, &["folder/note.txt".into()]), "delete again");
    check(must(b.empty_trash(&id), "empty trash") == 1 && must(b.trash(&id), "trash").is_empty(), "empty trash");

    // Export / move out.
    let out = home.join("out");
    let written = must(b.export(&id, &["folder/sub/blob2.bin".into()], &out, false), "export");
    check(written.len() == 1 && std::fs::read(&written[0]).unwrap() == payload, "export writes identical bytes");
    std::fs::remove_file(&written[0]).unwrap();
    let written = must(b.export(&id, &["folder/sub".into()], &out, true), "move out");
    check(written[0].join("blob2.bin").exists() && entry(b, &id, "folder", "sub").is_none(), "move out removes from vault");
    std::fs::remove_file(written[0].join("blob2.bin")).unwrap();
    std::fs::remove_dir(&written[0]).unwrap();

    // Lock / unlock, slots.
    b.lock(&id);
    check(b.list(&id, "").err().map(|e| e.is_locked()) == Some(true), "locked vault refuses list");
    let wrong = b.unlock(&id, SlotKind::Passphrase, &Secret::new("nope")).unwrap_err();
    check(wrong.is_wrong_secret() && wrong.text() == "Wrong passphrase or key.", "wrong passphrase text");
    must(b.unlock(&id, SlotKind::Passphrase, &Secret::new(PASS)), "unlock passphrase");
    b.lock(&id);
    must(b.unlock(&id, SlotKind::Recovery, &Secret::trimmed(&format!("  {}\n", created.recovery.as_str()))), "unlock recovery key (pasted with whitespace)");
    let slot = must(b.add_passphrase(&id, &Secret::new("second passphrase here")), "add passphrase slot");
    b.lock(&id);
    must(b.unlock(&id, SlotKind::Passphrase, &Secret::new("second passphrase here")), "unlock with the added passphrase");
    must(b.remove_slot(&id, &slot), "remove passphrase slot");
    b.lock(&id);
    check(b.unlock(&id, SlotKind::Passphrase, &Secret::new("second passphrase here")).is_err(), "removed passphrase no longer opens");
    must(b.unlock(&id, SlotKind::Passphrase, &Secret::new(PASS)), "first passphrase still opens");
    let v = b.vault(&id).unwrap();
    let rec = v.slots.iter().find(|s| s.kind == SlotKind::Recovery).unwrap().id.clone();
    let pw = v.slots.iter().find(|s| s.kind == SlotKind::Passphrase).unwrap().id.clone();
    must(b.remove_slot(&id, &rec), "remove recovery slot");
    check(b.remove_slot(&id, &pw).is_err(), "last portable slot can't be removed");

    must(b.rename_vault(&id, "Renamed"), "rename vault");
    check(b.vault(&id).unwrap().name == "Renamed", "vault renamed");
    id
}

/// The CLI as a second device, with its own state dir.
struct Cli {
    bin: String,
    home: PathBuf,
}

impl Cli {
    fn run(&self, args: &[&str], env: &[(&str, &str)]) -> (bool, String, String) {
        let mut c = Command::new(&self.bin);
        c.args(args).env("VAULTAGE_HOME", &self.home).stdin(Stdio::null());
        for k in ["VAULTAGE_PASSPHRASE", "VAULTAGE_RECOVERY_KEY", "VAULTAGE_INVITE", "VAULTAGE_NEW_PASSPHRASE"] {
            c.env_remove(k);
        }
        for (k, v) in env {
            c.env(k, v);
        }
        let o = c.output().expect("run the CLI");
        (o.status.success(), String::from_utf8_lossy(&o.stdout).into_owned(), String::from_utf8_lossy(&o.stderr).into_owned())
    }
}

fn wait(what: &str, secs: u64, mut ok: impl FnMut() -> bool) -> bool {
    let t = Instant::now();
    while t.elapsed() < Duration::from_secs(secs) {
        if ok() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(300));
    }
    println!("     (timed out waiting for {what})");
    false
}

fn synced(b: &Backend, home: &Path, url: &str, token: &str, cli_bin: &str, local_id: &str) {
    let tok = Secret::new(token);
    let created = must(b.create("Shared", Some((url, &tok)), Some(&Secret::new(PASS))), "create synced vault");
    let id = created.id.clone();
    check(b.create("Bad", Some(("http://example.com", &tok)), None).is_err(), "create refuses http:// to a remote host");
    let bad = b.create("Bad", Some((url, &Secret::new("wrong-token"))), None).unwrap_err();
    check(bad.code == "server" && bad.text().starts_with("The sync server refused the request"), &format!("wrong enrollment token: {}", bad.text()));
    must(b.import(&id, &[write(&home.join("s"), "hello.txt", b"from the gui")], "", false), "import into synced vault");
    must(b.sync_blocking(&id), "sync");
    let st = must(b.status(&id), "status");
    check(st.synced && st.sync.state == "idle" && st.summary.pending == 0, &format!("synced, nothing pending ({} {})", st.sync.state, st.summary.pending));
    check(logic::sync_line(&st).text.starts_with("Up to date"), "sync line: up to date");
    let usage = must(b.usage(&id), "usage");
    check(usage.records > 0 && usage.bytes > 0, "server usage");

    // Second device: the CLI joins with the passphrase, reads, adds a file.
    let cli = Cli { bin: cli_bin.into(), home: home.join("cli-home") };
    let (ok, out, err) = cli.run(&["join", "Shared", "--server", url, "--vault", &id], &[("VAULTAGE_PASSPHRASE", PASS)]);
    check(ok && out.contains("joined"), &format!("CLI joins with the passphrase {}", err.trim()));
    let (ok, out, _) = cli.run(&["Shared", "cat", "hello.txt"], &[("VAULTAGE_PASSPHRASE", PASS)]);
    check(ok && out == "from the gui", "CLI reads the GUI's file");
    let f2 = write(&home.join("c"), "from-cli.txt", b"from the cli");
    let (ok, _, err) = cli.run(&["Shared", "add", f2.to_str().unwrap()], &[("VAULTAGE_PASSPHRASE", PASS)]);
    check(ok, &format!("CLI adds a file {}", err.trim()));
    // Live refresh: the background sync thread pulls it; generation moves.
    let gen0 = must(b.status(&id), "status").generation;
    must(b.sync_now(&id), "sync now");
    check(wait("the CLI's file", 30, || entry(b, &id, "", "from-cli.txt").is_some()), "background sync brings the CLI's file");
    check(must(b.status(&id), "status").generation > gen0, "generation changes on a remote change (UI reloads on it)");

    // Directory lock: the CLI can't open a vault the GUI holds, and vice versa.
    let me = Cli { bin: cli_bin.into(), home: b.home.clone() };
    let (ok, _, err) = me.run(&["Renamed", "ls"], &[("VAULTAGE_PASSPHRASE", PASS)]);
    check(!ok && err.contains("another Vaultage process"), &format!("CLI refused while the GUI has the vault open ({})", err.trim()));
    b.lock(&id);
    let mut watch = Command::new(cli_bin)
        .args(["Shared", "sync", "--watch"])
        .env("VAULTAGE_HOME", &b.home)
        .env("VAULTAGE_PASSPHRASE", PASS)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn CLI");
    let mut in_use = None;
    wait("the CLI to take the lock", 15, || match b.unlock(&id, SlotKind::Passphrase, &Secret::new(PASS)) {
        Err(e) if e.is_in_use() => {
            in_use = Some(e);
            true
        }
        Ok(()) => {
            b.lock(&id);
            false
        }
        Err(_) => false,
    });
    let _ = watch.kill();
    let _ = watch.wait();
    check(in_use.as_ref().map(|e| e.text()) == Some(text::IN_USE.to_string()), "GUI unlock refused while the CLI holds the vault, readable text");
    must(b.unlock(&id, SlotKind::Passphrase, &Secret::new(PASS)), "unlock after the CLI quit");

    // Invites: GUI invites, CLI joins; revoke; GUI (second Backend) joins with the CLI's invite.
    let code = must(b.invite(&id, "cli"), "invite");
    let cli3 = Cli { bin: cli_bin.into(), home: home.join("cli3-home") };
    let (ok, out, err) = cli3.run(&["join", "Inv", "--invite"], &[("VAULTAGE_INVITE", code.as_str())]);
    check(ok && out.contains("recovery key:"), &format!("CLI joins with the GUI's invite {}", err.trim()));
    let list = must(b.invites(&id), "invites");
    check(list.iter().any(|i| i.label == "cli" && i.state == "used"), "invite list shows it used");
    check(logic::invite_state(&list[0]).starts_with("Used"), "invite state text");
    let reuse = Cli { bin: cli_bin.into(), home: home.join("cli4-home") };
    let (ok, _, _) = reuse.run(&["join", "Inv", "--invite"], &[("VAULTAGE_INVITE", code.as_str())]);
    check(!ok, "a used invite can't join again");
    let code2 = must(b.invite(&id, "to revoke"), "second invite");
    let inv2 = must(b.invites(&id), "invites").into_iter().find(|i| i.label == "to revoke").unwrap();
    must(b.revoke_invite(&id, &inv2.id), "revoke invite");
    check(must(b.invites(&id), "invites").iter().any(|i| i.id == inv2.id && i.state == "revoked"), "revoked invite listed as revoked");
    let other = must(Backend::open(Some(home.join("gui2-home"))), "second GUI backend");
    let gone = other.join_invite("Revoked", &Secret::new(code2.as_str())).unwrap_err();
    check(gone.message.contains("revoked"), &format!("revoked invite refused: {}", gone.text()));
    let (ok, out, _) = cli.run(&["Shared", "invite", "gui2"], &[("VAULTAGE_PASSPHRASE", PASS)]);
    let code3 = out.trim().to_string();
    check(ok && !code3.is_empty(), "CLI makes an invite");
    let joined = must(other.join_invite("Joined", &Secret::new(&code3)), "GUI join_invite");
    check(joined.id == id && joined.recovery.as_ref().map(|k| k.len() > 40) == Some(true), "GUI joins by invite, gets its own recovery key");
    check(wait("the joined device's first sync", 30, || entry(&other, &id, "", "hello.txt").is_some()), "joined device sees the files");
    check(other.join_invite("Again", &Secret::new(&code3)).unwrap_err().code == "exists", "joining a vault already here is refused");
    check(other.join_invite("X", &Secret::new("garbage")).unwrap_err().text().starts_with("An invite is one line"), "malformed invite text");

    // Join by server + vault id + recovery key, from a third GUI home.
    let third = must(Backend::open(Some(home.join("gui3-home"))), "third GUI backend");
    let wrong = third.join("W", url, &id, SlotKind::Recovery, &Secret::new("AAAAA-AAAAA")).unwrap_err();
    check(wrong.code != "crypto" || wrong.text().contains("doesn’t open"), "join with a wrong key: readable");
    must(third.join("Third", url, &id, SlotKind::Recovery, &Secret::trimmed(created.recovery.as_str())), "join with the recovery key");
    check(wait("the third device's first sync", 30, || entry(&third, &id, "", "hello.txt").is_some()), "third device sees the files");

    // Rotate keys on this device; the CLI and the joined GUI must adopt with the new secret.
    let newpass = "a brand new passphrase 42";
    let key1 = must(b.rotate_prepare(&id, Some(&Secret::new("throwaway passphrase"))), "rotate prepare");
    check(must(b.status(&id), "status").rotation_pending, "rotation pending after prepare");
    must(b.rotate_cancel(&id), "rotate cancel");
    check(!must(b.status(&id), "status").rotation_pending, "cancel clears it");
    let key2 = must(b.rotate_prepare(&id, Some(&Secret::new(newpass))), "rotate prepare again");
    check(*key1 != *key2, "a new prepare gives a new recovery key");
    must(b.rotate_commit(&id), "rotate commit");
    check(must(b.status(&id), "status").epoch == 1, "epoch 1 after rotation");
    must(b.sync_blocking(&id), "sync after rotation");
    b.lock(&id);
    check(b.unlock(&id, SlotKind::Passphrase, &Secret::new(PASS)).is_err(), "old passphrase is out");
    must(b.unlock(&id, SlotKind::Recovery, &Secret::new(key2.as_str())), "new recovery key opens");

    let (ok, _, err) = cli.run(&["Shared", "sync"], &[("VAULTAGE_PASSPHRASE", PASS)]);
    check(!ok && err.contains("rotated"), "CLI told to adopt");
    let (ok, out, err) = cli.run(&["Shared", "adopt"], &[("VAULTAGE_PASSPHRASE", newpass)]);
    check(ok && out.contains("rotated keys"), &format!("CLI adopts with the new passphrase {}", err.trim()));

    check(wait("the joined GUI to notice the rotation", 40, || other.status(&id).map(|s| s.rekeyed()).unwrap_or(false)), "joined GUI: status rekeyed");
    let st = must(other.status(&id), "status");
    let line = logic::sync_line(&st);
    check(line.rekeyed && line.text.starts_with("Keys rotated"), "rekeyed sync line offers the new key");
    check(other.adopt_rekey(&id, SlotKind::Passphrase, &Secret::new(PASS)).unwrap_err().text() == "That passphrase doesn’t open the rotated vault.", "adopt with the old passphrase: readable");
    must(other.adopt_rekey(&id, SlotKind::Passphrase, &Secret::new(newpass)), "GUI adopts with the new passphrase");
    must(other.sync_blocking(&id), "joined GUI syncs again");
    check(other.status(&id).map(|s| s.sync.state == "idle").unwrap_or(false), "joined GUI idle after adopt");

    // Attach: the local vault goes to the server; the CLI joins it.
    must(b.import(local_id, &[write(&home.join("a"), "attach.txt", b"kept history")], "", false), "import before attach");
    must(b.attach(local_id, url, &tok), "attach local vault");
    let st = must(b.status(local_id), "status");
    check(st.synced, "attached vault is synced");
    let vi = b.vault(local_id).unwrap();
    check(vi.remote.is_some(), "attached vault has a server");
    let cli5 = Cli { bin: cli_bin.into(), home: home.join("cli5-home") };
    let (ok, _, err) = cli5.run(&["join", "Att", "--server", url, "--vault", local_id], &[("VAULTAGE_PASSPHRASE", PASS)]);
    check(ok, &format!("CLI joins the attached vault {}", err.trim()));
    let (ok, out, _) = cli5.run(&["Att", "cat", "attach.txt"], &[("VAULTAGE_PASSPHRASE", PASS)]);
    check(ok && out == "kept history", "CLI reads the attached vault's file");

    // Certificate pinning: set, read, clear.
    check(b.pin(url).is_none(), "no pin by default");
    check(b.set_pin(url, Some("hello")).is_err(), "text that isn't PEM is refused");
    let pem = "-----BEGIN CERTIFICATE-----\nMIIBszCCAVmgAwIBAgIUYQ==\n-----END CERTIFICATE-----\n";
    must(b.set_pin(url, Some(pem)), "pin a certificate");
    check(b.pin(url).is_some_and(|p| p.contains("BEGIN CERTIFICATE")), "pin is stored");
    must(b.set_pin(url, None), "unpin");
    check(b.pin(url).is_none(), "unpinned");

    drop(other);
    drop(third);
}

fn main() {
    let posture = vaultage_core::harden::harden();
    println!("posture: core_dumps_off={} attach_denied={} memory_locked={}", posture.core_dumps_off, posture.attach_denied, posture.memory_locked);
    let Some(home) = vaultage_core::env_var("HOME").filter(|h| !h.is_empty()) else {
        eprintln!("set VAULTAGE_HOME to an empty temporary directory");
        std::process::exit(2);
    };
    let home = PathBuf::from(home);
    if std::fs::read_dir(&home).map(|mut d| d.next().is_some()).unwrap_or(false) {
        eprintln!("VAULTAGE_HOME must be empty");
        std::process::exit(2);
    }
    let b = must(Backend::open(None), "open state dir");
    check(b.home == home, "uses VAULTAGE_HOME");
    let id = local(&b, &home);
    match (vaultage_core::env_var("TEST_URL"), vaultage_core::env_var("TEST_TOKEN")) {
        (Some(url), Some(token)) => {
            let cli = vaultage_core::env_var("TEST_CLI").unwrap_or_else(|| "vaultage".into());
            synced(&b, &home, &url, &token, &cli, &id);
        }
        _ => println!("skip synced checks (set VAULTAGE_TEST_URL and VAULTAGE_TEST_TOKEN)"),
    }
    b.lock_all();
    check(b.unlocked_count() == 0, "lock all");
    let n = FAILS.load(Ordering::Relaxed);
    println!("{}", if n == 0 { "all checks passed".to_string() } else { format!("{n} failure(s)") });
    std::process::exit(if n == 0 { 0 } else { 1 });
}
