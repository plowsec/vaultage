//! The real client stack against the real server over HTTP.

use std::fs;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use coffer_core::crypto::KdfParams;
use coffer_core::header::SlotKind;
use coffer_core::http::{create_vault, HttpRemote};
use coffer_core::manager::Manager;
use coffer_core::remote::Remote;
use coffer_core::testkit::fuzz;
use coffer_core::vault::Vault;
use coffer_core::Error;
use coffer_server::{spawn, Config, ServerHandle};
use serde_json::{json, Value};

const TOKEN: &str = "enroll-token-for-tests";

fn server(data: &Path, bind: &str) -> (ServerHandle, String) {
    let h = spawn(Config { data_dir: data.to_path_buf(), enroll_token: Some(TOKEN.into()), ..Default::default() }, bind).unwrap();
    let url = format!("http://{}", h.addr());
    (h, url)
}

#[test]
fn fuzz_over_http() {
    for seed in 101..=106 {
        let data = tempfile::tempdir().unwrap();
        let (_h, url) = server(data.path(), "127.0.0.1:0");
        let registered = AtomicBool::new(false);
        fuzz(seed, 3, 90, &|v: &Vault| {
            if !registered.swap(true, Ordering::SeqCst) {
                create_vault(&url, TOKEN, &v.keys(), &v.portable_header()).unwrap();
            }
            Arc::new(HttpRemote::new(&url, &v.id_hex(), v.keys()).unwrap()) as Arc<dyn Remote>
        });
    }
}

fn names(m: &Manager, id: &str, dir: &str) -> Vec<String> {
    m.get(id).unwrap().v().list(dir).unwrap().into_iter().map(|i| i.name).collect()
}

#[test]
fn two_macs_end_to_end() {
    let tmp = tempfile::tempdir().unwrap();
    let (h, url) = server(&tmp.path().join("server"), "127.0.0.1:0");
    let addr = h.addr().to_string();
    let a = Manager::new(tmp.path().join("homeA"), false).unwrap();
    let b = Manager::new(tmp.path().join("homeB"), false).unwrap();

    // A wrong enrollment token leaves nothing behind.
    assert!(matches!(a.create("Nope", Some((&url, "wrong"))), Err(Error::Server(403, _))));
    assert!(a.list().is_empty());
    assert_eq!(fs::read_dir(tmp.path().join("homeA/vaults")).unwrap().count(), 0);

    let (id, recovery) = a.create("Docs", Some((&url, TOKEN))).unwrap();
    a.add_slot(&id, SlotKind::Passphrase, "Passphrase", b"correct horse battery", Value::Null, Some(KdfParams::weak_for_tests())).unwrap();

    // Import a tree from disk.
    let src = tmp.path().join("src/Project");
    fs::create_dir_all(src.join("sub/empty")).unwrap();
    fs::write(src.join("readme.md"), b"# hello").unwrap();
    fs::write(src.join("sub/data.bin"), vec![42u8; 300_000]).unwrap();
    fs::write(src.join(".DS_Store"), b"junk").unwrap();
    let rep = a.import(&id, &[src.clone()], "", false).unwrap();
    assert_eq!((rep.files, rep.skipped.len()), (2, 0));
    assert!(src.join("readme.md").exists());
    a.get(&id).unwrap().sync_blocking().unwrap();

    // Second Mac joins with only URL + vault id + passphrase.
    assert!(matches!(b.join("Docs", &url, &id, SlotKind::Passphrase, b"wrong"), Err(Error::Crypto(_))));
    assert!(b.list().is_empty());
    b.join("Docs", &url, &id, SlotKind::Passphrase, b"correct horse battery").unwrap();
    let ovb = b.get(&id).unwrap();
    ovb.sync_blocking().unwrap();
    assert_eq!(names(&b, &id, "Project"), ["readme.md", "sub"]);
    assert_eq!(names(&b, &id, "Project/sub"), ["data.bin", "empty"]);

    // Export from B and compare bytes with the originals.
    let out = tmp.path().join("out");
    let written = b.export(&id, &["Project".into()], &out, false).unwrap();
    assert_eq!(written, [out.join("Project")]);
    assert_eq!(fs::read(out.join("Project/readme.md")).unwrap(), b"# hello");
    assert_eq!(fs::read(out.join("Project/sub/data.bin")).unwrap(), vec![42u8; 300_000]);
    // Exporting again never overwrites.
    assert_eq!(b.export(&id, &["Project/readme.md".into()], &out.join("Project"), false).unwrap(), [out.join("Project/readme (2).md")]);

    // Server goes away: both keep working offline, then both edit the same file.
    h.shutdown();
    let edit = |m: &Manager, text: &[u8]| {
        let f = tmp.path().join("edit/readme.md");
        fs::create_dir_all(f.parent().unwrap()).unwrap();
        fs::write(&f, text).unwrap();
        m.import(&id, &[f], "Project", false).unwrap();
    };
    edit(&a, b"# edited on A");
    edit(&b, b"# edited on B");
    assert!(matches!(a.get(&id).unwrap().sync_blocking(), Err(Error::Net(_))));
    assert_eq!(a.get(&id).unwrap().status().state, "offline");

    // A is locked (quit) with unsynced work, and unlocked with the recovery key.
    a.lock(&id);
    assert!(matches!(a.get(&id), Err(Error::Locked)));
    assert!(a.unlock(&id, SlotKind::Passphrase, None, b"nope").is_err());
    a.unlock(&id, SlotKind::Recovery, None, recovery.as_bytes()).unwrap();
    assert_eq!(a.get(&id).unwrap().v().summary().pending, 1);

    // Server restarts on the same address with the same data.
    let (_h2, _) = server(&tmp.path().join("server"), &addr);
    a.get(&id).unwrap().sync_blocking().unwrap();
    ovb.sync_blocking().unwrap();
    a.get(&id).unwrap().sync_blocking().unwrap();
    let on_a = names(&a, &id, "Project");
    assert_eq!(on_a, names(&b, &id, "Project"));
    assert_eq!(on_a.len(), 3, "{on_a:?}");
    assert!(on_a.iter().any(|n| n.contains("(conflict")));
    assert!(!ovb.v().conflicts.is_empty());

    // Move out of the vault on B: plaintext lands on disk, entry disappears everywhere (still in trash).
    let moved = b.export(&id, &["Project/sub/data.bin".into()], &tmp.path().join("plain"), true).unwrap();
    assert_eq!(fs::read(&moved[0]).unwrap(), vec![42u8; 300_000]);
    ovb.sync_blocking().unwrap();
    a.get(&id).unwrap().sync_blocking().unwrap();
    assert_eq!(names(&a, &id, "Project/sub"), ["empty"]);
    assert_eq!(a.get(&id).unwrap().v().trash().len(), 1);

    // Move into the vault on A: original is removed only after the encrypted copy verified.
    let secret = tmp.path().join("secret.txt");
    fs::write(&secret, b"move me in").unwrap();
    let rep = a.import(&id, &[secret.clone()], "", true).unwrap();
    assert_eq!((rep.files, rep.sources_deleted), (1, 1));
    assert!(!secret.exists());
    let entry = a.get(&id).unwrap().v().find("secret.txt").unwrap().id;
    assert_eq!(a.read(&id, &entry, None, 1 << 20).unwrap(), b"move me in");

    // What the server stores never contains names or content.
    a.get(&id).unwrap().sync_blocking().unwrap();
    fn walk(p: &Path, out: &mut Vec<u8>) {
        for e in fs::read_dir(p).unwrap() {
            let e = e.unwrap().path();
            if e.is_dir() { walk(&e, out) } else { out.extend(fs::read(&e).unwrap()) }
        }
    }
    let mut all = Vec::new();
    walk(&tmp.path().join("server"), &mut all);
    for needle in [&b"readme"[..], b"edited on", b"move me in", b"Project", b"secret.txt"] {
        assert!(!all.windows(needle.len()).any(|w| w == needle), "server data contains {:?}", String::from_utf8_lossy(needle));
    }
}

#[test]
fn json_api_local_vault() {
    let tmp = tempfile::tempdir().unwrap();
    let m = Manager::new(tmp.path().join("home"), true).unwrap();
    let call = |req: Value, secret: &[u8]| -> Value {
        let r = coffer_core::api::call(&m, &req, secret);
        assert_eq!(r["ok"], true, "{req} -> {r}");
        r["data"].clone()
    };
    let created = call(json!({"op": "create", "name": "Private"}), b"");
    let (id, recovery) = (created["id"].as_str().unwrap().to_string(), created["recovery_key"].as_str().unwrap().to_string());
    call(json!({"op": "slot_add", "id": id, "kind": "passphrase", "label": "Passphrase"}), b"a real passphrase");
    call(json!({"op": "slot_add", "id": id, "kind": "secure-enclave", "label": "Touch ID", "public": {"key": "AAAA", "eph": "BBBB"}}), &[7u8; 32]);

    let f = tmp.path().join("note.txt");
    fs::write(&f, b"hi").unwrap();
    call(json!({"op": "mkdir", "id": id, "path": "inbox"}), b"");
    let rep = call(json!({"op": "import", "id": id, "sources": [f], "dest": "inbox"}), b"");
    assert_eq!(rep["files"], 1);
    let items = call(json!({"op": "list", "id": id, "path": "inbox"}), b"")["items"].clone();
    let entry = items[0]["id"].as_str().unwrap().to_string();
    assert_eq!(coffer_core::api::read(&m, &json!({"id": id, "entry": entry})).unwrap(), b"hi");
    call(json!({"op": "rename", "id": id, "from": "inbox/note.txt", "to": "note.txt"}), b"");
    call(json!({"op": "delete", "id": id, "paths": ["note.txt"]}), b"");
    assert_eq!(call(json!({"op": "trash", "id": id}), b"").as_array().unwrap().len(), 1);
    call(json!({"op": "restore", "id": id, "entry": entry}), b"");
    assert_eq!(call(json!({"op": "versions", "id": id, "entry": entry}), b"").as_array().unwrap().len(), 4);
    let st = call(json!({"op": "status", "id": id}), b"");
    assert_eq!((st["sync"]["state"].as_str(), st["summary"]["files"].as_u64()), (Some("local"), Some(1)));

    // Lock, then every kind of unlock.
    let vaults = call(json!({"op": "vaults"}), b"");
    let se_slot = vaults[0]["slots"].as_array().unwrap().iter().find(|s| s["kind"] == "secure-enclave").unwrap().clone();
    assert_eq!(se_slot["public"]["key"], "AAAA");
    for (kind, slot, secret) in [("passphrase", Value::Null, &b"a real passphrase"[..]), ("recovery", Value::Null, recovery.as_bytes()), ("secure-enclave", se_slot["id"].clone(), &[7u8; 32])] {
        call(json!({"op": "lock", "id": id}), b"");
        let locked = coffer_core::api::call(&m, &json!({"op": "list", "id": id, "path": ""}), b"");
        assert_eq!(locked["code"], "locked");
        let bad = coffer_core::api::call(&m, &json!({"op": "unlock", "id": id, "kind": kind, "slot": slot}), b"wrong wrong wrong wrong wrong wro");
        assert_eq!(bad["ok"], false);
        call(json!({"op": "unlock", "id": id, "kind": kind, "slot": slot}), secret);
        assert_eq!(call(json!({"op": "list", "id": id, "path": ""}), b"")["items"].as_array().unwrap().len(), 2);
    }
    assert_eq!(call(json!({"op": "posture"}), b"")["core_dumps_off"], true);
}
