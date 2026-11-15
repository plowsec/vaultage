//! The real client stack against a server whose storage is the (fake) GCS backend.

mod common;

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use coffer_core::header::SlotKind;
use coffer_core::http::{create_vault, HttpRemote};
use coffer_core::manager::Manager;
use coffer_core::remote::Remote;
use coffer_core::testkit::fuzz_opts;
use coffer_core::vault::Vault;
use common::{Env, Kind, TOKEN};

#[test]
fn fuzz_on_gcs_backend() {
    for (seed, purges) in [(401, false), (402, true), (403, true)] {
        let env = Env::new(Kind::Gcs);
        let h = env.start();
        let url = format!("http://{}", h.addr());
        let registered = AtomicBool::new(false);
        fuzz_opts(seed, 3, 70, purges, &|v: &Vault| {
            if !registered.swap(true, Ordering::SeqCst) {
                create_vault(&url, TOKEN, &v.keys(), &v.portable_header()).unwrap();
            }
            Arc::new(HttpRemote::new(&url, &v.id_hex(), v.keys()).unwrap()) as Arc<dyn Remote>
        });
    }
}

#[test]
fn two_devices_two_server_instances_on_one_bucket() {
    let env = Env::new(Kind::Gcs);
    let (h1, h2) = (env.start(), env.start()); // e.g. Cloud Run briefly running two instances
    let (url1, url2) = (format!("http://{}", h1.addr()), format!("http://{}", h2.addr()));
    let tmp = tempfile::tempdir().unwrap();
    let a = Manager::new(tmp.path().join("homeA"), false).unwrap();
    let b = Manager::new(tmp.path().join("homeB"), false).unwrap();
    let sync = |m: &Manager, id: &str| {
        let r = m.get(id).unwrap().sync_blocking().unwrap();
        assert!(r.errors.is_empty(), "{:?}", r.errors);
    };
    let read = |m: &Manager, id: &str, path: &str| {
        let e = m.get(id).unwrap().v().find(path).unwrap_or_else(|| panic!("no {path}")).id;
        m.read(id, &e, None, 1 << 24).unwrap()
    };

    let (id, recovery) = a.create("Docs", Some((&url1, TOKEN))).unwrap();
    a.get(&id).unwrap().v().put_bytes("a.txt", b"from A", 1).unwrap();
    sync(&a, &id);
    b.join("Docs", &url2, &id, SlotKind::Recovery, recovery.as_bytes()).unwrap(); // other instance
    sync(&b, &id);
    assert_eq!(read(&b, &id, "a.txt"), b"from A");

    // Both edit the same file through different instances.
    a.get(&id).unwrap().v().put_bytes("a.txt", b"A again", 2).unwrap();
    b.get(&id).unwrap().v().put_bytes("a.txt", b"B again", 2).unwrap();
    sync(&a, &id);
    sync(&b, &id);
    sync(&a, &id);
    let names = |m: &Manager| m.get(&id).unwrap().v().list("").unwrap().into_iter().map(|i| i.name).collect::<Vec<_>>();
    assert_eq!(names(&a), names(&b));
    assert_eq!(names(&a).len(), 2);

    // Rotate through instance 1; B (on instance 2) is locked out, then adopts.
    let new_recovery = a.rotate_prepare(&id, None, None).unwrap();
    a.rotate_commit(&id).unwrap();
    a.get(&id).unwrap().v().put_bytes("after.txt", b"new epoch", 3).unwrap();
    sync(&a, &id);
    std::thread::sleep(std::time::Duration::from_millis(2500)); // instance 2's auth cache window
    assert!(b.get(&id).unwrap().sync_blocking().is_err());
    assert_eq!(b.get(&id).unwrap().status().state, "rekeyed");
    b.adopt_rekey(&id, SlotKind::Recovery, new_recovery.as_bytes()).unwrap();
    sync(&b, &id);
    assert_eq!(read(&b, &id, "after.txt"), b"new epoch");
}

#[test]
fn one_time_invite_across_instances() {
    let env = Env::new(Kind::Gcs);
    let (h1, h2) = (env.start(), env.start());
    let (url1, url2) = (format!("http://{}", h1.addr()), format!("http://{}", h2.addr()));
    let tmp = tempfile::tempdir().unwrap();
    let a = Manager::new(tmp.path().join("homeA"), false).unwrap();
    let (id, _) = a.create("Docs", Some((&url1, TOKEN))).unwrap();
    a.get(&id).unwrap().v().put_bytes("a.txt", b"from A", 1).unwrap();
    a.get(&id).unwrap().sync_blocking().unwrap();
    let code = a.invite(&id, "B", None).unwrap();
    // A header write after the invite keeps it (meta is one document).
    a.add_slot(&id, SlotKind::Passphrase, "pw", b"pw", serde_json::Value::Null, Some(coffer_core::crypto::KdfParams::weak_for_tests())).unwrap();
    a.get(&id).unwrap().sync_blocking().unwrap();

    // Claimed through instance 2, refused through instance 1.
    let b = Manager::new(tmp.path().join("homeB"), false).unwrap();
    let (bid, key) = b.join_invite("Docs", &code.replacen(&url1, &url2, 1)).unwrap();
    assert!(key.is_some() && bid == id);
    let r = b.get(&id).unwrap().sync_blocking().unwrap();
    assert!(r.errors.is_empty(), "{:?}", r.errors);
    let c = Manager::new(tmp.path().join("homeC"), false).unwrap();
    assert!(matches!(c.join_invite("Docs", &code), Err(coffer_core::Error::Server(410, _))));
    assert_eq!(a.invites(&id).unwrap()[0].state, "used");
}
