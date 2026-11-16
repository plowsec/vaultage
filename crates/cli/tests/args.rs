//! Command-line parsing against the real binary, each test in its own fresh $COFFER_HOME.
//! Homes are left under target/tmp (nothing here deletes files).

use std::path::PathBuf;
use std::process::{Command, Output, Stdio};

fn home(tag: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
    PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("cli-{tag}-{}-{nanos}", std::process::id()))
}

fn vaultage(home: &PathBuf, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_vaultage"))
        .args(args)
        .env("VAULTAGE_HOME", home)
        .env_remove("COFFER_HOME")
        .env_remove("VAULTAGE_PASSPHRASE")
        .env_remove("COFFER_PASSPHRASE")
        .env_remove("VAULTAGE_RECOVERY_KEY")
        .env_remove("COFFER_RECOVERY_KEY")
        .env_remove("VAULTAGE_NEW_PASSPHRASE")
        .env_remove("COFFER_NEW_PASSPHRASE")
        .stdin(Stdio::null())
        .output()
        .unwrap()
}

fn vaults(home: &PathBuf) -> String {
    let o = vaultage(home, &["vaults"]);
    assert!(o.status.success());
    String::from_utf8(o.stdout).unwrap()
}

#[test]
fn help_anywhere_touches_nothing() {
    for args in [&["new", "--help"][..], &["new", "-h", "Work"], &["new", "Work", "--help"], &["forget", "--help"], &["Work", "rm", "--help"], &["help"]] {
        let h = home("help");
        let o = vaultage(&h, args);
        assert!(o.status.success(), "{args:?}");
        assert!(String::from_utf8_lossy(&o.stdout).contains("vaultage — encrypted vaults"), "{args:?}");
        assert!(!h.exists(), "{args:?} created {}", h.display());
    }
}

#[test]
fn misspelled_option_creates_no_vault() {
    let h = home("typo");
    for args in [&["new", "--pasphrase", "Work"][..], &["new", "Work", "--pasphrase"], &["new", "Work", "extra"], &["new", "--server"]] {
        let o = vaultage(&h, args);
        assert_eq!(o.status.code(), Some(1), "{args:?}");
    }
    assert_eq!(vaults(&h), "");
}

#[test]
fn options_before_the_name() {
    let h = home("order");
    let o = Command::new(env!("CARGO_BIN_EXE_vaultage"))
        .args(["new", "--passphrase", "Work"])
        .env("COFFER_HOME", &h) // pre-rename name still works
        .env_remove("VAULTAGE_HOME")
        .env("VAULTAGE_NEW_PASSPHRASE", "correct horse battery")
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    let list = vaults(&h);
    assert!(list.contains(" Work ") && list.contains("passphrase"), "{list}");
}

#[test]
fn dash_names_only_after_double_dash() {
    let h = home("dash");
    assert!(vaultage(&h, &["new", "--", "--help"]).status.success());
    assert!(vaults(&h).contains(" --help "));
    // How to remove a vault created by the old `new --help` bug.
    let o = vaultage(&h, &["forget", "--", "--help"]);
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    assert_eq!(vaults(&h), "");
}
