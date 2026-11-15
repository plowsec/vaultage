//! JSON front door used by the macOS app (over FFI). One request object in, one response out.
//! Secrets (passphrase, recovery key, Secure Enclave output) travel beside the JSON, never in it.
//!
//! Request: `{"op": "...", ...}`. Response: `{"ok": true, "data": ...}` or
//! `{"ok": false, "code": "<Error::code>", "error": "..."}`.
//!
//! | op | fields | data |
//! |---|---|---|
//! | posture | | harden::Posture |
//! | device | | {id, name} |
//! | vaults | | [VaultInfo] |
//! | create | name, url?, token? | {id, recovery_key} |
//! | join | name, url, vault_id, kind + secret | {id} |
//! | unlock | id, kind, slot? + secret | null |
//! | lock | id | null |
//! | lock_all | | null |
//! | forget | id | {path} |
//! | rename_vault | id, name | null |
//! | slot_add | id, kind, label, public? + secret | {slot} |
//! | slot_remove | id, slot | null |
//! | status | id | {sync, summary, generation, conflicts, activity} |
//! | sync | id | null (wakes background sync) |
//! | sync_pause | paused | null — hold/resume background sync for all vaults |
//! | dismiss_conflicts | id | null |
//! | list | id, path | {items, generation} |
//! | search | id, query | {items} |
//! | mkdir | id, path | null |
//! | rename | id, from, to | {moved} |
//! | delete | id, paths | {deleted} |
//! | import | id, sources, dest, delete_source? | ImportReport |
//! | export | id, paths, dest, remove? | {written} |
//! | versions | id, entry | [Version] |
//! | restore | id, entry, rev? | {path} |
//! | trash | id | [TrashItem] |
//! | purge | id, entries | {purged} — permanently erase trashed entries |
//! | empty_trash | id | {purged} |
//! | prune_versions | id, entry | null — keep only the current version |
//! | attach | id, url, token | null — turn a local vault into a synced one |
//! | rotate_prepare | id + secret (new passphrase, may be empty) | {recovery_key} — nothing changes yet |
//! | rotate_commit | id | null — new keys in effect; all old slots, devices and invites are out |
//! | rotate_cancel | id | null |
//! | adopt_rekey | id, kind + secret | null — after status.sync.state == "rekeyed" |
//! | invite | id, label, ttl_ms? | {code} — one-time invite, default 24 h |
//! | invites | id | [invite::InviteStatus] |
//! | revoke_invite | id, invite | null |
//! | join_invite | name + secret (the invite code) | {id, recovery_key?} — recovery_key: this member's own, show once |
//! | usage | id | proto::UsageResp |
//! | put | id, path, mtime?, unique? + secret (the file's bytes) | {id, path} — import from memory |
//! | trust | | [{url, pem}] — servers pinned to specific certificates |
//! | trust_set | url, pem? | null — pin a server's CA / certificate; no pem = unpin |
//!
//! `status` also returns `rotation_pending`, `epoch` and `synced`.
//!
//! `kind`: "passphrase" | "recovery" | "secure-enclave".

use std::path::PathBuf;

use serde_json::{json, Value};

use crate::error::{Error, Result};
use crate::harden;
use crate::header::SlotKind;
use crate::manager::Manager;
use crate::model::{normalize_path, now_ms, tagged_path, EntryId};

/// Largest file `read` will decrypt into memory.
pub const MAX_READ: u64 = 1 << 30;

fn s<'a>(req: &'a Value, key: &str) -> Result<&'a str> {
    req.get(key).and_then(Value::as_str).ok_or_else(|| Error::Invalid(format!("missing field '{key}'")))
}

fn strings(req: &Value, key: &str) -> Result<Vec<String>> {
    req.get(key)
        .and_then(Value::as_array)
        .map(|a| a.iter().filter_map(|v| v.as_str().map(String::from)).collect())
        .ok_or_else(|| Error::Invalid(format!("missing field '{key}'")))
}

fn flag(req: &Value, key: &str) -> bool {
    req.get(key).and_then(Value::as_bool).unwrap_or(false)
}

fn kind(req: &Value) -> Result<SlotKind> {
    serde_json::from_value(json!(s(req, "kind")?)).map_err(|_| Error::Invalid("unknown slot kind".into()))
}

fn dispatch(m: &Manager, req: &Value, secret: &[u8]) -> Result<Value> {
    let to = |v: &dyn erased::Ser| v.to_value();
    Ok(match s(req, "op")? {
        "posture" => to(&harden::harden()),
        "device" => to(&m.device()),
        "vaults" => to(&m.list()),
        "create" => {
            let remote = match req.get("url").and_then(Value::as_str).filter(|u| !u.trim().is_empty()) {
                Some(url) => Some((url, req.get("token").and_then(Value::as_str).unwrap_or(""))),
                None => None,
            };
            let (id, recovery_key) = m.create(s(req, "name")?, remote)?;
            json!({ "id": id, "recovery_key": recovery_key })
        }
        "join" => json!({ "id": m.join(s(req, "name")?, s(req, "url")?, s(req, "vault_id")?, kind(req)?, secret)? }),
        "unlock" => {
            m.unlock(s(req, "id")?, kind(req)?, req.get("slot").and_then(Value::as_str), secret)?;
            Value::Null
        }
        "lock" => {
            m.lock(s(req, "id")?);
            Value::Null
        }
        "lock_all" => {
            m.lock_all();
            Value::Null
        }
        "forget" => json!({ "path": m.forget(s(req, "id")?)?.display().to_string() }),
        "rename_vault" => {
            m.rename_vault(s(req, "id")?, s(req, "name")?)?;
            Value::Null
        }
        "slot_add" => {
            let public = req.get("public").cloned().unwrap_or(Value::Null);
            json!({ "slot": m.add_slot(s(req, "id")?, kind(req)?, s(req, "label")?, secret, public, None)? })
        }
        "slot_remove" => {
            m.remove_slot(s(req, "id")?, s(req, "slot")?)?;
            Value::Null
        }
        "status" => {
            let ov = m.get(s(req, "id")?)?;
            let v = ov.v();
            json!({ "sync": ov.status(), "summary": v.summary(), "generation": v.generation, "conflicts": v.conflicts, "activity": ov.activity(),
                    "rotation_pending": v.rotation_pending(), "epoch": v.header.epoch(), "synced": v.synced() })
        }
        "sync" => {
            m.get(s(req, "id")?)?.wake();
            Value::Null
        }
        "sync_pause" => {
            m.set_sync_paused(flag(req, "paused"));
            Value::Null
        }
        "dismiss_conflicts" => {
            m.get(s(req, "id")?)?.v().conflicts.clear();
            Value::Null
        }
        "list" => {
            let ov = m.get(s(req, "id")?)?;
            let v = ov.v();
            json!({ "items": v.list(s(req, "path")?)?, "generation": v.generation })
        }
        "search" => json!({ "items": m.get(s(req, "id")?)?.v().search(s(req, "query")?) }),
        "mkdir" => {
            let ov = m.get(s(req, "id")?)?;
            ov.v().mkdir(s(req, "path")?)?;
            ov.wake();
            Value::Null
        }
        "rename" => {
            let ov = m.get(s(req, "id")?)?;
            let moved = ov.v().rename(s(req, "from")?, s(req, "to")?)?;
            ov.wake();
            json!({ "moved": moved })
        }
        "delete" => {
            let ov = m.get(s(req, "id")?)?;
            let mut deleted = 0;
            for p in strings(req, "paths")? {
                deleted += ov.v().delete(&p)?;
            }
            ov.wake();
            json!({ "deleted": deleted })
        }
        "import" => {
            let sources: Vec<PathBuf> = strings(req, "sources")?.into_iter().map(PathBuf::from).collect();
            to(&m.import(s(req, "id")?, &sources, s(req, "dest")?, flag(req, "delete_source"))?)
        }
        "export" => {
            let written = m.export(s(req, "id")?, &strings(req, "paths")?, &PathBuf::from(s(req, "dest")?), flag(req, "remove"))?;
            json!({ "written": written.iter().map(|p| p.display().to_string()).collect::<Vec<_>>() })
        }
        "versions" => to(&m.get(s(req, "id")?)?.v().versions(&EntryId::parse(s(req, "entry")?)?)?),
        "restore" => {
            let ov = m.get(s(req, "id")?)?;
            let path = ov.v().restore(&EntryId::parse(s(req, "entry")?)?, req.get("rev").and_then(Value::as_u64))?;
            ov.wake();
            json!({ "path": path })
        }
        "trash" => to(&m.get(s(req, "id")?)?.v().trash()),
        "purge" => {
            let ov = m.get(s(req, "id")?)?;
            let ids = strings(req, "entries")?.iter().map(|e| EntryId::parse(e)).collect::<Result<Vec<_>>>()?;
            let purged = ov.v().purge(&ids)?;
            ov.wake();
            json!({ "purged": purged })
        }
        "empty_trash" => {
            let ov = m.get(s(req, "id")?)?;
            let purged = ov.v().empty_trash()?;
            ov.wake();
            json!({ "purged": purged })
        }
        "prune_versions" => {
            let ov = m.get(s(req, "id")?)?;
            ov.v().prune_versions(&EntryId::parse(s(req, "entry")?)?)?;
            ov.wake();
            Value::Null
        }
        "attach" => {
            m.attach(s(req, "id")?, s(req, "url")?, req.get("token").and_then(Value::as_str).unwrap_or(""))?;
            Value::Null
        }
        "rotate_prepare" => json!({ "recovery_key": m.rotate_prepare(s(req, "id")?, (!secret.is_empty()).then_some(secret), None)? }),
        "rotate_commit" => {
            m.rotate_commit(s(req, "id")?)?;
            Value::Null
        }
        "rotate_cancel" => {
            m.rotate_cancel(s(req, "id")?)?;
            Value::Null
        }
        "adopt_rekey" => {
            m.adopt_rekey(s(req, "id")?, kind(req)?, secret)?;
            Value::Null
        }
        "invite" => json!({ "code": m.invite(s(req, "id")?, req.get("label").and_then(Value::as_str).unwrap_or(""), req.get("ttl_ms").and_then(Value::as_i64))? }),
        "invites" => to(&m.invites(s(req, "id")?)?),
        "revoke_invite" => {
            m.revoke_invite(s(req, "id")?, s(req, "invite")?)?;
            Value::Null
        }
        "join_invite" => {
            let code = std::str::from_utf8(secret).map_err(|_| Error::Invalid("not a valid invite".into()))?;
            let (id, recovery) = m.join_invite(s(req, "name")?, code)?;
            json!({ "id": id, "recovery_key": recovery })
        }
        "usage" => to(&m.usage(s(req, "id")?)?),
        "put" => {
            let ov = m.get(s(req, "id")?)?;
            let mut path = normalize_path(s(req, "path")?)?;
            let mtime = req.get("mtime").and_then(Value::as_i64).unwrap_or_else(now_ms);
            if flag(req, "unique") {
                // Never turn an import into a new revision of some other file.
                let v = ov.v();
                let (base, mut n) = (path.clone(), 2);
                while v.find(&path).is_some() || v.is_dir(&path) {
                    path = tagged_path(&base, &n.to_string());
                    n += 1;
                }
            }
            let ing = ov.v().ingester(&path)?;
            let (content, size) = ing.ingest(&mut &secret[..])?;
            let entry = ov.v().commit_file(ing.id, &path, content, size, mtime)?;
            ov.wake();
            json!({ "id": entry.hex(), "path": path })
        }
        "trust" => Value::Array(m.trust().into_iter().map(|(url, pem)| json!({ "url": url, "pem": pem })).collect()),
        "trust_set" => {
            m.set_trust(s(req, "url")?, req.get("pem").and_then(Value::as_str))?;
            Value::Null
        }
        other => return Err(Error::Invalid(format!("unknown op '{other}'"))),
    })
}

mod erased {
    pub trait Ser {
        fn to_value(&self) -> serde_json::Value;
    }
    impl<T: serde::Serialize> Ser for T {
        fn to_value(&self) -> serde_json::Value {
            serde_json::to_value(self).unwrap_or(serde_json::Value::Null)
        }
    }
}

pub fn call(m: &Manager, req: &Value, secret: &[u8]) -> Value {
    match dispatch(m, req, secret) {
        Ok(data) => json!({ "ok": true, "data": data }),
        Err(e) => json!({ "ok": false, "code": e.code(), "error": e.to_string() }),
    }
}

/// Decrypt a file into memory: `{"id": vault, "entry": entry id, "rev"?: n}`.
pub fn read(m: &Manager, req: &Value) -> Result<Vec<u8>> {
    m.read(s(req, "id")?, &EntryId::parse(s(req, "entry")?)?, req.get("rev").and_then(Value::as_u64), MAX_READ)
}
