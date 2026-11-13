//! Vault header: key slots that each wrap the vault master key (VMK). Public; MAC'd under the VMK.

use serde::{Deserialize, Serialize};
use std::path::Path;

use crate::crypto::{self, KdfParams, Key};
use crate::error::{Error, Result};
use crate::hexutil;
use crate::model::now_ms;

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum SlotKind {
    /// Argon2id over a passphrase. Portable.
    Passphrase,
    /// 256-bit random key shown once at creation. Portable.
    Recovery,
    /// ECDH with a non-extractable Secure Enclave key. Bound to one device; never uploaded.
    SecureEnclave,
}

impl SlotKind {
    pub fn portable(self) -> bool {
        self != SlotKind::SecureEnclave
    }
    fn tag(self) -> &'static str {
        match self {
            SlotKind::Passphrase => "passphrase",
            SlotKind::Recovery => "recovery",
            SlotKind::SecureEnclave => "secure-enclave",
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Slot {
    pub id: String,
    pub kind: SlotKind,
    pub label: String,
    pub created: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kdf: Option<KdfParams>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub salt: String,
    /// Kind-specific public data (Secure Enclave: key blob + ephemeral public key).
    #[serde(default, skip_serializing_if = "serde_json::Value::is_null")]
    pub public: serde_json::Value,
    /// seal(KEK, VMK), hex.
    pub wrapped: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Header {
    pub format: u32,
    pub vault_id: String,
    /// Bumped on every slot change; the server only accepts increasing versions.
    pub version: u64,
    pub created: i64,
    pub slots: Vec<Slot>,
    /// Key rotation history: chain[i] = seal(key of epoch i+1, key of epoch i). Whoever holds the
    /// current key can read data of every earlier epoch; nobody holding an old key can go forward.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub chain: Vec<String>,
    /// Keyed BLAKE3 over the header (VMK-derived key): detects slot tampering after unlock.
    pub mac: String,
}

pub const FORMAT: u32 = 1;

fn kek(kind: SlotKind, secret: &[u8], kdf: Option<&KdfParams>, salt: &[u8]) -> Result<Key> {
    match kind {
        SlotKind::Passphrase => {
            let p = kdf.ok_or_else(|| Error::Format("passphrase slot without KDF parameters".into()))?;
            Ok(crypto::argon2id(secret, salt, p)?.derive("coffer v1 slot passphrase"))
        }
        SlotKind::Recovery => Ok(Key::from_slice(secret)?.derive("coffer v1 slot recovery")),
        SlotKind::SecureEnclave => {
            if secret.len() < 32 {
                return Err(Error::Invalid("secure enclave secret too short".into()));
            }
            Ok(Key::from_bytes(blake3::derive_key("coffer v1 slot secure-enclave", secret)))
        }
    }
}

impl Header {
    pub fn vault_id(&self) -> Result<[u8; 16]> {
        hexutil::decode_array::<16>(&self.vault_id).ok_or_else(|| Error::Format("vault id".into()))
    }

    fn slot_aad(&self, slot_id: &str, kind: SlotKind) -> Vec<u8> {
        format!("coffer/slot/v1|{}|{}|{}", self.vault_id, slot_id, kind.tag()).into_bytes()
    }

    fn compute_mac(&self, vmk: &Key) -> String {
        let mut h = self.clone();
        h.mac = String::new();
        let bytes = serde_json::to_vec(&h).expect("header serialises");
        hexutil::encode(&vmk.derive("coffer v1 header mac").mac(&bytes))
    }

    fn reseal(&mut self, vmk: &Key) {
        self.version += 1;
        self.mac = self.compute_mac(vmk);
    }

    pub fn verify(&self, vmk: &Key) -> Result<()> {
        if self.format != FORMAT {
            return Err(Error::Format(format!("unsupported vault format {}", self.format)));
        }
        let got = hexutil::decode(&self.mac).unwrap_or_default();
        let want = hexutil::decode(&self.compute_mac(vmk)).unwrap();
        if !crypto::ct_eq(&got, &want) {
            return Err(Error::Integrity("vault header was modified".into()));
        }
        Ok(())
    }

    /// New vault: random VMK, one recovery slot. Returns the recovery key text (show once).
    pub fn create() -> (Header, Key, String) {
        let vmk = Key::random();
        let mut h = Header {
            format: FORMAT,
            vault_id: hexutil::encode(&crypto::random::<16>()),
            version: 0,
            created: now_ms(),
            slots: vec![],
            chain: vec![],
            mac: String::new(),
        };
        let recovery = crypto::random::<32>();
        let text = crypto::recovery_encode(&recovery);
        h.add_slot(&vmk, SlotKind::Recovery, "Recovery key", &recovery, None, serde_json::Value::Null)
            .expect("recovery slot");
        (h, vmk, text)
    }

    /// Wrap the VMK under a new secret. Returns the slot id.
    pub fn add_slot(
        &mut self,
        vmk: &Key,
        kind: SlotKind,
        label: &str,
        secret: &[u8],
        kdf: Option<KdfParams>,
        public: serde_json::Value,
    ) -> Result<String> {
        if kind == SlotKind::Passphrase && secret.is_empty() {
            return Err(Error::Invalid("empty passphrase".into()));
        }
        let id = hexutil::encode(&crypto::random::<8>());
        let salt = crypto::random::<16>();
        let kdf = match kind {
            SlotKind::Passphrase => Some(kdf.unwrap_or_else(KdfParams::strong)),
            _ => None,
        };
        let k = kek(kind, secret, kdf.as_ref(), &salt)?;
        let wrapped = crypto::seal(&k, &self.slot_aad(&id, kind), vmk.expose());
        self.slots.push(Slot {
            id: id.clone(),
            kind,
            label: label.to_string(),
            created: now_ms(),
            kdf,
            salt: if kind == SlotKind::Passphrase { hexutil::encode(&salt) } else { String::new() },
            public,
            wrapped: hexutil::encode(&wrapped),
        });
        self.reseal(vmk);
        Ok(id)
    }

    pub fn remove_slot(&mut self, vmk: &Key, slot_id: &str) -> Result<()> {
        let i = self.slots.iter().position(|s| s.id == slot_id).ok_or_else(|| Error::NotFound("slot".into()))?;
        let portable_left = self.slots.iter().enumerate().filter(|(j, s)| *j != i && s.kind.portable()).count();
        if portable_left == 0 {
            return Err(Error::Invalid("cannot remove the last passphrase/recovery slot: the vault would die with this device".into()));
        }
        self.slots.remove(i);
        self.reseal(vmk);
        Ok(())
    }

    /// Unwrap the VMK with one slot, then verify the whole header.
    pub fn unlock(&self, slot_id: &str, secret: &[u8]) -> Result<Key> {
        let slot = self.slots.iter().find(|s| s.id == slot_id).ok_or_else(|| Error::NotFound("slot".into()))?;
        let salt = hexutil::decode(&slot.salt).unwrap_or_default();
        let k = kek(slot.kind, secret, slot.kdf.as_ref(), &salt)?;
        let wrapped = hexutil::decode(&slot.wrapped).ok_or_else(|| Error::Format("slot".into()))?;
        let mut vmk = crypto::open(&k, &self.slot_aad(&slot.id, slot.kind), &wrapped)
            .map_err(|_| Error::Crypto("wrong passphrase or key"))?;
        let key = Key::from_slice(&vmk);
        zeroize::Zeroize::zeroize(&mut vmk);
        let key = key?;
        self.verify(&key)?;
        Ok(key)
    }

    /// Try every slot of `kind` (text secrets: passphrase bytes, or a recovery key string).
    pub fn unlock_any(&self, kind: SlotKind, secret: &[u8]) -> Result<Key> {
        let decoded;
        let secret = if kind == SlotKind::Recovery {
            let text = std::str::from_utf8(secret).map_err(|_| Error::Invalid("not a valid recovery key".into()))?;
            decoded = crypto::recovery_decode(text)?;
            &decoded.expose()[..]
        } else {
            secret
        };
        let mut last = Error::NotFound(format!("no {} slot in this vault", kind.tag()));
        for s in self.slots.iter().filter(|s| s.kind == kind) {
            match self.unlock(&s.id, secret) {
                Ok(k) => return Ok(k),
                Err(e) => last = e,
            }
        }
        Err(last)
    }

    /// Current key epoch (number of rotations so far).
    pub fn epoch(&self) -> u32 {
        self.chain.len() as u32
    }

    fn chain_aad(&self, index: usize) -> Vec<u8> {
        format!("coffer/chain/v1|{}|{}", self.vault_id, index).into_bytes()
    }

    /// Master keys of every epoch, oldest first; the last one is `current`.
    pub fn masters(&self, current: &Key) -> Result<Vec<Key>> {
        let mut keys = vec![current.clone()];
        for (i, link) in self.chain.iter().enumerate().rev() {
            let sealed = hexutil::decode(link).ok_or_else(|| Error::Format("key chain".into()))?;
            let mut older = crypto::open(&keys[0].derive("coffer v1 key chain"), &self.chain_aad(i), &sealed)
                .map_err(|_| Error::Integrity("key rotation chain is broken".into()))?;
            let k = Key::from_slice(&older);
            zeroize::Zeroize::zeroize(&mut older);
            keys.insert(0, k?);
        }
        Ok(keys)
    }

    /// Start a new key epoch: fresh master key, fresh recovery key, no other slots (every old
    /// passphrase/device slot dies with the old key). Returns (header, new key, recovery text).
    pub fn rotate(&self, old: &Key) -> Result<(Header, Key, String)> {
        self.verify(old)?;
        let new = Key::random();
        let mut h = self.clone();
        h.slots.clear();
        let link = crypto::seal(&new.derive("coffer v1 key chain"), &self.chain_aad(self.chain.len()), old.expose());
        h.chain.push(hexutil::encode(&link));
        let recovery = crypto::random::<32>();
        let text = crypto::recovery_encode(&recovery);
        h.add_slot(&new, SlotKind::Recovery, "Recovery key", &recovery, None, serde_json::Value::Null)?;
        Ok((h, new, text))
    }

    /// Take over the portable slots another device changed (same epoch); keep this device's own.
    /// `keep_local`: this device has slot changes the server has not seen; keep those too (the
    /// result then needs uploading, so its version goes one past the server's).
    pub fn merge_portable(&mut self, server: &Header, vmk: &Key, keep_local: bool) -> Result<bool> {
        if server.vault_id != self.vault_id || server.epoch() != self.epoch() || server.version < self.version {
            return Ok(false);
        }
        if server.version == self.version && !keep_local {
            return Ok(false);
        }
        server.verify(vmk)?;
        let mut slots: Vec<Slot> = server.slots.iter().filter(|s| s.kind.portable()).cloned().collect();
        let mine: Vec<Slot> = self.slots.iter().filter(|s| !s.kind.portable() || (keep_local && !slots.iter().any(|o| o.id == s.id))).cloned().collect();
        slots.extend(mine);
        self.slots = slots;
        self.version = server.version + keep_local as u64;
        self.mac = self.compute_mac(vmk);
        Ok(true)
    }

    /// Raise the version (to get past a newer header on the server) and re-MAC.
    pub fn set_version(&mut self, version: u64, vmk: &Key) {
        self.version = version;
        self.mac = self.compute_mac(vmk);
    }

    /// Copy without device-bound slots, for the server. Re-MAC'd, same version.
    pub fn portable(&self, vmk: &Key) -> Header {
        let mut h = self.clone();
        h.slots.retain(|s| s.kind.portable());
        h.mac = h.compute_mac(vmk);
        h
    }

    pub fn load(path: &Path) -> Result<Header> {
        Ok(serde_json::from_slice(&std::fs::read(path)?)?)
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        crate::store::atomic_write(path, &serde_json::to_vec_pretty(self)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slots_unlock_and_tamper_detection() {
        let (mut h, vmk, recovery) = Header::create();
        let pid = h.add_slot(&vmk, SlotKind::Passphrase, "pw", b"correct horse", Some(KdfParams::weak_for_tests()), serde_json::Value::Null).unwrap();
        let sid = h.add_slot(&vmk, SlotKind::SecureEnclave, "se", &[9u8; 32], None, serde_json::json!({"blob": "x"})).unwrap();

        assert_eq!(h.unlock(&pid, b"correct horse").unwrap().expose(), vmk.expose());
        assert!(matches!(h.unlock(&pid, b"wrong"), Err(Error::Crypto(_))));
        assert_eq!(h.unlock_any(SlotKind::Recovery, recovery.as_bytes()).unwrap().expose(), vmk.expose());
        assert_eq!(h.unlock(&sid, &[9u8; 32]).unwrap().expose(), vmk.expose());
        assert!(h.unlock(&sid, &[8u8; 32]).is_err());

        // Portable copy drops the device-bound slot and still verifies.
        let p = h.portable(&vmk);
        assert_eq!(p.slots.len(), 2);
        assert_eq!(p.unlock_any(SlotKind::Passphrase, b"correct horse").unwrap().expose(), vmk.expose());

        // An attacker swapping in a slot for their own key is caught by the MAC.
        let mut evil = h.clone();
        evil.slots.remove(1);
        assert!(matches!(evil.unlock_any(SlotKind::Recovery, recovery.as_bytes()), Err(Error::Integrity(_))));

        // Rotation: new key opens old epochs, old key and old secrets open nothing new.
        let (h2, k2, rec2) = h.rotate(&vmk).unwrap();
        assert_eq!(h2.epoch(), 1);
        assert!(h2.unlock_any(SlotKind::Recovery, recovery.as_bytes()).is_err());
        assert!(h2.unlock_any(SlotKind::Passphrase, b"correct horse").is_err());
        let got = h2.unlock_any(SlotKind::Recovery, rec2.as_bytes()).unwrap();
        assert_eq!(got.expose(), k2.expose());
        let masters = h2.masters(&k2).unwrap();
        assert_eq!((masters.len(), masters[0].expose() == vmk.expose()), (2, true));
        assert!(h2.verify(&vmk).is_err());
        let (h3, k3, _) = h2.rotate(&k2).unwrap();
        let m3 = h3.masters(&k3).unwrap();
        assert!(m3[0].expose() == vmk.expose() && m3[1].expose() == k2.expose());
        assert!(h3.masters(&k2).is_err());

        // Portable slots changed on another device are adopted; the local Touch ID slot stays.
        let mut other = h.portable(&vmk);
        other.add_slot(&vmk, SlotKind::Passphrase, "pw2", b"second", Some(KdfParams::weak_for_tests()), serde_json::Value::Null).unwrap();
        other.version = h.version + 5;
        other.mac = other.compute_mac(&vmk);
        let mut mine = h.clone();
        assert!(mine.merge_portable(&other, &vmk, false).unwrap());
        assert_eq!(mine.slots.len(), 4);
        assert!(mine.unlock_any(SlotKind::Passphrase, b"second").is_ok() && mine.unlock(&sid, &[9u8; 32]).is_ok());

        // Cannot strand the vault on one device.
        let rid = h.slots[0].id.clone();
        h.remove_slot(&vmk, &rid).unwrap();
        assert!(h.remove_slot(&vmk, &pid).is_err());
    }
}
