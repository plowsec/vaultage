//! One-time invites. The line `server#vault-id#secret` names an invite the server holds until
//! someone claims it; the server then deletes it. The secret never reaches the server.
//!
//! From the 32-byte secret: `id` (server lookup), `claim` (Ed25519, signs the claim request),
//! `wrap` (seals the payload: vault key + label). The inviter also stores `info` (the label,
//! sealed under the vault key) so members can list their invites; the server sees neither.

use ed25519_dalek::SigningKey;
use serde::Serialize;

use crate::crypto::{self, Key};
use crate::error::{Error, Result};
use crate::hexutil;

/// Default lifetime of an unclaimed invite.
pub const DEFAULT_TTL_MS: i64 = 24 * 3600 * 1000;

pub struct InviteKeys {
    /// 16 bytes hex.
    pub id: String,
    pub claim: SigningKey,
    wrap: Key,
}

impl InviteKeys {
    pub fn from_secret(secret: &Key) -> InviteKeys {
        let id = secret.derive("coffer v1 invite id");
        InviteKeys {
            id: hexutil::encode(&id.expose()[..16]),
            claim: SigningKey::from_bytes(secret.derive("coffer v1 invite claim").expose()),
            wrap: secret.derive("coffer v1 invite wrap"),
        }
    }

    pub fn claim_pub_hex(&self) -> String {
        hexutil::encode(self.claim.verifying_key().as_bytes())
    }

    fn aad(&self, vault: &str, what: &str) -> Vec<u8> {
        format!("coffer/invite/v1|{what}|{vault}|{}", self.id).into_bytes()
    }

    /// Payload = vault key (32) || label (UTF-8).
    pub fn seal_payload(&self, vault: &str, vmk: &Key, label: &str) -> Vec<u8> {
        let mut pt = vmk.expose().to_vec();
        pt.extend_from_slice(label.as_bytes());
        let out = crypto::seal(&self.wrap, &self.aad(vault, "payload"), &pt);
        zeroize::Zeroize::zeroize(&mut pt);
        out
    }

    pub fn open_payload(&self, vault: &str, sealed: &[u8]) -> Result<(Key, String)> {
        let mut pt = crypto::open(&self.wrap, &self.aad(vault, "payload"), sealed)
            .map_err(|_| Error::Integrity("the server returned an invite this code does not open".into()))?;
        let res = (|| {
            if pt.len() < 32 {
                return Err(Error::Format("invite payload".into()));
            }
            let label = String::from_utf8(pt[32..].to_vec()).map_err(|_| Error::Format("invite label".into()))?;
            Ok((Key::from_slice(&pt[..32])?, label))
        })();
        zeroize::Zeroize::zeroize(&mut pt);
        res
    }
}

fn info_aad(vault: &str, id: &str) -> Vec<u8> {
    format!("coffer/invite/v1|info|{vault}|{id}").into_bytes()
}

/// Label sealed for members (vault key), opaque to the server.
pub fn seal_info(vmk: &Key, vault: &str, id: &str, label: &str) -> Vec<u8> {
    crypto::seal(&vmk.derive("coffer v1 invite info"), &info_aad(vault, id), label.as_bytes())
}

pub fn open_info(vmk: &Key, vault: &str, id: &str, sealed: &[u8]) -> Option<String> {
    let pt = crypto::open(&vmk.derive("coffer v1 invite info"), &info_aad(vault, id), sealed).ok()?;
    String::from_utf8(pt).ok()
}

/// `server#vault-id#secret`.
pub struct InviteLine {
    pub url: String,
    pub vault: String,
    pub secret: String,
}

pub fn parse_line(code: &str) -> Result<InviteLine> {
    let parts: Vec<&str> = code.trim().split('#').collect();
    let [url, vault, secret] = parts[..] else { return Err(Error::Invalid("not a valid invite".into())) };
    let vault = vault.trim().to_lowercase();
    if hexutil::decode_array::<16>(&vault).is_none() {
        return Err(Error::Invalid("not a valid invite: bad vault id".into()));
    }
    Ok(InviteLine { url: url.trim().to_string(), vault, secret: secret.trim().to_string() })
}

/// One invite as members see it.
#[derive(Serialize, Clone, Debug)]
pub struct InviteStatus {
    pub id: String,
    pub label: String,
    pub created: i64,
    pub expires: i64,
    pub claimed: Option<i64>,
    pub revoked: Option<i64>,
    /// waiting | used | expired | revoked
    pub state: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn payload_round_trip_and_binding() {
        let secret = Key::random();
        let k = InviteKeys::from_secret(&secret);
        let vmk = Key::random();
        let vault = "00112233445566778899aabbccddeeff";
        let sealed = k.seal_payload(vault, &vmk, "Sam");
        let (got, label) = k.open_payload(vault, &sealed).unwrap();
        assert_eq!((got.expose(), label.as_str()), (vmk.expose(), "Sam"));
        // Bound to the vault and to this invite.
        assert!(k.open_payload("ffeeddccbbaa99887766554433221100", &sealed).is_err());
        let other = InviteKeys::from_secret(&Key::random());
        assert!(other.open_payload(vault, &sealed).is_err());
        assert_ne!(k.id, other.id);
        // Same secret, same keys.
        assert_eq!(InviteKeys::from_secret(&secret).claim_pub_hex(), k.claim_pub_hex());

        let info = seal_info(&vmk, vault, &k.id, "Sam");
        assert_eq!(open_info(&vmk, vault, &k.id, &info).as_deref(), Some("Sam"));
        assert!(open_info(&vmk, vault, &other.id, &info).is_none());
    }

    #[test]
    fn line_parsing() {
        let l = parse_line(" https://h.example#00112233445566778899AABBCCDDEEFF#ABCDE-12345 \n").unwrap();
        assert_eq!((l.url.as_str(), l.vault.as_str(), l.secret.as_str()), ("https://h.example", "00112233445566778899aabbccddeeff", "ABCDE-12345"));
        assert!(parse_line("https://h.example#nothex#k").is_err());
        assert!(parse_line("https://h.example#k").is_err());
    }
}
