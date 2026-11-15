//! One-time invites, kept in the vault's meta document so every change is one atomic meta write
//! (FS: under the vault lock; GCS: generation precondition). Pure functions over the list.

use coffer_core::proto::{InviteCreateReq, InviteInfo, INVITE_MAX_FIELD, INVITE_MAX_PENDING, INVITE_MAX_TTL_MS, INVITE_RETRY_MS};
use serde::{Deserialize, Serialize};

use super::{is_hex, SErr, R};

/// Tombstones (used/expired/revoked) kept per vault; the oldest go first.
const MAX_TOMBSTONES: usize = 256;

#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct InviteRec {
    pub id: String,
    pub claim_pub: String,
    /// Sealed payload, hex. Emptied once claimed (after the retry window), expired or revoked.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub blob: String,
    pub info: String,
    pub created_ms: i64,
    pub expires_ms: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claimed_ms: Option<i64>,
    /// blake3 of the claimer's nonce: only that claimer may fetch the payload again.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub claim_nonce: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoked_ms: Option<i64>,
}

impl InviteRec {
    fn pending(&self, now: i64) -> bool {
        self.claimed_ms.is_none() && self.revoked_ms.is_none() && self.expires_ms > now
    }

    /// May the payload still be handed out? (unclaimed and open, or claimed inside the retry window)
    fn payload_live(&self, now: i64) -> bool {
        match self.claimed_ms {
            Some(t) => self.revoked_ms.is_none() && now < t + INVITE_RETRY_MS,
            None => self.pending(now),
        }
    }

    pub fn info(&self) -> InviteInfo {
        InviteInfo {
            id: self.id.clone(),
            info: self.info.clone(),
            created_ms: self.created_ms,
            expires_ms: self.expires_ms,
            claimed_ms: self.claimed_ms,
            revoked_ms: self.revoked_ms,
        }
    }
}

/// What a change to the list produced.
pub enum InviteOut {
    None,
    List(Vec<InviteInfo>),
    /// Claimed payload, hex.
    Blob(String),
    /// Claim refused: used, expired or revoked (410). Not an error, so the tidied list is written.
    Gone(String),
}

/// Is there a payload at rest that may no longer be handed out? (`tidy` would erase it)
pub fn stale(list: &[InviteRec], now: i64) -> bool {
    list.iter().any(|r| !r.blob.is_empty() && !r.payload_live(now))
}

/// Drop payloads that may no longer be handed out, and old tombstones. Run before every change.
pub fn tidy(list: &mut Vec<InviteRec>, now: i64) {
    for r in list.iter_mut() {
        if !r.payload_live(now) {
            r.blob.clear();
        }
    }
    let dead: Vec<usize> = (0..list.len()).filter(|&i| list[i].blob.is_empty()).collect();
    if dead.len() > MAX_TOMBSTONES {
        let mut by_age = dead;
        by_age.sort_by_key(|&i| list[i].created_ms);
        let drop: std::collections::HashSet<usize> = by_age[..by_age.len() - MAX_TOMBSTONES].iter().copied().collect();
        let mut i = 0;
        list.retain(|_| {
            i += 1;
            !drop.contains(&(i - 1))
        });
    }
}

pub fn validate(req: &InviteCreateReq, now: i64) -> R<()> {
    let bad = |m: &str| Err(SErr::Bad(m.to_owned()));
    if !is_hex(&req.id, 32) {
        return bad("bad invite id");
    }
    let Some(pk) = coffer_core::hexutil::decode_array::<32>(&req.claim_pub) else { return bad("bad claim key") };
    if ed25519_dalek::VerifyingKey::from_bytes(&pk).is_err() {
        return bad("bad claim key");
    }
    for f in [&req.blob, &req.info] {
        if f.is_empty() || f.len() > INVITE_MAX_FIELD || f.len() % 2 != 0 || !f.bytes().all(|b| b.is_ascii_hexdigit()) {
            return bad("bad invite payload");
        }
    }
    if req.expires_ms <= now || req.expires_ms > now + INVITE_MAX_TTL_MS + 60_000 {
        return bad("invite expiry out of range (at most 7 days)");
    }
    Ok(())
}

pub fn create(list: &mut Vec<InviteRec>, req: &InviteCreateReq, now: i64) -> R<InviteOut> {
    tidy(list, now);
    if list.iter().any(|r| r.id == req.id) {
        return Err(SErr::Exists);
    }
    if list.iter().filter(|r| r.pending(now)).count() >= INVITE_MAX_PENDING {
        return Err(SErr::Bad(format!("too many open invites (at most {INVITE_MAX_PENDING}); revoke some first")));
    }
    list.push(InviteRec {
        id: req.id.clone(),
        claim_pub: req.claim_pub.to_ascii_lowercase(),
        blob: req.blob.to_ascii_lowercase(),
        info: req.info.to_ascii_lowercase(),
        created_ms: now,
        expires_ms: req.expires_ms,
        claimed_ms: None,
        claim_nonce: String::new(),
        revoked_ms: None,
    });
    Ok(InviteOut::None)
}

pub fn list_all(list: &mut Vec<InviteRec>, now: i64) -> R<InviteOut> {
    tidy(list, now);
    Ok(InviteOut::List(list.iter().map(InviteRec::info).collect()))
}

pub fn revoke(list: &mut Vec<InviteRec>, id: &str, now: i64) -> R<InviteOut> {
    tidy(list, now);
    let r = list.iter_mut().find(|r| r.id == id).ok_or(SErr::NoInvite)?;
    if r.revoked_ms.is_none() && r.claimed_ms.is_none() {
        r.revoked_ms = Some(now);
        r.blob.clear();
    }
    Ok(InviteOut::None)
}

/// The claim key of an invite (to verify the claim signature before `claim`).
pub fn claim_key(list: &[InviteRec], id: &str) -> R<[u8; 32]> {
    let r = list.iter().find(|r| r.id == id).ok_or(SErr::NoInvite)?;
    coffer_core::hexutil::decode_array::<32>(&r.claim_pub).ok_or_else(|| SErr::Internal("stored claim key".into()))
}

/// Caller has verified the request signature against `claim_key`. A refusal is `Ok(Gone)`: the
/// store then writes the tidied list, so a refused claim erases a payload that is past its time.
pub fn claim(list: &mut Vec<InviteRec>, id: &str, nonce: &str, now: i64) -> R<InviteOut> {
    if !is_hex(nonce, 32) {
        return Err(SErr::Bad("bad nonce".into()));
    }
    tidy(list, now);
    let tag = blake3::hash(nonce.as_bytes()).to_hex().to_string();
    let r = list.iter_mut().find(|r| r.id == id).ok_or(SErr::NoInvite)?;
    if r.revoked_ms.is_some() {
        return Ok(InviteOut::Gone("invite revoked".into()));
    }
    if r.claimed_ms.is_some() {
        // Same claimer after a lost reply, inside the retry window: hand it out again.
        if !r.blob.is_empty() && r.claim_nonce == tag {
            return Ok(InviteOut::Blob(r.blob.clone()));
        }
        return Ok(InviteOut::Gone("invite already used".into()));
    }
    if r.expires_ms <= now {
        return Ok(InviteOut::Gone("invite expired".into()));
    }
    r.claimed_ms = Some(now);
    r.claim_nonce = tag;
    Ok(InviteOut::Blob(r.blob.clone()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req(id: u8, now: i64) -> InviteCreateReq {
        let sk = ed25519_dalek::SigningKey::from_bytes(&[id; 32]);
        InviteCreateReq {
            id: format!("{id:02x}").repeat(16),
            claim_pub: coffer_core::hexutil::encode(sk.verifying_key().as_bytes()),
            blob: "abcd".into(),
            info: "ef01".into(),
            expires_ms: now + 1000,
        }
    }

    #[test]
    fn one_claim_then_gone() {
        let now = 1_000_000;
        let mut l = vec![];
        let a = req(1, now);
        validate(&a, now).ok().unwrap();
        create(&mut l, &a, now).ok().unwrap();
        assert!(matches!(create(&mut l, &a, now), Err(SErr::Exists)));
        let n1 = "11".repeat(16);
        let n2 = "22".repeat(16);
        assert!(matches!(claim(&mut l, &a.id, &n1, now + 1), Ok(InviteOut::Blob(b)) if b == "abcd"));
        // Lost reply: same nonce gets it again within the window; anyone else is refused.
        assert!(matches!(claim(&mut l, &a.id, &n1, now + 2), Ok(InviteOut::Blob(_))));
        assert!(matches!(claim(&mut l, &a.id, &n2, now + 2), Ok(InviteOut::Gone(_))));
        assert!(!stale(&l, now + 2) && stale(&l, now + 1 + INVITE_RETRY_MS));
        // After the window the payload is gone, even for the first claimer.
        assert!(matches!(claim(&mut l, &a.id, &n1, now + 1 + INVITE_RETRY_MS), Ok(InviteOut::Gone(_))));
        assert!(l[0].blob.is_empty() && !stale(&l, now + 1 + INVITE_RETRY_MS));
        // The id stays taken.
        assert!(matches!(create(&mut l, &a, now + 2), Err(SErr::Exists)));
        assert!(matches!(claim(&mut l, &"99".repeat(16), &n1, now), Err(SErr::NoInvite)));
    }

    #[test]
    fn expiry_and_revoke() {
        let now = 5_000_000;
        let mut l = vec![];
        let (a, b) = (req(1, now), req(2, now));
        create(&mut l, &a, now).ok().unwrap();
        create(&mut l, &b, now).ok().unwrap();
        revoke(&mut l, &b.id, now + 1).ok().unwrap();
        assert!(matches!(claim(&mut l, &b.id, &"11".repeat(16), now + 2), Ok(InviteOut::Gone(m)) if m.contains("revoked")));
        assert!(!stale(&l, now + 999) && stale(&l, now + 1000));
        assert!(matches!(claim(&mut l, &a.id, &"11".repeat(16), now + 1000), Ok(InviteOut::Gone(m)) if m.contains("expired")));
        assert!(l.iter().all(|r| r.blob.is_empty()));
        let mut bad = req(3, now);
        bad.expires_ms = now + INVITE_MAX_TTL_MS * 2;
        assert!(validate(&bad, now).is_err());
        bad.expires_ms = now + 10;
        bad.claim_pub = "00".repeat(31);
        assert!(validate(&bad, now).is_err());
    }

    #[test]
    fn pending_cap_and_tombstone_cap() {
        let now = 9_000_000;
        let mut l = vec![];
        for i in 0..INVITE_MAX_PENDING as u8 {
            create(&mut l, &req(i, now), now).ok().unwrap();
        }
        assert!(matches!(create(&mut l, &req(200, now), now), Err(SErr::Bad(_))));
        // Fill with tombstones beyond the cap: the oldest are dropped.
        let mut l: Vec<InviteRec> = (0..MAX_TOMBSTONES + 10)
            .map(|i| InviteRec { id: format!("{i:032x}"), claim_pub: String::new(), blob: String::new(), info: String::new(), created_ms: i as i64, expires_ms: 0, claimed_ms: Some(1), claim_nonce: String::new(), revoked_ms: None })
            .collect();
        tidy(&mut l, now);
        assert_eq!(l.len(), MAX_TOMBSTONES);
        assert_eq!(l[0].created_ms, 10);
    }
}
