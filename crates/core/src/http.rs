//! HTTP client for the sync server. TLS required except to loopback. Every request is signed with
//! a key derived from the vault key; no password or bearer token ever crosses the wire.

use std::collections::HashMap;
use std::sync::{Arc, OnceLock, RwLock};
use std::time::Duration;

use ureq::tls::{Certificate, PemItem, RootCerts, TlsConfig};

use crate::error::{Error, Result};
use crate::header::Header;
use crate::hexutil;
use crate::model::{now_ms, ChunkId, EntryId};
use crate::proto::*;
use crate::remote::{CommitOutcome, Record, Remote};
use crate::vault::Keys;

type Pins = HashMap<String, Arc<Vec<Certificate<'static>>>>;

/// Server origin -> the only certificates trusted for it (CA pinning). Unpinned origins use the
/// built-in Mozilla roots.
static PINS: OnceLock<RwLock<Pins>> = OnceLock::new();

fn pins() -> &'static RwLock<Pins> {
    PINS.get_or_init(Default::default)
}

/// Certificates in a PEM text. Errors unless it holds at least one certificate and nothing else.
pub fn parse_ca_pem(pem: &str) -> Result<Vec<Certificate<'static>>> {
    let bad = || Error::Invalid("not a PEM certificate (expected -----BEGIN CERTIFICATE-----)".into());
    let mut out = Vec::new();
    for item in ureq::tls::parse_pem(pem.as_bytes()) {
        match item {
            Ok(PemItem::Certificate(c)) => out.push(c),
            Ok(_) => return Err(Error::Invalid("paste certificates only, never a private key".into())),
            Err(_) => return Err(bad()),
        }
    }
    if out.is_empty() {
        return Err(bad());
    }
    Ok(out)
}

/// Pin `url` to the certificates in `pem`: TLS to that server is accepted only if its chain ends
/// in one of them (a private CA, or a self-signed non-CA server certificate). `None` unpins.
/// Applies to agents built afterwards. Returns the normalised origin.
pub fn set_pin(url: &str, pem: Option<&str>) -> Result<String> {
    let base = check_url(url)?;
    let certs = pem.map(parse_ca_pem).transpose()?;
    let mut map = pins().write().unwrap_or_else(|p| p.into_inner());
    match certs {
        Some(c) => map.insert(base.clone(), Arc::new(c)),
        None => map.remove(&base),
    };
    Ok(base)
}

fn agent(base: &str) -> ureq::Agent {
    let mut cfg = ureq::Agent::config_builder()
        .http_status_as_error(false)
        .max_redirects(0)
        .timeout_resolve(Some(Duration::from_secs(10)))
        .timeout_connect(Some(Duration::from_secs(10)))
        // A link that goes silent (VPN dropped, captive portal) fails fast; a slow one that
        // still moves bytes gets the full budget.
        .timeout_per_read(Some(Duration::from_secs(20)))
        .timeout_per_write(Some(Duration::from_secs(20)))
        .timeout_global(Some(Duration::from_secs(180)));
    if let Some(certs) = pins().read().unwrap_or_else(|p| p.into_inner()).get(base) {
        cfg = cfg.tls_config(TlsConfig::builder().root_certs(RootCerts::Specific(certs.clone())).build());
    }
    cfg.build().into()
}

/// Normalise a server URL: origin only, https (plain http allowed for loopback only).
pub fn check_url(url: &str) -> Result<String> {
    let url = url.trim().trim_end_matches('/');
    let (scheme, rest) = url.split_once("://").ok_or_else(|| Error::Invalid("server URL must start with https://".into()))?;
    if rest.is_empty() || rest.contains(['/', '?', '#', '@']) {
        return Err(Error::Invalid("server URL must be just https://host[:port]".into()));
    }
    let host = if rest.starts_with('[') { rest.split(']').next().unwrap_or("") } else { rest.split(':').next().unwrap_or("") };
    let loopback = matches!(host, "localhost" | "127.0.0.1" | "[::1");
    match scheme {
        "https" => Ok(url.to_string()),
        "http" if loopback => Ok(url.to_string()),
        "http" => Err(Error::Invalid("refusing unencrypted http:// to a remote host; use https://".into())),
        _ => Err(Error::Invalid("server URL must start with https://".into())),
    }
}

fn call(agent: &ureq::Agent, method: &str, url: &str, headers: &[(&str, &str)], body: Option<&[u8]>) -> Result<(u16, Vec<u8>)> {
    let net = |e: ureq::Error| Error::Net(e.to_string());
    let mut resp = match (method, body) {
        ("GET", _) => {
            let mut r = agent.get(url);
            for (k, v) in headers {
                r = r.header(*k, *v);
            }
            r.call().map_err(net)?
        }
        (m, body) => {
            let mut r = if m == "PUT" { agent.put(url) } else { agent.post(url) };
            for (k, v) in headers {
                r = r.header(*k, *v);
            }
            r.send(body.unwrap_or(&[])).map_err(net)?
        }
    };
    let status = resp.status().as_u16();
    let data = resp.body_mut().with_config().limit(MAX_JSON_BODY as u64 * 2).read_to_vec().map_err(net)?;
    Ok((status, data))
}

fn server_error(status: u16, body: &[u8]) -> Error {
    if status == 429 || status == 503 {
        return Error::Net(format!("server busy ({status}); will retry"));
    }
    let msg = serde_json::from_slice::<ErrorResp>(body).map(|e| e.error).unwrap_or_else(|_| String::from_utf8_lossy(&body[..body.len().min(200)]).into_owned());
    Error::Server(status, msg)
}

pub struct HttpRemote {
    agent: ureq::Agent,
    base: String,
    vault: String,
    keys: Arc<Keys>,
}

impl HttpRemote {
    pub fn new(url: &str, vault_id_hex: &str, keys: Arc<Keys>) -> Result<HttpRemote> {
        let base = check_url(url)?;
        Ok(HttpRemote { agent: agent(&base), base, vault: vault_id_hex.to_string(), keys })
    }

    pub fn url(&self) -> &str {
        &self.base
    }
    pub fn vault_id(&self) -> &str {
        &self.vault
    }

    fn signed(&self, method: &str, tail: &str, body: Option<&[u8]>, json: bool) -> Result<(u16, Vec<u8>)> {
        let path = format!("/v1/vaults/{}/{}", self.vault, tail);
        let auth = sign_request(&self.keys.auth, method, &path, now_ms(), body.unwrap_or(&[]));
        let ct = if json { "application/json" } else { "application/octet-stream" };
        call(&self.agent, method, &format!("{}{}", self.base, path), &[("Authorization", &auth), ("Content-Type", ct)], body)
    }

    /// Switch the vault to a new signing key and header (key rotation). Signed with the old key.
    pub fn rekey(&self, new_auth_pub_hex: &str, header: &Header) -> Result<()> {
        let req = RekeyReq { auth_pub: new_auth_pub_hex.to_string(), header: serde_json::to_value(header)? };
        match self.signed("POST", "rekey", Some(&serde_json::to_vec(&req)?), true)? {
            (200, _) => Ok(()),
            (s, b) => Err(server_error(s, &b)),
        }
    }

    pub fn usage(&self) -> Result<UsageResp> {
        match self.signed("GET", "usage", None, true)? {
            (200, b) => Ok(serde_json::from_slice(&b)?),
            (s, b) => Err(server_error(s, &b)),
        }
    }

    /// Store a one-time invite on the server (see `invite`).
    pub fn create_invite(&self, req: &InviteCreateReq) -> Result<()> {
        match self.signed("POST", "invites", Some(&serde_json::to_vec(req)?), true)? {
            (200 | 201, _) => Ok(()),
            (s, b) => Err(server_error(s, &b)),
        }
    }

    pub fn list_invites(&self) -> Result<Vec<InviteInfo>> {
        match self.signed("GET", "invites", None, true)? {
            (200, b) => Ok(serde_json::from_slice::<InvitesResp>(&b)?.invites),
            (s, b) => Err(server_error(s, &b)),
        }
    }

    pub fn revoke_invite(&self, invite_id: &str) -> Result<()> {
        if hexutil::decode_array::<16>(invite_id).is_none() {
            return Err(Error::Invalid("invite id must be 32 hex characters".into()));
        }
        match self.signed("POST", &format!("invites/{invite_id}/revoke"), Some(b"{}"), true)? {
            (200, _) => Ok(()),
            (404, _) => Err(Error::NotFound("no such invite".into())),
            (s, b) => Err(server_error(s, &b)),
        }
    }

    /// Upload the portable header. Ok(false) = the server already has this or a newer version.
    pub fn put_header(&self, header: &Header) -> Result<bool> {
        match self.signed("PUT", "header", Some(&serde_json::to_vec(header)?), true)? {
            (200, _) => Ok(true),
            (409, _) => Ok(false),
            (s, b) => Err(server_error(s, &b)),
        }
    }
}

/// Register a new vault on a server (needs the server's enrollment token).
pub fn create_vault(url: &str, enroll_token: &str, keys: &Keys, header: &Header) -> Result<()> {
    let base = check_url(url)?;
    let req = CreateVaultReq { vault_id: header.vault_id.clone(), auth_pub: keys.auth_pub_hex(), header: serde_json::to_value(header)? };
    let body = serde_json::to_vec(&req)?;
    match call(&agent(&base), "POST", &format!("{base}/v1/vaults"), &[(ENROLL_HEADER, enroll_token.trim()), ("Content-Type", "application/json")], Some(&body))? {
        (200 | 201, _) => Ok(()),
        (403, _) => Err(Error::Server(403, "enrollment token rejected".into())),
        (s, b) => Err(server_error(s, &b)),
    }
}

/// Fetch a vault's portable header (to join it from a new device).
pub fn fetch_header(url: &str, vault_id_hex: &str) -> Result<Header> {
    let base = check_url(url)?;
    if hexutil::decode_array::<16>(vault_id_hex).is_none() {
        return Err(Error::Invalid("vault id must be 32 hex characters".into()));
    }
    match call(&agent(&base), "GET", &format!("{base}/v1/vaults/{vault_id_hex}/header"), &[], None)? {
        (200, b) => Ok(serde_json::from_slice(&b)?),
        (404, _) => Err(Error::NotFound("no such vault on this server".into())),
        (s, b) => Err(server_error(s, &b)),
    }
}

/// Claim a one-time invite: returns its sealed payload. Signed with the invite's claim key.
/// `nonce` (16 bytes hex) names this claimer: the server hands the payload to the same nonce again
/// for `INVITE_RETRY_MS`, so a lost reply or a join that failed later doesn't burn the invite.
pub fn claim_invite(url: &str, vault_id_hex: &str, keys: &crate::invite::InviteKeys, nonce: &str) -> Result<Vec<u8>> {
    let base = check_url(url)?;
    let agent = agent(&base);
    let path = format!("/v1/vaults/{vault_id_hex}/invites/{}/claim", keys.id);
    let body = serde_json::to_vec(&InviteClaimReq { nonce: nonce.to_string() })?;
    let mut attempt = 0;
    loop {
        let auth = sign_request(&keys.claim, "POST", &path, now_ms(), &body);
        let res = call(&agent, "POST", &format!("{base}{path}"), &[("Authorization", &auth), ("Content-Type", "application/json")], Some(&body));
        match res {
            Ok((200, b)) => {
                let r: InviteClaimResp = serde_json::from_slice(&b)?;
                return hexutil::decode(&r.blob).ok_or_else(|| Error::Format("invite blob".into()));
            }
            Ok((404, _)) => return Err(Error::NotFound("no such invite on this server".into())),
            Ok((s, b)) => return Err(server_error(s, &b)),
            Err(e @ Error::Net(_)) if attempt >= 3 => return Err(e),
            Err(Error::Net(_)) => {
                attempt += 1;
                std::thread::sleep(Duration::from_millis(500 << attempt));
            }
            Err(e) => return Err(e),
        }
    }
}

impl Remote for HttpRemote {
    fn pull(&self, after: u64, limit: u32) -> Result<(u64, Vec<Record>)> {
        match self.signed("GET", &format!("log?after={after}&limit={limit}"), None, true)? {
            (200, b) => {
                let resp: LogResp = serde_json::from_slice(&b)?;
                let records = resp
                    .records
                    .into_iter()
                    .map(|r| Ok(Record { seq: r.seq, entry: EntryId::parse(&r.entry)?, rev: r.rev, blob: hexutil::decode(&r.blob).ok_or_else(|| Error::Format("record blob".into()))? }))
                    .collect::<Result<Vec<_>>>()?;
                Ok((resp.head, records))
            }
            (s, b) => Err(server_error(s, &b)),
        }
    }

    fn commit(&self, entry: &EntryId, base_rev: u64, rev: u64, blob: &[u8], refs: &[ChunkId]) -> Result<CommitOutcome> {
        let req = CommitReq { entry: entry.hex(), base_rev, rev, blob: hexutil::encode(blob), refs: refs.iter().map(|r| r.hex()).collect() };
        match self.signed("POST", "commit", Some(&serde_json::to_vec(&req)?), true)? {
            (200, b) => Ok(CommitOutcome::Committed(serde_json::from_slice::<CommitResp>(&b)?.seq)),
            (409, b) => Ok(CommitOutcome::Conflict(serde_json::from_slice::<ConflictResp>(&b)?.current_rev)),
            (422, b) => Ok(CommitOutcome::MissingRefs(parse_ids(serde_json::from_slice::<MissingResp>(&b)?.missing)?)),
            (s, b) => Err(server_error(s, &b)),
        }
    }

    fn missing(&self, ids: &[ChunkId]) -> Result<Vec<ChunkId>> {
        if ids.is_empty() {
            return Ok(vec![]);
        }
        let req = MissingReq { ids: ids.iter().map(|r| r.hex()).collect() };
        match self.signed("POST", "missing", Some(&serde_json::to_vec(&req)?), true)? {
            (200, b) => parse_ids(serde_json::from_slice::<MissingResp>(&b)?.missing),
            (s, b) => Err(server_error(s, &b)),
        }
    }

    fn put_chunk(&self, id: &ChunkId, data: &[u8]) -> Result<()> {
        match self.signed("PUT", &format!("chunks/{}", id.hex()), Some(data), false)? {
            (200 | 201, _) => Ok(()),
            (507, _) => Err(Error::Server(507, "the server's storage quota for this vault is full".into())),
            (s, b) => Err(server_error(s, &b)),
        }
    }

    fn get_chunk(&self, id: &ChunkId) -> Result<Vec<u8>> {
        match self.signed("GET", &format!("chunks/{}", id.hex()), None, false)? {
            (200, b) => Ok(b),
            (404, _) => Err(Error::NotFound(format!("chunk {} on server", id.hex()))),
            (s, b) => Err(server_error(s, &b)),
        }
    }

    fn prune(&self, items: &[(EntryId, u64)]) -> Result<()> {
        let req = PruneReq { items: items.iter().map(|(e, below)| PruneItem { entry: e.hex(), below: *below }).collect() };
        match self.signed("POST", "prune", Some(&serde_json::to_vec(&req)?), true)? {
            (200, _) => Ok(()),
            (s, b) => Err(server_error(s, &b)),
        }
    }
}

fn parse_ids(v: Vec<String>) -> Result<Vec<ChunkId>> {
    v.iter().map(|s| ChunkId::parse(s)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn url_policy() {
        assert_eq!(check_url("https://files.example.com/").unwrap(), "https://files.example.com");
        assert!(check_url("http://files.example.com").is_err());
        assert!(check_url("http://127.0.0.1.evil.com").is_err());
        assert!(check_url("http://localhost:8787").is_ok());
        assert!(check_url("http://127.0.0.1:8787").is_ok());
        assert!(check_url("http://[::1]:8787").is_ok());
        assert!(check_url("https://user@host").is_err());
        assert!(check_url("https://host/path").is_err());
        assert!(check_url("ftp://host").is_err());
    }

    #[test]
    fn pin_parsing() {
        assert!(parse_ca_pem("").is_err());
        assert!(parse_ca_pem("hello").is_err());
        assert!(parse_ca_pem("-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n").is_err());
        let pem = "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n";
        assert_eq!(parse_ca_pem(pem).unwrap().len(), 1);
        assert_eq!(parse_ca_pem(&format!("{pem}{pem}")).unwrap().len(), 2);
        assert!(set_pin("http://remote.example", Some(pem)).is_err());
        assert_eq!(set_pin("https://pin.example/", Some(pem)).unwrap(), "https://pin.example");
        assert!(pins().read().unwrap().contains_key("https://pin.example"));
        set_pin("https://pin.example", None).unwrap();
        assert!(!pins().read().unwrap().contains_key("https://pin.example"));
    }
}
