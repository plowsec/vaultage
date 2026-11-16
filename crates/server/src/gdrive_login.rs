//! `vaultaged gdrive-login`: one-time OAuth consent (loopback redirect, installed-app flow) for
//! the `drive.file` scope, then creates the chunk folder. That scope sees only files this
//! client created, so the folder must be created here, not in the Drive UI.

use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;

use crate::store::gdrive::{self, form, token_request, Drive, DEFAULT_TOKEN_URL, SCOPE};
use crate::DriveConfig;

const AUTH_URL: &str = "https://accounts.google.com/o/oauth2/v2/auth";

#[derive(Clone, Default)]
pub struct Opts {
    pub client_id: String,
    pub client_secret: String,
    /// None: don't create a folder (new token for an existing one).
    pub folder_name: Option<String>,
    /// Overrides (tests).
    pub auth_url: Option<String>,
    pub token_url: Option<String>,
    pub drive_endpoint: Option<String>,
}

pub struct Out {
    pub refresh_token: String,
    pub folder_id: Option<String>,
}

fn pct_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'+' => out.push(b' '),
            b'%' if i + 2 < b.len() => {
                let hexv = |c: u8| (c as char).to_digit(16);
                match (hexv(b[i + 1]), hexv(b[i + 2])) {
                    (Some(h), Some(l)) => {
                        out.push((h * 16 + l) as u8);
                        i += 2;
                    }
                    _ => out.push(b'%'),
                }
            }
            c => out.push(c),
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn query_param(target: &str, key: &str) -> Option<String> {
    let q = target.split_once('?')?.1;
    q.split('&').find_map(|kv| {
        let (k, v) = kv.split_once('=').unwrap_or((kv, ""));
        (pct_decode(k) == key).then(|| pct_decode(v))
    })
}

/// Waits for the browser's redirect; returns the authorization code.
fn wait_for_code(l: &TcpListener, state: &str) -> Result<String, String> {
    loop {
        let (mut s, _) = l.accept().map_err(|e| format!("accept: {e}"))?;
        let mut line = String::new();
        BufReader::new(&s).read_line(&mut line).map_err(|e| format!("read: {e}"))?;
        let target = line.split(' ').nth(1).unwrap_or("").to_owned();
        let reply = |s: &mut std::net::TcpStream, code: u16, msg: &str| {
            let _ = write!(
                s,
                "HTTP/1.1 {code} X\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{msg}",
                msg.len()
            );
        };
        if query_param(&target, "state").is_none() && query_param(&target, "error").is_none() {
            reply(&mut s, 404, "not found"); // favicon and the like
            continue;
        }
        if let Some(e) = query_param(&target, "error") {
            reply(&mut s, 400, "Consent was not given. You can close this tab.");
            return Err(format!("consent refused: {e}"));
        }
        if query_param(&target, "state").as_deref() != Some(state) {
            reply(&mut s, 400, "State mismatch. Start again.");
            return Err("state mismatch in redirect".into());
        }
        let Some(code) = query_param(&target, "code") else {
            reply(&mut s, 400, "No code. Start again.");
            return Err("redirect without a code".into());
        };
        reply(&mut s, 200, "Done. You can close this tab and go back to the terminal.");
        return Ok(code);
    }
}

/// Runs the flow; `show` receives the consent URL to open.
pub fn login(o: &Opts, show: impl FnOnce(&str)) -> Result<Out, String> {
    let l = TcpListener::bind("127.0.0.1:0").map_err(|e| format!("bind: {e}"))?;
    let redirect = format!("http://127.0.0.1:{}", l.local_addr().map_err(|e| e.to_string())?.port());
    let state = crate::store::unique_id();
    let url = format!(
        "{}?{}",
        o.auth_url.as_deref().unwrap_or(AUTH_URL),
        form(&[
            ("client_id", &o.client_id),
            ("redirect_uri", &redirect),
            ("response_type", "code"),
            ("scope", SCOPE),
            ("access_type", "offline"),
            ("prompt", "consent"),
            ("state", &state),
        ])
    );
    show(&url);
    let code = wait_for_code(&l, &state)?;
    let token_url = o.token_url.as_deref().unwrap_or(DEFAULT_TOKEN_URL);
    let v = token_request(
        &gdrive::agent(),
        token_url,
        &form(&[
            ("code", &code),
            ("client_id", &o.client_id),
            ("client_secret", &o.client_secret),
            ("redirect_uri", &redirect),
            ("grant_type", "authorization_code"),
        ]),
    )?;
    let refresh_token = v["refresh_token"]
        .as_str()
        .ok_or("no refresh_token in the reply (revoke the app's access at myaccount.google.com and retry)")?
        .to_owned();
    let access = v["access_token"].as_str().ok_or("no access_token in the reply")?;
    let Some(name) = &o.folder_name else {
        return Ok(Out { refresh_token, folder_id: None });
    };
    let d = Drive::new(&DriveConfig {
        folder: "unused".into(),
        endpoint: o.drive_endpoint.clone(),
        token: Some(access.to_owned()),
        ..Default::default()
    })
    .map_err(|e| e.to_string())?;
    let folder_id = d
        .create_folder(name, None)
        .map_err(|e| format!("create folder: {e:?}"))?;
    Ok(Out {
        refresh_token,
        folder_id: Some(folder_id),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode() {
        assert_eq!(pct_decode("4%2F0Ab+c%zz"), "4/0Ab c%zz");
        assert_eq!(query_param("/?state=s1&code=4%2Fx", "code").as_deref(), Some("4/x"));
        assert_eq!(query_param("/favicon.ico", "code"), None);
    }
}
