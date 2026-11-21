//! User-facing strings: error texts (same wording as `app/Sources/CofferKit/CofferCore.swift`),
//! sizes, dates, passphrase strength, name and address checks.

use vaultage_core::Error;

/// A core error kept as (code, message), like the macOS app sees it over the JSON API.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UiError {
    pub code: &'static str,
    pub message: String,
}

pub type R<T> = std::result::Result<T, UiError>;

impl From<Error> for UiError {
    fn from(e: Error) -> Self {
        UiError { code: e.code(), message: e.to_string() }
    }
}

impl std::fmt::Display for UiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.text())
    }
}

pub const QUOTA_FULL: &str = "The server’s storage quota for this vault is full. Empty the Trash or delete older versions to free space.";
pub const IN_USE: &str = "This vault is open in another Vaultage program (the command-line tool or another window). Close it there and try again.";

impl UiError {
    pub fn invalid(m: impl Into<String>) -> Self {
        UiError { code: "invalid", message: m.into() }
    }
    /// Tampering or corruption. Never auto-dismiss these.
    pub fn is_integrity(&self) -> bool {
        self.code == "integrity"
    }
    pub fn is_wrong_secret(&self) -> bool {
        self.code == "crypto"
    }
    pub fn is_locked(&self) -> bool {
        self.code == "locked"
    }
    /// The vault's directory lock is held by the CLI or another GUI.
    pub fn is_in_use(&self) -> bool {
        self.message.contains("open in another Vaultage process")
    }

    /// One-time invite that can't be claimed: "used", "expired" or "revoked".
    pub fn invite_gone(&self) -> Option<&'static str> {
        if self.code != "server" || server_status(&self.message) != Some(410) {
            return None;
        }
        ["used", "expired", "revoked"].into_iter().find(|w| self.message.contains(w)).or(Some("used"))
    }

    /// Text for a failed invite join.
    pub fn invite_problem(&self) -> Option<String> {
        match self.invite_gone() {
            Some("expired") => Some("This invite has expired. Ask for a new one.".into()),
            Some("revoked") => Some("This invite was revoked by the person who sent it. Ask for a new one.".into()),
            Some(_) => Some("This invite was already used. If it wasn’t you, someone else has it: tell the person who sent it to rotate the vault’s keys.".into()),
            None if self.code == "not_found" => Some("The server doesn’t know this invite. It may never have been created there, or the vault’s keys were rotated.".into()),
            None => None,
        }
    }

    /// The user-facing text.
    pub fn text(&self) -> String {
        if self.is_in_use() {
            return IN_USE.into();
        }
        let mut m = self.message.as_str();
        // "No such file or directory (os error 2)" -> "No such file or directory"
        if let Some(i) = m.rfind(" (os error ") {
            if m.ends_with(')') {
                m = &m[..i];
            }
        }
        match self.code {
            "crypto" => "Wrong passphrase or key.".into(),
            "locked" => "This vault is locked. Unlock it and try again.".into(),
            "network" => format!("Can’t reach the sync server. {}", sentence(strip(m, "network: "))),
            "server" if server_status(m) == Some(507) => QUOTA_FULL.into(),
            "server" => format!("The sync server refused the request: {}", sentence(strip_server(m))),
            "not_found" => {
                let what = strip(m, "not found: ");
                if what.is_empty() { "Not found.".into() } else { format!("Couldn’t find “{what}”.") }
            }
            "exists" => format!("“{}” already exists.", strip(m, "already exists: ")),
            "integrity" => format!("Integrity check failed: {}", sentence(strip(m, "integrity check failed: "))),
            "format" => format!("Unreadable data: {}", sentence(strip(m, "bad format: "))),
            _ => sentence(m),
        }
    }
}

/// User-facing text for a raw `status.sync.error` string.
pub fn readable_sync(raw: &str) -> String {
    if server_status(raw) == Some(507) || raw.contains("quota") {
        return QUOTA_FULL.into();
    }
    if server_status(raw).is_some() {
        return sentence(strip_server(raw));
    }
    sentence(strip(raw, "network: "))
}

/// HTTP status in a core message like "server (507): …".
fn server_status(m: &str) -> Option<u16> {
    let rest = m.strip_prefix("server (")?;
    let code = rest.get(..3)?;
    if rest.get(3..4) != Some(")") {
        return None;
    }
    code.parse().ok()
}

fn strip_server(m: &str) -> &str {
    if server_status(m).is_some() {
        m.get("server (000): ".len()..).unwrap_or("")
    } else {
        strip(m, "server ")
    }
}

fn strip<'a>(s: &'a str, prefix: &str) -> &'a str {
    s.strip_prefix(prefix).unwrap_or(s)
}

/// Capitalised, ends with punctuation.
pub fn sentence(s: &str) -> String {
    let mut c = s.chars();
    let Some(first) = c.next() else { return "Something went wrong.".into() };
    let mut out: String = first.to_uppercase().chain(c).collect();
    if !out.ends_with(['.', '!', '?']) {
        out.push('.');
    }
    out
}

// ---- formatting ----

/// "512 bytes", "1.5 KB", "12 MB" (decimal units, as Files shows them).
pub fn bytes(n: u64) -> String {
    if n < 1000 {
        return if n == 1 { "1 byte".into() } else { format!("{n} bytes") };
    }
    let units = ["KB", "MB", "GB", "TB", "PB"];
    let mut v = n as f64 / 1000.0;
    let mut u = 0;
    while v >= 999.95 && u + 1 < units.len() {
        v /= 1000.0;
        u += 1;
    }
    if v < 10.0 { format!("{:.1} {}", v, units[u]) } else { format!("{:.0} {}", v, units[u]) }
}

/// "3 files", "1 file".
pub fn count(n: u64, singular: &str) -> String {
    count2(n, singular, &format!("{singular}s"))
}

pub fn count2(n: u64, singular: &str, plural: &str) -> String {
    format!("{n} {}", if n == 1 { singular } else { plural })
}

fn local(ms: i64) -> libc::tm {
    let t: libc::time_t = (ms / 1000) as libc::time_t;
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    unsafe { libc::localtime_r(&t, &mut tm) };
    tm
}

const MONTHS: [&str; 12] = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];

fn day_key(tm: &libc::tm) -> i64 {
    (tm.tm_year as i64) * 400 + tm.tm_yday as i64
}

/// "Today, 14:03", "Yesterday, 09:12", "12 Nov 2026, 14:03"; "—" for 0.
pub fn date(ms: i64) -> String {
    if ms <= 0 {
        return "—".into();
    }
    let tm = local(ms);
    let now = local(vaultage_core::model::now_ms());
    let hm = format!("{:02}:{:02}", tm.tm_hour, tm.tm_min);
    let d = day_key(&now) - day_key(&tm);
    if d == 0 {
        format!("Today, {hm}")
    } else if d == 1 {
        format!("Yesterday, {hm}")
    } else {
        format!("{} {} {}, {hm}", tm.tm_mday, MONTHS[tm.tm_mon.clamp(0, 11) as usize], tm.tm_year + 1900)
    }
}

/// "14:03" today, else as [`date`].
pub fn short_time(ms: i64) -> String {
    let tm = local(ms);
    if ms > 0 && day_key(&local(vaultage_core::model::now_ms())) == day_key(&tm) {
        format!("{:02}:{:02}", tm.tm_hour, tm.tm_min)
    } else {
        date(ms)
    }
}

// ---- passphrase strength (same scoring as the macOS app) ----

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Strength {
    Empty,
    Weak,
    Fair,
    Good,
    Strong,
}

impl Strength {
    pub fn of(s: &str) -> Strength {
        if s.is_empty() {
            return Strength::Empty;
        }
        let mut classes = 0;
        classes += s.chars().any(|c| c.is_lowercase()) as u32;
        classes += s.chars().any(|c| c.is_uppercase()) as u32;
        classes += s.chars().any(|c| c.is_ascii_digit()) as u32;
        classes += s.chars().any(|c| !c.is_alphanumeric() && !c.is_whitespace()) as u32;
        let words = s.split([' ', '-']).filter(|w| !w.is_empty()).count();
        let score = s.chars().count() as f64 * (1.0 + classes as f64 * 0.25) + (words.saturating_sub(1)) as f64 * 6.0;
        match score {
            x if x < 14.0 => Strength::Weak,
            x if x < 22.0 => Strength::Fair,
            x if x < 32.0 => Strength::Good,
            _ => Strength::Strong,
        }
    }
    pub fn label(self) -> &'static str {
        match self {
            Strength::Empty => "",
            Strength::Weak => "Weak — easy to guess",
            Strength::Fair => "Fair — consider a longer passphrase",
            Strength::Good => "Good",
            Strength::Strong => "Strong",
        }
    }
    /// CSS class for the hint label.
    pub fn css(self) -> &'static str {
        match self {
            Strength::Empty | Strength::Good | Strength::Strong => "success",
            Strength::Weak => "error",
            Strength::Fair => "warning",
        }
    }
}

// ---- checks ----

/// Problem with a new file or folder name, or None.
pub fn name_problem(name: &str) -> Option<&'static str> {
    let t = name.trim();
    if t.is_empty() {
        Some("Enter a name.")
    } else if t.contains('/') {
        Some("Names can’t contain “/”.")
    } else if t == "." || t == ".." {
        Some("That name is reserved.")
    } else {
        None
    }
}

/// Client-side check mirroring the core's rules: https://host[:port], http only for loopback.
pub fn server_url_problem(raw: &str) -> Option<&'static str> {
    let s = raw.trim();
    if s.is_empty() {
        return Some("Enter the sync server’s address.");
    }
    let Some((scheme, rest)) = s.split_once("://") else { return Some("The address must start with https://.") };
    let rest = rest.trim_end_matches('/');
    if rest.is_empty() {
        return Some("Use the form https://host or https://host:port.");
    }
    if rest.contains(['/', '?', '#', '@']) {
        return Some("Enter just the server address, without a path.");
    }
    let host = if rest.starts_with('[') { rest.split(']').next().map(|h| &h[1..]).unwrap_or("") } else { rest.split(':').next().unwrap_or("") };
    let loopback = matches!(host, "localhost" | "127.0.0.1" | "::1");
    match scheme.to_ascii_lowercase().as_str() {
        "https" => None,
        "http" if loopback => None,
        "http" => Some("Use https:// — unencrypted http:// is only allowed for localhost."),
        _ => Some("The address must start with https://."),
    }
}

pub fn vault_id_problem(raw: &str) -> Option<&'static str> {
    let t = raw.trim();
    if t.is_empty() {
        Some("Enter the vault ID.")
    } else if !(t.len() == 32 && t.chars().all(|c| c.is_ascii_hexdigit())) {
        Some("A vault ID is 32 characters, 0–9 and a–f.")
    } else {
        None
    }
}

pub fn invite_line_problem(raw: &str) -> Option<&'static str> {
    let t = raw.trim();
    if t.is_empty() {
        return Some("Paste the invite.");
    }
    let parts: Vec<&str> = t.split('#').collect();
    if parts.len() != 3 || parts[2].is_empty() {
        return Some("An invite is one line of three parts separated by “#”. Paste it exactly as you received it.");
    }
    if server_url_problem(parts[0]).is_some() {
        return Some("The invite’s server address isn’t valid.");
    }
    if vault_id_problem(parts[1]).is_some() {
        return Some("The invite’s vault ID isn’t valid.");
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_texts() {
        let e = |code, m: &str| UiError { code, message: m.into() };
        assert_eq!(e("crypto", "wrong key").text(), "Wrong passphrase or key.");
        assert_eq!(e("network", "network: connection refused").text(), "Can’t reach the sync server. Connection refused.");
        assert_eq!(e("server", "server (507): quota").text(), QUOTA_FULL);
        assert_eq!(e("server", "server (403): bad token").text(), "The sync server refused the request: Bad token.");
        let clock = "This device’s clock is about 12 minutes behind the server’s. Set the date and time, then try again.";
        assert_eq!(e("clock", clock).text(), clock);
        assert_eq!(readable_sync(clock), clock);
        assert_eq!(e("not_found", "not found: a.txt").text(), "Couldn’t find “a.txt”.");
        assert_eq!(e("io", "No such file or directory (os error 2)").text(), "No such file or directory.");
        assert_eq!(e("server", "server (410): invite expired").invite_gone(), Some("expired"));
        assert_eq!(readable_sync("server (500): boom"), "Boom.");
        assert!(e("invalid", "vault is open in another Vaultage process").is_in_use());
    }

    #[test]
    fn checks() {
        assert!(server_url_problem("https://a.example").is_none());
        assert!(server_url_problem("http://127.0.0.1:8787").is_none());
        assert!(server_url_problem("http://a.example").is_some());
        assert!(server_url_problem("https://a.example/x").is_some());
        assert!(name_problem("a/b").is_some());
        assert_eq!(bytes(1500), "1.5 KB");
        assert_eq!(bytes(12_000_000), "12 MB");
        assert!(Strength::of("correct horse battery staple") >= Strength::Good);
        assert_eq!(Strength::of("abc"), Strength::Weak);
    }
}
