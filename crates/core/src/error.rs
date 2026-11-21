use std::fmt;

#[derive(Debug)]
pub enum Error {
    Io(std::io::Error),
    /// Wrong key/passphrase or tampered ciphertext.
    Crypto(&'static str),
    /// Data failed an integrity or consistency check. Never auto-repaired.
    Integrity(String),
    Format(String),
    NotFound(String),
    Exists(String),
    Invalid(String),
    Locked,
    /// Transport failure: retry later.
    Net(String),
    /// Server refused the request.
    Server(u16, String),
    /// Server refused the request because this device's clock is wrong. The text is for the user.
    Clock(String),
}

pub type Result<T> = std::result::Result<T, Error>;

impl Error {
    pub fn code(&self) -> &'static str {
        match self {
            Error::Io(_) => "io",
            Error::Crypto(_) => "crypto",
            Error::Integrity(_) => "integrity",
            Error::Format(_) => "format",
            Error::NotFound(_) => "not_found",
            Error::Exists(_) => "exists",
            Error::Invalid(_) => "invalid",
            Error::Locked => "locked",
            Error::Net(_) => "network",
            Error::Server(..) => "server",
            Error::Clock(_) => "clock",
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Io(e) => write!(f, "{e}"),
            Error::Crypto(m) => write!(f, "{m}"),
            Error::Integrity(m) => write!(f, "integrity check failed: {m}"),
            Error::Format(m) => write!(f, "bad format: {m}"),
            Error::NotFound(m) => write!(f, "not found: {m}"),
            Error::Exists(m) => write!(f, "already exists: {m}"),
            Error::Invalid(m) => write!(f, "{m}"),
            Error::Locked => write!(f, "vault is locked"),
            Error::Net(m) => write!(f, "network: {m}"),
            Error::Server(c, m) => write!(f, "server ({c}): {m}"),
            Error::Clock(m) => write!(f, "{m}"),
        }
    }
}

impl std::error::Error for Error {}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::Io(e)
    }
}
impl From<serde_json::Error> for Error {
    fn from(e: serde_json::Error) -> Self {
        Error::Format(e.to_string())
    }
}
