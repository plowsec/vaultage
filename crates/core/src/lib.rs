pub mod api;
pub mod crypto;
pub mod error;
pub mod harden;
pub mod header;
pub mod hexutil;
pub mod http;
pub mod invite;
pub mod manager;
pub mod model;
pub mod proto;
pub mod remote;
pub mod store;
pub mod sync;
#[cfg(test)]
mod sync_tests;
#[cfg(any(test, feature = "testing"))]
pub mod testkit;
pub mod vault;

pub use error::{Error, Result};

/// `VAULTAGE_<name>`, else `COFFER_<name>` (the name before the rename; the iOS app still sets it).
pub fn env_var_os(name: &str) -> Option<std::ffi::OsString> {
    std::env::var_os(format!("VAULTAGE_{name}")).or_else(|| std::env::var_os(format!("COFFER_{name}")))
}

/// [`env_var_os`] as UTF-8; a value that isn't UTF-8 counts as unset.
pub fn env_var(name: &str) -> Option<String> {
    env_var_os(name).and_then(|v| v.into_string().ok())
}
