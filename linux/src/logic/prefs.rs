//! App preferences (not secret): `$XDG_CONFIG_HOME/vaultage/gui.json`, or `<VAULTAGE_HOME>/gui.json`
//! when VAULTAGE_HOME is set (keeps test runs apart).

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(default)]
pub struct Prefs {
    /// Lock all vaults after this many idle minutes; 0 = never.
    pub auto_lock_minutes: u32,
    /// Lock all vaults when the screen locks or the machine suspends.
    pub lock_on_screen_lock: bool,
    /// Import moves files in (deletes originals after verifying) instead of copying.
    pub import_move: bool,
    pub grid_view: bool,
    pub show_thumbnails: bool,
    pub show_preview: bool,
}

impl Default for Prefs {
    fn default() -> Self {
        Prefs { auto_lock_minutes: 10, lock_on_screen_lock: true, import_move: false, grid_view: false, show_thumbnails: true, show_preview: true }
    }
}

pub fn path() -> PathBuf {
    if let Some(h) = vaultage_core::env_var_os("HOME") {
        return PathBuf::from(h).join("gui.json");
    }
    let home = PathBuf::from(std::env::var_os("HOME").unwrap_or_default());
    std::env::var_os("XDG_CONFIG_HOME").map(PathBuf::from).unwrap_or_else(|| home.join(".config")).join("vaultage/gui.json")
}

impl Prefs {
    pub fn load() -> Prefs {
        std::fs::read(path()).ok().and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or_default()
    }
    pub fn save(&self) -> std::io::Result<()> {
        let p = path();
        if let Some(d) = p.parent() {
            std::fs::create_dir_all(d)?;
        }
        let tmp = p.with_extension("json.tmp");
        std::fs::write(&tmp, serde_json::to_vec_pretty(self).unwrap_or_default())?;
        std::fs::rename(&tmp, &p)
    }
}
