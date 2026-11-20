//! Vaultage for Linux. `logic`: GTK-free (tested headless by `vaultage-gui-selftest`); `ui`: GTK4 + libadwaita.

pub mod logic;
pub mod ui;

pub const APP_ID: &str = "local.vaultage.app";
