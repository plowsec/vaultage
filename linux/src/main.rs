//! `vaultage-gui`: the Linux desktop app.

fn main() -> std::process::ExitCode {
    // Before any thread starts or secret exists: no core dumps, not dumpable (no ptrace or
    // /proc/<pid>/mem from other processes of this user).
    let posture = vaultage_core::harden::harden();
    vaultage_gui::ui::run(posture).into()
}
