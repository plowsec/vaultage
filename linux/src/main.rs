//! `vaultage-gui`: the Linux desktop app.

fn main() -> std::process::ExitCode {
    // Before any thread starts or secret exists: no core dumps, not dumpable (no ptrace or
    // /proc/<pid>/mem from other processes of this user).
    let posture = vaultage_core::harden::harden();
    // Still single-threaded, and before GTK reads it: file dialogs stay in-process (see policy).
    let gdk_debug = vaultage_gui::logic::policy::gdk_debug_without_portals(std::env::var("GDK_DEBUG").ok().as_deref());
    std::env::set_var("GDK_DEBUG", gdk_debug);
    vaultage_gui::ui::run(posture).into()
}
