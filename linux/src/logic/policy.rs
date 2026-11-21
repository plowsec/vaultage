//! When to drop keys: idle timeout, screen lock / suspend, quit. Also: no desktop portals.

use std::time::{Duration, Instant};

/// `GDK_DEBUG` with portals off, other flags kept. GTK 4.18+ sends file dialogs through
/// xdg-desktop-portal whenever one runs; the portal refuses a non-dumpable process ("Unable to
/// open /proc/PID/root"), so the chooser never opens. With `no-portals` GTK shows its own.
pub fn gdk_debug_without_portals(current: Option<&str>) -> String {
    let mut flags: Vec<&str> = current
        .unwrap_or("")
        .split([':', ';', ',', ' ', '\t'])
        .filter(|f| !f.is_empty() && !f.eq_ignore_ascii_case("portals") && !f.eq_ignore_ascii_case("no-portals"))
        .collect();
    flags.push("no-portals");
    flags.join(",")
}

/// Why all vaults are being locked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LockReason {
    Idle,
    ScreenLocked,
    Suspend,
    Quit,
    User,
}

#[derive(Debug)]
pub struct LockPolicy {
    pub idle_minutes: u32,
    pub on_screen_lock: bool,
    last_activity: Instant,
}

impl LockPolicy {
    pub fn new(idle_minutes: u32, on_screen_lock: bool) -> Self {
        LockPolicy { idle_minutes, on_screen_lock, last_activity: Instant::now() }
    }

    /// Input in a window of ours.
    pub fn note_activity(&mut self, now: Instant) {
        self.last_activity = now;
    }

    /// Call about once a second. `busy`: an import/export runs (never pull keys from under it,
    /// and it counts as activity). `any_open`: at least one vault is unlocked.
    pub fn idle_due(&mut self, now: Instant, busy: bool, any_open: bool) -> bool {
        if self.idle_minutes == 0 || !any_open {
            return false;
        }
        if busy {
            self.last_activity = now;
            return false;
        }
        now.duration_since(self.last_activity) > Duration::from_secs(self.idle_minutes as u64 * 60)
    }

    /// A session event: should all vaults lock now?
    pub fn event_due(&self, reason: LockReason) -> bool {
        match reason {
            LockReason::ScreenLocked | LockReason::Suspend => self.on_screen_lock,
            LockReason::Quit | LockReason::User | LockReason::Idle => true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn portals_off() {
        assert_eq!(gdk_debug_without_portals(None), "no-portals");
        assert_eq!(gdk_debug_without_portals(Some("")), "no-portals");
        assert_eq!(gdk_debug_without_portals(Some("portals")), "no-portals");
        assert_eq!(gdk_debug_without_portals(Some("no-portals")), "no-portals");
        assert_eq!(gdk_debug_without_portals(Some("gl-disable:portals; frames")), "gl-disable,frames,no-portals");
    }

    #[test]
    fn idle() {
        let t0 = Instant::now();
        let mut p = LockPolicy::new(1, true);
        p.note_activity(t0);
        assert!(!p.idle_due(t0 + Duration::from_secs(59), false, true));
        assert!(p.idle_due(t0 + Duration::from_secs(61), false, true));
        assert!(!p.idle_due(t0 + Duration::from_secs(61), false, false));
        assert!(!p.idle_due(t0 + Duration::from_secs(61), true, true));
        assert!(!p.idle_due(t0 + Duration::from_secs(100), false, true));
        p.idle_minutes = 0;
        assert!(!p.idle_due(t0 + Duration::from_secs(9999), false, true));
        assert!(!LockPolicy::new(5, false).event_due(LockReason::Suspend));
        assert!(LockPolicy::new(5, false).event_due(LockReason::Quit));
    }
}
