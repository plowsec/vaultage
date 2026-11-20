//! Lock all vaults when the screen locks or the machine suspends (if the preference says so).
//!
//! | Signal | Bus |
//! |---|---|
//! | `org.freedesktop.login1.Manager.PrepareForSleep(true)` | system |
//! | `org.freedesktop.login1.Session.Lock` (our session) | system |
//! | `org.gnome.ScreenSaver.ActiveChanged(true)` | session |
//! | `org.freedesktop.ScreenSaver.ActiveChanged(true)` | session (KDE, others) |

use std::rc::Rc;

use gtk::{gio, glib};

use super::App;
use crate::logic::policy::LockReason;

pub fn watch(app: &Rc<App>) {
    let a = app.clone();
    gio::bus_get(gio::BusType::System, None::<&gio::Cancellable>, move |r| match r {
        Ok(c) => system(&a, c),
        Err(e) => eprintln!("vaultage: no system bus ({e}); suspend/lock signals not watched"),
    });
    let a = app.clone();
    gio::bus_get(gio::BusType::Session, None::<&gio::Cancellable>, move |r| match r {
        Ok(c) => session(&a, c),
        Err(e) => eprintln!("vaultage: no session bus ({e}); screen-lock signals not watched"),
    });
}

fn system(app: &Rc<App>, c: gio::DBusConnection) {
    let a = Rc::downgrade(app);
    let sub = c.subscribe_to_signal(
        Some("org.freedesktop.login1"),
        Some("org.freedesktop.login1.Manager"),
        Some("PrepareForSleep"),
        Some("/org/freedesktop/login1"),
        None,
        gio::DBusSignalFlags::NONE,
        move |s| {
            let going = s.parameters.get::<(bool,)>().map(|(b,)| b).unwrap_or(false);
            if let (true, Some(a)) = (going, a.upgrade()) {
                a.lock_all(LockReason::Suspend);
            }
        },
    );
    keep(app, sub);

    // Our session's object path, then its Lock signal.
    let pid = std::process::id();
    let (a, c2) = (app.clone(), c.clone());
    c.call(
        Some("org.freedesktop.login1"),
        "/org/freedesktop/login1",
        "org.freedesktop.login1.Manager",
        "GetSessionByPID",
        Some(&glib::Variant::from((pid,))),
        Some(glib::VariantTy::new("(o)").unwrap()),
        gio::DBusCallFlags::NONE,
        5000,
        None::<&gio::Cancellable>,
        move |r| {
            let path = r.ok().and_then(|v| v.child_value(0).get::<glib::variant::ObjectPath>()).map(|p| p.as_str().to_string());
            let w = Rc::downgrade(&a);
            let sub = c2.subscribe_to_signal(
                Some("org.freedesktop.login1"),
                Some("org.freedesktop.login1.Session"),
                Some("Lock"),
                path.as_deref(),
                None,
                gio::DBusSignalFlags::NONE,
                move |_| {
                    if let Some(a) = w.upgrade() {
                        a.lock_all(LockReason::ScreenLocked);
                    }
                },
            );
            keep(&a, sub);
        },
    );
}

fn session(app: &Rc<App>, c: gio::DBusConnection) {
    for (iface, path) in [("org.gnome.ScreenSaver", "/org/gnome/ScreenSaver"), ("org.freedesktop.ScreenSaver", "/org/freedesktop/ScreenSaver")] {
        let a = Rc::downgrade(app);
        let sub = c.subscribe_to_signal(None, Some(iface), Some("ActiveChanged"), Some(path), None, gio::DBusSignalFlags::NONE, move |s| {
            let active = s.parameters.get::<(bool,)>().map(|(b,)| b).unwrap_or(false);
            if let (true, Some(a)) = (active, a.upgrade()) {
                a.lock_all(LockReason::ScreenLocked);
            }
        });
        keep(app, sub);
    }
}

/// Subscriptions end when dropped; keep them for the app's lifetime.
fn keep(_app: &Rc<App>, sub: gio::SignalSubscription) {
    std::mem::forget(sub);
}
