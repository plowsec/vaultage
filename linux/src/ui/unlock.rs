//! Locked vault: passphrase or recovery key.

use std::rc::Rc;

use adw::prelude::*;
use gtk::glib;
use vaultage_core::header::SlotKind;
use vaultage_core::manager::VaultInfo;

use super::util::{bg, take_secret};
use super::App;
use crate::logic::{has_passphrase, UiError};

pub struct UnlockPage {
    pub root: adw::ToolbarView,
    pass: adw::PasswordEntryRow,
    recovery: adw::PasswordEntryRow,
    expander: adw::ExpanderRow,
    error: gtk::Label,
    button: gtk::Button,
    has_pass: bool,
}

impl UnlockPage {
    pub fn new(app: &Rc<App>, v: &VaultInfo) -> Rc<UnlockPage> {
        let root = adw::ToolbarView::new();
        let header = adw::HeaderBar::new();
        let gear = gtk::Button::from_icon_name("emblem-system-symbolic");
        gear.set_tooltip_text(Some("Vault Settings"));
        gear.set_action_name(Some("app.vault-settings"));
        gear.set_action_target_value(Some(&v.id.to_variant()));
        header.pack_end(&gear);
        root.add_top_bar(&header);

        let has_pass = has_passphrase(v);
        let group = adw::PreferencesGroup::new();
        let pass = adw::PasswordEntryRow::builder().title("Passphrase").build();
        let recovery = adw::PasswordEntryRow::builder().title("Recovery key").build();
        recovery.add_css_class("monospace");
        let expander = adw::ExpanderRow::builder().title("Use recovery key…").subtitle("The key you saved when the vault was created.").build();
        expander.add_row(&recovery);
        if has_pass {
            group.add(&pass);
        } else {
            expander.set_expanded(true);
        }
        group.add(&expander);

        let error = gtk::Label::builder().wrap(true).justify(gtk::Justification::Center).visible(false).build();
        error.add_css_class("error");
        let button = super::util::pill("Unlock", true);
        let col = gtk::Box::new(gtk::Orientation::Vertical, 18);
        col.append(&group);
        col.append(&error);
        col.append(&button);
        let clamp = adw::Clamp::builder().maximum_size(400).child(&col).build();
        let missing = v.missing;
        let page = adw::StatusPage::builder()
            .icon_name("system-lock-screen-symbolic")
            .title(&v.name)
            .description(if missing {
                "The vault’s folder is missing or unreadable."
            } else if v.remote.is_some() {
                "Synced vault · locked"
            } else {
                "Vault on this computer · locked"
            })
            .child(&clamp)
            .vexpand(true)
            .build();
        root.set_content(Some(&page));

        let p = Rc::new(UnlockPage { root, pass, recovery, expander, error, button, has_pass });
        let (a, id, me) = (app.clone(), v.id.clone(), Rc::downgrade(&p));
        let go = move || {
            if let Some(me) = me.upgrade() {
                me.unlock(&a, &id);
            }
        };
        let g = go.clone();
        p.pass.connect_entry_activated(move |_| g());
        let g = go.clone();
        p.recovery.connect_entry_activated(move |_| g());
        p.button.connect_clicked(move |_| go());
        p.button.set_sensitive(!missing);
        p
    }

    pub fn clear_error(&self) {
        self.error.set_visible(false);
    }

    pub fn focus(&self) {
        let (p, r, h) = (self.pass.clone(), self.recovery.clone(), self.has_pass);
        glib::idle_add_local_once(move || {
            if h {
                p.grab_focus();
            } else {
                r.grab_focus();
            }
        });
    }

    fn unlock(self: &Rc<Self>, app: &Rc<App>, id: &str) {
        // Recovery key wins if the user opened that field and typed one.
        let use_recovery = self.expander.is_expanded() && !self.recovery.text().trim().is_empty() || !self.has_pass;
        let (kind, secret) = if use_recovery { (SlotKind::Recovery, take_secret(&self.recovery, true)) } else { (SlotKind::Passphrase, take_secret(&self.pass, false)) };
        if secret.is_empty() {
            return;
        }
        self.error.set_visible(false);
        self.button.set_sensitive(false);
        let s = gtk::Spinner::new();
        s.start();
        self.button.set_child(Some(&s));
        let (b, a, me, id2) = (app.backend.clone(), app.clone(), self.clone(), id.to_string());
        bg(move || b.unlock(&id2, kind, &secret), move |r: Result<(), UiError>| {
            me.button.set_label("Unlock");
            me.button.set_sensitive(true);
            match r {
                Ok(()) => {
                    a.policy.borrow_mut().note_activity(std::time::Instant::now());
                    a.refresh_vaults();
                }
                Err(e) => {
                    if e.is_integrity() {
                        a.error("Integrity check failed", &e);
                    }
                    me.error.set_label(&if e.is_wrong_secret() { "That didn’t work. Check it and try again.".to_string() } else { e.text() });
                    me.error.set_visible(true);
                    me.root.error_bell();
                    if kind == SlotKind::Passphrase {
                        me.pass.grab_focus();
                    } else {
                        me.recovery.grab_focus();
                    }
                }
            }
        });
    }
}
