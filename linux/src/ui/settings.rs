//! Vault settings (name, sync, sharing, unlock methods, keys, certificate pin, removal), the tasks
//! they start (attach, invite, rotate, adopt), app preferences and the security posture.

use std::cell::RefCell;
use std::rc::Rc;

use adw::prelude::*;
use gtk::{gio, glib};
use vaultage_core::header::SlotKind;
use vaultage_core::invite::InviteStatus;
use vaultage_core::manager::VaultInfo;
use vaultage_core::proto::UsageResp;

use super::dialogs::{show_key, KeyView};
use super::util::{bg, confirm, copy_secret, sheet, take_secret, update_strength};
use super::App;
use crate::logic::{invite_state, text, Secret, VaultStatus};

thread_local! {
    /// Vaults whose rotation dialog is open (hides the "unfinished rotation" banner).
    static ROTATING: RefCell<Vec<String>> = const { RefCell::new(vec![]) };
    static OPEN_SETTINGS: RefCell<Option<(String, glib::WeakRef<adw::PreferencesDialog>)>> = const { RefCell::new(None) };
}

pub fn rotation_dialog_open(id: &str) -> bool {
    ROTATING.with(|r| r.borrow().iter().any(|x| x == id))
}

struct Data {
    v: VaultInfo,
    status: Option<VaultStatus>,
    usage: Option<Result<UsageResp, String>>,
    invites: Option<Result<Vec<InviteStatus>, String>>,
    pin: Option<String>,
}

pub fn vault_settings(app: &Rc<App>, id: &str) {
    let d = adw::PreferencesDialog::new();
    d.set_title("Vault Settings");
    d.set_search_enabled(false);
    // Filled in after it opens; a dialog keeps its first size.
    d.set_content_width(620);
    d.set_content_height(680);
    OPEN_SETTINGS.with(|o| *o.borrow_mut() = Some((id.to_string(), d.downgrade())));
    refresh_settings(app, &d, id);
    d.present(Some(&app.window));
}

/// Re-read and rebuild the open settings dialog (after a change).
fn reopen(app: &Rc<App>, id: &str) {
    let d = OPEN_SETTINGS.with(|o| o.borrow().as_ref().filter(|(i, _)| i == id).and_then(|(_, w)| w.upgrade()));
    if let Some(d) = d {
        refresh_settings(app, &d, id);
    }
    app.refresh_vaults();
}

fn refresh_settings(app: &Rc<App>, d: &adw::PreferencesDialog, id: &str) {
    let (b, id2, a, d2) = (app.backend.clone(), id.to_string(), app.clone(), d.clone());
    bg(
        move || {
            let v = b.vault(&id2)?;
            let status = b.status(&id2).ok();
            let synced = v.remote.is_some() && v.unlocked;
            let usage = synced.then(|| b.usage(&id2).map_err(|e| e.text()));
            let invites = synced.then(|| b.invites(&id2).map_err(|e| e.text()));
            let pin = v.remote.as_deref().and_then(|u| b.pin(u));
            Some(Data { v, status, usage, invites, pin })
        },
        move |data| match data {
            Some(data) => build(&a, &d2, data),
            None => {
                d2.force_close();
            }
        },
    );
}

fn row(title: &str, subtitle: &str) -> adw::ActionRow {
    adw::ActionRow::builder().title(glib::markup_escape_text(title)).subtitle(glib::markup_escape_text(subtitle)).build()
}

fn copy_button(value: &str, what: &str) -> gtk::Button {
    let b = gtk::Button::from_icon_name("edit-copy-symbolic");
    b.add_css_class("flat");
    b.set_valign(gtk::Align::Center);
    b.set_tooltip_text(Some(&format!("Copy {what}")));
    let v = value.to_string();
    b.connect_clicked(move |b| {
        b.clipboard().set_text(&v);
    });
    b
}

fn button(label: &str) -> gtk::Button {
    let b = gtk::Button::with_label(label);
    b.set_valign(gtk::Align::Center);
    b
}

fn build(app: &Rc<App>, d: &adw::PreferencesDialog, data: Data) {
    // Replace the page wholesale.
    while let Some(p) = d.visible_page() {
        d.remove(&p);
    }
    let v = &data.v;
    let id = v.id.clone();
    let page = adw::PreferencesPage::new();
    let synced = v.remote.is_some();

    // General
    let g = adw::PreferencesGroup::builder().title("Vault").build();
    let name = adw::EntryRow::builder().title("Name").text(&v.name).show_apply_button(true).build();
    let (a, id2) = (app.clone(), id.clone());
    name.connect_apply(move |e| {
        let (b, id3, n, a2) = (a.backend.clone(), id2.clone(), e.text().to_string(), a.clone());
        bg(move || b.rename_vault(&id3, &n), move |r| match r {
            Ok(()) => a2.refresh_vaults(),
            Err(e) => a2.error("Couldn’t rename the vault", &e),
        });
    });
    g.add(&name);
    let r = row("Vault ID", &v.id);
    r.add_css_class("property");
    r.add_suffix(&copy_button(&v.id, "vault ID"));
    g.add(&r);
    let r = row("Encrypted folder", &v.path);
    r.add_css_class("property");
    let open = gtk::Button::from_icon_name("folder-open-symbolic");
    open.add_css_class("flat");
    open.set_valign(gtk::Align::Center);
    open.set_tooltip_text(Some("Show the encrypted folder"));
    let (p, w) = (v.path.clone(), app.window.clone());
    open.connect_clicked(move |_| {
        super::util::open_folder(&w, std::path::Path::new(&p));
    });
    r.add_suffix(&open);
    g.add(&r);
    page.add(&g);

    // Sync
    let g = adw::PreferencesGroup::builder().title("Sync").build();
    match &v.remote {
        Some(url) => {
            let r = row("Sync server", url);
            r.add_css_class("property");
            r.add_suffix(&copy_button(url, "server address"));
            g.add(&r);
            let usage = match &data.usage {
                Some(Ok(u)) => format!("{} in {} on the server{}", text::bytes(u.bytes), text::count(u.chunks, "chunk"), u.quota.map(|q| format!(" · quota {}", text::bytes(q))).unwrap_or_default()),
                Some(Err(e)) => e.clone(),
                None => "Unlock the vault to see storage use.".into(),
            };
            g.add(&row("Storage", &usage));
            let pin_r = row(
                "Server certificate",
                &match &data.pin {
                    Some(pem) => format!("Pinned to {} you trust", text::count2(pem.matches("BEGIN CERTIFICATE").count() as u64, "certificate", "certificates")),
                    None => "Public certificate authorities".into(),
                },
            );
            let pin_b = button(if data.pin.is_some() { "Unpin" } else { "Pin…" });
            let (a, url2, idp, pinned) = (app.clone(), url.clone(), id.clone(), data.pin.is_some());
            pin_b.connect_clicked(move |_| {
                if pinned {
                    let (b, u, a2, id3) = (a.backend.clone(), url2.clone(), a.clone(), idp.clone());
                    bg(move || b.set_pin(&u, None), move |r| match r {
                        Ok(()) => reopen(&a2, &id3),
                        Err(e) => a2.error("Couldn’t unpin", &e),
                    });
                } else {
                    pin_from_file(&a, &url2, &idp);
                }
            });
            pin_r.add_suffix(&pin_b);
            g.set_description(Some("To use this vault on another device, choose Join Existing Vault there and enter the server, vault ID and your recovery key or passphrase, or send an invite."));
            g.add(&pin_r);
            if v.unlocked {
                let r = row("Sync now", "Changes sync automatically; this checks the server at once.");
                let b = button("Sync Now");
                let (a, id3) = (app.clone(), id.clone());
                b.connect_clicked(move |_| {
                    if let Some(br) = a.browser(&id3) {
                        br.sync_now();
                    }
                });
                r.add_suffix(&b);
                g.add(&r);
            }
        }
        None => {
            let r = row("Local only — not synced", if v.unlocked { "Upload this vault, encrypted, to a sync server to use it on other devices." } else { "Unlock the vault to connect it to a server." });
            let b = button("Sync with a Server…");
            b.set_sensitive(v.unlocked);
            let (a, id3) = (app.clone(), id.clone());
            b.connect_clicked(move |_| attach(&a, &id3));
            r.add_suffix(&b);
            g.add(&r);
        }
    }
    page.add(&g);

    // Sharing
    if synced {
        let g = adw::PreferencesGroup::builder()
            .title("Sharing")
            .description("An invite works once, within 24 hours. A used, expired or revoked invite opens nothing. To cut off someone who already joined, rotate keys.")
            .build();
        let r = row("Invite someone", "Creates a one-line invite with full read and write access.");
        let b = button("Invite…");
        b.set_sensitive(v.unlocked);
        let (a, id3) = (app.clone(), id.clone());
        b.connect_clicked(move |_| invite(&a, &id3));
        r.add_suffix(&b);
        g.add(&r);
        match &data.invites {
            Some(Ok(list)) => {
                for i in list.iter().take(20) {
                    let r = row(if i.label.is_empty() { "Invite" } else { &i.label }, &invite_state(i));
                    if i.state == "waiting" {
                        let b = button("Revoke");
                        let (a, id3, inv) = (app.clone(), id.clone(), i.clone());
                        b.connect_clicked(move |_| {
                            let (a2, id4, inv2) = (a.clone(), id3.clone(), inv.clone());
                            confirm(&a.window, &format!("Revoke the invite “{}”?", if inv.label.is_empty() { "Invite" } else { &inv.label }), "Nobody can join with it any more.", "Revoke", true, move || {
                                let (b, id5, i5, a3, vid) = (a2.backend.clone(), id4.clone(), inv2.id.clone(), a2.clone(), id4.clone());
                                bg(move || b.revoke_invite(&id5, &i5), move |r| match r {
                                    Ok(()) => reopen(&a3, &vid),
                                    Err(e) => a3.error("Couldn’t revoke the invite", &e),
                                });
                            });
                        });
                        r.add_suffix(&b);
                    }
                    g.add(&r);
                }
            }
            Some(Err(e)) => g.add(&row("Invites", e)),
            None => {}
        }
        page.add(&g);
    }

    // Unlock methods
    let g = adw::PreferencesGroup::builder()
        .title("Unlock Methods")
        .description(if v.unlocked { "Passphrases and recovery keys work on any device. At least one must remain." } else { "Unlock the vault to change its unlock methods." })
        .build();
    let portable = v.slots.iter().filter(|s| s.kind != SlotKind::SecureEnclave).count();
    for s in &v.slots {
        let (title, sub) = match s.kind {
            SlotKind::Passphrase => (if s.label.is_empty() { "Passphrase".to_string() } else { s.label.clone() }, format!("Added {}", text::date(s.created))),
            SlotKind::Recovery if s.label.starts_with("Invite") => (s.label.clone(), format!("Invite · full access · created {}", text::date(s.created))),
            SlotKind::Recovery => (if s.label.is_empty() { "Recovery key".to_string() } else { s.label.clone() }, format!("Added {}", text::date(s.created))),
            SlotKind::SecureEnclave => (s.label.clone(), "Touch ID on a Mac (not usable here)".into()),
        };
        let r = row(&title, &sub);
        r.add_prefix(&gtk::Image::from_icon_name(match s.kind {
            SlotKind::Passphrase => "dialog-password-symbolic",
            SlotKind::Recovery => "channel-secure-symbolic",
            SlotKind::SecureEnclave => "computer-symbolic",
        }));
        let rm = gtk::Button::from_icon_name("user-trash-symbolic");
        rm.add_css_class("flat");
        rm.set_valign(gtk::Align::Center);
        rm.set_tooltip_text(Some("Remove…"));
        rm.set_sensitive(v.unlocked && (s.kind == SlotKind::SecureEnclave || portable > 1));
        let (a, id3, slot, kind, label) = (app.clone(), id.clone(), s.id.clone(), s.kind, title.clone());
        rm.connect_clicked(move |_| {
            let consequence = match kind {
                SlotKind::Recovery if label.starts_with("Invite") => "The invite can no longer be used to join this vault.\n\nThis does not revoke anyone who already joined with it: their device keeps full access. To cut them off, rotate the vault’s keys.",
                SlotKind::Recovery => "The recovery key you saved will no longer open this vault.",
                SlotKind::Passphrase => "This passphrase will no longer open this vault on any device.",
                SlotKind::SecureEnclave => "That Mac will no longer unlock this vault with Touch ID.",
            };
            let (a2, id4, slot2) = (a.clone(), id3.clone(), slot.clone());
            confirm(&a.window, &format!("Remove “{label}”?"), consequence, "Remove", true, move || {
                let (b, id5, s5, a3, vid) = (a2.backend.clone(), id4.clone(), slot2.clone(), a2.clone(), id4.clone());
                bg(move || b.remove_slot(&id5, &s5), move |r| match r {
                    Ok(()) => reopen(&a3, &vid),
                    Err(e) => a3.error("Couldn’t remove it", &e),
                });
            });
        });
        r.add_suffix(&rm);
        g.add(&r);
    }
    if v.unlocked {
        let exp = adw::ExpanderRow::builder().title("Add a passphrase").build();
        let p1 = adw::PasswordEntryRow::builder().title("New passphrase").build();
        let p2 = adw::PasswordEntryRow::builder().title("Confirm").build();
        let hint = super::util::strength_label();
        let add = gtk::Button::with_label("Add Passphrase");
        add.add_css_class("suggested-action");
        add.set_sensitive(false);
        // Strength hint and button share one row; the row itself takes no focus.
        let addr = adw::ActionRow::builder().activatable(false).focusable(false).build();
        add.set_valign(gtk::Align::Center);
        addr.add_prefix(&hint);
        addr.add_suffix(&add);
        exp.add_row(&p1);
        exp.add_row(&p2);
        exp.add_row(&addr);
        for e in [&p1, &p2] {
            let (p1c, p2c, h, ad) = (p1.clone(), p2.clone(), hint.clone(), add.clone());
            e.connect_changed(move |_| {
                let (a, b) = (p1c.text(), p2c.text());
                update_strength(&h, &a, &b);
                ad.set_sensitive(!a.is_empty() && a == b);
            });
        }
        let (a, id3) = (app.clone(), id.clone());
        add.connect_clicked(move |_| {
            let s = take_secret(&p1, false);
            p2.set_text("");
            let (b, id4, a2, vid) = (a.backend.clone(), id3.clone(), a.clone(), id3.clone());
            bg(move || b.add_passphrase(&id4, &s), move |r| match r {
                Ok(_) => {
                    a2.toast("Passphrase added");
                    reopen(&a2, &vid);
                }
                Err(e) => a2.error("Couldn’t add the passphrase", &e),
            });
        });
        g.add(&exp);
    }
    page.add(&g);

    // Security
    let g = adw::PreferencesGroup::builder().title("Security").build();
    let pending = data.status.as_ref().map(|s| s.rotation_pending).unwrap_or(false);
    let r = row(
        if pending { "Key rotation not finished" } else { "Rotate keys" },
        if synced {
            "New keys. Revokes every passphrase, recovery key and invite; other devices stop syncing until they enter the new key."
        } else {
            "New keys. Revokes every passphrase and recovery key."
        },
    );
    let b = button(if pending { "Finish…" } else { "Rotate Keys…" });
    b.set_sensitive(v.unlocked);
    let (a, id3) = (app.clone(), id.clone());
    b.connect_clicked(move |_| rotate(&a, &id3, pending));
    r.add_suffix(&b);
    g.add(&r);
    if let Some(st) = &data.status {
        if st.rekeyed() {
            let r = row("Keys rotated on another device", "Enter the new recovery key or passphrase to keep syncing.");
            let b = button("Enter New Key…");
            let (a, id3) = (app.clone(), id.clone());
            b.connect_clicked(move |_| adopt(&a, &id3));
            r.add_suffix(&b);
            g.add(&r);
        }
    }
    page.add(&g);

    // Remove
    let g = adw::PreferencesGroup::new();
    let r = row("Remove from this computer", "Locks the vault and removes it from Vaultage. The encrypted folder stays on disk.");
    let b = button("Remove…");
    b.add_css_class("destructive-action");
    let (a, id3, dd) = (app.clone(), id.clone(), d.clone());
    b.connect_clicked(move |_| {
        dd.close();
        forget(&a, &id3);
    });
    r.add_suffix(&b);
    g.add(&r);
    page.add(&g);
    d.add(&page);
    // Don't land in the name field (typing would rename the vault).
    let d2 = d.clone();
    glib::idle_add_local_once(move || d2.set_focus(None::<&gtk::Widget>));
}

fn pin_from_file(app: &Rc<App>, url: &str, id: &str) {
    let f = gtk::FileFilter::new();
    f.add_suffix("pem");
    f.add_suffix("crt");
    f.add_suffix("cer");
    f.set_name(Some("Certificates (PEM)"));
    let filters = gio::ListStore::new::<gtk::FileFilter>();
    filters.append(&f);
    let d = gtk::FileDialog::builder().title("Pin Server Certificate").accept_label("Pin").filters(&filters).modal(true).build();
    let (a, url, id) = (app.clone(), url.to_string(), id.to_string());
    d.open(Some(&app.window), None::<&gio::Cancellable>, move |r| {
        let Ok(file) = r else { return };
        let Some(path) = file.path() else { return };
        let (b, a2, u, id2) = (a.backend.clone(), a.clone(), url.clone(), id.clone());
        bg(
            move || {
                let pem = std::fs::read_to_string(&path).map_err(|e| crate::logic::UiError::invalid(format!("Can’t read the file: {e}")))?;
                b.set_pin(&u, Some(&pem))
            },
            move |r| match r {
                Ok(()) => {
                    a2.toast("Server certificate pinned");
                    reopen(&a2, &id2);
                }
                Err(e) => a2.error("Couldn’t pin the certificate", &e),
            },
        );
    });
}

/// Remove a vault from this computer (files stay).
pub fn forget(app: &Rc<App>, id: &str) {
    let Some(v) = app.vault(id) else { return };
    let body = format!(
        "The vault is locked and removed from Vaultage’s list. Its encrypted folder stays on disk.{}",
        if v.remote.is_some() { " The copy on the sync server is not affected." } else { " This is a local vault: without its folder, the files are gone." }
    );
    let (a, id) = (app.clone(), id.to_string());
    confirm(&app.window, &format!("Remove “{}” from this computer?", v.name), &body, "Remove", true, move || {
        if let Some(b) = a.browsers.borrow_mut().remove(&id) {
            b.tear_down();
        }
        let (b, id2, a2, name) = (a.backend.clone(), id.clone(), a.clone(), v.name.clone());
        bg(move || b.forget(&id2), move |r| {
            a2.refresh_vaults();
            match r {
                Ok(p) => {
                    let d = adw::AlertDialog::new(Some(&format!("“{name}” was removed")), Some(&format!("Its encrypted folder is still at {}.", p.display())));
                    d.add_response("keep", "Keep Folder");
                    d.add_response("show", "Show Folder");
                    d.set_default_response(Some("keep"));
                    d.set_close_response("keep");
                    let w = a2.window.clone();
                    d.connect_response(None, move |_, r| {
                        if r == "show" {
                            super::util::open_folder(&w, p.parent().unwrap_or(&p));
                        }
                    });
                    d.present(Some(&a2.window));
                }
                Err(e) => a2.error("Couldn’t remove the vault", &e),
            }
        });
    });
}

// ---- attach ----

pub fn attach(app: &Rc<App>, id: &str) {
    let name = app.vault_name(id);
    let s = Rc::new(sheet("Sync with a Server", "Start Syncing", 480));
    let g = adw::PreferencesGroup::builder()
        .description("The server only ever sees encrypted data. While the upload runs, the vault is read-only; if it’s interrupted, choose Retry to continue where it stopped.")
        .build();
    let url = adw::EntryRow::builder().title("Server address (https://…)").input_purpose(gtk::InputPurpose::Url).build();
    let token = adw::PasswordEntryRow::builder().title("Enrollment token (from your server administrator)").build();
    g.add(&url);
    g.add(&token);
    let col = gtk::Box::new(gtk::Orientation::Vertical, 12);
    col.append(&super::util::dim(&format!("Uploads “{name}”, encrypted, with its kept history.")));
    col.append(&g);
    let progress = gtk::ProgressBar::builder().show_text(true).visible(false).build();
    col.append(&progress);
    s.set_body(&col);
    let (act, u2) = (s.action.clone(), url.clone());
    let check = move || act.set_sensitive(text::server_url_problem(&u2.text()).is_none());
    check();
    url.connect_changed(move |_| check());
    let (a, s2, id2) = (app.clone(), s.clone(), id.to_string());
    s.action.connect_clicked(move |_| {
        let tok = Secret::new(&token.text());
        s2.working(true);
        s2.show_error("");
        progress.set_visible(true);
        progress.set_text(Some("Connecting to the server…"));
        // Progress from the vault's activity while it uploads.
        let (pb, a3, id3) = (progress.clone(), a.clone(), id2.clone());
        let timer = glib::timeout_add_local(std::time::Duration::from_millis(400), move || {
            if let Ok(st) = a3.backend.status(&id3) {
                if let Some(act) = st.activity {
                    pb.set_fraction(if act.total == 0 { 0.0 } else { act.done as f64 / act.total as f64 });
                    pb.set_text(Some(&format!("{} · {} of {}", act.label, act.done, act.total)));
                }
            }
            glib::ControlFlow::Continue
        });
        let (b, u, id4, a2, s3, pb2, vid) = (a.backend.clone(), url.text().to_string(), id2.clone(), a.clone(), s2.clone(), progress.clone(), id2.clone());
        bg(move || b.attach(&id4, &u, &tok), move |r| {
            timer.remove();
            match r {
                Ok(()) => {
                    s3.dialog.force_close();
                    a2.toast("Vault is now synced");
                    reopen(&a2, &vid);
                }
                Err(e) => {
                    pb2.set_visible(false);
                    s3.done_working("Retry");
                    s3.show_error(&e.text());
                }
            }
        });
    });
    s.dialog.present(Some(&app.window));
}

// ---- invite ----

pub fn invite(app: &Rc<App>, id: &str) {
    let name = app.vault_name(id);
    let s = Rc::new(sheet("Invite Someone", "Create Invite", 480));
    let g = adw::PreferencesGroup::builder()
        .description("The name appears under Sharing, where you can see whether the invite was used and revoke it. The invite works once, for 24 hours, and gives full read and write access.")
        .build();
    let label = adw::EntryRow::builder().title("For (e.g. Alex, or Work laptop)").build();
    g.add(&label);
    let col = gtk::Box::new(gtk::Orientation::Vertical, 12);
    col.append(&super::util::dim(&format!("Let another person or device join “{name}”.")));
    col.append(&g);
    s.set_body(&col);
    let (a, s2, id2, name2) = (app.clone(), s.clone(), id.to_string(), name.clone());
    s.action.connect_clicked(move |_| {
        s2.working(true);
        s2.show_error("");
        let (b, id3, l, a2, s3, nm, vid) = (a.backend.clone(), id2.clone(), label.text().trim().to_string(), a.clone(), s2.clone(), name2.clone(), id2.clone());
        let l2 = l.clone();
        bg(move || b.invite(&id3, &l), move |r| match r {
            Ok(code) => {
                s3.dialog.set_title("Invite Ready");
                s3.action.set_visible(false);
                s3.cancel.set_visible(false);
                let done = gtk::Button::with_label("Done");
                done.add_css_class("suggested-action");
                let (d, a3) = (s3.dialog.clone(), a2.clone());
                done.connect_clicked(move |_| {
                    d.force_close();
                });
                s3.header.pack_end(&done);
                let col = gtk::Box::new(gtk::Orientation::Vertical, 14);
                col.append(&super::util::dim(&if l2.is_empty() { format!("For “{nm}”") } else { format!("For {l2}") }));
                if let Some(t) = super::util::qr_texture(&code, 6) {
                    let pic = gtk::Picture::for_paintable(&t);
                    pic.set_can_shrink(false);
                    pic.set_halign(gtk::Align::Center);
                    pic.update_property(&[gtk::accessible::Property::Label("Invite QR code")]);
                    col.append(&pic);
                }
                let code_l = gtk::Label::builder().label(code.as_str()).selectable(true).wrap(true).wrap_mode(gtk::pango::WrapMode::Char).build();
                // Pango would add a hyphen where it breaks a line; in a code that reads as part of it.
                let attrs = gtk::pango::AttrList::new();
                attrs.insert(gtk::pango::AttrInt::new_insert_hyphens(false));
                code_l.set_attributes(Some(&attrs));
                code_l.add_css_class("monospace");
                code_l.add_css_class("caption");
                col.append(&code_l);
                let copy = gtk::Button::with_label("Copy");
                copy.set_halign(gtk::Align::Center);
                let c2 = code.clone();
                copy.connect_clicked(move |b| {
                    copy_secret(b, &c2);
                    b.set_label("Copied — clears in 60 s");
                });
                col.append(&copy);
                col.append(&gtk::Label::builder()
                    .label(format!("Works once, within 24 hours. Whoever uses it first can open “{nm}” and read, change or delete every file. Scanning the code keeps it off chats and clipboards; otherwise send it over a channel you trust. On their device: Join Existing Vault → An invite.\n\nOnce used, the line opens nothing. If your recipient is told it was already used, someone else got it first: rotate the vault’s keys. Revoke an unused invite in Vault Settings → Sharing."))
                    .wrap(true)
                    .xalign(0.0)
                    .build());
                s3.set_body(&col);
                reopen(&a3, &vid);
            }
            Err(e) => {
                s3.done_working("Create Invite");
                s3.show_error(&e.text());
            }
        });
    });
    s.dialog.present(Some(&app.window));
}

// ---- rotate ----

pub fn rotate(app: &Rc<App>, id: &str, resume: bool) {
    let name = app.vault_name(id);
    let synced = app.vault(id).map(|v| v.remote.is_some()).unwrap_or(false);
    let s = Rc::new(sheet("Rotate Keys", "Continue", 520));
    s.dialog.set_widget_name(id);
    ROTATING.with(|r| r.borrow_mut().push(id.to_string()));
    let idc = id.to_string();
    s.dialog.connect_closed(move |_| ROTATING.with(|r| r.borrow_mut().retain(|x| *x != idc)));

    let col = gtk::Box::new(gtk::Orientation::Vertical, 14);
    col.append(&super::util::dim(&format!("Give “{name}” new keys and cut off old ones.")));
    let what = adw::PreferencesGroup::builder().title("What Happens").build();
    for (icon, t) in [
        ("action-unavailable-symbolic", format!("Every passphrase, the current recovery key{} stop working.", if synced { ", every invite and every other device" } else { "" })),
        ("emblem-synchronizing-symbolic", "Your other devices pause syncing until the new recovery key or passphrase is entered on each of them.".to_string()),
        ("dialog-warning-symbolic", "Files already on a revoked device stay readable there. Rotation protects changes made from now on.".to_string()),
    ] {
        let r = adw::ActionRow::builder().title(glib::markup_escape_text(&t)).title_lines(0).build();
        r.add_prefix(&gtk::Image::from_icon_name(icon));
        what.add(&r);
    }
    col.append(&what);
    let g = adw::PreferencesGroup::builder().title("New Passphrase").description("Without one, only the new recovery key opens the vault. Next you’ll see the new recovery key. Nothing changes until you confirm you stored it.").build();
    let p1 = adw::PasswordEntryRow::builder().title("New passphrase (optional)").build();
    let p2 = adw::PasswordEntryRow::builder().title("Confirm").build();
    g.add(&p1);
    g.add(&p2);
    let hint = super::util::strength_label();
    col.append(&g);
    col.append(&hint);
    s.set_body(&col);
    for e in [&p1, &p2] {
        let (a1, a2, h, act) = (p1.clone(), p2.clone(), hint.clone(), s.action.clone());
        e.connect_changed(move |_| {
            update_strength(&h, &a1.text(), &a2.text());
            act.set_sensitive(a1.text() == a2.text());
        });
    }

    let prepare = {
        let (a, s, id, name) = (app.clone(), s.clone(), id.to_string(), name.clone());
        Rc::new(move |pass: Option<Secret>| {
            s.working(true);
            s.show_error("");
            let (b, id2, a2, s2, nm) = (a.backend.clone(), id.clone(), a.clone(), s.clone(), name.clone());
            let had_pass = pass.as_ref().map(|p| !p.is_empty()).unwrap_or(false);
            let idw = id2.clone();
            bg(move || b.rotate_prepare(&idw, pass.as_ref()), move |r| match r {
                Ok(key) => {
                    let (a3, s3, id3) = (a2.clone(), s2.clone(), id2.clone());
                    let (a4, s4, id4) = (a2.clone(), s2.clone(), id2.clone());
                    show_key(
                        &s2,
                        &nm,
                        key,
                        KeyView {
                            title: "Save the New Recovery Key".into(),
                            subtitle: "Nothing has changed yet.".into(),
                            message: format!("When you rotate, this key replaces the current recovery key of “{nm}”. Vaultage doesn’t keep a copy."),
                            note: None,
                            done: "Rotate Keys".into(),
                            secondary: Some("Cancel Rotation".into()),
                        },
                        move || {
                            let (b, id5, a5, s5) = (a3.backend.clone(), id3.clone(), a3.clone(), s3.clone());
                            s3.dialog.set_sensitive(false);
                            let idw = id5.clone();
                            bg(move || b.rotate_commit(&idw), move |r| {
                                s5.dialog.set_sensitive(true);
                                match r {
                                    Ok(()) => {
                                        s5.dialog.force_close();
                                        super::util::alert(
                                            &a5.window,
                                            "Keys Rotated",
                                            &format!(
                                                "On each of your other devices, open Vaultage and enter the new recovery key{} when asked. They don’t sync until then.\n\nAnyone you invited before needs a new invite.",
                                                if had_pass { " or the new passphrase" } else { "" }
                                            ),
                                        );
                                        reopen(&a5, &id5);
                                    }
                                    Err(e) => super::util::error(&s5.dialog, "The keys weren’t rotated", &e),
                                }
                            });
                        },
                        Some(Box::new(move || {
                            let (b, id5, a5, s5) = (a4.backend.clone(), id4.clone(), a4.clone(), s4.clone());
                            let idw = id5.clone();
                            bg(move || b.rotate_cancel(&idw), move |r| match r {
                                Ok(()) => {
                                    s5.dialog.force_close();
                                    reopen(&a5, &id5);
                                }
                                Err(e) => super::util::error(&s5.dialog, "The rotation can’t be cancelled", &e),
                            });
                        })),
                    );
                }
                Err(e) => {
                    s2.done_working("Try Again");
                    s2.show_error(&e.text());
                }
            });
        })
    };
    let p = prepare.clone();
    s.action.connect_clicked(move |_| {
        let pass = take_secret(&p1, false);
        p2.set_text("");
        p(Some(pass));
    });
    s.dialog.present(Some(&app.window));
    if resume {
        // A staged rotation: show its recovery key again (prepare with no passphrase returns it).
        prepare(None);
    }
}

// ---- adopt ----

pub fn adopt(app: &Rc<App>, id: &str) {
    let name = app.vault_name(id);
    let s = Rc::new(sheet("Enter the New Key", "Continue", 480));
    s.cancel.set_label("Later");
    let g = adw::PreferencesGroup::builder()
        .description(format!("This vault’s keys were rotated on another device. Until you enter the new recovery key or passphrase, this computer can’t sync “{name}”. Files already here stay readable. Ask whoever rotated the keys if you don’t have them."))
        .build();
    let kind = adw::ComboRow::builder().title("Unlock with").model(&gtk::StringList::new(&["New recovery key", "New passphrase"])).build();
    let secret = adw::PasswordEntryRow::builder().title("Recovery key").build();
    let st = secret.clone();
    kind.connect_selected_notify(move |k| st.set_title(if k.selected() == 0 { "Recovery key" } else { "Passphrase" }));
    g.add(&kind);
    g.add(&secret);
    s.set_body(&g);
    let (a, s2, id2) = (app.clone(), s.clone(), id.to_string());
    let go = Rc::new(move || {
        let k = if kind.selected() == 0 { SlotKind::Recovery } else { SlotKind::Passphrase };
        let sec = take_secret(&secret, k == SlotKind::Recovery);
        if sec.is_empty() {
            return;
        }
        s2.working(true);
        s2.show_error("");
        let (b, id3, a2, s3) = (a.backend.clone(), id2.clone(), a.clone(), s2.clone());
        let idw = id3.clone();
        bg(move || b.adopt_rekey(&idw, k, &sec), move |r| match r {
            Ok(()) => {
                s3.dialog.force_close();
                a2.toast("Syncing again with the new keys");
                reopen(&a2, &id3);
            }
            Err(e) => {
                s3.done_working("Continue");
                s3.show_error(&e.text());
            }
        });
    });
    let g2 = go.clone();
    s.action.connect_clicked(move |_| g2());
    s.dialog.present(Some(&app.window));
}

// ---- app preferences ----

pub fn preferences(app: &Rc<App>) {
    let d = adw::PreferencesDialog::new();
    let page = adw::PreferencesPage::new();
    let p = app.prefs.borrow().clone();
    let g = adw::PreferencesGroup::builder().title("Locking").description("Locking drops the keys from memory. Pending changes stay encrypted and sync after the next unlock.").build();
    const MINUTES: [u32; 8] = [0, 1, 2, 5, 10, 15, 30, 60];
    let labels: Vec<String> = MINUTES.iter().map(|m| if *m == 0 { "Never".into() } else { text::count(*m as u64, "minute") }).collect();
    let refs: Vec<&str> = labels.iter().map(String::as_str).collect();
    let idle = adw::ComboRow::builder().title("Lock after inactivity").model(&gtk::StringList::new(&refs)).build();
    idle.set_selected(MINUTES.iter().position(|m| *m == p.auto_lock_minutes).unwrap_or(4) as u32);
    let screen = adw::SwitchRow::builder().title("Lock when the screen locks or the computer sleeps").active(p.lock_on_screen_lock).build();
    g.add(&idle);
    g.add(&screen);
    page.add(&g);
    let g = adw::PreferencesGroup::builder().title("Files").build();
    let mv = adw::SwitchRow::builder().title("Dropped files move in").subtitle("Delete each original after its encrypted copy is verified. Shift-drag does the opposite.").active(p.import_move).build();
    let th = adw::SwitchRow::builder().title("Thumbnails").subtitle("Decrypted in memory, never cached on disk.").active(p.show_thumbnails).build();
    g.add(&mv);
    g.add(&th);
    page.add(&g);
    d.add(&page);
    let a = app.clone();
    let save = Rc::new(move |f: &dyn Fn(&mut crate::logic::prefs::Prefs)| {
        f(&mut a.prefs.borrow_mut());
        a.apply_prefs();
    });
    let s = save.clone();
    idle.connect_selected_notify(move |c| {
        let m = MINUTES.get(c.selected() as usize).copied().unwrap_or(10);
        s(&|p| p.auto_lock_minutes = m);
    });
    let s = save.clone();
    screen.connect_active_notify(move |w| {
        let on = w.is_active();
        s(&|p| p.lock_on_screen_lock = on);
    });
    let s = save.clone();
    mv.connect_active_notify(move |w| {
        let on = w.is_active();
        s(&|p| p.import_move = on);
    });
    th.connect_active_notify(move |w| {
        let on = w.is_active();
        save(&|p| p.show_thumbnails = on);
    });
    d.present(Some(&app.window));
}

// ---- security posture ----

pub fn posture_needs_attention(app: &App) -> bool {
    !app.posture.attach_denied || !app.posture.core_dumps_off || !app.wayland
}

pub fn posture_popover(app: &Rc<App>) -> gtk::Popover {
    let p = &app.posture;
    let rows: Vec<(&str, bool, String)> = vec![
        (
            "Memory closed to other programs",
            p.attach_denied,
            if p.attach_denied { "Debuggers and same-user programs can’t read Vaultage’s memory (not dumpable)." } else { "Not applied (debug build): programs running as you could read Vaultage’s memory." }.into(),
        ),
        ("Core dumps off", p.core_dumps_off, if p.core_dumps_off { "A crash can’t write memory, including keys, to disk." } else { "A crash could write memory to disk." }.into()),
        (
            "Memory locking",
            p.memory_locked,
            if p.memory_locked { "Key memory can be kept out of swap." } else { "Keys could reach swap. Use encrypted swap or none." }.into(),
        ),
        (
            "Display server",
            app.wayland,
            if app.wayland { "Wayland: other apps can’t read this window or your typing." } else { "X11: any app on this display can read this window and your keystrokes." }.into(),
        ),
        ("No recent files", true, "Vaultage turns off the recently-used list, so imports and exports aren’t recorded.".into()),
        ("Root and the kernel", false, "Can read any memory. Vaultage can’t protect against them.".into()),
    ];
    let attention = posture_needs_attention(app);
    let col = gtk::Box::new(gtk::Orientation::Vertical, 10);
    col.set_margin_top(12);
    col.set_margin_bottom(12);
    col.set_margin_start(12);
    col.set_margin_end(12);
    col.set_width_request(340);
    let h = gtk::Label::builder().label("Security Status").xalign(0.0).build();
    h.add_css_class("heading");
    col.append(&h);
    col.append(&super::util::dim(if attention { "Some protections are missing in this session." } else { "Vaultage’s memory is closed to other programs you run." }));
    for (title, ok, expl) in rows {
        let r = gtk::Box::new(gtk::Orientation::Horizontal, 8);
        let i = gtk::Image::from_icon_name(if ok { "emblem-ok-symbolic" } else { "dialog-warning-symbolic" });
        i.add_css_class(if ok { "success" } else { "warning" });
        i.set_valign(gtk::Align::Start);
        r.append(&i);
        let t = gtk::Box::new(gtk::Orientation::Vertical, 2);
        let tl = gtk::Label::builder().label(title).xalign(0.0).build();
        tl.add_css_class("heading");
        let el = gtk::Label::builder().label(&expl).xalign(0.0).wrap(true).max_width_chars(42).build();
        el.add_css_class("caption");
        el.add_css_class("dim-label");
        t.append(&tl);
        t.append(&el);
        r.append(&t);
        col.append(&r);
    }
    let pop = gtk::Popover::new();
    pop.set_child(Some(&col));
    pop
}

