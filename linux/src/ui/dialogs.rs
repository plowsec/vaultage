//! New vault, join, recovery key, versions, move to, shortcuts, about.

use std::cell::{Cell, RefCell};
use std::rc::Rc;

use adw::prelude::*;
use gtk::{gdk, glib};
use vaultage_core::header::SlotKind;
use vaultage_core::model::{basename, parent};
use vaultage_core::vault::{Item, Version};
use zeroize::Zeroizing;

use super::util::{bg, copy_secret, sheet, take_secret, update_strength, Sheet};
use super::App;
use crate::logic::{key_groups, preview, text, UiError};

/// Dialogs with this widget name are closed when vaults lock (they show decrypted data).
pub const CLOSE_ON_LOCK: &str = "vaultage-close-on-lock";

// ---- recovery key ----

pub struct KeyView {
    pub title: String,
    pub subtitle: String,
    pub message: String,
    pub note: Option<String>,
    pub done: String,
    /// Optional second button (e.g. "Cancel Rotation").
    pub secondary: Option<String>,
}

/// Replace a sheet's content with the recovery key. `done` runs on the action button, which is
/// enabled once "I stored it" is ticked. The dialog can't be dismissed otherwise.
pub fn show_key(s: &Rc<Sheet>, vault_name: &str, key: Zeroizing<String>, v: KeyView, done: impl Fn() + 'static, secondary: Option<Box<dyn Fn()>>) {
    let _ = vault_name;
    s.dialog.set_title(&v.title);
    s.dialog.set_can_close(false);
    s.show_error("");
    // Fresh buttons: the old ones still carry the previous step's handlers.
    s.action.set_visible(false);
    s.cancel.set_visible(false);
    let action = gtk::Button::with_label(&v.done);
    action.add_css_class("suggested-action");
    action.set_sensitive(false);
    s.header.pack_end(&action);
    if let (Some(t), Some(f)) = (&v.secondary, secondary) {
        let b = gtk::Button::with_label(t);
        b.connect_clicked(move |_| f());
        s.header.pack_start(&b);
    }
    action.connect_clicked(move |_| done());

    let col = gtk::Box::new(gtk::Orientation::Vertical, 14);
    let head = gtk::Label::builder().label(&v.subtitle).xalign(0.0).wrap(true).build();
    head.add_css_class("title-4");
    col.append(&head);
    col.append(&gtk::Label::builder().label(&v.message).xalign(0.0).wrap(true).build());
    let k = gtk::Label::builder().label(key_groups(&key)).selectable(true).justify(gtk::Justification::Center).wrap(false).build();
    k.add_css_class("monospace");
    k.add_css_class("title-3");
    k.update_property(&[gtk::accessible::Property::Label("Recovery key")]);
    let frame = gtk::Frame::new(None);
    let kb = gtk::Box::new(gtk::Orientation::Vertical, 0);
    kb.set_margin_top(16);
    kb.set_margin_bottom(16);
    kb.append(&k);
    frame.set_child(Some(&kb));
    col.append(&frame);
    let copy = gtk::Button::with_label("Copy");
    copy.set_halign(gtk::Align::Start);
    copy.connect_clicked(move |b| {
        copy_secret(b, &key);
        b.set_label("Copied — clears in 60 s");
        let b = b.clone();
        glib::timeout_add_seconds_local_once(60, move || b.set_label("Copy"));
    });
    col.append(&copy);
    if let Some(n) = &v.note {
        let l = gtk::Label::builder().label(n).xalign(0.0).wrap(true).build();
        l.add_css_class("warning");
        col.append(&l);
    }
    let stored = gtk::CheckButton::with_label("I stored it somewhere safe (a password manager or on paper)");
    col.append(&stored);
    stored.connect_toggled(move |c| action.set_sensitive(c.is_active()));
    s.set_body(&col);
}

// ---- new vault ----

pub fn new_vault(app: &Rc<App>) {
    let s = sheet("New Vault", "Create Vault", 520);
    let intro = super::util::dim("Files in a vault are encrypted on this computer with a key only you hold.");
    let g1 = adw::PreferencesGroup::new();
    let name = adw::EntryRow::builder().title("Name").build();
    let synced = adw::SwitchRow::builder().title("Sync with a server").subtitle("Use the vault on other devices. The server only ever sees encrypted data.").build();
    g1.add(&name);
    g1.add(&synced);
    let g2 = adw::PreferencesGroup::builder().title("Sync Server").visible(false).build();
    let url = adw::EntryRow::builder().title("Server address (https://…)").input_purpose(gtk::InputPurpose::Url).build();
    let token = adw::PasswordEntryRow::builder().title("Enrollment token (from your server administrator)").build();
    g2.add(&url);
    g2.add(&token);
    let url_hint = gtk::Label::builder().xalign(0.0).wrap(true).visible(false).build();
    url_hint.add_css_class("error");
    url_hint.add_css_class("caption");
    let g3 = adw::PreferencesGroup::builder().title("Unlocking").description("The recovery key is always created and shown once.").build();
    let use_pass = adw::SwitchRow::builder().title("Passphrase").subtitle("Works on any device. Needed to join from another device without the recovery key.").active(true).build();
    let pass = adw::PasswordEntryRow::builder().title("Passphrase").build();
    let confirm = adw::PasswordEntryRow::builder().title("Confirm passphrase").build();
    g3.add(&use_pass);
    g3.add(&pass);
    g3.add(&confirm);
    let strength = super::util::strength_label();
    let col = gtk::Box::new(gtk::Orientation::Vertical, 18);
    col.append(&intro);
    col.append(&g1);
    col.append(&g2);
    col.append(&url_hint);
    col.append(&g3);
    col.append(&strength);
    s.set_body(&col);
    let s = Rc::new(s);

    let check = {
        let (name, synced, url, use_pass, pass, confirm, act, url_hint, strength) = (name.clone(), synced.clone(), url.clone(), use_pass.clone(), pass.clone(), confirm.clone(), s.action.clone(), url_hint.clone(), strength.clone());
        Rc::new(move || {
            let up = synced.is_active().then(|| text::server_url_problem(&url.text())).flatten();
            url_hint.set_label(up.unwrap_or(""));
            url_hint.set_visible(up.is_some() && !url.text().is_empty());
            let (p, c) = (pass.text(), confirm.text());
            if use_pass.is_active() {
                update_strength(&strength, &p, &c);
            } else {
                strength.set_visible(false);
            }
            let pass_ok = !use_pass.is_active() || (!p.is_empty() && p == c);
            act.set_sensitive(!name.text().trim().is_empty() && up.is_none() && pass_ok);
        })
    };
    check();
    for e in [name.upcast_ref::<gtk::Editable>(), url.upcast_ref(), pass.upcast_ref(), confirm.upcast_ref()] {
        let c = check.clone();
        e.connect_changed(move |_| c());
    }
    let (c, g2c) = (check.clone(), g2.clone());
    synced.connect_active_notify(move |sw| {
        g2c.set_visible(sw.is_active());
        c();
    });
    let (c, p2, c2) = (check.clone(), pass.clone(), confirm.clone());
    use_pass.connect_active_notify(move |sw| {
        p2.set_visible(sw.is_active());
        c2.set_visible(sw.is_active());
        c();
    });

    let (a, s2, name_f) = (app.clone(), s.clone(), name.clone());
    s.action.connect_clicked(move |_| {
        let nm = name.text().trim().to_string();
        let remote = synced.is_active().then(|| (url.text().trim().to_string(), take_secret(&token, true)));
        let passphrase = use_pass.is_active().then(|| take_secret(&pass, false));
        confirm.set_text("");
        s2.working(true);
        s2.show_error("");
        let (b, a2, s3, nm2) = (a.backend.clone(), a.clone(), s2.clone(), nm.clone());
        let has_pass = passphrase.is_some();
        bg(move || b.create(&nm, remote.as_ref().map(|(u, t)| (u.as_str(), t)), passphrase.as_ref()), move |r| match r {
            Ok(c) => {
                let id = c.id.clone();
                // The vault exists now: show it in the sidebar while the key is on screen.
                a2.added_vault(&id);
                let (a3, s4) = (a2.clone(), s3.clone());
                show_key(
                    &s3,
                    &nm2,
                    c.recovery,
                    KeyView {
                        title: "Save Your Recovery Key".into(),
                        subtitle: format!("“{nm2}” was created."),
                        message: if has_pass && c.warning.is_none() {
                            "This key opens the vault if you forget your passphrase or lose this computer. Vaultage doesn’t keep a copy.".into()
                        } else {
                            "This key is the only way into the vault if this computer is lost or replaced. Vaultage doesn’t keep a copy.".into()
                        },
                        note: c.warning,
                        done: "Done".into(),
                        secondary: None,
                    },
                    move || {
                        s4.dialog.force_close();
                        a3.added_vault(&id);
                    },
                    None,
                );
            }
            Err(e) => {
                s3.done_working("Create Vault");
                s3.show_error(&e.text());
            }
        });
    });
    s.dialog.present(Some(&app.window));
    name_f.grab_focus();
}

// ---- join ----

pub fn join_vault(app: &Rc<App>) {
    let s = sheet("Join Existing Vault", "Join", 520);
    let intro = super::util::dim("Add a synced vault from another device, or one you were invited to.");
    let mode = adw::ComboRow::builder().title("Join with").model(&gtk::StringList::new(&["Server and vault ID", "An invite"])).build();
    let g0 = adw::PreferencesGroup::new();
    g0.add(&mode);
    let name = adw::EntryRow::builder().title("Name on this computer").build();
    g0.add(&name);

    let gs = adw::PreferencesGroup::builder().description("Find the server and vault ID in Vault Settings on the other device.").build();
    let url = adw::EntryRow::builder().title("Server address (https://…)").input_purpose(gtk::InputPurpose::Url).build();
    let vid = adw::EntryRow::builder().title("Vault ID (32 characters)").build();
    let kind = adw::ComboRow::builder().title("Unlock with").model(&gtk::StringList::new(&["Recovery key", "Passphrase"])).build();
    let secret = adw::PasswordEntryRow::builder().title("Recovery key").build();
    gs.add(&url);
    gs.add(&vid);
    gs.add(&kind);
    gs.add(&secret);
    let gi = adw::PreferencesGroup::builder()
        .description("The one-line code the vault’s owner sent you. It works once and gives this computer full access to the vault.")
        .visible(false)
        .build();
    let invite = adw::PasswordEntryRow::builder().title("Invite").build();
    gi.add(&invite);
    let hint = gtk::Label::builder().xalign(0.0).wrap(true).visible(false).build();
    hint.add_css_class("caption");
    hint.add_css_class("error");
    let col = gtk::Box::new(gtk::Orientation::Vertical, 18);
    col.append(&intro);
    col.append(&g0);
    col.append(&gs);
    col.append(&gi);
    col.append(&hint);
    s.set_body(&col);
    let s = Rc::new(s);

    let check = {
        let (mode, url, vid, secret, invite, act, hint) = (mode.clone(), url.clone(), vid.clone(), secret.clone(), invite.clone(), s.action.clone(), hint.clone());
        Rc::new(move || {
            let problem = if mode.selected() == 1 {
                (!invite.text().is_empty()).then(|| text::invite_line_problem(&invite.text())).flatten()
            } else {
                let u = (!url.text().is_empty()).then(|| text::server_url_problem(&url.text())).flatten();
                u.or_else(|| (!vid.text().is_empty()).then(|| text::vault_id_problem(&vid.text())).flatten())
            };
            hint.set_label(problem.unwrap_or(""));
            hint.set_visible(problem.is_some());
            let filled = if mode.selected() == 1 { !invite.text().trim().is_empty() } else { !url.text().is_empty() && !vid.text().is_empty() && !secret.text().is_empty() };
            act.set_sensitive(filled && problem.is_none());
        })
    };
    check();
    for e in [url.upcast_ref::<gtk::Editable>(), vid.upcast_ref(), secret.upcast_ref(), invite.upcast_ref()] {
        let c = check.clone();
        e.connect_changed(move |_| c());
    }
    let (c, gs2, gi2) = (check.clone(), gs.clone(), gi.clone());
    mode.connect_selected_notify(move |m| {
        gs2.set_visible(m.selected() == 0);
        gi2.set_visible(m.selected() == 1);
        c();
    });
    let s_title = secret.clone();
    kind.connect_selected_notify(move |k| s_title.set_title(if k.selected() == 0 { "Recovery key" } else { "Passphrase" }));

    let (a, s2) = (app.clone(), s.clone());
    s.action.connect_clicked(move |_| {
        let nm = name.text().trim().to_string();
        s2.working(true);
        s2.show_error("");
        let (b, a2, s3) = (a.backend.clone(), a.clone(), s2.clone());
        if mode.selected() == 1 {
            let code = take_secret(&invite, true);
            let nm2 = nm.clone();
            bg(move || b.join_invite(&nm, &code), move |r| match r {
                Ok(j) => {
                    let id = j.id.clone();
                    match j.recovery {
                        Some(k) => {
                            a2.added_vault(&id);
                            let label = if nm2.is_empty() { "Vault".to_string() } else { nm2.clone() };
                            let (a3, s4) = (a2.clone(), s3.clone());
                            show_key(
                                &s3,
                                &label,
                                k,
                                KeyView {
                                    title: "Save Your Recovery Key".into(),
                                    subtitle: format!("You joined “{label}”."),
                                    message: "The invite is used up and opens nothing now. This recovery key is your own way into the vault, on this computer or another device. Vaultage doesn’t keep a copy.".into(),
                                    note: Some("Add a passphrase in Vault Settings → Unlock Methods if you’d rather not type the recovery key.".into()),
                                    done: "Done".into(),
                                    secondary: None,
                                },
                                move || {
                                    s4.dialog.force_close();
                                    a3.added_vault(&id);
                                },
                                None,
                            );
                        }
                        None => {
                            s3.dialog.force_close();
                            a2.toast("Vault added");
                            a2.added_vault(&id);
                        }
                    }
                }
                Err(e) => {
                    s3.done_working("Join");
                    s3.show_error(&e.text());
                }
            });
        } else {
            let k = if kind.selected() == 0 { SlotKind::Recovery } else { SlotKind::Passphrase };
            let sec = take_secret(&secret, k == SlotKind::Recovery);
            let (u, v) = (url.text().to_string(), vid.text().to_string());
            bg(move || b.join(&nm, &u, &v, k, &sec), move |r| match r {
                Ok(id) => {
                    s3.dialog.force_close();
                    a2.toast("Vault added. It syncs now.");
                    a2.added_vault(&id);
                }
                Err(e) => {
                    s3.done_working("Join");
                    s3.show_error(&e.text());
                }
            });
        }
    });
    s.dialog.present(Some(&app.window));
}

// ---- move to ----

pub fn move_to(app: &Rc<App>, id: &str, paths: Vec<String>, done: impl Fn(Vec<String>, Option<UiError>) + 'static) {
    let s = sheet("Move To", "Move", 420);
    // The folder list fills in after the dialog opens; a dialog keeps its first size.
    s.dialog.set_content_height(440);
    let list = gtk::ListBox::new();
    list.add_css_class("boxed-list");
    list.set_selection_mode(gtk::SelectionMode::Single);
    let col = gtk::Box::new(gtk::Orientation::Vertical, 12);
    let what = if paths.len() == 1 { format!("“{}”", basename(&paths[0])) } else { format!("{} items", paths.len()) };
    col.append(&super::util::dim(&format!("Choose the folder for {what}.")));
    col.append(&list);
    s.set_body(&col);
    s.action.set_sensitive(false);
    let s = Rc::new(s);
    let folders: Rc<RefCell<Vec<String>>> = Rc::default();
    let act = s.action.clone();
    list.connect_row_selected(move |_, r| act.set_sensitive(r.is_some()));
    let vault_name = app.vault_name(id);
    let (b, id2, l2, f2, ps) = (app.backend.clone(), id.to_string(), list.clone(), folders.clone(), paths.clone());
    bg(move || b.folders(&id2), move |r| {
        let mut all = vec![String::new()];
        all.extend(r.unwrap_or_default().into_iter().filter(|f| !ps.iter().any(|p| f == p || f.starts_with(&format!("{p}/")))));
        for f in &all {
            let depth = if f.is_empty() { 0 } else { f.matches('/').count() + 1 };
            let row = gtk::Box::new(gtk::Orientation::Horizontal, 8);
            row.set_margin_start(12 + 18 * depth as i32);
            row.set_margin_top(8);
            row.set_margin_bottom(8);
            row.append(&gtk::Image::from_icon_name(if f.is_empty() { "drive-harddisk-symbolic" } else { "folder-symbolic" }));
            row.append(&gtk::Label::new(Some(if f.is_empty() { &vault_name } else { basename(f) })));
            l2.append(&row);
        }
        *f2.borrow_mut() = all;
    });
    let (a, s2, id3) = (app.clone(), s.clone(), id.to_string());
    let done = Rc::new(done);
    s.action.connect_clicked(move |_| {
        let Some(r) = list.selected_row() else { return };
        let Some(dir) = folders.borrow().get(r.index() as usize).cloned() else { return };
        s2.dialog.force_close();
        let (b, id, paths, done) = (a.backend.clone(), id3.clone(), paths.clone(), done.clone());
        bg(move || b.move_to(&id, &paths, &dir), move |(moved, err)| done(moved, err));
    });
    s.dialog.present(Some(&app.window));
}

// ---- versions ----

pub fn versions(app: &Rc<App>, id: &str, item: &Item) {
    let Some(entry) = item.id.clone() else { return };
    let dialog = adw::Dialog::builder().title(&format!("Versions of “{}”", item.name)).content_width(760).content_height(520).build();
    dialog.set_widget_name(CLOSE_ON_LOCK);
    let tv = adw::ToolbarView::new();
    let header = adw::HeaderBar::new();
    tv.add_top_bar(&header);
    let list = gtk::ListBox::new();
    list.add_css_class("navigation-sidebar");
    let left = gtk::ScrolledWindow::builder().child(&list).width_request(280).hscrollbar_policy(gtk::PolicyType::Never).build();
    let stack = gtk::Stack::new();
    stack.set_hexpand(true);
    stack.set_vexpand(true);
    let picture = gtk::Picture::builder().content_fit(gtk::ContentFit::Contain).can_shrink(true).build();
    let textv = gtk::TextView::builder().editable(false).monospace(true).cursor_visible(false).wrap_mode(gtk::WrapMode::WordChar).left_margin(12).top_margin(12).right_margin(12).build();
    let info = adw::StatusPage::builder().icon_name(preview::icon_name(&item.name, false)).build();
    info.add_css_class("compact");
    let sp = gtk::Spinner::new();
    sp.start();
    sp.set_halign(gtk::Align::Center);
    sp.set_valign(gtk::Align::Center);
    stack.add_named(&picture, Some("image"));
    stack.add_named(&gtk::ScrolledWindow::builder().child(&textv).build(), Some("text"));
    stack.add_named(&info, Some("info"));
    stack.add_named(&sp, Some("loading"));
    let restore = gtk::Button::with_label("Restore This Version");
    restore.add_css_class("suggested-action");
    restore.set_sensitive(false);
    let prune = gtk::Button::with_label("Delete Older Versions…");
    prune.add_css_class("destructive-action");
    prune.set_sensitive(false);
    let bar = gtk::Box::new(gtk::Orientation::Horizontal, 8);
    bar.set_margin_top(8);
    bar.set_margin_bottom(8);
    bar.set_margin_start(12);
    bar.set_margin_end(12);
    bar.append(&prune);
    let spacer = gtk::Box::new(gtk::Orientation::Horizontal, 0);
    spacer.set_hexpand(true);
    bar.append(&spacer);
    bar.append(&restore);
    let right = gtk::Box::new(gtk::Orientation::Vertical, 0);
    right.append(&stack);
    let paned = gtk::Paned::builder().start_child(&left).end_child(&right).shrink_start_child(false).resize_start_child(false).build();
    tv.set_content(Some(&paned));
    tv.add_bottom_bar(&bar);
    dialog.set_child(Some(&tv));

    let vs: Rc<RefCell<Vec<Version>>> = Rc::default();
    let seq = Rc::new(Cell::new(0u64));
    let load = {
        let (a, id, entry, vs, list, prune) = (app.clone(), id.to_string(), entry.clone(), vs.clone(), list.clone(), prune.clone());
        Rc::new(move || {
            let (b, id2, e2, vs2, l2, p2) = (a.backend.clone(), id.clone(), entry.clone(), vs.clone(), list.clone(), prune.clone());
            bg(move || b.versions(&id2, &e2), move |r| {
                while let Some(c) = l2.first_child() {
                    l2.remove(&c);
                }
                let v = r.unwrap_or_default();
                for ver in &v {
                    let row = gtk::Box::new(gtk::Orientation::Vertical, 2);
                    row.set_margin_top(6);
                    row.set_margin_bottom(6);
                    let mut tags = vec![];
                    if ver.current {
                        tags.push("current");
                    }
                    if ver.deleted {
                        tags.push("deleted");
                    }
                    if ver.pending {
                        tags.push("not yet synced");
                    }
                    let t = gtk::Label::builder().label(format!("{}{}", text::date(ver.ts), if tags.is_empty() { String::new() } else { format!(" · {}", tags.join(", ")) })).xalign(0.0).build();
                    t.add_css_class("heading");
                    let d = gtk::Label::builder()
                        .label(format!("Version {} · {}{}", ver.rev, text::bytes(ver.size), if ver.device.is_empty() { String::new() } else { format!(" · {}", ver.device) }))
                        .xalign(0.0)
                        .build();
                    d.add_css_class("caption");
                    d.add_css_class("dim-label");
                    row.append(&t);
                    row.append(&d);
                    if basename(&ver.path) != basename(&v[0].path) || parent(&ver.path) != parent(&v[0].path) {
                        let p = gtk::Label::builder().label(format!("at {}", ver.path)).xalign(0.0).ellipsize(gtk::pango::EllipsizeMode::Middle).build();
                        p.add_css_class("caption");
                        p.add_css_class("dim-label");
                        row.append(&p);
                    }
                    l2.append(&row);
                }
                p2.set_sensitive(v.len() > 1);
                *vs2.borrow_mut() = v;
                if let Some(r) = l2.row_at_index(0) {
                    l2.select_row(Some(&r));
                }
            });
        })
    };
    load();

    {
        let (a, id, entry, vs, stack, picture, textv, info, restore, seq, name) =
            (app.clone(), id.to_string(), entry.clone(), vs.clone(), stack.clone(), picture.clone(), textv.clone(), info.clone(), restore.clone(), seq.clone(), item.name.clone());
        list.connect_row_selected(move |_, r| {
            picture.set_paintable(None::<&gdk::Paintable>);
            textv.buffer().set_text("");
            let Some(r) = r else { return };
            let Some(ver) = vs.borrow().get(r.index() as usize).cloned() else { return };
            restore.set_sensitive(!ver.current);
            restore.set_label(if ver.deleted { "Restore" } else { "Restore This Version" });
            if ver.deleted || !preview::can_preview(&name, ver.size) {
                info.set_title(if ver.deleted { "Deleted" } else { "No Preview" });
                info.set_description(Some(if ver.deleted { "The file was deleted in this version." } else { "This kind of file can’t be previewed." }));
                stack.set_visible_child_name("info");
                return;
            }
            stack.set_visible_child_name("loading");
            let n = seq.get() + 1;
            seq.set(n);
            let (b, id2, e2, st, pic, tv2, inf, sq, nm) = (a.backend.clone(), id.clone(), entry.clone(), stack.clone(), picture.clone(), textv.clone(), info.clone(), seq.clone(), name.clone());
            bg(move || b.read(&id2, &e2, Some(ver.rev), preview::MAX_PREVIEW), move |r| {
                if sq.get() != n {
                    return;
                }
                match r {
                    Ok(data) => {
                        if preview::guess(&nm) != preview::Guess::Text {
                            if let Ok(t) = gdk::Texture::from_bytes(&glib::Bytes::from_owned(Zeroizing::new(data.to_vec()))) {
                                pic.set_paintable(Some(&t));
                                st.set_visible_child_name("image");
                                return;
                            }
                        }
                        if preview::guess(&nm) == preview::Guess::Text || preview::looks_like_text(&data) {
                            let (mut s, _) = preview::text_of(&data);
                            tv2.buffer().set_text(&s);
                            crate::logic::wipe(&mut s);
                            st.set_visible_child_name("text");
                        } else {
                            inf.set_title("No Preview");
                            inf.set_description(Some("This kind of file can’t be previewed."));
                            st.set_visible_child_name("info");
                        }
                    }
                    Err(e) => {
                        inf.set_title("Can’t Read This Version");
                        inf.set_description(Some(&e.text()));
                        st.set_visible_child_name("info");
                    }
                }
            });
        });
    }
    {
        let (a, id, entry, vs, list, load, d) = (app.clone(), id.to_string(), entry.clone(), vs.clone(), list.clone(), load.clone(), dialog.clone());
        restore.connect_clicked(move |_| {
            let Some(r) = list.selected_row() else { return };
            let Some(ver) = vs.borrow().get(r.index() as usize).cloned() else { return };
            let (b, id2, e2, a2, load, d, id4) = (a.backend.clone(), id.clone(), entry.clone(), a.clone(), load.clone(), d.clone(), id.clone());
            let rev = if ver.deleted { None } else { Some(ver.rev) };
            bg(move || b.restore(&id2, &e2, rev), move |r| match r {
                Ok(p) => {
                    a2.toast(&format!("Restored “{}”", basename(&p)));
                    if let Some(b) = a2.browser(&id4) {
                        b.reload();
                    }
                    load();
                }
                Err(e) => super::util::error(&d, "Couldn’t restore", &e),
            });
        });
    }
    {
        let (a, id, entry, vs, load, d, name) = (app.clone(), id.to_string(), entry.clone(), vs.clone(), load.clone(), dialog.clone(), item.name.clone());
        prune.connect_clicked(move |_| {
            let older = vs.borrow().len().saturating_sub(1) as u64;
            let synced = a.vault(&id).map(|v| v.remote.is_some()).unwrap_or(false);
            let scope = if synced { "on this computer, on the sync server and on all your other devices" } else { "on this computer. This vault isn’t synced, so no other copy exists" };
            let (a2, id2, e2, load, d2) = (a.clone(), id.clone(), entry.clone(), load.clone(), d.clone());
            super::util::confirm(
                &d,
                &format!("Delete {} of “{name}”?", text::count2(older, "older version", "older versions")),
                &format!("Only the current version is kept. The older versions are erased {scope}.\n\nThis can’t be undone."),
                "Delete Older Versions",
                true,
                move || {
                    let (b, id3, e3, load, d3) = (a2.backend.clone(), id2.clone(), e2.clone(), load.clone(), d2.clone());
                    bg(move || b.prune_versions(&id3, &e3), move |r| match r {
                        Ok(()) => load(),
                        Err(e) => super::util::error(&d3, "Couldn’t delete the older versions", &e),
                    });
                },
            );
        });
    }
    dialog.present(Some(&app.window));
}

// ---- shortcuts, about ----

pub fn shortcuts(app: &Rc<App>) {
    let rows: &[(&str, &[(&str, &str)])] = &[
        ("Vaults", &[("<Control>n", "New vault"), ("<Control><Shift>j", "Join existing vault"), ("<Control>l", "Lock this vault"), ("<Control><Shift>l", "Lock all vaults")]),
        (
            "Files",
            &[
                ("<Control>o", "Add files"),
                ("<Control><Shift>n", "New folder"),
                ("F2", "Rename"),
                ("<Control>m", "Move to…"),
                ("Delete", "Move to Trash"),
                ("<Control>e", "Export"),
                ("<Control>i", "Versions"),
                ("<Control>a", "Select all"),
            ],
        ),
        ("Navigation", &[("<Alt>Left", "Back"), ("<Alt>Right", "Forward"), ("<Alt>Up", "Enclosing folder"), ("<Control>f", "Search"), ("F9", "Preview pane"), ("<Control>r", "Sync now")]),
        ("General", &[("<Control>comma", "Preferences"), ("<Control>question", "Keyboard shortcuts"), ("<Control>q", "Quit")]),
    ];
    let mut xml = String::from(r#"<interface><object class="GtkShortcutsWindow" id="w"><property name="modal">1</property><child><object class="GtkShortcutsSection"><property name="section-name">main</property>"#);
    for (title, items) in rows {
        xml += &format!(r#"<child><object class="GtkShortcutsGroup"><property name="title">{}</property>"#, glib::markup_escape_text(title));
        for (accel, what) in items.iter() {
            xml += &format!(
                r#"<child><object class="GtkShortcutsShortcut"><property name="accelerator">{}</property><property name="title">{}</property></object></child>"#,
                glib::markup_escape_text(accel),
                glib::markup_escape_text(what)
            );
        }
        xml += "</object></child>";
    }
    xml += "</object></child></object></interface>";
    let b = gtk::Builder::from_string(&xml);
    #[allow(deprecated)]
    if let Some(w) = b.object::<gtk::ShortcutsWindow>("w") {
        w.set_transient_for(Some(&app.window));
        w.present();
    }
}

pub fn about(app: &Rc<App>) {
    let d = adw::AboutDialog::builder()
        .application_name("Vaultage")
        .application_icon(crate::APP_ID)
        .version(env!("CARGO_PKG_VERSION"))
        .comments("End-to-end-encrypted file vaults, with optional zero-knowledge sync.")
        .license_type(gtk::License::MitX11)
        .build();
    d.present(Some(&app.window));
}

