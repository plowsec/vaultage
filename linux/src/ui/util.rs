//! Small UI helpers: run blocking core calls off the main thread, dialogs, clipboard, QR.

use adw::prelude::*;
use gtk::{gdk, gio, glib};

use crate::logic::UiError;

/// Run `f` on a worker thread, then `done` on the main thread.
pub fn bg<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static, done: impl FnOnce(T) + 'static) {
    glib::spawn_future_local(async move {
        if let Ok(v) = gio::spawn_blocking(f).await {
            done(v);
        }
    });
}

/// Alert with one OK button.
pub fn alert(parent: &impl IsA<gtk::Widget>, title: &str, body: &str) {
    let d = adw::AlertDialog::new(Some(title), Some(body));
    d.add_response("ok", "OK");
    d.set_default_response(Some("ok"));
    d.present(Some(parent));
}

pub fn error(parent: &impl IsA<gtk::Widget>, title: &str, e: &UiError) {
    alert(parent, title, &e.text());
}

/// Confirm, then run `yes`. `destructive` colours the action red.
pub fn confirm(parent: &impl IsA<gtk::Widget>, title: &str, body: &str, action: &str, destructive: bool, yes: impl Fn() + 'static) {
    let d = adw::AlertDialog::new(Some(title), Some(body));
    d.add_response("cancel", "Cancel");
    d.add_response("ok", action);
    d.set_response_appearance("ok", if destructive { adw::ResponseAppearance::Destructive } else { adw::ResponseAppearance::Suggested });
    d.set_default_response(Some(if destructive { "cancel" } else { "ok" }));
    d.set_close_response("cancel");
    d.connect_response(None, move |_, r| {
        if r == "ok" {
            yes();
        }
    });
    d.present(Some(parent));
}

/// Ask for one line of text (rename, new folder). `ok` gets the text; return an error text to keep
/// the dialog open... kept simple: the caller reports errors itself.
pub fn ask_text(parent: &impl IsA<gtk::Widget>, title: &str, body: &str, initial: &str, action: &str, ok: impl Fn(String) + 'static) {
    let d = adw::AlertDialog::new(Some(title), if body.is_empty() { None } else { Some(body) });
    let entry = gtk::Entry::builder().text(initial).activates_default(true).build();
    d.set_extra_child(Some(&entry));
    d.add_response("cancel", "Cancel");
    d.add_response("ok", action);
    d.set_response_appearance("ok", adw::ResponseAppearance::Suggested);
    d.set_default_response(Some("ok"));
    d.set_close_response("cancel");
    let e2 = entry.clone();
    d.connect_response(None, move |_, r| {
        if r == "ok" {
            ok(e2.text().to_string());
        }
    });
    d.present(Some(parent));
    // Select the name without its extension, as Files does.
    let stem = match initial.rfind('.') {
        Some(i) if i > 0 => i as i32,
        _ => -1,
    };
    // After the dialog maps: focusing an entry selects all of it.
    let e3 = entry.clone();
    glib::idle_add_local_once(move || {
        e3.grab_focus();
        e3.select_region(0, stem);
    });
}

pub fn toast(overlay: &adw::ToastOverlay, text: &str) {
    let t = adw::Toast::new(text);
    t.set_timeout(5);
    overlay.add_toast(t);
}

pub fn toast_action(overlay: &adw::ToastOverlay, text: &str, button: &str, f: impl Fn() + 'static) {
    let t = adw::Toast::new(text);
    t.set_timeout(8);
    t.set_button_label(Some(button));
    t.connect_button_clicked(move |_| f());
    overlay.add_toast(t);
}

/// Put a secret (recovery key, invite) on the clipboard and clear it after 60 s if it is still ours.
/// No `x-kde-passwordManagerHint`: GTK4 offered it but served it empty (seen with `wl-paste`;
/// likely GDK wants `type/subtype` names), which managers don't honour.
pub fn copy_secret(w: &impl IsA<gtk::Widget>, text: &str) {
    let clip = w.as_ref().clipboard();
    let bytes = glib::Bytes::from_owned(zeroize::Zeroizing::new(text.as_bytes().to_vec()));
    let providers = [gdk::ContentProvider::for_bytes("text/plain;charset=utf-8", &bytes), gdk::ContentProvider::for_bytes("text/plain", &bytes)];
    let p = gdk::ContentProvider::new_union(&providers);
    clip.set_content(Some(&p)).ok();
    glib::timeout_add_seconds_local_once(60, move || {
        if clip.content().as_ref() == Some(&p) {
            clip.set_content(None::<&gdk::ContentProvider>).ok();
        }
    });
}

/// QR code as a texture, `px` pixels per module, 4-module quiet zone.
pub fn qr_texture(text: &str, px: i32) -> Option<gdk::Texture> {
    let (n, mods) = crate::logic::qr(text)?;
    let side = (n + 8) * px;
    let mut buf = vec![255u8; (side * side * 4) as usize];
    for y in 0..n {
        for x in 0..n {
            if mods[(y * n + x) as usize] {
                for dy in 0..px {
                    for dx in 0..px {
                        let (cx, cy) = ((x + 4) * px + dx, (y + 4) * px + dy);
                        let i = ((cy * side + cx) * 4) as usize;
                        buf[i..i + 3].copy_from_slice(&[0, 0, 0]);
                    }
                }
            }
        }
    }
    let t = gdk::MemoryTexture::new(side, side, gdk::MemoryFormat::R8g8b8a8, &glib::Bytes::from_owned(buf), (side * 4) as usize);
    Some(t.upcast())
}

/// Open a folder in the file manager. Not through gtk::FileLauncher: it goes via the OpenURI
/// portal, which refuses a non-dumpable process.
pub fn open_folder(w: &impl IsA<gtk::Widget>, path: &std::path::Path) {
    let uri = gio::File::for_path(path).uri();
    let ctx = w.as_ref().display().app_launch_context();
    if let Err(e) = gio::AppInfo::launch_default_for_uri(&uri, Some(&ctx)) {
        eprintln!("vaultage: can't open {}: {e}", path.display());
    }
}

/// The app icon (256 px PNG embedded at build time).
pub fn app_icon() -> Option<gdk::Texture> {
    gdk::Texture::from_bytes(&glib::Bytes::from_static(include_bytes!("../../data/local.vaultage.app.png"))).ok()
}

/// A label for secondary text.
pub fn dim(text: &str) -> gtk::Label {
    let l = gtk::Label::builder().label(text).wrap(true).xalign(0.0).build();
    l.add_css_class("dim-label");
    l
}

pub fn pill(label: &str, suggested: bool) -> gtk::Button {
    let b = gtk::Button::with_label(label);
    b.add_css_class("pill");
    if suggested {
        b.add_css_class("suggested-action");
    }
    b.set_halign(gtk::Align::Center);
    b
}

/// A dialog with a header bar holding Cancel (start) and an action button (end).
pub struct Sheet {
    pub dialog: adw::Dialog,
    pub header: adw::HeaderBar,
    pub cancel: gtk::Button,
    pub action: gtk::Button,
    pub toolbar: adw::ToolbarView,
    pub error: gtk::Label,
}

pub fn sheet(title: &str, action: &str, width: i32) -> Sheet {
    let dialog = adw::Dialog::builder().title(title).content_width(width).build();
    let header = adw::HeaderBar::builder().show_end_title_buttons(false).show_start_title_buttons(false).build();
    let cancel = gtk::Button::with_label("Cancel");
    let action_b = gtk::Button::with_label(action);
    action_b.add_css_class("suggested-action");
    header.pack_start(&cancel);
    header.pack_end(&action_b);
    let toolbar = adw::ToolbarView::new();
    toolbar.add_top_bar(&header);
    dialog.set_child(Some(&toolbar));
    let d2 = dialog.clone();
    cancel.connect_clicked(move |_| {
        d2.close();
    });
    let error = gtk::Label::builder().wrap(true).xalign(0.0).visible(false).build();
    error.add_css_class("error");
    Sheet { dialog, header, cancel, action: action_b, toolbar, error }
}

impl Sheet {
    /// Content in a scrolled, clamped column with the error label at the bottom.
    pub fn set_body(&self, body: &impl IsA<gtk::Widget>) {
        let col = gtk::Box::new(gtk::Orientation::Vertical, 18);
        col.set_margin_top(12);
        col.set_margin_bottom(24);
        col.set_margin_start(12);
        col.set_margin_end(12);
        // Error first: a dialog doesn't grow after it is shown, so text at the bottom would hide.
        col.append(&self.error);
        col.append(body);
        let clamp = adw::Clamp::builder().maximum_size(560).child(&col).build();
        let sc = gtk::ScrolledWindow::builder().hscrollbar_policy(gtk::PolicyType::Never).propagate_natural_height(true).child(&clamp).build();
        self.toolbar.set_content(Some(&sc));
        // Enter in any field triggers the action button, when it's enabled.
        enter_activates(body.as_ref(), &self.action);
        // Start in the first field, so typing goes there.
        if let Some(e) = first_entry(body.as_ref()) {
            self.dialog.set_focus(Some(&e));
        }
        self.fit();
    }
    /// An open dialog keeps its size: grow it to its content (up to the window).
    fn fit(&self) {
        let (Some(sc), true) = (self.toolbar.content(), self.dialog.is_mapped()) else { return };
        let Some(inner) = sc.downcast_ref::<gtk::ScrolledWindow>().and_then(|s| s.child()) else { return };
        let w = self.dialog.width().max(320);
        let (_, nat, _, _) = inner.measure(gtk::Orientation::Vertical, w);
        let (_, head, _, _) = self.header.measure(gtk::Orientation::Vertical, w);
        let max = self.dialog.root().map(|r| r.height() - 48).unwrap_or(nat + head);
        self.dialog.set_content_height((nat + head).min(max).max(self.dialog.height()));
    }
    pub fn show_error(&self, text: &str) {
        self.error.set_label(text);
        self.error.set_visible(!text.is_empty());
        self.fit();
    }
    /// Disable inputs while working; the action button shows a spinner.
    pub fn working(&self, on: bool) {
        self.action.set_sensitive(!on);
        self.cancel.set_sensitive(!on);
        if on {
            let s = gtk::Spinner::new();
            s.start();
            self.action.set_child(Some(&s));
        }
    }
    pub fn done_working(&self, label: &str) {
        self.cancel.set_sensitive(true);
        self.action.set_sensitive(true);
        self.action.set_label(label);
    }
}

fn enter_activates(w: &gtk::Widget, action: &gtk::Button) {
    if let Some(e) = w.downcast_ref::<adw::EntryRow>() {
        let a = action.clone();
        e.connect_entry_activated(move |_| {
            if a.is_sensitive() && a.is_visible() {
                a.emit_clicked();
            }
        });
        return;
    }
    let mut c = w.first_child();
    while let Some(x) = c {
        enter_activates(&x, action);
        c = x.next_sibling();
    }
}

fn first_entry(w: &gtk::Widget) -> Option<gtk::Widget> {
    if w.is::<adw::EntryRow>() {
        return Some(w.clone());
    }
    let mut c = w.first_child();
    while let Some(x) = c {
        if let Some(e) = first_entry(&x) {
            return Some(e);
        }
        c = x.next_sibling();
    }
    None
}

/// Take a secret out of a password row and clear the row.
pub fn take_secret(row: &adw::PasswordEntryRow, trim: bool) -> crate::logic::Secret {
    let mut s = row.text().to_string();
    let out = if trim { crate::logic::Secret::trimmed(&s) } else { crate::logic::Secret::new(&s) };
    crate::logic::wipe(&mut s);
    row.set_text("");
    out
}

/// Strength hint under a new passphrase.
pub fn strength_label() -> gtk::Label {
    // Always visible (blank when there's nothing to say): the dialog keeps the height it opened with.
    let l = gtk::Label::builder().xalign(0.0).label("\u{a0}").build();
    l.add_css_class("caption");
    l
}

pub fn update_strength(label: &gtk::Label, pass: &str, confirm: &str) {
    let s = crate::logic::text::Strength::of(pass);
    let mismatch = !confirm.is_empty() && confirm != pass;
    for c in ["success", "warning", "error"] {
        label.remove_css_class(c);
    }
    if mismatch {
        label.set_label("Passphrases don’t match");
        label.add_css_class("error");
    } else if !pass.is_empty() {
        label.set_label(s.label());
        label.add_css_class(s.css());
    } else {
        label.set_label("\u{a0}");
    }
}

pub fn boxed_list() -> gtk::ListBox {
    let l = gtk::ListBox::new();
    l.set_selection_mode(gtk::SelectionMode::None);
    l.add_css_class("boxed-list");
    l
}
