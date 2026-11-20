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
    entry.grab_focus();
    entry.select_region(0, stem);
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

/// Put a secret (recovery key, invite) on the clipboard, marked for clipboard managers not to keep
/// (`x-kde-passwordManagerHint: secret`), and clear it after 60 s if it is still ours.
pub fn copy_secret(w: &impl IsA<gtk::Widget>, text: &str) {
    let clip = w.as_ref().clipboard();
    let bytes = glib::Bytes::from_owned(zeroize::Zeroizing::new(text.as_bytes().to_vec()));
    let providers = [
        gdk::ContentProvider::for_bytes("text/plain;charset=utf-8", &bytes),
        gdk::ContentProvider::for_bytes("text/plain", &bytes),
        gdk::ContentProvider::for_bytes("UTF8_STRING", &bytes),
        gdk::ContentProvider::for_bytes("x-kde-passwordManagerHint", &glib::Bytes::from_static(b"secret")),
    ];
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
        col.append(body);
        col.append(&self.error);
        let clamp = adw::Clamp::builder().maximum_size(560).child(&col).build();
        let sc = gtk::ScrolledWindow::builder().hscrollbar_policy(gtk::PolicyType::Never).propagate_natural_height(true).child(&clamp).build();
        self.toolbar.set_content(Some(&sc));
    }
    pub fn show_error(&self, text: &str) {
        self.error.set_label(text);
        self.error.set_visible(!text.is_empty());
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
    let l = gtk::Label::builder().xalign(0.0).visible(false).build();
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
        label.set_visible(true);
    } else if !pass.is_empty() {
        label.set_label(s.label());
        label.add_css_class(s.css());
        label.set_visible(true);
    } else {
        label.set_visible(false);
    }
}

pub fn boxed_list() -> gtk::ListBox {
    let l = gtk::ListBox::new();
    l.set_selection_mode(gtk::SelectionMode::None);
    l.add_css_class("boxed-list");
    l
}
