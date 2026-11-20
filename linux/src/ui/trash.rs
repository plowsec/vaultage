//! A vault's Trash: restore, delete permanently, empty.

use std::rc::{Rc, Weak};

use adw::prelude::*;
use vaultage_core::model::basename;
use vaultage_core::vault::TrashItem;

use super::util::{bg, confirm, toast};
use super::App;
use crate::logic::text;

pub struct TrashPage {
    app: Weak<App>,
    pub id: String,
    pub root: adw::ToolbarView,
    list: gtk::ListBox,
    stack: gtk::Stack,
    empty_btn: gtk::Button,
    items: std::cell::RefCell<Vec<TrashItem>>,
}

impl TrashPage {
    pub fn new(app: &Rc<App>, id: &str) -> Rc<TrashPage> {
        let root = adw::ToolbarView::new();
        let header = adw::HeaderBar::new();
        let empty_btn = gtk::Button::with_label("Empty Trash…");
        empty_btn.add_css_class("destructive-action");
        header.pack_end(&empty_btn);
        root.add_top_bar(&header);
        let list = super::util::boxed_list();
        let synced = app.vault(id).map(|v| v.remote.is_some()).unwrap_or(false);
        let note = super::util::dim(if synced {
            "Deleted files from all your devices. Deleting one permanently erases it, with every saved version, everywhere."
        } else {
            "Deleted files. Deleting one permanently erases it, with every saved version."
        });
        let col = gtk::Box::new(gtk::Orientation::Vertical, 12);
        col.set_margin_top(18);
        col.set_margin_bottom(18);
        col.set_margin_start(12);
        col.set_margin_end(12);
        col.append(&note);
        col.append(&list);
        let sc = gtk::ScrolledWindow::builder().child(&adw::Clamp::builder().maximum_size(760).child(&col).build()).vexpand(true).build();
        let stack = gtk::Stack::new();
        stack.add_named(&sc, Some("list"));
        stack.add_named(&adw::StatusPage::builder().icon_name("user-trash-symbolic").title("Trash Is Empty").description("Deleted files show up here until you erase them.").build(), Some("empty"));
        root.set_content(Some(&stack));
        let t = Rc::new(TrashPage { app: Rc::downgrade(app), id: id.into(), root, list, stack, empty_btn, items: Default::default() });
        let me = Rc::downgrade(&t);
        t.empty_btn.connect_clicked(move |_| {
            if let Some(me) = me.upgrade() {
                me.empty();
            }
        });
        t
    }

    pub fn reload(self: &Rc<Self>) {
        let Some(app) = self.app.upgrade() else { return };
        let (b, id, me) = (app.backend.clone(), self.id.clone(), self.clone());
        bg(move || b.trash(&id), move |r| match r {
            Ok(items) => me.show(items),
            Err(e) if e.is_locked() => {}
            Err(e) => {
                if let Some(a) = me.app.upgrade() {
                    a.error("Couldn’t read the Trash", &e);
                }
            }
        });
    }

    fn show(self: &Rc<Self>, items: Vec<TrashItem>) {
        while let Some(c) = self.list.first_child() {
            self.list.remove(&c);
        }
        for t in &items {
            let row = adw::ActionRow::builder()
                .title(glib_escape(basename(&t.path)))
                .subtitle(glib_escape(&format!("{} · deleted {}{} · {}", t.path, text::date(t.deleted_ts), if t.device.is_empty() { String::new() } else { format!(" on {}", t.device) }, text::bytes(t.size))))
                .build();
            row.add_prefix(&gtk::Image::from_icon_name(crate::logic::preview::icon_name(&t.path, false)));
            let restore = gtk::Button::with_label("Restore");
            restore.set_valign(gtk::Align::Center);
            let purge = gtk::Button::from_icon_name("edit-delete-symbolic");
            purge.set_tooltip_text(Some("Delete Permanently…"));
            purge.add_css_class("flat");
            purge.set_valign(gtk::Align::Center);
            row.add_suffix(&restore);
            row.add_suffix(&purge);
            let (me, t2) = (self.clone(), t.clone());
            restore.connect_clicked(move |_| me.restore(&t2));
            let (me, t2) = (self.clone(), t.clone());
            purge.connect_clicked(move |_| me.purge(vec![t2.clone()]));
            self.list.append(&row);
        }
        self.stack.set_visible_child_name(if items.is_empty() { "empty" } else { "list" });
        self.empty_btn.set_sensitive(!items.is_empty());
        *self.items.borrow_mut() = items;
    }

    fn restore(self: &Rc<Self>, t: &TrashItem) {
        let Some(app) = self.app.upgrade() else { return };
        let (b, id, me, entry) = (app.backend.clone(), self.id.clone(), self.clone(), t.id.clone());
        bg(move || b.restore(&id, &entry, None), move |r| {
            let Some(app) = me.app.upgrade() else { return };
            match r {
                Ok(p) => toast(&app.toasts, &format!("Restored to “{p}”")),
                Err(e) => app.error("Couldn’t restore", &e),
            }
            me.reload();
            if let Some(b) = app.browser(&me.id) {
                b.reload();
            }
        });
    }

    fn scope(&self, app: &App) -> &'static str {
        if app.vault(&self.id).map(|v| v.remote.is_some()).unwrap_or(false) {
            "on this computer, on the sync server and on all your other devices"
        } else {
            "on this computer. This vault isn’t synced, so no other copy exists"
        }
    }

    fn purge(self: &Rc<Self>, items: Vec<TrashItem>) {
        let Some(app) = self.app.upgrade() else { return };
        let size: u64 = items.iter().map(|t| t.size).sum();
        let one = items.len() == 1;
        let what = if one { format!("“{}”", basename(&items[0].path)) } else { text::count(items.len() as u64, "item") };
        let synced = app.vault(&self.id).map(|v| v.remote.is_some()).unwrap_or(false);
        let body = format!(
            "{} ({}, with every saved version) will be erased {}.{}\n\nThis can’t be undone.",
            if one { "It" } else { "They" },
            text::bytes(size),
            self.scope(&app),
            if synced { " If another device changed a file in the meantime, that change wins and the file is kept." } else { "" }
        );
        let me = self.clone();
        confirm(&app.window, &format!("Delete {what} permanently?"), &body, "Delete Permanently", true, move || {
            let Some(app) = me.app.upgrade() else { return };
            let ids: Vec<String> = items.iter().map(|t| t.id.clone()).collect();
            let (b, id, me2) = (app.backend.clone(), me.id.clone(), me.clone());
            bg(move || b.purge(&id, &ids), move |r| {
                let Some(app) = me2.app.upgrade() else { return };
                match r {
                    Ok(n) => toast(&app.toasts, &format!("Permanently deleted {}", text::count(n as u64, "item"))),
                    Err(e) => app.error("Couldn’t delete", &e),
                }
                me2.reload();
                if let Some(b) = app.browser(&me2.id) {
                    b.reload();
                }
            });
        });
    }

    fn empty(self: &Rc<Self>) {
        let Some(app) = self.app.upgrade() else { return };
        let items = self.items.borrow().clone();
        if items.is_empty() {
            return;
        }
        let size: u64 = items.iter().map(|t| t.size).sum();
        let synced = app.vault(&self.id).map(|v| v.remote.is_some()).unwrap_or(false);
        let body = format!(
            "{} ({}), with every saved version, will be erased {}.{}\n\nThis can’t be undone.",
            text::count(items.len() as u64, "item"),
            text::bytes(size),
            self.scope(&app),
            if synced { " If another device changed a file in the meantime, that change wins and the file is kept." } else { "" }
        );
        let me = self.clone();
        confirm(&app.window, &format!("Empty the Trash of “{}”?", app.vault_name(&self.id)), &body, "Empty Trash", true, move || {
            let Some(app) = me.app.upgrade() else { return };
            let (b, id, me2) = (app.backend.clone(), me.id.clone(), me.clone());
            bg(move || b.empty_trash(&id), move |r| {
                let Some(app) = me2.app.upgrade() else { return };
                match r {
                    Ok(0) => toast(&app.toasts, "Nothing was erased"),
                    Ok(n) => toast(&app.toasts, &format!("Permanently deleted {}", text::count(n as u64, "item"))),
                    Err(e) => app.error("Couldn’t empty the Trash", &e),
                }
                me2.reload();
                if let Some(b) = app.browser(&me2.id) {
                    b.reload();
                }
            });
        });
    }
}

/// Row titles are Pango markup; file names are not.
pub fn glib_escape(s: &str) -> String {
    gtk::glib::markup_escape_text(s).to_string()
}
