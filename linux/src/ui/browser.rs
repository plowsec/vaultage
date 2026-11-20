//! An unlocked vault: folders and files (list or grid), search, preview, status bar, banners.
//! Decrypted bytes stay in memory: previews and thumbnails are built from buffers, never files.

use std::cell::{Cell, RefCell};
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::rc::{Rc, Weak};

use adw::prelude::*;
use gtk::{gdk, gio, glib};
use vaultage_core::vault::Item;
use zeroize::Zeroizing;

use super::util::{bg, confirm, toast, toast_action};
use super::{dialogs, App, Sel};
use crate::logic::{self, preview, sort_items, text, Nav, SortKey, Tone, UiError, VaultStatus};

pub struct Browser {
    app: Weak<App>,
    pub id: String,
    pub root: adw::ToolbarView,
    nav: RefCell<Nav>,
    items: RefCell<Vec<Item>>,
    store: gio::ListStore,
    sel: gtk::MultiSelection,
    views: gtk::Stack,
    search: gtk::SearchEntry,
    search_bar: gtk::SearchBar,
    title: adw::WindowTitle,
    pv: PreviewPane,
    status: StatusBar,
    banner: adw::Banner,
    integrity: adw::Banner,
    actions: gio::SimpleActionGroup,
    generation: Cell<Option<u64>>,
    sort: Cell<(SortKey, bool)>,
    thumbs: RefCell<HashMap<String, gdk::Texture>>,
    thumbs_pending: RefCell<HashSet<String>>,
    /// Grid cells waiting for a thumbnail: (key, cell). GTK doesn't rebind a cell whose item object
    /// is unchanged, so the cell is updated directly when its texture arrives.
    thumb_wait: RefCell<Vec<(String, glib::WeakRef<gtk::Box>)>>,
    /// (entry, rev) in the preview pane.
    previewing: RefCell<Option<(String, u64)>>,
    preview_seq: Cell<u64>,
    search_seq: Cell<u64>,
    polling: Cell<bool>,
    closed: Cell<bool>,
    pub trash_count: Cell<usize>,
    last_status: RefCell<Option<VaultStatus>>,
    /// Paths to select after the next reload (new folder, rename, move).
    pending_select: RefCell<Vec<String>>,
}

struct PreviewPane {
    root: gtk::Box,
    stack: gtk::Stack,
    picture: gtk::Picture,
    text: gtk::TextView,
    info: adw::StatusPage,
    name: gtk::Label,
    details: gtk::Label,
    buttons: gtk::Box,
}

struct StatusBar {
    root: gtk::Box,
    icon: gtk::Image,
    spinner: gtk::Spinner,
    label: gtk::Label,
    retry: gtk::Button,
    rekey: gtk::Button,
    activity: gtk::Box,
    activity_label: gtk::Label,
    progress: gtk::ProgressBar,
    summary: gtk::Label,
}

fn obj(it: &Item) -> glib::BoxedAnyObject {
    glib::BoxedAnyObject::new(it.clone())
}

fn item_of(o: &glib::Object) -> Option<Item> {
    o.downcast_ref::<glib::BoxedAnyObject>().map(|b| b.borrow::<Item>().clone())
}

impl Browser {
    pub fn new(app: &Rc<App>, id: &str) -> Rc<Browser> {
        let store = gio::ListStore::new::<glib::BoxedAnyObject>();
        let sel = gtk::MultiSelection::new(Some(store.clone()));
        let prefs = app.prefs.borrow().clone();

        let root = adw::ToolbarView::new();
        let header = adw::HeaderBar::new();
        let title = adw::WindowTitle::new("", "");
        header.set_title_widget(Some(&title));
        let nav_box = gtk::Box::new(gtk::Orientation::Horizontal, 0);
        nav_box.add_css_class("linked");
        for (icon, act, tip) in [("go-previous-symbolic", "browser.back", "Back"), ("go-next-symbolic", "browser.forward", "Forward"), ("go-up-symbolic", "browser.up", "Enclosing Folder")] {
            let b = gtk::Button::from_icon_name(icon);
            b.set_action_name(Some(act));
            b.set_tooltip_text(Some(tip));
            nav_box.append(&b);
        }
        header.pack_start(&nav_box);
        let add = gtk::Button::from_icon_name("list-add-symbolic");
        add.set_tooltip_text(Some("Add Files…"));
        add.set_action_name(Some("browser.import"));
        header.pack_start(&add);

        let menu = gio::Menu::new();
        let s = gio::Menu::new();
        s.append(Some("New Folder…"), Some("browser.new-folder"));
        s.append(Some("Add Files…"), Some("browser.import"));
        s.append(Some("Add Folder…"), Some("browser.import-folder"));
        s.append(Some("Move Files In…"), Some("browser.import-move"));
        menu.append_section(None, &s);
        let s = gio::Menu::new();
        s.append(Some("Select All"), Some("browser.select-all"));
        menu.append_section(None, &s);
        let s = gio::Menu::new();
        s.append(Some("Sync Now"), Some("browser.sync"));
        s.append(Some("Vault Settings"), Some(&format!("app.vault-settings::{id}")));
        s.append(Some("Lock Vault"), Some(&format!("app.lock-vault::{id}")));
        menu.append_section(None, &s);
        let mb = gtk::MenuButton::builder().icon_name("view-more-symbolic").menu_model(&menu).tooltip_text("Vault menu").build();
        header.pack_end(&mb);

        let vm = gio::Menu::new();
        let s = gio::Menu::new();
        s.append(Some("List"), Some("browser.view::list"));
        s.append(Some("Grid"), Some("browser.view::grid"));
        vm.append_section(None, &s);
        let s = gio::Menu::new();
        s.append(Some("Name"), Some("browser.sort::name"));
        s.append(Some("Size"), Some("browser.sort::size"));
        s.append(Some("Modified"), Some("browser.sort::modified"));
        s.append(Some("Descending"), Some("browser.sort-desc"));
        vm.append_section(Some("Sort"), &s);
        let s = gio::Menu::new();
        s.append(Some("Preview Pane"), Some("browser.preview"));
        s.append(Some("Thumbnails"), Some("browser.thumbnails"));
        vm.append_section(None, &s);
        let vb = gtk::MenuButton::builder().icon_name("view-grid-symbolic").menu_model(&vm).tooltip_text("View options").build();
        header.pack_end(&vb);
        let st = gtk::ToggleButton::builder().icon_name("system-search-symbolic").tooltip_text("Search").build();
        header.pack_end(&st);
        root.add_top_bar(&header);

        let search = gtk::SearchEntry::builder().placeholder_text("Search file names in this vault").hexpand(true).build();
        let search_bar = gtk::SearchBar::builder().child(&adw::Clamp::builder().maximum_size(500).child(&search).build()).build();
        search_bar.connect_entry(&search);
        st.bind_property("active", &search_bar, "search-mode-enabled").bidirectional().build();
        root.add_top_bar(&search_bar);
        let banner = adw::Banner::new("");
        root.add_top_bar(&banner);
        let integrity = adw::Banner::new("");
        integrity.set_button_label(Some("Dismiss"));
        integrity.connect_button_clicked(|b| b.set_revealed(false));
        root.add_top_bar(&integrity);

        // Views.
        let list = gtk::ColumnView::new(Some(sel.clone()));
        list.set_enable_rubberband(true);
        list.set_reorderable(false);
        list.add_css_class("data-table");
        let grid = gtk::GridView::new(Some(sel.clone()), None::<gtk::ListItemFactory>);
        grid.set_enable_rubberband(true);
        grid.set_max_columns(12);
        grid.set_min_columns(2);
        let views = gtk::Stack::new();
        let empty = adw::StatusPage::builder().icon_name("folder-symbolic").title("Folder Is Empty").description("Drop files here or choose Add Files. Files are encrypted on this computer before they’re stored.").build();
        views.add_named(&gtk::ScrolledWindow::builder().child(&list).vexpand(true).build(), Some("list"));
        views.add_named(&gtk::ScrolledWindow::builder().child(&grid).vexpand(true).build(), Some("grid"));
        views.add_named(&empty, Some("empty"));
        let noresult = adw::StatusPage::builder().icon_name("edit-find-symbolic").title("No Results").description("No file name in this vault matches.").build();
        views.add_named(&noresult, Some("noresult"));

        let pv = PreviewPane::new();
        let paned = gtk::Paned::builder().orientation(gtk::Orientation::Horizontal).start_child(&views).end_child(&pv.root).resize_start_child(true).resize_end_child(false).shrink_end_child(false).position(700).build();
        pv.root.set_visible(prefs.show_preview);
        root.set_content(Some(&paned));

        let status = StatusBar::new();
        root.add_bottom_bar(&status.root);

        let b = Rc::new(Browser {
            app: Rc::downgrade(app),
            id: id.to_string(),
            root,
            nav: RefCell::new(Nav::default()),
            items: RefCell::new(vec![]),
            store,
            sel,
            views,
            search,
            search_bar,
            title,
            pv,
            status,
            banner,
            integrity,
            actions: gio::SimpleActionGroup::new(),
            generation: Cell::new(None),
            sort: Cell::new((SortKey::Name, true)),
            thumbs: RefCell::new(HashMap::new()),
            thumbs_pending: RefCell::new(HashSet::new()),
            thumb_wait: RefCell::new(Vec::new()),
            previewing: RefCell::new(None),
            preview_seq: Cell::new(0),
            search_seq: Cell::new(0),
            polling: Cell::new(false),
            closed: Cell::new(false),
            trash_count: Cell::new(0),
            last_status: RefCell::new(None),
            pending_select: RefCell::new(vec![]),
        });
        b.search_bar.set_key_capture_widget(Some(&b.root));
        b.setup_list(&list);
        b.setup_grid(&grid);
        b.setup_actions(prefs.grid_view, prefs.show_preview, prefs.show_thumbnails);
        b.setup_drop();
        b.setup_shortcuts();

        let me = Rc::downgrade(&b);
        b.sel.connect_selection_changed(move |_, _, _| {
            if let Some(me) = me.upgrade() {
                me.selection_changed();
            }
        });
        let me = Rc::downgrade(&b);
        list.connect_activate(move |_, pos| {
            if let Some(me) = me.upgrade() {
                me.activate(pos);
            }
        });
        let me = Rc::downgrade(&b);
        grid.connect_activate(move |_, pos| {
            if let Some(me) = me.upgrade() {
                me.activate(pos);
            }
        });
        let me = Rc::downgrade(&b);
        b.search.connect_search_changed(move |_| {
            if let Some(me) = me.upgrade() {
                me.reload();
            }
        });
        let me = Rc::downgrade(&b);
        b.search_bar.connect_search_mode_enabled_notify(move |sb| {
            if let Some(me) = me.upgrade() {
                if !sb.is_search_mode() && !me.search.text().is_empty() {
                    me.search.set_text("");
                }
            }
        });
        let me = Rc::downgrade(&b);
        b.status.retry.connect_clicked(move |_| {
            if let Some(me) = me.upgrade() {
                me.sync_now();
            }
        });
        let me = Rc::downgrade(&b);
        b.status.rekey.connect_clicked(move |_| {
            if let (Some(me), Some(a)) = (me.upgrade(), me.upgrade().and_then(|m| m.app.upgrade())) {
                super::settings::adopt(&a, &me.id);
            }
        });
        let me = Rc::downgrade(&b);
        b.banner.connect_button_clicked(move |_| {
            if let Some(me) = me.upgrade() {
                me.banner_action();
            }
        });
        b.update_title();
        b.selection_changed();
        b
    }

    fn app(&self) -> Option<Rc<App>> {
        self.app.upgrade()
    }

    // ---- views ----

    fn setup_list(self: &Rc<Self>, cv: &gtk::ColumnView) {
        let me = Rc::downgrade(self);
        let name = gtk::SignalListItemFactory::new();
        name.connect_setup(move |_, li| {
            let li = li.downcast_ref::<gtk::ListItem>().unwrap();
            let b = gtk::Box::new(gtk::Orientation::Horizontal, 8);
            let icon = gtk::Image::new();
            let label = gtk::Label::builder().xalign(0.0).ellipsize(gtk::pango::EllipsizeMode::Middle).hexpand(true).build();
            let pend = gtk::Image::from_icon_name("send-to-symbolic");
            pend.add_css_class("dim-label");
            pend.set_tooltip_text(Some("Not yet on the server"));
            b.append(&icon);
            b.append(&label);
            b.append(&pend);
            li.set_child(Some(&b));
            if let Some(me) = me.upgrade() {
                me.attach_context(&b, li);
            }
        });
        let me2 = Rc::downgrade(self);
        name.connect_bind(move |_, li| {
            let li = li.downcast_ref::<gtk::ListItem>().unwrap();
            let (Some(it), Some(b)) = (li.item().and_then(|o| item_of(&o)), li.child().and_downcast::<gtk::Box>()) else { return };
            let icon = b.first_child().and_downcast::<gtk::Image>().unwrap();
            icon.set_icon_name(Some(preview::icon_name(&it.name, it.is_dir)));
            let label = icon.next_sibling().and_downcast::<gtk::Label>().unwrap();
            label.set_label(&it.name);
            // Full path only where it adds something (search results from other folders).
            let searching = me2.upgrade().is_some_and(|m| m.is_searching());
            label.set_tooltip_text(searching.then_some(it.path.as_str()));
            label.next_sibling().unwrap().set_visible(it.pending);
        });
        let col = gtk::ColumnViewColumn::new(Some("Name"), Some(name));
        col.set_expand(true);
        cv.append_column(&col);

        for (title, f) in [("Size", 0u8), ("Modified", 1u8)] {
            let me = Rc::downgrade(self);
            let fac = gtk::SignalListItemFactory::new();
            fac.connect_setup(move |_, li| {
                let li = li.downcast_ref::<gtk::ListItem>().unwrap();
                let l = gtk::Label::builder().xalign(if f == 0 { 1.0 } else { 0.0 }).build();
                l.add_css_class("dim-label");
                if f == 0 {
                    l.add_css_class("numeric");
                }
                li.set_child(Some(&l));
                if let Some(me) = me.upgrade() {
                    me.attach_context(&l, li);
                }
            });
            fac.connect_bind(move |_, li| {
                let li = li.downcast_ref::<gtk::ListItem>().unwrap();
                let (Some(it), Some(l)) = (li.item().and_then(|o| item_of(&o)), li.child().and_downcast::<gtk::Label>()) else { return };
                l.set_label(&match f {
                    0 if it.is_dir => text::count(it.count, "file"),
                    0 => text::bytes(it.size),
                    _ => text::date(it.mtime),
                });
            });
            let col = gtk::ColumnViewColumn::new(Some(title), Some(fac));
            col.set_fixed_width(if f == 0 { 110 } else { 190 });
            cv.append_column(&col);
        }
    }

    fn setup_grid(self: &Rc<Self>, grid: &gtk::GridView) {
        let me = Rc::downgrade(self);
        let fac = gtk::SignalListItemFactory::new();
        fac.connect_setup(move |_, li| {
            let li = li.downcast_ref::<gtk::ListItem>().unwrap();
            let b = gtk::Box::new(gtk::Orientation::Vertical, 6);
            b.set_size_request(120, 140);
            b.set_margin_top(6);
            b.set_margin_bottom(6);
            let pic = gtk::Picture::builder().width_request(96).height_request(96).content_fit(gtk::ContentFit::Contain).can_shrink(true).build();
            let icon = gtk::Image::builder().pixel_size(64).width_request(96).height_request(96).build();
            let l = gtk::Label::builder().wrap(true).wrap_mode(gtk::pango::WrapMode::WordChar).lines(2).ellipsize(gtk::pango::EllipsizeMode::Middle).justify(gtk::Justification::Center).max_width_chars(14).build();
            b.append(&pic);
            b.append(&icon);
            b.append(&l);
            li.set_child(Some(&b));
            if let Some(me) = me.upgrade() {
                me.attach_context(&b, li);
            }
        });
        let me = Rc::downgrade(self);
        fac.connect_bind(move |_, li| {
            let li = li.downcast_ref::<gtk::ListItem>().unwrap();
            let (Some(it), Some(b)) = (li.item().and_then(|o| item_of(&o)), li.child().and_downcast::<gtk::Box>()) else { return };
            let pic = b.first_child().and_downcast::<gtk::Picture>().unwrap();
            let icon = pic.next_sibling().and_downcast::<gtk::Image>().unwrap();
            let l = icon.next_sibling().and_downcast::<gtk::Label>().unwrap();
            l.set_label(&it.name);
            let searching = me.upgrade().is_some_and(|m| m.is_searching());
            b.set_tooltip_text((searching || it.name.chars().count() > 28).then_some(it.path.as_str()));
            icon.set_icon_name(Some(preview::icon_name(&it.name, it.is_dir)));
            let tex = match me.upgrade() {
                Some(me) => {
                    let (key, tex) = me.thumbnail(&it);
                    b.set_widget_name(&key);
                    if tex.is_none() && !key.is_empty() {
                        let mut w = me.thumb_wait.borrow_mut();
                        w.retain(|(_, c)| c.upgrade().is_some_and(|c| c != b));
                        w.push((key, b.downgrade()));
                    }
                    tex
                }
                None => None,
            };
            show_thumb(&b, tex.as_ref());
        });
        grid.set_factory(Some(&fac));
    }

    /// Right-click on an item: select it (unless already in the selection), show the item menu.
    fn attach_context(self: &Rc<Self>, w: &impl IsA<gtk::Widget>, li: &gtk::ListItem) {
        let g = gtk::GestureClick::builder().button(3).build();
        let (me, li) = (Rc::downgrade(self), li.downgrade());
        let w2 = w.clone().upcast::<gtk::Widget>();
        g.connect_pressed(move |g, _, x, y| {
            let (Some(me), Some(li)) = (me.upgrade(), li.upgrade()) else { return };
            let pos = li.position();
            if pos == gtk::INVALID_LIST_POSITION {
                return;
            }
            if !me.sel.is_selected(pos) {
                me.sel.select_item(pos, true);
            }
            let pop = gtk::PopoverMenu::from_model(Some(&me.item_menu()));
            pop.set_parent(&w2);
            pop.set_has_arrow(false);
            pop.set_pointing_to(Some(&gdk::Rectangle::new(x as i32, y as i32, 1, 1)));
            pop.connect_closed(|p| {
                let p = p.clone();
                glib::idle_add_local_once(move || p.unparent());
            });
            pop.popup();
            g.set_state(gtk::EventSequenceState::Claimed);
        });
        w.add_controller(g);
    }

    fn item_menu(&self) -> gio::Menu {
        let m = gio::Menu::new();
        let s = gio::Menu::new();
        s.append(Some("Open"), Some("browser.open"));
        s.append(Some("Versions…"), Some("browser.versions"));
        m.append_section(None, &s);
        let s = gio::Menu::new();
        s.append(Some("Rename…"), Some("browser.rename"));
        s.append(Some("Move To…"), Some("browser.move"));
        m.append_section(None, &s);
        let s = gio::Menu::new();
        s.append(Some("Export…"), Some("browser.export"));
        s.append(Some("Move Out of Vault…"), Some("browser.move-out"));
        m.append_section(None, &s);
        let s = gio::Menu::new();
        s.append(Some("Move to Trash"), Some("browser.delete"));
        m.append_section(None, &s);
        m
    }

    fn setup_actions(self: &Rc<Self>, grid: bool, show_preview: bool, thumbs: bool) {
        let g = &self.actions;
        let add = |name: &str, f: Box<dyn Fn(&Rc<Browser>)>| {
            let act = gio::SimpleAction::new(name, None);
            let me = Rc::downgrade(self);
            act.connect_activate(move |_, _| {
                if let Some(me) = me.upgrade() {
                    f(&me);
                }
            });
            g.add_action(&act);
        };
        add("back", Box::new(|b| {
            if b.nav.borrow_mut().back() {
                b.went();
            }
        }));
        add("forward", Box::new(|b| {
            if b.nav.borrow_mut().forward() {
                b.went();
            }
        }));
        add("up", Box::new(|b| {
            let child = b.nav.borrow_mut().up();
            if let Some(c) = child {
                b.went();
                b.select_after_reload(vec![c]);
            }
        }));
        add("open", Box::new(|b| {
            if let Some(pos) = b.selected_positions().first() {
                b.activate(*pos);
            }
        }));
        add("import", Box::new(|b| b.choose_import(false, false)));
        add("import-folder", Box::new(|b| b.choose_import(true, false)));
        add("import-move", Box::new(|b| b.choose_import(false, true)));
        add("new-folder", Box::new(|b| b.new_folder()));
        add("rename", Box::new(|b| b.rename()));
        add("move", Box::new(|b| b.move_to()));
        add("delete", Box::new(|b| b.delete()));
        add("export", Box::new(|b| b.export(false)));
        add("move-out", Box::new(|b| b.export(true)));
        add("versions", Box::new(|b| {
            if let (Some(a), Some(it)) = (b.app(), b.single_file()) {
                dialogs::versions(&a, &b.id, &it);
            }
        }));
        add("select-all", Box::new(|b| {
            b.sel.select_all();
        }));
        add("sync", Box::new(|b| b.sync_now()));
        add("search", Box::new(|b| {
            b.search_bar.set_search_mode(true);
            b.search.grab_focus();
        }));

        let view = gio::SimpleAction::new_stateful("view", Some(glib::VariantTy::STRING), &(if grid { "grid" } else { "list" }).to_variant());
        let me = Rc::downgrade(self);
        view.connect_activate(move |a, p| {
            let Some(v) = p.and_then(|p| p.get::<String>()) else { return };
            a.set_state(&v.to_variant());
            if let Some(me) = me.upgrade() {
                if let Some(app) = me.app() {
                    app.prefs.borrow_mut().grid_view = v == "grid";
                    app.apply_prefs();
                }
            }
        });
        g.add_action(&view);
        let sort = gio::SimpleAction::new_stateful("sort", Some(glib::VariantTy::STRING), &"name".to_variant());
        let me = Rc::downgrade(self);
        sort.connect_activate(move |a, p| {
            let Some(v) = p.and_then(|p| p.get::<String>()) else { return };
            a.set_state(&v.to_variant());
            if let Some(me) = me.upgrade() {
                let key = match v.as_str() {
                    "size" => SortKey::Size,
                    "modified" => SortKey::Modified,
                    _ => SortKey::Name,
                };
                me.sort.set((key, me.sort.get().1));
                me.resort();
            }
        });
        g.add_action(&sort);
        let desc = gio::SimpleAction::new_stateful("sort-desc", None, &false.to_variant());
        let me = Rc::downgrade(self);
        desc.connect_activate(move |a, _| {
            let on = !a.state().and_then(|s| s.get::<bool>()).unwrap_or(false);
            a.set_state(&on.to_variant());
            if let Some(me) = me.upgrade() {
                me.sort.set((me.sort.get().0, !on));
                me.resort();
            }
        });
        g.add_action(&desc);
        for (name, init) in [("preview", show_preview), ("thumbnails", thumbs)] {
            let act = gio::SimpleAction::new_stateful(name, None, &init.to_variant());
            let me = Rc::downgrade(self);
            let n = name.to_string();
            act.connect_activate(move |a, _| {
                let on = !a.state().and_then(|s| s.get::<bool>()).unwrap_or(false);
                a.set_state(&on.to_variant());
                if let Some(app) = me.upgrade().and_then(|m| m.app()) {
                    if n == "preview" {
                        app.prefs.borrow_mut().show_preview = on;
                    } else {
                        app.prefs.borrow_mut().show_thumbnails = on;
                    }
                    app.apply_prefs();
                }
            });
            g.add_action(&act);
        }
        self.root.insert_action_group("browser", Some(g));
    }

    /// Keys that act on the file list; local so text fields keep them (Delete, Space…).
    fn setup_shortcuts(&self) {
        let sc = gtk::ShortcutController::new();
        sc.set_scope(gtk::ShortcutScope::Local);
        sc.set_propagation_phase(gtk::PropagationPhase::Bubble);
        for (keys, action) in [
            ("Delete|KP_Delete", "browser.delete"),
            ("F2", "browser.rename"),
            ("<Control>o", "browser.import"),
            ("<Control><Shift>n", "browser.new-folder"),
            ("<Control>e", "browser.export"),
            ("<Control>m", "browser.move"),
            ("<Control>i", "browser.versions"),
            ("<Alt>Left|BackSpace", "browser.back"),
            ("<Alt>Right", "browser.forward"),
            ("<Alt>Up", "browser.up"),
            ("<Control>f", "browser.search"),
            ("<Control>r|F5", "browser.sync"),
            ("F9", "browser.preview"),
        ] {
            if let Some(t) = gtk::ShortcutTrigger::parse_string(keys) {
                sc.add_shortcut(gtk::Shortcut::new(Some(t), Some(gtk::NamedAction::new(action))));
            }
        }
        self.root.add_controller(sc);
    }

    /// Files dropped from Files: copy in; a Move drag (Shift) moves in, after a confirmation.
    fn setup_drop(self: &Rc<Self>) {
        let dt = gtk::DropTarget::new(gdk::FileList::static_type(), gdk::DragAction::COPY | gdk::DragAction::MOVE);
        let me = Rc::downgrade(self);
        dt.connect_drop(move |dt, value, _, _| {
            let (Some(me), Ok(list)) = (me.upgrade(), value.get::<gdk::FileList>()) else { return false };
            let paths: Vec<PathBuf> = list.files().iter().filter_map(|f| f.path()).collect();
            if paths.is_empty() {
                return false;
            }
            let shift_move = dt.current_drop().map(|d| d.actions() == gdk::DragAction::MOVE).unwrap_or(false);
            let pref_move = me.app().map(|a| a.prefs.borrow().import_move).unwrap_or(false);
            me.import(paths, shift_move != pref_move, false);
            true
        });
        self.views.add_controller(dt);
    }

    // ---- state ----

    pub fn update_title(&self) {
        let name = self.app().map(|a| a.vault_name(&self.id)).unwrap_or_default();
        let path = self.nav.borrow().path.clone();
        if self.is_searching() {
            self.title.set_title("Search");
            self.title.set_subtitle(&name);
        } else if path.is_empty() {
            self.title.set_title(&name);
            self.title.set_subtitle("");
        } else {
            self.title.set_title(vaultage_core::model::basename(&path));
            self.title.set_subtitle(&format!("{name} / {}", path.replace('/', " / ")));
        }
        let n = self.nav.borrow();
        let set = |a: &str, on: bool| {
            if let Some(act) = self.actions.lookup_action(a).and_downcast::<gio::SimpleAction>() {
                act.set_enabled(on);
            }
        };
        set("back", n.can_back());
        set("forward", n.can_forward());
        set("up", !n.path.is_empty());
    }

    fn is_searching(&self) -> bool {
        !self.search.text().trim().is_empty()
    }

    fn went(self: &Rc<Self>) {
        if self.is_searching() {
            self.search.set_text("");
        }
        self.sel.unselect_all();
        self.update_title();
        self.reload();
    }

    fn selected_positions(&self) -> Vec<u32> {
        (0..self.store.n_items()).filter(|i| self.sel.is_selected(*i)).collect()
    }

    fn selected(&self) -> Vec<Item> {
        let items = self.items.borrow();
        self.selected_positions().into_iter().filter_map(|i| items.get(i as usize).cloned()).collect()
    }

    fn single_file(&self) -> Option<Item> {
        let s = self.selected();
        (s.len() == 1 && !s[0].is_dir).then(|| s[0].clone())
    }

    fn activate(self: &Rc<Self>, pos: u32) {
        let it = self.items.borrow().get(pos as usize).cloned();
        let Some(it) = it else { return };
        if it.is_dir {
            self.nav.borrow_mut().go(&it.path);
            self.went();
        } else {
            self.sel.select_item(pos, true);
            if !self.pv.root.is_visible() {
                if let Some(a) = self.actions.lookup_action("preview") {
                    a.activate(None);
                }
            }
        }
    }

    fn selection_changed(self: &Rc<Self>) {
        let sel = self.selected();
        let any = !sel.is_empty();
        let one = sel.len() == 1;
        let set = |a: &str, on: bool| {
            if let Some(act) = self.actions.lookup_action(a).and_downcast::<gio::SimpleAction>() {
                act.set_enabled(on);
            }
        };
        set("rename", one);
        set("move", any);
        set("delete", any);
        set("export", any);
        set("move-out", any);
        set("open", one);
        set("versions", one && !sel[0].is_dir);
        set("new-folder", !self.is_searching());
        self.show_preview();
    }

    pub fn prefs_changed(self: &Rc<Self>) {
        let Some(app) = self.app() else { return };
        let p = app.prefs.borrow().clone();
        self.pv.root.set_visible(p.show_preview);
        if !p.show_preview {
            self.clear_preview();
        } else {
            self.show_preview();
        }
        if !p.show_thumbnails {
            self.thumbs.borrow_mut().clear();
        }
        self.apply_view();
        // Rebind (thumbnails on/off).
        let n = self.store.n_items();
        self.store.items_changed(0, n, n);
    }

    fn apply_view(&self) {
        let grid = self.app().map(|a| a.prefs.borrow().grid_view).unwrap_or(false);
        let page = if self.items.borrow().is_empty() {
            if self.is_searching() { "noresult" } else { "empty" }
        } else if grid {
            "grid"
        } else {
            "list"
        };
        self.views.set_visible_child_name(page);
    }

    /// Reload the current folder (or search results) from the vault.
    pub fn reload(self: &Rc<Self>) {
        if self.closed.get() {
            return;
        }
        let Some(app) = self.app() else { return };
        let (b, id) = (app.backend.clone(), self.id.clone());
        let q = self.search.text().trim().to_string();
        let path = self.nav.borrow().path.clone();
        let seq = self.search_seq.get() + 1;
        self.search_seq.set(seq);
        let me = self.clone();
        bg(
            move || {
                let items = if q.is_empty() { b.list(&id, &path) } else { b.search(&id, &q).map(|i| (i, 0)) };
                let trash = b.trash(&id).map(|t| t.len()).unwrap_or(0);
                let gen = b.status(&id).map(|s| s.generation).ok();
                (items, trash, gen)
            },
            move |(r, trash, gen)| {
                if me.closed.get() || seq != me.search_seq.get() {
                    return;
                }
                match r {
                    Ok((items, _)) => {
                        if let Some(g) = gen {
                            me.generation.set(Some(g));
                        }
                        let changed = me.trash_count.replace(trash) != trash;
                        me.set_items(items);
                        if changed {
                            if let Some(a) = me.app() {
                                a.rebuild_sidebar();
                            }
                        }
                    }
                    Err(e) if e.is_locked() => {
                        if let Some(a) = me.app() {
                            a.refresh_vaults();
                        }
                    }
                    Err(e) if e.code == "not_found" || e.code == "invalid" => {
                        // Folder gone (renamed/deleted elsewhere): back to the top.
                        me.nav.borrow_mut().go("");
                        me.update_title();
                        me.reload();
                    }
                    Err(e) => me.report("Couldn’t list the folder", &e),
                }
            },
        );
    }

    fn set_items(self: &Rc<Self>, mut items: Vec<Item>) {
        let (key, asc) = self.sort.get();
        sort_items(&mut items, key, asc);
        let keep: HashSet<String> = self.selected().into_iter().map(|i| i.path).collect();
        let pending = std::mem::take(&mut *self.pending_select.borrow_mut());
        let want: HashSet<String> = if pending.is_empty() { keep } else { pending.into_iter().collect() };
        let objs: Vec<glib::BoxedAnyObject> = items.iter().map(obj).collect();
        *self.items.borrow_mut() = items;
        self.store.splice(0, self.store.n_items(), &objs);
        let items = self.items.borrow().clone();
        for (i, it) in items.iter().enumerate() {
            if want.contains(&it.path) {
                self.sel.select_item(i as u32, false);
            }
        }
        self.apply_view();
        self.update_title();
        self.selection_changed();
    }

    fn resort(self: &Rc<Self>) {
        let items = self.items.borrow().clone();
        self.set_items(items);
    }

    fn select_after_reload(&self, paths: Vec<String>) {
        *self.pending_select.borrow_mut() = paths;
    }

    fn report(&self, title: &str, e: &UiError) {
        if e.is_integrity() {
            self.integrity.set_title(&e.text());
            self.integrity.set_revealed(true);
        }
        if let Some(a) = self.app() {
            a.error(title, e);
        }
    }

    /// Once a second: status bar, banners; reload when the vault changed (sync, other device).
    pub fn poll(self: &Rc<Self>) {
        if self.closed.get() || self.polling.replace(true) {
            return;
        }
        let Some(app) = self.app() else { return };
        let (b, id, me) = (app.backend.clone(), self.id.clone(), self.clone());
        bg(move || b.status(&id), move |r| {
            me.polling.set(false);
            if me.closed.get() {
                return;
            }
            match r {
                Ok(st) => {
                    me.show_status(&st);
                    let changed = me.generation.get().is_some_and(|g| g != st.generation);
                    *me.last_status.borrow_mut() = Some(st);
                    if changed {
                        me.reload();
                    }
                }
                Err(e) if e.is_locked() => {
                    if let Some(a) = me.app() {
                        a.refresh_vaults();
                    }
                }
                Err(_) => {}
            }
        });
    }

    fn show_status(&self, st: &VaultStatus) {
        let line = logic::sync_line(st);
        if let Some(act) = self.actions.lookup_action("sync").and_downcast::<gio::SimpleAction>() {
            act.set_enabled(st.synced);
        }
        let s = &self.status;
        s.icon.set_icon_name(Some(line.icon));
        s.icon.set_visible(!line.spinning);
        s.spinner.set_visible(line.spinning);
        s.spinner.set_spinning(line.spinning);
        s.label.set_label(&line.text);
        s.label.set_tooltip_text(Some(&line.text));
        for c in ["warning", "error"] {
            s.label.remove_css_class(c);
            s.icon.remove_css_class(c);
        }
        let css = match line.tone {
            Tone::Warning => Some("warning"),
            Tone::Error => Some("error"),
            Tone::Normal => None,
        };
        if let Some(c) = css {
            s.label.add_css_class(c);
            s.icon.add_css_class(c);
        }
        s.retry.set_visible(line.retry);
        s.rekey.set_visible(line.rekeyed);
        match &st.activity {
            Some(a) => {
                s.activity.set_visible(true);
                s.activity_label.set_label(&format!("{} · {} of {}", a.label, a.done, a.total));
                s.progress.set_fraction(if a.total == 0 { 0.0 } else { a.done as f64 / a.total as f64 });
            }
            None => s.activity.set_visible(false),
        }
        s.summary.set_label(&logic::summary_line(&st.summary, self.trash_count.get()));

        // One banner, most important first.
        let rot_open = super::settings::rotation_dialog_open(&self.id);
        let (text, button) = if st.rekeyed() {
            ("This vault’s keys were rotated on another device. Enter the new recovery key or passphrase to keep syncing.".to_string(), "Enter New Key…")
        } else if st.rotation_pending && !rot_open {
            ("A key rotation was started on this computer and not finished.".to_string(), "Finish…")
        } else if !st.conflicts.is_empty() {
            let n = st.conflicts.len() as u64;
            (format!("{} edited on two devices at once. Both versions were kept: “{}”.", text::count2(n, "file was", "files were"), st.conflicts[0]), "Dismiss")
        } else {
            (String::new(), "")
        };
        if text.is_empty() {
            self.banner.set_revealed(false);
        } else {
            self.banner.set_title(&text);
            self.banner.set_button_label(Some(button));
            self.banner.set_revealed(true);
        }
        if let Some(p) = st.integrity_problem() {
            self.integrity.set_title(&text::sentence(p));
            self.integrity.set_revealed(true);
        }
    }

    fn banner_action(self: &Rc<Self>) {
        let Some(app) = self.app() else { return };
        let st = self.last_status.borrow().clone();
        let Some(st) = st else { return };
        if st.rekeyed() {
            super::settings::adopt(&app, &self.id);
        } else if st.rotation_pending {
            super::settings::rotate(&app, &self.id, true);
        } else if !st.conflicts.is_empty() {
            let (b, id, me) = (app.backend.clone(), self.id.clone(), self.clone());
            bg(move || b.dismiss_conflicts(&id), move |_| me.poll());
        }
    }

    pub fn sync_now(&self) {
        let Some(app) = self.app() else { return };
        let (b, id) = (app.backend.clone(), self.id.clone());
        bg(move || b.sync_now(&id), |_| {});
    }

    /// Drop everything derived from decrypted data (lock).
    pub fn tear_down(&self) {
        self.closed.set(true);
        self.clear_preview();
        self.thumbs.borrow_mut().clear();
        self.store.remove_all();
        self.items.borrow_mut().clear();
        self.search.set_text("");
    }

    // ---- preview ----

    fn clear_preview(&self) {
        *self.previewing.borrow_mut() = None;
        self.preview_seq.set(self.preview_seq.get() + 1);
        self.pv.picture.set_paintable(None::<&gdk::Paintable>);
        self.pv.text.buffer().set_text("");
    }

    fn show_preview(self: &Rc<Self>) {
        let sel = self.selected();
        if !self.pv.root.is_visible() {
            return;
        }
        let pv = &self.pv;
        match sel.as_slice() {
            [] => {
                self.clear_preview();
                pv.stack.set_visible_child_name("empty");
                pv.name.set_label("");
                pv.details.set_label("");
                pv.buttons.set_visible(false);
            }
            [it] if it.is_dir => {
                self.clear_preview();
                pv.info.set_icon_name(Some("folder-symbolic"));
                pv.info.set_title("Folder");
                pv.info.set_description(Some(&format!("{} · {}", text::count(it.count, "file"), text::bytes(it.size))));
                pv.stack.set_visible_child_name("info");
                pv.name.set_label(&it.name);
                pv.details.set_label(&format!("Modified {}", text::date(it.mtime)));
                pv.buttons.set_visible(false);
            }
            [it] => {
                pv.name.set_label(&it.name);
                pv.details.set_label(&format!(
                    "{} · {}\nModified {}\nVersion {}{}",
                    preview::kind_label(&it.name, false),
                    text::bytes(it.size),
                    text::date(it.mtime),
                    it.rev,
                    if it.device.is_empty() { String::new() } else { format!(" · from {}", it.device) }
                ));
                pv.buttons.set_visible(true);
                let key = (it.id.clone().unwrap_or_default(), it.rev);
                if self.previewing.borrow().as_ref() == Some(&key) {
                    return;
                }
                self.clear_preview();
                *self.previewing.borrow_mut() = Some(key.clone());
                if !preview::can_preview(&it.name, it.size) {
                    self.info(it, if it.size > preview::MAX_PREVIEW { "Too large to preview." } else { "No preview for this kind of file. Export it to open it in another app." });
                    return;
                }
                pv.stack.set_visible_child_name("loading");
                let Some(app) = self.app() else { return };
                let (b, id, entry, seq, me, it2) = (app.backend.clone(), self.id.clone(), key.0, self.preview_seq.get(), self.clone(), it.clone());
                bg(move || b.read(&id, &entry, None, preview::MAX_PREVIEW), move |r| {
                    if me.closed.get() || me.preview_seq.get() != seq {
                        return;
                    }
                    match r {
                        Ok(data) => me.show_data(&it2, data),
                        Err(e) => {
                            if e.is_integrity() {
                                me.integrity.set_title(&e.text());
                                me.integrity.set_revealed(true);
                            }
                            me.info(&it2, &e.text());
                        }
                    }
                });
            }
            many => {
                self.clear_preview();
                let size: u64 = many.iter().map(|i| i.size).sum();
                pv.info.set_icon_name(Some("edit-select-all-symbolic"));
                pv.info.set_title(&text::count(many.len() as u64, "item"));
                pv.info.set_description(Some(&text::bytes(size)));
                pv.stack.set_visible_child_name("info");
                pv.name.set_label("");
                pv.details.set_label("");
                pv.buttons.set_visible(false);
            }
        }
    }

    fn info(&self, it: &Item, note: &str) {
        self.pv.info.set_icon_name(Some(preview::icon_name(&it.name, false)));
        self.pv.info.set_title(&preview::kind_label(&it.name, false));
        self.pv.info.set_description(Some(note));
        self.pv.stack.set_visible_child_name("info");
    }

    /// Show decrypted bytes. The buffer is wiped when the texture/text is built.
    fn show_data(&self, it: &Item, data: Zeroizing<Vec<u8>>) {
        let guess = preview::guess(&it.name);
        if data.is_empty() {
            self.info(it, "This file is empty.");
            return;
        }
        if guess != preview::Guess::Text {
            let bytes = glib::Bytes::from_owned(Zeroizing::new(data.to_vec()));
            if let Ok(t) = gdk::Texture::from_bytes(&bytes) {
                self.pv.picture.set_paintable(Some(&t));
                self.pv.stack.set_visible_child_name("image");
                return;
            }
        }
        if guess == preview::Guess::Text || preview::looks_like_text(&data) {
            let (mut s, cut) = preview::text_of(&data);
            if cut {
                s.push_str("\n\n[… preview shows the first 1 MB]");
            }
            self.pv.text.buffer().set_text(&s);
            logic::wipe(&mut s);
            self.pv.stack.set_visible_child_name("text");
            return;
        }
        self.info(it, "No preview for this kind of file. Export it to open it in another app.");
    }

    /// (cache key, texture if ready). An empty key: no thumbnail for this item.
    fn thumbnail(self: &Rc<Self>, it: &Item) -> (String, Option<gdk::Texture>) {
        let show = self.app().map(|a| a.prefs.borrow().show_thumbnails).unwrap_or(false);
        let (Some(entry), Some(app)) = (it.id.clone(), self.app()) else { return (String::new(), None) };
        if it.is_dir || !show || !preview::can_thumbnail(&it.name, it.size) {
            return (String::new(), None);
        }
        let key = format!("{entry}:{}", it.rev);
        if let Some(t) = self.thumbs.borrow().get(&key) {
            return (key, Some(t.clone()));
        }
        if !self.thumbs_pending.borrow_mut().insert(key.clone()) {
            return (key, None);
        }
        let (b, id, me, k2) = (app.backend.clone(), self.id.clone(), self.clone(), key.clone());
        bg(move || b.read(&id, &entry, None, preview::MAX_THUMB), move |r| {
            if me.closed.get() {
                return;
            }
            let Ok(data) = r else { return };
            let bytes = glib::Bytes::from_owned(data);
            let stream = gio::MemoryInputStream::from_bytes(&bytes);
            glib::spawn_future_local(async move {
                let pb = gtk::gdk_pixbuf::Pixbuf::from_stream_at_scale_future(&stream, 192, 192, true).await;
                drop(stream);
                if me.closed.get() {
                    return;
                }
                let Ok(pb) = pb else { return };
                #[allow(deprecated)]
                let tex = gdk::Texture::for_pixbuf(&pb);
                me.thumb_wait.borrow_mut().retain(|(k, c)| {
                    let Some(c) = c.upgrade() else { return false };
                    if *k != key {
                        return true;
                    }
                    if c.widget_name() == key {
                        show_thumb(&c, Some(&tex));
                    }
                    false
                });
                me.thumbs.borrow_mut().insert(key, tex);
            });
        });
        (k2, None)
    }

    // ---- operations ----

    fn dest(&self) -> String {
        if self.is_searching() { String::new() } else { self.nav.borrow().path.clone() }
    }

    fn choose_import(self: &Rc<Self>, folders: bool, move_in: bool) {
        let Some(app) = self.app() else { return };
        let name = app.vault_name(&self.id);
        let d = gtk::FileDialog::builder()
            .title(if move_in { format!("Move Into “{name}”") } else { format!("Add to “{name}”") })
            .accept_label(if move_in { "Move In" } else { "Add" })
            .modal(true)
            .build();
        let me = self.clone();
        let done = move |r: Result<gio::ListModel, glib::Error>| {
            let Ok(list) = r else { return };
            let paths: Vec<PathBuf> = (0..list.n_items()).filter_map(|i| list.item(i).and_downcast::<gio::File>()).filter_map(|f| f.path()).collect();
            if !paths.is_empty() {
                me.import(paths, move_in, false);
            }
        };
        if folders {
            d.select_multiple_folders(Some(&app.window), None::<&gio::Cancellable>, done);
        } else {
            d.open_multiple(Some(&app.window), None::<&gio::Cancellable>, done);
        }
    }

    fn import(self: &Rc<Self>, paths: Vec<PathBuf>, move_in: bool, confirmed: bool) {
        let Some(app) = self.app() else { return };
        if move_in && !confirmed {
            let n = paths.len();
            let what = if n == 1 { format!("“{}”", paths[0].file_name().map(|s| s.to_string_lossy().into_owned()).unwrap_or_default()) } else { format!("{n} items") };
            let me = self.clone();
            confirm(
                &app.window,
                &format!("Move {what} into “{}”?", app.vault_name(&self.id)),
                "Each original is deleted from its current location after its encrypted copy has been verified.",
                "Move into Vault",
                false,
                move || me.import(paths.clone(), true, true),
            );
            return;
        }
        app.busy(true);
        let (b, id, dest, me) = (app.backend.clone(), self.id.clone(), self.dest(), self.clone());
        bg(move || b.import(&id, &paths, &dest, move_in), move |r| {
            let Some(app) = me.app() else { return };
            app.busy(false);
            me.reload();
            match r {
                Ok(rep) => {
                    let (t, warn) = logic::import_summary(&rep, move_in);
                    if warn {
                        let (w, skipped) = (app.window.clone(), rep.skipped.clone());
                        toast_action(&app.toasts, &t, "Details", move || {
                            let mut body = skipped.iter().take(30).cloned().collect::<Vec<_>>().join("\n");
                            if skipped.len() > 30 {
                                body += &format!("\n… and {} more", skipped.len() - 30);
                            }
                            super::util::alert(&w, "Some items were skipped", &body);
                        });
                    } else {
                        toast(&app.toasts, &t);
                    }
                }
                Err(e) => me.report("Couldn’t add the files", &e),
            }
        });
    }

    fn new_folder(self: &Rc<Self>) {
        let Some(app) = self.app() else { return };
        if self.is_searching() {
            return;
        }
        let (b, id, dir, me) = (app.backend.clone(), self.id.clone(), self.dest(), self.clone());
        let b2 = b.clone();
        let (id2, dir2) = (id.clone(), dir.clone());
        bg(move || b2.free_folder_name(&id2, &dir2), move |r| {
            let Some(app) = me.app() else { return };
            let name = r.unwrap_or_else(|_| "untitled folder".into());
            let me2 = me.clone();
            super::util::ask_text(&app.window, "New Folder", "", &name, "Create", move |n| {
                let (b, id, dir, me3) = (b.clone(), id.clone(), dir.clone(), me2.clone());
                bg(move || b.mkdir(&id, &dir, &n), move |r| match r {
                    Ok(p) => {
                        me3.select_after_reload(vec![p]);
                        me3.reload();
                    }
                    Err(e) => me3.report("Can’t create the folder", &e),
                });
            });
        });
    }

    fn rename(self: &Rc<Self>) {
        let sel = self.selected();
        let (Some(app), [it]) = (self.app(), sel.as_slice()) else { return };
        let it = it.clone();
        let me = self.clone();
        let (title, initial) = (format!("Rename “{}”", it.name), it.name.clone());
        super::util::ask_text(&app.window, &title, "", &initial, "Rename", move |n| {
            let (b, id, me2, path, old) = (me.app().unwrap().backend.clone(), me.id.clone(), me.clone(), it.path.clone(), it.name.clone());
            bg(move || b.rename(&id, &path, &n), move |r| match r {
                Ok(p) => {
                    me2.select_after_reload(vec![p]);
                    me2.reload();
                }
                Err(e) => me2.report(&format!("Can’t rename “{old}”"), &e),
            });
        });
    }

    fn move_to(self: &Rc<Self>) {
        let Some(app) = self.app() else { return };
        let paths: Vec<String> = self.selected().into_iter().map(|i| i.path).collect();
        if paths.is_empty() {
            return;
        }
        let me = self.clone();
        dialogs::move_to(&app, &self.id, paths, move |moved, err| {
            me.select_after_reload(moved.clone());
            me.reload();
            let Some(app) = me.app() else { return };
            if let Some(e) = err {
                me.report("Couldn’t move everything", &e);
            } else if !moved.is_empty() {
                toast(&app.toasts, &format!("Moved {}", text::count(moved.len() as u64, "item")));
            }
        });
    }

    fn delete(self: &Rc<Self>) {
        let Some(app) = self.app() else { return };
        let paths: Vec<String> = self.selected().into_iter().map(|i| i.path).collect();
        if paths.is_empty() {
            return;
        }
        let what = if paths.len() == 1 { format!("“{}”", vaultage_core::model::basename(&paths[0])) } else { format!("{} items", paths.len()) };
        let synced = app.vault(&self.id).map(|v| v.remote.is_some()).unwrap_or(false);
        let me = self.clone();
        confirm(
            &app.window,
            &format!("Delete {what}?"),
            &format!("Deleted files go to this vault’s Trash{}. You can restore them from the Trash or from version history.", if synced { " on all your devices" } else { "" }),
            "Delete",
            true,
            move || {
                let (b, id, me2, paths) = (me.app().unwrap().backend.clone(), me.id.clone(), me.clone(), paths.clone());
                bg(move || b.delete(&id, &paths), move |r| {
                    let Some(app) = me2.app() else { return };
                    me2.sel.unselect_all();
                    me2.reload();
                    match r {
                        Ok(n) => {
                            let (a, id) = (app.clone(), me2.id.clone());
                            toast_action(&app.toasts, &format!("Moved {} to the vault’s Trash", text::count(n as u64, "item")), "Show Trash", move || a.select(Sel::Trash(id.clone())));
                        }
                        Err(e) => me2.report("Couldn’t delete", &e),
                    }
                });
            },
        );
    }

    fn export(self: &Rc<Self>, remove: bool) {
        let Some(app) = self.app() else { return };
        let paths: Vec<String> = self.selected().into_iter().map(|i| i.path).collect();
        if paths.is_empty() {
            return;
        }
        let what = if paths.len() == 1 { format!("“{}”", vaultage_core::model::basename(&paths[0])) } else { format!("{} items", paths.len()) };
        let me = self.clone();
        let what2 = what.clone();
        let choose = move || {
            let what = what2.clone();
            let Some(app) = me.app() else { return };
            let d = gtk::FileDialog::builder().title(if remove { "Move Out To" } else { "Export To" }).accept_label(if remove { "Move Out" } else { "Export" }).modal(true).build();
            let (me2, paths, what) = (me.clone(), paths.clone(), what.clone());
            d.select_folder(Some(&app.window), None::<&gio::Cancellable>, move |r| {
                let Ok(dir) = r else { return };
                let Some(dest) = dir.path() else { return };
                let Some(app) = me2.app() else { return };
                app.busy(true);
                let (b, id, me3, dname, dest2) = (app.backend.clone(), me2.id.clone(), me2.clone(), dir.basename().map(|p| p.display().to_string()).unwrap_or_default(), dest.clone());
                let what = what.clone();
                bg(move || b.export(&id, &paths, &dest, remove), move |r| {
                    let Some(app) = me3.app() else { return };
                    app.busy(false);
                    if remove {
                        me3.sel.unselect_all();
                        me3.reload();
                    }
                    match r {
                        Ok(out) => {
                            let w = app.window.clone();
                            // Name what landed on disk ("note (2).txt" when the name was taken).
                            let what = match out.as_slice() {
                                [one] => format!("“{}”", one.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default()),
                                _ => what,
                            };
                            toast_action(&app.toasts, &format!("{} {what} to “{dname}”", if remove { "Moved" } else { "Exported" }), "Open Folder", move || {
                                super::util::open_folder(&w, &dest2);
                            });
                        }
                        Err(e) => me3.report("Couldn’t export", &e),
                    }
                });
            });
        };
        if remove {
            confirm(
                &app.window,
                &format!("Move {what} out of “{}”?", app.vault_name(&self.id)),
                "They will be decrypted into the folder you choose and removed from the vault. The copies on disk are NOT encrypted. Until the vault’s Trash history is gone, they can still be restored here.",
                "Choose Destination…",
                false,
                choose,
            );
        } else {
            choose();
        }
    }
}

impl PreviewPane {
    fn new() -> PreviewPane {
        let root = gtk::Box::new(gtk::Orientation::Vertical, 0);
        root.set_width_request(300);
        root.add_css_class("view");
        let stack = gtk::Stack::new();
        stack.set_vexpand(true);
        stack.add_named(&adw::StatusPage::builder().icon_name("document-open-symbolic").title("No Selection").description("Select a file to preview it. Previews are decrypted in memory only.").build(), Some("empty"));
        let sp = gtk::Spinner::new();
        sp.start();
        sp.set_size_request(32, 32);
        sp.set_halign(gtk::Align::Center);
        sp.set_valign(gtk::Align::Center);
        stack.add_named(&sp, Some("loading"));
        let picture = gtk::Picture::builder().content_fit(gtk::ContentFit::Contain).can_shrink(true).margin_top(12).margin_bottom(12).margin_start(12).margin_end(12).build();
        stack.add_named(&picture, Some("image"));
        let text = gtk::TextView::builder().editable(false).cursor_visible(false).monospace(true).wrap_mode(gtk::WrapMode::WordChar).left_margin(12).right_margin(12).top_margin(12).bottom_margin(12).build();
        stack.add_named(&gtk::ScrolledWindow::builder().child(&text).build(), Some("text"));
        let info = adw::StatusPage::new();
        info.add_css_class("compact");
        stack.add_named(&info, Some("info"));
        root.append(&stack);
        let meta = gtk::Box::new(gtk::Orientation::Vertical, 6);
        meta.set_margin_start(12);
        meta.set_margin_end(12);
        meta.set_margin_bottom(12);
        meta.set_margin_top(6);
        let name = gtk::Label::builder().xalign(0.0).wrap(true).wrap_mode(gtk::pango::WrapMode::WordChar).selectable(false).build();
        name.add_css_class("heading");
        let details = gtk::Label::builder().xalign(0.0).wrap(true).build();
        details.add_css_class("dim-label");
        details.add_css_class("caption");
        let buttons = gtk::Box::new(gtk::Orientation::Horizontal, 6);
        let v = gtk::Button::with_label("Versions…");
        v.set_action_name(Some("browser.versions"));
        let e = gtk::Button::with_label("Export…");
        e.set_action_name(Some("browser.export"));
        buttons.append(&v);
        buttons.append(&e);
        meta.append(&name);
        meta.append(&details);
        meta.append(&buttons);
        root.append(&gtk::Separator::new(gtk::Orientation::Horizontal));
        root.append(&meta);
        PreviewPane { root, stack, picture, text, info, name, details, buttons }
    }
}

impl StatusBar {
    fn new() -> StatusBar {
        let root = gtk::Box::new(gtk::Orientation::Horizontal, 8);
        root.set_margin_start(12);
        root.set_margin_end(12);
        root.set_margin_top(4);
        root.set_margin_bottom(4);
        let icon = gtk::Image::new();
        let spinner = gtk::Spinner::new();
        let label = gtk::Label::builder().xalign(0.0).ellipsize(gtk::pango::EllipsizeMode::End).hexpand(true).build();
        label.add_css_class("caption");
        let retry = gtk::Button::with_label("Retry");
        retry.add_css_class("flat");
        retry.add_css_class("caption");
        let rekey = gtk::Button::with_label("Enter New Key…");
        rekey.add_css_class("flat");
        rekey.add_css_class("caption");
        let activity = gtk::Box::new(gtk::Orientation::Horizontal, 6);
        let activity_label = gtk::Label::builder().ellipsize(gtk::pango::EllipsizeMode::Middle).max_width_chars(36).build();
        activity_label.add_css_class("caption");
        activity_label.add_css_class("dim-label");
        let progress = gtk::ProgressBar::builder().width_request(120).valign(gtk::Align::Center).build();
        activity.append(&activity_label);
        activity.append(&progress);
        activity.set_visible(false);
        let summary = gtk::Label::new(None);
        summary.add_css_class("caption");
        summary.add_css_class("dim-label");
        summary.add_css_class("numeric");
        for w in [icon.upcast_ref::<gtk::Widget>(), spinner.upcast_ref(), label.upcast_ref(), retry.upcast_ref(), rekey.upcast_ref(), activity.upcast_ref(), summary.upcast_ref()] {
            root.append(w);
        }
        retry.set_visible(false);
        rekey.set_visible(false);
        StatusBar { root, icon, spinner, label, retry, rekey, activity, activity_label, progress, summary }
    }
}

/// A grid cell: picture (thumbnail) or icon.
fn show_thumb(cell: &gtk::Box, tex: Option<&gdk::Texture>) {
    let pic = cell.first_child().and_downcast::<gtk::Picture>().unwrap();
    let icon = pic.next_sibling().and_downcast::<gtk::Image>().unwrap();
    pic.set_visible(tex.is_some());
    pic.set_paintable(tex);
    icon.set_visible(tex.is_none());
}
