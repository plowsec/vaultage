//! GTK4 + libadwaita front end. One window: vault list (sidebar) and the selected vault (content).

mod browser;
mod dialogs;
mod session;
mod settings;
mod trash;
mod unlock;
pub mod util;

use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use std::rc::Rc;
use std::sync::Arc;
use std::time::Instant;

use adw::prelude::*;
use gtk::{gdk, gio, glib};
use vaultage_core::harden::Posture;
use vaultage_core::manager::VaultInfo;

use crate::logic::policy::{LockPolicy, LockReason};
use crate::logic::prefs::Prefs;
use crate::logic::{Backend, UiError};
use util::bg;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Sel {
    Vault(String),
    Trash(String),
}

impl Sel {
    pub fn id(&self) -> &str {
        match self {
            Sel::Vault(id) | Sel::Trash(id) => id,
        }
    }
}

pub struct App {
    pub gtk_app: adw::Application,
    pub backend: Arc<Backend>,
    pub posture: Posture,
    pub wayland: bool,
    pub prefs: RefCell<Prefs>,
    pub policy: RefCell<LockPolicy>,
    pub window: adw::ApplicationWindow,
    pub toasts: adw::ToastOverlay,
    split: adw::NavigationSplitView,
    sidebar: gtk::ListBox,
    rows: RefCell<Vec<Sel>>,
    rebuilding: Cell<bool>,
    pub vaults: RefCell<Vec<VaultInfo>>,
    pub selection: RefCell<Option<Sel>>,
    /// What the content pane shows now: (selection, unlocked).
    shown: RefCell<Option<(Option<Sel>, bool)>>,
    content: adw::NavigationPage,
    pub browsers: RefCell<HashMap<String, Rc<browser::Browser>>>,
    /// Imports/exports running: idle lock waits.
    pub busy: Cell<u32>,
    tick: Cell<u64>,
    refreshing: Cell<bool>,
    unlock_page: RefCell<Option<(String, Rc<unlock::UnlockPage>)>>,
    trash_page: RefCell<Option<Rc<trash::TrashPage>>>,
}

pub fn run(posture: Posture) -> glib::ExitCode {
    let gtk_app = adw::Application::builder().application_id(crate::APP_ID).build();
    let posture = Rc::new(posture);
    gtk_app.connect_activate(move |a| {
        if let Some(w) = a.active_window() {
            w.present();
            return;
        }
        start(a, (*posture).clone());
    });
    gtk_app.run()
}

fn start(gtk_app: &adw::Application, posture: Posture) {
    // No recently-used list: file choosers would otherwise record what was imported/exported.
    if let Some(s) = gtk::Settings::default() {
        s.set_gtk_recent_files_enabled(false);
        s.set_gtk_recent_files_max_age(0);
    }
    gtk::Window::set_default_icon_name(crate::APP_ID);
    let backend = match Backend::open(None) {
        Ok(b) => Arc::new(b),
        Err(e) => {
            let w = adw::ApplicationWindow::builder().application(gtk_app).default_width(480).default_height(300).build();
            let page = adw::StatusPage::builder().icon_name("dialog-error-symbolic").title("Vaultage can’t start").description(e.text()).build();
            let tv = adw::ToolbarView::new();
            tv.add_top_bar(&adw::HeaderBar::new());
            tv.set_content(Some(&page));
            w.set_content(Some(&tv));
            w.present();
            return;
        }
    };
    let prefs = Prefs::load();
    let policy = LockPolicy::new(prefs.auto_lock_minutes, prefs.lock_on_screen_lock);
    let wayland = gdk::Display::default().map(|d| d.type_().name().contains("Wayland")).unwrap_or(false);

    let window = adw::ApplicationWindow::builder().application(gtk_app).title("Vaultage").default_width(1120).default_height(720).width_request(360).height_request(300).build();
    let toasts = adw::ToastOverlay::new();
    let split = adw::NavigationSplitView::new();
    split.set_min_sidebar_width(220.0);
    split.set_max_sidebar_width(300.0);
    toasts.set_child(Some(&split));
    window.set_content(Some(&toasts));
    let bp = adw::Breakpoint::new(adw::BreakpointCondition::parse("max-width: 640sp").unwrap());
    bp.add_setter(&split, "collapsed", Some(&true.to_value()));
    window.add_breakpoint(bp);

    let sidebar = gtk::ListBox::new();
    sidebar.add_css_class("navigation-sidebar");
    let content = adw::NavigationPage::builder().title("Vaultage").tag("content").build();

    let app = Rc::new(App {
        gtk_app: gtk_app.clone(),
        backend,
        posture,
        wayland,
        prefs: RefCell::new(prefs),
        policy: RefCell::new(policy),
        window: window.clone(),
        toasts,
        split: split.clone(),
        sidebar: sidebar.clone(),
        rows: RefCell::new(vec![]),
        rebuilding: Cell::new(false),
        vaults: RefCell::new(vec![]),
        selection: RefCell::new(None),
        shown: RefCell::new(None),
        content: content.clone(),
        browsers: RefCell::new(HashMap::new()),
        busy: Cell::new(0),
        tick: Cell::new(0),
        refreshing: Cell::new(false),
        unlock_page: RefCell::new(None),
        trash_page: RefCell::new(None),
    });

    split.set_sidebar(Some(&build_sidebar(&app)));
    split.set_content(Some(&content));
    setup_actions(&app);
    track_activity(&app);
    session::watch(&app);

    let a = app.clone();
    sidebar.connect_row_selected(move |_, row| {
        if a.rebuilding.get() {
            return;
        }
        let Some(row) = row else { return };
        let sel = a.rows.borrow().get(row.index() as usize).cloned();
        if let Some(sel) = sel {
            a.select(sel);
            a.split.set_show_content(true);
        }
    });

    let a = app.clone();
    gtk_app.connect_shutdown(move |_| {
        // Quit: drop every key, stop sync threads.
        a.tear_down_all();
        a.backend.lock_all();
    });

    let a = app.clone();
    glib::timeout_add_seconds_local(1, move || {
        a.on_tick();
        glib::ControlFlow::Continue
    });

    window.present();
    app.refresh_vaults();
}

fn build_sidebar(app: &Rc<App>) -> adw::NavigationPage {
    let header = adw::HeaderBar::new();
    let add = gtk::MenuButton::builder().icon_name("list-add-symbolic").tooltip_text("Add a vault").build();
    let m = gio::Menu::new();
    m.append(Some("New Vault…"), Some("app.new-vault"));
    m.append(Some("Join Existing Vault…"), Some("app.join-vault"));
    add.set_menu_model(Some(&m));
    header.pack_start(&add);
    let menu = gtk::MenuButton::builder().icon_name("open-menu-symbolic").tooltip_text("Main menu").primary(true).build();
    let mm = gio::Menu::new();
    let s1 = gio::Menu::new();
    s1.append(Some("Lock All Vaults"), Some("app.lock-all"));
    mm.append_section(None, &s1);
    let s2 = gio::Menu::new();
    s2.append(Some("Preferences"), Some("app.preferences"));
    s2.append(Some("Keyboard Shortcuts"), Some("app.shortcuts"));
    s2.append(Some("About Vaultage"), Some("app.about"));
    mm.append_section(None, &s2);
    menu.set_menu_model(Some(&mm));
    header.pack_end(&menu);

    let scroller = gtk::ScrolledWindow::builder().hscrollbar_policy(gtk::PolicyType::Never).vexpand(true).child(&app.sidebar).build();
    let tv = adw::ToolbarView::new();
    tv.add_top_bar(&header);
    tv.set_content(Some(&scroller));

    // Security posture, as on the Mac.
    let attention = settings::posture_needs_attention(app);
    let pb = gtk::MenuButton::new();
    let inner = gtk::Box::new(gtk::Orientation::Horizontal, 6);
    let icon = gtk::Image::from_icon_name(if attention { "dialog-warning-symbolic" } else { "security-high-symbolic" });
    icon.add_css_class(if attention { "warning" } else { "success" });
    inner.append(&icon);
    inner.append(&gtk::Label::new(Some(if attention { "Check" } else { "Protected" })));
    pb.set_child(Some(&inner));
    pb.add_css_class("flat");
    pb.set_tooltip_text(Some("Security status"));
    pb.set_popover(Some(&settings::posture_popover(app)));
    let bar = gtk::Box::new(gtk::Orientation::Horizontal, 0);
    bar.set_margin_start(6);
    bar.set_margin_end(6);
    bar.set_margin_top(4);
    bar.set_margin_bottom(4);
    bar.append(&pb);
    tv.add_bottom_bar(&bar);

    // Right-click on a vault: lock, settings, remove.
    let a = app.clone();
    let g = gtk::GestureClick::builder().button(3).build();
    g.connect_pressed(move |g, _, x, y| {
        let Some(row) = a.sidebar.row_at_y(y as i32) else { return };
        let sel = a.rows.borrow().get(row.index() as usize).cloned();
        let Some(Sel::Vault(id)) = sel else { return };
        a.sidebar.select_row(Some(&row));
        let unlocked = a.vault(&id).map(|v| v.unlocked).unwrap_or(false);
        let m = gio::Menu::new();
        if unlocked {
            m.append(Some("Lock"), Some(&format!("app.lock-vault::{id}")));
        }
        m.append(Some("Vault Settings"), Some(&format!("app.vault-settings::{id}")));
        m.append(Some("Remove from This Computer…"), Some(&format!("app.forget-vault::{id}")));
        let pop = gtk::PopoverMenu::from_model(Some(&m));
        pop.set_parent(&a.sidebar);
        pop.set_has_arrow(false);
        pop.set_pointing_to(Some(&gdk::Rectangle::new(x as i32, y as i32, 1, 1)));
        pop.connect_closed(|p| {
            let p = p.clone();
            glib::idle_add_local_once(move || p.unparent());
        });
        pop.popup();
        g.set_state(gtk::EventSequenceState::Claimed);
    });
    app.sidebar.add_controller(g);

    adw::NavigationPage::builder().title("Vaultage").child(&tv).build()
}

fn setup_actions(app: &Rc<App>) {
    let ga = &app.gtk_app;
    let add = |name: &str, accels: &[&str], f: Box<dyn Fn()>| {
        let act = gio::SimpleAction::new(name, None);
        act.connect_activate(move |_, _| f());
        ga.add_action(&act);
        if !accels.is_empty() {
            ga.set_accels_for_action(&format!("app.{name}"), accels);
        }
    };
    let a = app.clone();
    add("new-vault", &["<Control>n"], Box::new(move || dialogs::new_vault(&a)));
    let a = app.clone();
    add("join-vault", &["<Control><Shift>j"], Box::new(move || dialogs::join_vault(&a)));
    let a = app.clone();
    add("lock-all", &["<Control><Shift>l"], Box::new(move || a.lock_all(LockReason::User)));
    let a = app.clone();
    add("preferences", &["<Control>comma"], Box::new(move || settings::preferences(&a)));
    let a = app.clone();
    add("shortcuts", &["<Control>question"], Box::new(move || dialogs::shortcuts(&a)));
    let a = app.clone();
    add("about", &[], Box::new(move || dialogs::about(&a)));
    let a = app.clone();
    add("quit", &["<Control>q"], Box::new(move || a.window.close()));
    let a = app.clone();
    add("lock-vault-current", &["<Control>l"], Box::new(move || {
        if let Some(s) = a.selection.borrow().clone() {
            a.lock_vault(s.id());
        }
    }));

    let with_id = |name: &str, f: Box<dyn Fn(String)>| {
        let act = gio::SimpleAction::new(name, Some(glib::VariantTy::STRING));
        act.connect_activate(move |_, p| {
            if let Some(id) = p.and_then(|p| p.get::<String>()) {
                f(id);
            }
        });
        ga.add_action(&act);
    };
    let a = app.clone();
    with_id("lock-vault", Box::new(move |id| a.lock_vault(&id)));
    let a = app.clone();
    with_id("vault-settings", Box::new(move |id| settings::vault_settings(&a, &id)));
    let a = app.clone();
    with_id("forget-vault", Box::new(move |id| settings::forget(&a, &id)));
}

/// Input in our window counts as activity for the idle lock.
fn track_activity(app: &Rc<App>) {
    let note = {
        let a = app.clone();
        move || a.policy.borrow_mut().note_activity(Instant::now())
    };
    let k = gtk::EventControllerKey::new();
    k.set_propagation_phase(gtk::PropagationPhase::Capture);
    let n = note.clone();
    k.connect_key_pressed(move |_, _, _, _| {
        n();
        glib::Propagation::Proceed
    });
    app.window.add_controller(k);
    let c = gtk::GestureClick::new();
    c.set_button(0);
    c.set_propagation_phase(gtk::PropagationPhase::Capture);
    let n = note.clone();
    c.connect_pressed(move |_, _, _, _| n());
    app.window.add_controller(c);
    let m = gtk::EventControllerMotion::new();
    m.set_propagation_phase(gtk::PropagationPhase::Capture);
    let n = note.clone();
    m.connect_motion(move |_, _, _| n());
    app.window.add_controller(m);
    let s = gtk::EventControllerScroll::new(gtk::EventControllerScrollFlags::BOTH_AXES);
    s.set_propagation_phase(gtk::PropagationPhase::Capture);
    s.connect_scroll(move |_, _, _| {
        note();
        glib::Propagation::Proceed
    });
    app.window.add_controller(s);
}

impl App {
    pub fn vault(&self, id: &str) -> Option<VaultInfo> {
        self.vaults.borrow().iter().find(|v| v.id == id).cloned()
    }

    pub fn vault_name(&self, id: &str) -> String {
        self.vault(id).map(|v| v.name).unwrap_or_else(|| "Vault".into())
    }

    pub fn toast(&self, text: &str) {
        util::toast(&self.toasts, text);
    }

    pub fn error(&self, title: &str, e: &UiError) {
        util::error(&self.window, title, e);
    }

    pub fn busy(&self, on: bool) {
        self.busy.set(if on { self.busy.get() + 1 } else { self.busy.get().saturating_sub(1) });
    }

    fn on_tick(self: &Rc<Self>) {
        let t = self.tick.get() + 1;
        self.tick.set(t);
        let browsers: Vec<Rc<browser::Browser>> = self.browsers.borrow().values().cloned().collect();
        for b in browsers {
            b.poll();
        }
        if t % 10 == 0 {
            self.refresh_vaults();
        }
        let open = !self.browsers.borrow().is_empty();
        let due = self.policy.borrow_mut().idle_due(Instant::now(), self.busy.get() > 0, open);
        if due {
            self.lock_all(LockReason::Idle);
        }
    }

    /// Reload the vault list from the core, then sessions, sidebar and content.
    pub fn refresh_vaults(self: &Rc<Self>) {
        if self.refreshing.replace(true) {
            return;
        }
        let b = self.backend.clone();
        let a = self.clone();
        bg(move || b.vaults(), move |list| {
            a.refreshing.set(false);
            a.apply_vaults(list);
        });
    }

    fn apply_vaults(self: &Rc<Self>, list: Vec<VaultInfo>) {
        // Sessions follow lock state.
        let unlocked: Vec<String> = list.iter().filter(|v| v.unlocked).map(|v| v.id.clone()).collect();
        let stale: Vec<String> = self.browsers.borrow().keys().filter(|id| !unlocked.contains(id)).cloned().collect();
        for id in stale {
            if let Some(b) = self.browsers.borrow_mut().remove(&id) {
                b.tear_down();
            }
        }
        for id in &unlocked {
            if !self.browsers.borrow().contains_key(id) {
                let b = browser::Browser::new(self, id);
                self.browsers.borrow_mut().insert(id.clone(), b.clone());
                b.reload();
            }
        }
        *self.vaults.borrow_mut() = list;
        // Selection still valid?
        let sel = self.selection.borrow().clone();
        let valid = match &sel {
            Some(Sel::Vault(id)) => self.vault(id).is_some(),
            Some(Sel::Trash(id)) => self.browsers.borrow().contains_key(id),
            None => false,
        };
        if !valid {
            let next = match &sel {
                Some(Sel::Trash(id)) if self.vault(id).is_some() => Some(Sel::Vault(id.clone())),
                _ => self.vaults.borrow().first().map(|v| Sel::Vault(v.id.clone())),
            };
            *self.selection.borrow_mut() = next;
        }
        self.rebuild_sidebar();
        self.show_content();
        for b in self.browsers.borrow().values() {
            b.update_title();
        }
    }

    fn rebuild_sidebar(&self) {
        self.rebuilding.set(true);
        while let Some(c) = self.sidebar.first_child() {
            self.sidebar.remove(&c);
        }
        let mut rows = vec![];
        let sel = self.selection.borrow().clone();
        let mut select_row = None;
        for v in self.vaults.borrow().iter() {
            let b = gtk::Box::new(gtk::Orientation::Horizontal, 10);
            let icon = gtk::Image::from_icon_name(if v.unlocked { "folder-open-symbolic" } else { "system-lock-screen-symbolic" });
            b.append(&icon);
            let l = gtk::Label::builder().label(&v.name).xalign(0.0).hexpand(true).ellipsize(gtk::pango::EllipsizeMode::End).build();
            b.append(&l);
            if v.missing {
                let m = gtk::Image::from_icon_name("dialog-warning-symbolic");
                m.set_tooltip_text(Some("The vault’s folder is missing or unreadable"));
                b.append(&m);
            } else if v.remote.is_some() {
                let s = gtk::Image::from_icon_name("emblem-synchronizing-symbolic");
                s.add_css_class("dim-label");
                s.set_tooltip_text(Some("Synced"));
                b.append(&s);
            }
            let row = gtk::ListBoxRow::builder().child(&b).build();
            row.update_property(&[gtk::accessible::Property::Label(&format!("{}{}", v.name, if v.unlocked { "" } else { ", locked" }))]);
            self.sidebar.append(&row);
            let me = Sel::Vault(v.id.clone());
            if sel.as_ref() == Some(&me) {
                select_row = Some(row.clone());
            }
            rows.push(me);
            if v.unlocked {
                let tb = gtk::Box::new(gtk::Orientation::Horizontal, 10);
                tb.set_margin_start(24);
                tb.append(&gtk::Image::from_icon_name("user-trash-symbolic"));
                tb.append(&gtk::Label::builder().label("Trash").xalign(0.0).hexpand(true).build());
                let n = self.browsers.borrow().get(&v.id).map(|b| b.trash_count.get()).unwrap_or(0);
                if n > 0 {
                    let c = gtk::Label::new(Some(&n.to_string()));
                    c.add_css_class("dim-label");
                    tb.append(&c);
                }
                let trow = gtk::ListBoxRow::builder().child(&tb).build();
                self.sidebar.append(&trow);
                let me = Sel::Trash(v.id.clone());
                if sel.as_ref() == Some(&me) {
                    select_row = Some(trow.clone());
                }
                rows.push(me);
            }
        }
        *self.rows.borrow_mut() = rows;
        self.sidebar.select_row(select_row.as_ref());
        self.rebuilding.set(false);
    }

    pub fn select(self: &Rc<Self>, sel: Sel) {
        if self.selection.borrow().as_ref() == Some(&sel) {
            return;
        }
        *self.selection.borrow_mut() = Some(sel);
        self.show_content();
        if let Some(Sel::Trash(id)) = self.selection.borrow().clone() {
            if let Some(t) = self.trash_page.borrow().as_ref() {
                if t.id == id {
                    t.reload();
                }
            }
        }
        self.rebuild_sidebar();
    }

    /// Put the right page in the content pane, unless it is already there.
    fn show_content(self: &Rc<Self>) {
        let sel = self.selection.borrow().clone();
        let unlocked = sel.as_ref().and_then(|s| self.vault(s.id())).map(|v| v.unlocked).unwrap_or(false);
        let key = (sel.clone(), unlocked);
        if self.shown.borrow().as_ref() == Some(&key) {
            return;
        }
        *self.shown.borrow_mut() = Some(key);
        *self.trash_page.borrow_mut() = None;
        let (title, child): (String, gtk::Widget) = match &sel {
            None => ("Vaultage".into(), self.empty_page().upcast()),
            Some(Sel::Vault(id)) if unlocked => {
                *self.unlock_page.borrow_mut() = None;
                let b = self.browsers.borrow().get(id).cloned();
                match b {
                    Some(b) => (self.vault_name(id), b.root.clone().upcast()),
                    None => (self.vault_name(id), self.empty_page().upcast()),
                }
            }
            Some(Sel::Vault(id)) => {
                let v = self.vault(id);
                match v {
                    Some(v) => {
                        let p = unlock::UnlockPage::new(self, &v);
                        let w = p.root.clone();
                        *self.unlock_page.borrow_mut() = Some((id.clone(), p.clone()));
                        p.focus();
                        (v.name.clone(), w.upcast())
                    }
                    None => ("Vaultage".into(), self.empty_page().upcast()),
                }
            }
            Some(Sel::Trash(id)) => {
                let t = trash::TrashPage::new(self, id);
                let w = t.root.clone();
                *self.trash_page.borrow_mut() = Some(t.clone());
                t.reload();
                (format!("Trash — {}", self.vault_name(id)), w.upcast())
            }
        };
        self.content.set_title(&title);
        self.content.set_child(Some(&child));
    }

    /// Re-show the content even if the selection didn't change (after unlock, lock).
    pub fn reshow(self: &Rc<Self>) {
        *self.shown.borrow_mut() = None;
        self.show_content();
    }

    fn empty_page(self: &Rc<Self>) -> adw::ToolbarView {
        let tv = adw::ToolbarView::new();
        tv.add_top_bar(&adw::HeaderBar::new());
        let col = gtk::Box::new(gtk::Orientation::Vertical, 12);
        col.set_halign(gtk::Align::Center);
        let n = util::pill("New Vault…", true);
        n.set_action_name(Some("app.new-vault"));
        let j = util::pill("Join Existing Vault…", false);
        j.set_action_name(Some("app.join-vault"));
        col.append(&n);
        col.append(&j);
        let page = adw::StatusPage::builder()
            .title("No Vaults")
            .description("A vault keeps files encrypted on this computer with a key only you hold. Create one, or join one from another device.")
            .child(&col)
            .build();
        // The icon ships inside the binary, so it shows before install too.
        page.set_paintable(util::app_icon().as_ref());
        tv.set_content(Some(&page));
        tv
    }

    pub fn lock_vault(self: &Rc<Self>, id: &str) {
        if let Some(b) = self.browsers.borrow_mut().remove(id) {
            b.tear_down();
        }
        let b = self.backend.clone();
        let a = self.clone();
        let id = id.to_string();
        bg(move || b.lock(&id), move |_| {
            a.refresh_vaults();
        });
    }

    fn tear_down_all(&self) {
        let all: Vec<_> = self.browsers.borrow_mut().drain().map(|(_, b)| b).collect();
        for b in all {
            b.tear_down();
        }
    }

    /// Lock every vault now (subject to the policy for screen lock / suspend).
    pub fn lock_all(self: &Rc<Self>, reason: LockReason) {
        if !self.policy.borrow().event_due(reason) {
            return;
        }
        let had = !self.browsers.borrow().is_empty();
        self.tear_down_all();
        // Close dialogs that show decrypted data (versions). Not a recovery key still to be saved.
        for _ in 0..8 {
            match self.window.visible_dialog() {
                Some(d) if d.widget_name() == dialogs::CLOSE_ON_LOCK => {
                    d.force_close();
                }
                _ => break,
            }
        }
        let b = self.backend.clone();
        let a = self.clone();
        bg(move || b.lock_all(), move |_| {
            a.refresh_vaults();
            if had && reason == LockReason::Idle {
                a.toast("Vaults locked after inactivity");
            }
        });
    }

    pub fn apply_prefs(&self) {
        let p = self.prefs.borrow().clone();
        {
            let mut pol = self.policy.borrow_mut();
            pol.idle_minutes = p.auto_lock_minutes;
            pol.on_screen_lock = p.lock_on_screen_lock;
        }
        if let Err(e) = p.save() {
            self.toast(&format!("Preferences not saved: {e}"));
        }
        for b in self.browsers.borrow().values() {
            b.prefs_changed();
        }
    }

    /// After create / join: show the new vault.
    pub fn added_vault(self: &Rc<Self>, id: &str) {
        *self.selection.borrow_mut() = Some(Sel::Vault(id.to_string()));
        self.refresh_vaults();
    }

    pub fn browser(&self, id: &str) -> Option<Rc<browser::Browser>> {
        self.browsers.borrow().get(id).cloned()
    }
}
