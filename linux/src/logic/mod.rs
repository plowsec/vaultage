//! Everything the GUI does that isn't drawing: vault list, sessions, file operations, sync status
//! texts, lock policy, preferences. No GTK here, so `vaultage-gui-selftest` drives the same code.
//! Every `Backend` method blocks (crypto, disk, network): call it off the GTK main thread.

pub mod policy;
pub mod prefs;
pub mod preview;
pub mod text;

use std::cmp::Ordering;
use std::path::{Path, PathBuf};

use vaultage_core::header::SlotKind;
use vaultage_core::invite::InviteStatus;
use vaultage_core::manager::{Activity, ImportReport, Manager, SyncStatus, VaultInfo};
use vaultage_core::model::{basename, join, parent, EntryId};
use vaultage_core::proto::UsageResp;
use vaultage_core::vault::{Item, Summary, TrashItem, Version};
use zeroize::{Zeroize, Zeroizing};

pub use text::{UiError, R};

/// Passphrase, recovery key or invite bytes; wiped on drop. Build it straight from the entry's
/// text and clear the entry.
pub struct Secret(Zeroizing<Vec<u8>>);

impl Secret {
    pub fn new(text: &str) -> Secret {
        Secret(Zeroizing::new(text.as_bytes().to_vec()))
    }
    /// Trimmed (recovery keys and invites are pasted with stray whitespace).
    pub fn trimmed(text: &str) -> Secret {
        Secret::new(text.trim())
    }
    pub fn bytes(&self) -> &[u8] {
        &self.0
    }
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
    pub fn as_str(&self) -> &str {
        std::str::from_utf8(&self.0).unwrap_or("")
    }
}

/// A vault's live state, polled about once a second.
#[derive(Clone, Debug)]
pub struct VaultStatus {
    pub sync: SyncStatus,
    pub summary: Summary,
    pub generation: u64,
    pub conflicts: Vec<String>,
    pub activity: Option<Activity>,
    pub rotation_pending: bool,
    pub epoch: u32,
    pub synced: bool,
}

impl VaultStatus {
    pub fn rekeyed(&self) -> bool {
        self.sync.state == "rekeyed"
    }
    pub fn integrity_problem(&self) -> Option<&str> {
        self.sync.error.as_deref().filter(|e| e.starts_with("integrity"))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tone {
    Normal,
    Warning,
    Error,
}

/// The status bar's sync line.
#[derive(Debug, Clone, PartialEq)]
pub struct SyncLine {
    pub icon: &'static str,
    pub text: String,
    pub tone: Tone,
    pub spinning: bool,
    /// Offer "Retry".
    pub retry: bool,
    /// Offer "Enter New Key…".
    pub rekeyed: bool,
}

/// Same states and wording as the macOS status bar.
pub fn sync_line(st: &VaultStatus) -> SyncLine {
    let pending = st.summary.pending;
    let waiting = format!("{} waiting", text::count(pending, "change"));
    let line = |icon, text: String, tone| SyncLine { icon, text, tone, spinning: false, retry: false, rekeyed: false };
    match st.sync.state.as_str() {
        "local" => line("drive-harddisk-symbolic", "Local vault — not synced".into(), Tone::Normal),
        "syncing" => SyncLine { spinning: true, ..line("emblem-synchronizing-symbolic", if pending > 0 { format!("Syncing · {waiting}") } else { "Syncing…".into() }, Tone::Normal) },
        "paused" => line("media-playback-pause-symbolic", "Sync paused".into(), Tone::Normal),
        "offline" => SyncLine {
            retry: true,
            ..line("network-offline-symbolic", if pending > 0 { format!("{waiting} — server unreachable, will retry") } else { "Offline — server unreachable, will retry".into() }, Tone::Warning)
        },
        "error" => SyncLine { retry: true, ..line("dialog-error-symbolic", format!("Sync error: {}", text::readable_sync(st.sync.error.as_deref().unwrap_or("unknown"))), Tone::Error) },
        "rekeyed" => SyncLine { rekeyed: true, ..line("dialog-password-symbolic", "Keys rotated on another device — enter the new key to sync".into(), Tone::Warning) },
        _ => {
            if st.sync.last_ok_ms == 0 {
                line("emblem-synchronizing-symbolic", "Waiting for first sync…".into(), Tone::Normal)
            } else if let Some(e) = &st.sync.error {
                line("dialog-warning-symbolic", format!("Synced {} with problems: {}", text::short_time(st.sync.last_ok_ms), text::readable_sync(e)), Tone::Warning)
            } else if pending > 0 {
                line("send-to-symbolic", format!("{waiting} to upload"), Tone::Normal)
            } else {
                line("emblem-ok-symbolic", format!("Up to date · synced {}", text::short_time(st.sync.last_ok_ms)), Tone::Normal)
            }
        }
    }
}

/// "12 files · 3.4 MB · 2 in Trash"
pub fn summary_line(s: &Summary, trash: usize) -> String {
    let mut t = format!("{} · {}", text::count(s.files, "file"), text::bytes(s.bytes));
    if trash > 0 {
        t += &format!(" · {trash} in Trash");
    }
    t
}

// ---- sorting & navigation ----

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SortKey {
    Name,
    Size,
    Modified,
}

/// "file2" before "file10", case-insensitive.
pub fn natural_cmp(a: &str, b: &str) -> Ordering {
    let (mut x, mut y) = (a.chars().peekable(), b.chars().peekable());
    loop {
        match (x.peek().copied(), y.peek().copied()) {
            (None, None) => return a.cmp(b),
            (None, _) => return Ordering::Less,
            (_, None) => return Ordering::Greater,
            (Some(c), Some(d)) if c.is_ascii_digit() && d.is_ascii_digit() => {
                let mut na = String::new();
                while let Some(c) = x.peek().copied().filter(char::is_ascii_digit) {
                    na.push(c);
                    x.next();
                }
                let mut nb = String::new();
                while let Some(d) = y.peek().copied().filter(char::is_ascii_digit) {
                    nb.push(d);
                    y.next();
                }
                let (ta, tb) = (na.trim_start_matches('0'), nb.trim_start_matches('0'));
                let o = ta.len().cmp(&tb.len()).then_with(|| ta.cmp(tb));
                if o != Ordering::Equal {
                    return o;
                }
            }
            (Some(c), Some(d)) => {
                let o = c.to_lowercase().cmp(d.to_lowercase());
                if o != Ordering::Equal {
                    return o;
                }
                x.next();
                y.next();
            }
        }
    }
}

/// Folders first, then by `key`; ties by name.
pub fn sort_items(items: &mut [Item], key: SortKey, ascending: bool) {
    items.sort_by(|a, b| {
        if a.is_dir != b.is_dir {
            return b.is_dir.cmp(&a.is_dir);
        }
        let name = natural_cmp(&a.name, &b.name);
        let o = match key {
            SortKey::Name => name,
            SortKey::Size => a.size.cmp(&b.size).then(name),
            SortKey::Modified => a.mtime.cmp(&b.mtime).then(name),
        };
        if ascending { o } else { o.reverse() }
    });
}

/// Folder history of one browser.
#[derive(Debug, Default, Clone)]
pub struct Nav {
    pub path: String,
    back: Vec<String>,
    fwd: Vec<String>,
}

impl Nav {
    pub fn go(&mut self, p: &str) {
        if p == self.path {
            return;
        }
        self.back.push(std::mem::replace(&mut self.path, p.to_string()));
        self.fwd.clear();
    }
    pub fn back(&mut self) -> bool {
        match self.back.pop() {
            Some(p) => {
                self.fwd.push(std::mem::replace(&mut self.path, p));
                true
            }
            None => false,
        }
    }
    pub fn forward(&mut self) -> bool {
        match self.fwd.pop() {
            Some(p) => {
                self.back.push(std::mem::replace(&mut self.path, p));
                true
            }
            None => false,
        }
    }
    /// Go to the parent folder; returns the folder we came from (to select it).
    pub fn up(&mut self) -> Option<String> {
        if self.path.is_empty() {
            return None;
        }
        let child = self.path.clone();
        self.go(&parent(&child).to_string());
        Some(child)
    }
    pub fn can_back(&self) -> bool {
        !self.back.is_empty()
    }
    pub fn can_forward(&self) -> bool {
        !self.fwd.is_empty()
    }
    /// (label, path) for each breadcrumb, root first.
    pub fn crumbs(&self, root: &str) -> Vec<(String, String)> {
        let mut out = vec![(root.to_string(), String::new())];
        let mut acc = String::new();
        for c in self.path.split('/').filter(|c| !c.is_empty()) {
            acc = join(&acc, c);
            out.push((c.to_string(), acc.clone()));
        }
        out
    }
}

/// Synced vaults first, then local; each by name.
pub fn sorted_vaults(mut v: Vec<VaultInfo>) -> Vec<VaultInfo> {
    v.sort_by(|a, b| b.remote.is_some().cmp(&a.remote.is_some()).then_with(|| natural_cmp(&a.name, &b.name)));
    v
}

pub fn has_passphrase(v: &VaultInfo) -> bool {
    v.slots.iter().any(|s| s.kind == SlotKind::Passphrase)
}

/// Text of an import's result banner. (text, needs attention)
pub fn import_summary(rep: &ImportReport, moved: bool) -> (String, bool) {
    if rep.files == 0 && rep.skipped.is_empty() {
        return ("Nothing to add.".into(), false);
    }
    let mut t = format!("{} {} ({})", if moved { "Moved" } else { "Encrypted" }, text::count(rep.files, "file"), text::bytes(rep.bytes));
    if moved && rep.sources_deleted > 0 {
        t += " · originals removed";
    }
    if !rep.skipped.is_empty() {
        t += &format!(" · {} skipped", rep.skipped.len());
    }
    (t, !rep.skipped.is_empty())
}

pub struct Created {
    pub id: String,
    pub recovery: Zeroizing<String>,
    /// The vault exists, but something optional failed (e.g. adding the passphrase).
    pub warning: Option<String>,
}

// Debug without the secrets.
impl std::fmt::Debug for Created {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Created({})", self.id)
    }
}

impl std::fmt::Debug for Joined {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Joined({})", self.id)
    }
}

pub struct Joined {
    pub id: String,
    /// One-time invite: this member's own recovery key. Show once.
    pub recovery: Option<Zeroizing<String>>,
}

/// The GUI's handle on the core. Thread-safe; share as `Arc<Backend>`.
pub struct Backend {
    pub m: Manager,
    pub home: PathBuf,
}

impl Backend {
    /// Opens the state dir (`default_home()` unless given) with background sync on.
    pub fn open(home: Option<PathBuf>) -> R<Backend> {
        let home = home.unwrap_or_else(vaultage_core::manager::default_home);
        Ok(Backend { m: Manager::new(home.clone(), true)?, home })
    }

    pub fn vaults(&self) -> Vec<VaultInfo> {
        sorted_vaults(self.m.list())
    }

    pub fn vault(&self, id: &str) -> Option<VaultInfo> {
        self.m.list().into_iter().find(|v| v.id == id)
    }

    pub fn device_name(&self) -> String {
        self.m.device().name
    }

    // ---- vaults ----

    /// New vault, unlocked. `remote` = (server URL, enrollment token). A passphrase slot is added
    /// if given; the recovery key must be shown whatever happens after the vault exists.
    pub fn create(&self, name: &str, remote: Option<(&str, &Secret)>, passphrase: Option<&Secret>) -> R<Created> {
        if name.trim().is_empty() {
            return Err(UiError::invalid("Enter a name for the vault."));
        }
        if let Some((url, _)) = remote {
            if let Some(p) = text::server_url_problem(url) {
                return Err(UiError::invalid(p));
            }
        }
        let (id, recovery) = self.m.create(name, remote.map(|(u, t)| (u.trim(), t.as_str())))?;
        let recovery = Zeroizing::new(recovery);
        let mut warning = None;
        if let Some(p) = passphrase.filter(|p| !p.is_empty()) {
            if let Err(e) = self.add_passphrase(&id, p) {
                warning = Some(format!("The passphrase couldn’t be added ({}). Add one later in Vault Settings.", UiError::from(e).text()));
            }
        }
        Ok(Created { id, recovery, warning })
    }

    /// Add a vault from a server with a passphrase or recovery key.
    pub fn join(&self, name: &str, url: &str, vault_id: &str, kind: SlotKind, secret: &Secret) -> R<String> {
        if let Some(p) = text::server_url_problem(url).or_else(|| text::vault_id_problem(vault_id)) {
            return Err(UiError::invalid(p));
        }
        self.m.join(name, url.trim(), vault_id, kind, secret.bytes()).map_err(|e| {
            let e = UiError::from(e);
            if e.is_wrong_secret() {
                UiError::invalid(if kind == SlotKind::Recovery { "That recovery key doesn’t open this vault." } else { "That passphrase doesn’t open this vault." })
            } else {
                e
            }
        })
    }

    pub fn join_invite(&self, name: &str, code: &Secret) -> R<Joined> {
        if let Some(p) = text::invite_line_problem(code.as_str()) {
            return Err(UiError::invalid(p));
        }
        match self.m.join_invite(name, code.as_str()) {
            Ok((id, recovery)) => Ok(Joined { id, recovery: recovery.map(Zeroizing::new) }),
            Err(e) => {
                let e = UiError::from(e);
                if e.is_wrong_secret() {
                    return Err(UiError::invalid("That invite doesn’t open the vault. It may have been removed, or the keys were rotated."));
                }
                Err(e.invite_problem().map(UiError::invalid).unwrap_or(e))
            }
        }
    }

    pub fn unlock(&self, id: &str, kind: SlotKind, secret: &Secret) -> R<()> {
        Ok(self.m.unlock(id, kind, None, secret.bytes())?)
    }

    pub fn lock(&self, id: &str) {
        self.m.lock(id)
    }

    pub fn lock_all(&self) {
        self.m.lock_all()
    }

    pub fn unlocked_count(&self) -> usize {
        self.m.list().iter().filter(|v| v.unlocked).count()
    }

    /// Remove from the list; returns the encrypted folder, which stays on disk.
    pub fn forget(&self, id: &str) -> R<PathBuf> {
        Ok(self.m.forget(id)?)
    }

    pub fn rename_vault(&self, id: &str, name: &str) -> R<()> {
        Ok(self.m.rename_vault(id, name)?)
    }

    pub fn add_passphrase(&self, id: &str, p: &Secret) -> R<String> {
        if p.is_empty() {
            return Err(UiError::invalid("Enter a passphrase."));
        }
        Ok(self.m.add_slot(id, SlotKind::Passphrase, "Passphrase", p.bytes(), serde_json::Value::Null, None)?)
    }

    pub fn remove_slot(&self, id: &str, slot: &str) -> R<()> {
        Ok(self.m.remove_slot(id, slot)?)
    }

    pub fn status(&self, id: &str) -> R<VaultStatus> {
        let ov = self.m.get(id)?;
        let sync = ov.status();
        let activity = ov.activity();
        let v = ov.v();
        Ok(VaultStatus {
            sync,
            summary: v.summary(),
            generation: v.generation,
            conflicts: v.conflicts.clone(),
            activity,
            rotation_pending: v.rotation_pending(),
            epoch: v.header.epoch(),
            synced: v.synced(),
        })
    }

    pub fn sync_now(&self, id: &str) -> R<()> {
        self.m.get(id)?.wake();
        Ok(())
    }

    /// One sync round on this thread (tests).
    pub fn sync_blocking(&self, id: &str) -> R<()> {
        self.m.get(id)?.sync_blocking()?;
        Ok(())
    }

    pub fn dismiss_conflicts(&self, id: &str) -> R<()> {
        self.m.get(id)?.v().conflicts.clear();
        Ok(())
    }

    // ---- files ----

    pub fn list(&self, id: &str, path: &str) -> R<(Vec<Item>, u64)> {
        let ov = self.m.get(id)?;
        let v = ov.v();
        Ok((v.list(path)?, v.generation))
    }

    pub fn search(&self, id: &str, q: &str) -> R<Vec<Item>> {
        Ok(self.m.get(id)?.v().search(q.trim()))
    }

    /// Every folder path in the vault, sorted ("" = top level is not included).
    pub fn folders(&self, id: &str) -> R<Vec<String>> {
        let ov = self.m.get(id)?;
        let v = ov.v();
        let mut set = std::collections::BTreeSet::new();
        for m in v.live() {
            let mut p = if m.kind == vaultage_core::model::Kind::Dir { m.path.as_str() } else { parent(&m.path) };
            while !p.is_empty() && set.insert(p.to_string()) {
                p = parent(p);
            }
        }
        let mut out: Vec<String> = set.into_iter().collect();
        out.sort_by(|a, b| natural_cmp(a, b));
        Ok(out)
    }

    /// "untitled folder", "untitled folder 2", … not yet used in `dir`.
    pub fn free_folder_name(&self, id: &str, dir: &str) -> R<String> {
        let (items, _) = self.list(id, dir)?;
        let mut name = "untitled folder".to_string();
        let mut n = 2;
        while items.iter().any(|i| i.name == name) {
            name = format!("untitled folder {n}");
            n += 1;
        }
        Ok(name)
    }

    pub fn mkdir(&self, id: &str, dir: &str, name: &str) -> R<String> {
        if let Some(p) = text::name_problem(name) {
            return Err(UiError::invalid(p));
        }
        let path = join(dir, name.trim());
        let ov = self.m.get(id)?;
        {
            let mut v = ov.v();
            if v.find(&path).is_some() || v.is_dir(&path) {
                return Err(UiError { code: "exists", message: format!("already exists: {}", name.trim()) });
            }
            v.mkdir(&path)?;
        }
        ov.wake();
        Ok(path)
    }

    /// Rename in place; returns the new path.
    pub fn rename(&self, id: &str, path: &str, new_name: &str) -> R<String> {
        if let Some(p) = text::name_problem(new_name) {
            return Err(UiError::invalid(p));
        }
        let to = join(parent(path), new_name.trim());
        if to == path {
            return Ok(to);
        }
        let ov = self.m.get(id)?;
        ov.v().rename(path, &to)?;
        ov.wake();
        Ok(to)
    }

    /// Move items into `dir`. Skips moves onto themselves or into their own subfolder.
    /// Stops at the first error; returns the new paths of what moved.
    pub fn move_to(&self, id: &str, paths: &[String], dir: &str) -> (Vec<String>, Option<UiError>) {
        let ov = match self.m.get(id) {
            Ok(ov) => ov,
            Err(e) => return (vec![], Some(e.into())),
        };
        let mut moved = vec![];
        for p in paths {
            let to = join(dir, basename(p));
            if to == *p || dir == p || dir.starts_with(&format!("{p}/")) {
                continue;
            }
            let res = ov.v().rename(p, &to);
            match res {
                Ok(_) => moved.push(to),
                Err(e) => {
                    ov.wake();
                    return (moved, Some(e.into()));
                }
            }
        }
        ov.wake();
        (moved, None)
    }

    /// To the vault's Trash. Returns how many entries were deleted.
    pub fn delete(&self, id: &str, paths: &[String]) -> R<usize> {
        let ov = self.m.get(id)?;
        let mut n = 0;
        for p in paths {
            let r = ov.v().delete(p);
            n += r?;
        }
        ov.wake();
        Ok(n)
    }

    pub fn import(&self, id: &str, sources: &[PathBuf], dest: &str, move_in: bool) -> R<ImportReport> {
        Ok(self.m.import(id, sources, dest, move_in)?)
    }

    /// Decrypt to `dest` (plaintext on disk). `remove` = move out of the vault.
    pub fn export(&self, id: &str, paths: &[String], dest: &Path, remove: bool) -> R<Vec<PathBuf>> {
        let out = self.m.export(id, paths, dest, remove)?;
        if remove {
            self.m.get(id)?.wake();
        }
        Ok(out)
    }

    /// Decrypt one file (or revision) into memory; wiped on drop.
    pub fn read(&self, id: &str, entry: &str, rev: Option<u64>, max: u64) -> R<Zeroizing<Vec<u8>>> {
        Ok(Zeroizing::new(self.m.read(id, &EntryId::parse(entry)?, rev, max)?))
    }

    pub fn versions(&self, id: &str, entry: &str) -> R<Vec<Version>> {
        Ok(self.m.get(id)?.v().versions(&EntryId::parse(entry)?)?)
    }

    /// Restore a revision (None = undelete the latest). Returns the path it landed at.
    pub fn restore(&self, id: &str, entry: &str, rev: Option<u64>) -> R<String> {
        let ov = self.m.get(id)?;
        let p = ov.v().restore(&EntryId::parse(entry)?, rev)?;
        ov.wake();
        Ok(p)
    }

    pub fn trash(&self, id: &str) -> R<Vec<TrashItem>> {
        let mut t = self.m.get(id)?.v().trash();
        t.sort_by(|a, b| b.deleted_ts.cmp(&a.deleted_ts));
        Ok(t)
    }

    pub fn purge(&self, id: &str, entries: &[String]) -> R<usize> {
        let ids = entries.iter().map(|e| EntryId::parse(e)).collect::<vaultage_core::Result<Vec<_>>>()?;
        let ov = self.m.get(id)?;
        let n = ov.v().purge(&ids)?;
        ov.wake();
        Ok(n)
    }

    pub fn empty_trash(&self, id: &str) -> R<usize> {
        let ov = self.m.get(id)?;
        let n = ov.v().empty_trash()?;
        ov.wake();
        Ok(n)
    }

    pub fn prune_versions(&self, id: &str, entry: &str) -> R<()> {
        let ov = self.m.get(id)?;
        ov.v().prune_versions(&EntryId::parse(entry)?)?;
        ov.wake();
        Ok(())
    }

    // ---- sync settings ----

    pub fn attach(&self, id: &str, url: &str, token: &Secret) -> R<()> {
        if let Some(p) = text::server_url_problem(url) {
            return Err(UiError::invalid(p));
        }
        Ok(self.m.attach(id, url.trim(), token.as_str())?)
    }

    pub fn usage(&self, id: &str) -> R<UsageResp> {
        Ok(self.m.usage(id)?)
    }

    /// Step 1: new keys staged, nothing changes yet. Returns the new recovery key.
    pub fn rotate_prepare(&self, id: &str, passphrase: Option<&Secret>) -> R<Zeroizing<String>> {
        Ok(Zeroizing::new(self.m.rotate_prepare(id, passphrase.filter(|p| !p.is_empty()).map(|p| p.bytes()), None)?))
    }

    pub fn rotate_commit(&self, id: &str) -> R<()> {
        Ok(self.m.rotate_commit(id)?)
    }

    pub fn rotate_cancel(&self, id: &str) -> R<()> {
        Ok(self.m.rotate_cancel(id)?)
    }

    /// After `status.rekeyed()`: take over the rotated keys with the NEW secret.
    pub fn adopt_rekey(&self, id: &str, kind: SlotKind, secret: &Secret) -> R<()> {
        self.m.adopt_rekey(id, kind, secret.bytes()).map_err(|e| {
            let e = UiError::from(e);
            if e.is_wrong_secret() {
                UiError::invalid(if kind == SlotKind::Recovery { "That recovery key doesn’t open the rotated vault." } else { "That passphrase doesn’t open the rotated vault." })
            } else {
                e
            }
        })
    }

    /// One-time invite line (24 h).
    pub fn invite(&self, id: &str, label: &str) -> R<Zeroizing<String>> {
        Ok(Zeroizing::new(self.m.invite(id, label, None)?))
    }

    pub fn invites(&self, id: &str) -> R<Vec<InviteStatus>> {
        Ok(self.m.invites(id)?)
    }

    pub fn revoke_invite(&self, id: &str, invite: &str) -> R<()> {
        Ok(self.m.revoke_invite(id, invite)?)
    }

    /// Pinned certificate (PEM) for a server, if any.
    pub fn pin(&self, url: &str) -> Option<String> {
        let t = self.m.trust();
        let u = url.trim().trim_end_matches('/');
        t.get(u).cloned()
    }

    pub fn set_pin(&self, url: &str, pem: Option<&str>) -> R<()> {
        Ok(self.m.set_trust(url, pem)?)
    }
}

/// Status line for an invite in the list.
pub fn invite_state(i: &InviteStatus) -> String {
    match i.state.as_str() {
        "waiting" => format!("Not used yet · expires {}", text::date(i.expires)),
        "used" => format!("Used {}", text::date(i.claimed.unwrap_or(i.created))),
        "revoked" => format!("Revoked {}", text::date(i.revoked.unwrap_or(i.created))),
        _ => format!("Expired unused {}", text::date(i.expires)),
    }
}

/// Recovery key in groups for display: "ABCDE-FGHIJ-…" → lines of 4 groups.
pub fn key_groups(key: &str) -> String {
    let g: Vec<&str> = key.split('-').collect();
    g.chunks(4).map(|c| c.join("  ")).collect::<Vec<_>>().join("\n")
}

/// QR modules for a text (true = dark), with its size.
pub fn qr(text: &str) -> Option<(i32, Vec<bool>)> {
    let q = qrcodegen::QrCode::encode_text(text, qrcodegen::QrCodeEcc::Medium).ok()?;
    let n = q.size();
    let mut v = Vec::with_capacity((n * n) as usize);
    for y in 0..n {
        for x in 0..n {
            v.push(q.get_module(x, y));
        }
    }
    Some((n, v))
}

/// Wipe a String in place (text taken out of an entry).
pub fn wipe(s: &mut String) {
    s.zeroize();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nav_and_sort() {
        let mut n = Nav::default();
        n.go("a");
        n.go("a/b");
        assert_eq!(n.up(), Some("a/b".into()));
        assert_eq!(n.path, "a");
        assert!(n.back());
        assert_eq!(n.path, "a/b");
        assert!(n.forward());
        assert_eq!(n.crumbs("V").len(), 2);
        assert_eq!(natural_cmp("file2", "file10"), Ordering::Less);
        assert_eq!(natural_cmp("B", "a"), Ordering::Greater);
    }
}
