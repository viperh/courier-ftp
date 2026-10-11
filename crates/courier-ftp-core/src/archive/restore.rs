//! Bringing an [`Archive`] into this setup (T73): vault items through
//! [`ItemVault`], the config into `config.json`, the queue as new items.
//!
//! Items keep their ids and are merged field by field with what the vault
//! holds (T81's last-writer-wins merge), so restoring the same backup twice
//! changes nothing and a newer local edit is never overwritten by an older
//! backup. Sites can instead go into a new folder: they then get new ids
//! (their bookmarks and queue items follow), so nothing already stored is
//! touched.
//!
//! Conflicts are reported, never resolved silently:
//! - a site or folder whose name is taken in its folder is renamed
//!   `name (2)`;
//! - a global bookmark whose name is taken is skipped;
//! - a host key or certificate for a server that already has a different
//!   one stored is skipped (the stored one stays trusted);
//! - an item the vault refuses (read-only, another kind under the same id)
//!   is skipped.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::Path;

use ciborium::Value;
use serde_json::{Map, Value as Json};

use super::{Archive, Section, SettingsDoc};
use crate::model::item::{ItemBody, ItemId, ItemKind, SiteFolder, merge};
use crate::queue::{ExportError, ImportReport, QueueServer, import_json};
use crate::settings::{LoadReport, Settings, merge_values, read_user_config, write_user_config};
use crate::vault::backup::BackupItem;
use crate::vault::{ItemVault, ItemVaultExt, ItemWrite, VaultError};

/// How imported settings meet the current ones.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SettingsMode {
    /// Imported values win; settings the import doesn't mention stay.
    Merge,
    /// The imported config replaces the current one (what it doesn't
    /// mention goes back to the defaults).
    Replace,
}

/// Where imported sites go.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SitesMode {
    /// Restore: same items, merged with what is stored (newer changes win).
    Merge,
    /// Into a new top-level folder of this name (made unique), as new items.
    NewFolder(String),
}

/// What to import.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ImportChoice {
    /// The config (and the proxy credentials it uses).
    pub settings: Option<SettingsMode>,
    /// Sites, folders, bookmarks, SSH keys.
    pub sites: Option<SitesMode>,
    /// Connection history.
    pub history: bool,
    /// Trusted host keys and certificates.
    pub trust: bool,
    /// Queue items.
    pub queue: bool,
}

impl ImportChoice {
    /// Everything `archive` holds: settings replaced, items merged (a full
    /// restore).
    pub fn everything(archive: &Archive) -> Self {
        Self {
            settings: archive
                .has(Section::Settings)
                .then_some(SettingsMode::Replace),
            sites: archive.has(Section::Sites).then_some(SitesMode::Merge),
            history: archive.has(Section::History),
            trust: archive.has(Section::Trust),
            queue: archive.has(Section::Queue),
        }
    }

    /// Whether anything needs the vault.
    pub fn needs_vault(&self, archive: &Archive) -> bool {
        self.sites.is_some()
            || self.history
            || self.trust
            || (self.settings.is_some() && !archive.items_of(Section::Settings).is_empty())
    }
}

/// What [`restore_items`] did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RestoreReport {
    /// New items.
    pub added: usize,
    /// Items that existed and changed.
    pub updated: usize,
    /// Items that were already up to date.
    pub unchanged: usize,
    /// Conflicts and skipped items, one line each.
    pub conflicts: Vec<String>,
    /// The folder sites went into ([`SitesMode::NewFolder`]).
    pub folder: Option<ItemId>,
    /// Old → new ids of sites and folders imported as new items.
    pub new_ids: HashMap<ItemId, ItemId>,
}

impl RestoreReport {
    /// One line, e.g. "5 added, 2 updated, 1 unchanged, 1 conflict".
    pub fn summary(&self) -> String {
        let mut parts = vec![
            format!("{} added", self.added),
            format!("{} updated", self.updated),
            format!("{} unchanged", self.unchanged),
        ];
        if !self.conflicts.is_empty() {
            parts.push(super::plural(self.conflicts.len(), "conflict", "conflicts"));
        }
        parts.join(", ")
    }
}

fn text_of(body: &ItemBody, key: &str) -> Option<String> {
    body.get(key).and_then(Value::as_text).map(str::to_owned)
}

fn id_of(body: &ItemBody, key: &str) -> Option<ItemId> {
    body.get(key).and_then(ItemId::from_value)
}

fn int_of(body: &ItemBody, key: &str) -> Option<i64> {
    body.get(key)
        .and_then(Value::as_integer)
        .and_then(|i| i64::try_from(i).ok())
}

fn label(body: &ItemBody) -> String {
    let name = text_of(body, "name")
        .or_else(|| text_of(body, "label"))
        .or_else(|| text_of(body, "host"))
        .unwrap_or_default();
    format!("{} “{name}”", body.kind)
}

/// How one write went.
enum Put {
    Added,
    Updated,
    Unchanged,
}

/// Writes `body` to item `id`, merged with what is stored, then sets
/// `edits` with fresh stamps.
async fn put_merged(
    vault: &dyn ItemVault,
    id: ItemId,
    body: ItemBody,
    edits: Vec<(&'static str, Value)>,
) -> Result<Put, VaultError> {
    let existed = vault.get(id).await?.is_some();
    let kind = body.kind;
    let changed = vault
        .put(ItemWrite {
            id,
            kind,
            vault: None,
            edit: Box::new(move |current, clock, device| {
                // Keep the local clock ahead of every restored stamp, so a
                // later local edit wins over them.
                for stamped in body.fields.values() {
                    let _ = clock.observe_stamp(stamped);
                }
                let mut merged = merge(current, &body).body;
                for (key, value) in edits {
                    merged.set(key, value, clock, device);
                }
                *current = merged;
            }),
        })
        .await?;
    Ok(match (changed, existed) {
        (false, _) => Put::Unchanged,
        (true, true) => Put::Updated,
        (true, false) => Put::Added,
    })
}

/// Restores the vault items `choice` asks for from `archive`.
///
/// # Errors
/// [`VaultError::Locked`] (or another error that stops every write);
/// errors on single items are reported as conflicts instead.
pub async fn restore_items(
    vault: &dyn ItemVault,
    archive: &Archive,
    choice: &ImportChoice,
) -> Result<RestoreReport, VaultError> {
    let mut r = Restorer {
        vault,
        report: RestoreReport::default(),
    };
    if choice.settings.is_some() {
        for item in archive.items_of(Section::Settings) {
            r.merge(item, Vec::new()).await?;
        }
    }
    match &choice.sites {
        Some(SitesMode::Merge) => r.sites_merged(archive.items_of(Section::Sites)).await?,
        Some(SitesMode::NewFolder(name)) => {
            r.sites_in_folder(archive.items_of(Section::Sites), name)
                .await?;
        }
        None => {}
    }
    if choice.history {
        for item in archive.items_of(Section::History) {
            r.merge(item, Vec::new()).await?;
        }
    }
    if choice.trust {
        r.trust(archive.items_of(Section::Trust)).await?;
    }
    Ok(r.report)
}

struct Restorer<'a> {
    vault: &'a dyn ItemVault,
    report: RestoreReport,
}

/// Whether an error stops the whole restore (rather than one item).
fn fatal(e: &VaultError) -> bool {
    matches!(
        e,
        VaultError::Locked | VaultError::Busy | VaultError::Storage(_)
    )
}

impl Restorer<'_> {
    async fn write(
        &mut self,
        id: ItemId,
        body: ItemBody,
        edits: Vec<(&'static str, Value)>,
    ) -> Result<(), VaultError> {
        let what = label(&body);
        match put_merged(self.vault, id, body, edits).await {
            Ok(Put::Added) => self.report.added += 1,
            Ok(Put::Updated) => self.report.updated += 1,
            Ok(Put::Unchanged) => self.report.unchanged += 1,
            Err(e) if fatal(&e) => return Err(e),
            Err(e) => self.report.conflicts.push(format!("{what}: skipped ({e})")),
        }
        Ok(())
    }

    async fn merge(
        &mut self,
        item: &BackupItem,
        edits: Vec<(&'static str, Value)>,
    ) -> Result<(), VaultError> {
        self.write(item.id, item.body.clone(), edits).await
    }

    /// Names taken in each folder (`None` = top level), from the vault.
    async fn taken_names(&self) -> Result<HashMap<Option<ItemId>, HashSet<String>>, VaultError> {
        let mut taken: HashMap<Option<ItemId>, HashSet<String>> = HashMap::new();
        for kind in [ItemKind::SiteFolder, ItemKind::Site] {
            for item in self.vault.list(kind).await? {
                if let Some(name) = text_of(&item.body, "name") {
                    taken
                        .entry(id_of(&item.body, "parent"))
                        .or_default()
                        .insert(name);
                }
            }
        }
        Ok(taken)
    }

    /// Lower-cased names of the global bookmarks.
    async fn global_bookmarks(&self) -> Result<HashSet<String>, VaultError> {
        Ok(self
            .vault
            .list(ItemKind::Bookmark)
            .await?
            .iter()
            .filter(|i| id_of(&i.body, "site_id").is_none())
            .filter_map(|i| text_of(&i.body, "name"))
            .map(|n| n.to_lowercase())
            .collect())
    }

    /// A global bookmark (`id`) unless its name is taken.
    async fn global_bookmark(
        &mut self,
        id: ItemId,
        body: ItemBody,
        globals: &mut HashSet<String>,
    ) -> Result<(), VaultError> {
        let name = text_of(&body, "name").unwrap_or_default();
        if !globals.insert(name.to_lowercase()) {
            self.report.conflicts.push(format!(
                "Bookmark “{name}”: a bookmark of that name exists; skipped"
            ));
            return Ok(());
        }
        self.write(id, body, Vec::new()).await
    }

    /// Restore: same ids, merged. A new site or folder whose name is taken
    /// in its folder is renamed.
    async fn sites_merged(&mut self, items: &[BackupItem]) -> Result<(), VaultError> {
        let mut taken = self.taken_names().await?;
        let mut globals = self.global_bookmarks().await?;
        for item in ordered(items) {
            let body = &item.body;
            match body.kind {
                ItemKind::SiteFolder | ItemKind::Site
                    if self.vault.get(item.id).await?.is_none() =>
                {
                    let name = text_of(body, "name").unwrap_or_default();
                    let names = taken.entry(id_of(body, "parent")).or_default();
                    let free = unique(names, &name);
                    names.insert(free.clone());
                    let mut edits = Vec::new();
                    if free != name {
                        self.report.conflicts.push(format!(
                            "{}: the name is taken in its folder; imported as “{free}”",
                            label(body)
                        ));
                        edits.push(("name", Value::Text(free)));
                    }
                    self.merge(item, edits).await?;
                }
                ItemKind::Bookmark
                    if id_of(body, "site_id").is_none()
                        && self.vault.get(item.id).await?.is_none() =>
                {
                    self.global_bookmark(item.id, body.clone(), &mut globals)
                        .await?;
                }
                _ => self.merge(item, Vec::new()).await?,
            }
        }
        Ok(())
    }

    /// Into a new top-level folder, as new items.
    async fn sites_in_folder(
        &mut self,
        items: &[BackupItem],
        name: &str,
    ) -> Result<(), VaultError> {
        let mut taken = self.taken_names().await?;
        let mut globals = self.global_bookmarks().await?;
        let folder_name = unique(taken.entry(None).or_default(), name);
        let folder = ItemId::new();
        self.vault
            .put_view(
                folder,
                None,
                SiteFolder {
                    name: folder_name,
                    parent: None,
                    read_only: false,
                },
            )
            .await?;
        self.report.added += 1;
        self.report.folder = Some(folder);
        let new_ids: HashMap<ItemId, ItemId> = items
            .iter()
            .filter(|i| matches!(i.body.kind, ItemKind::Site | ItemKind::SiteFolder))
            .map(|i| (i.id, ItemId::new()))
            .collect();
        self.report.new_ids.clone_from(&new_ids);
        for item in ordered(items) {
            let body = item.body.clone();
            match body.kind {
                ItemKind::SiteFolder | ItemKind::Site => {
                    let parent = id_of(&body, "parent")
                        .and_then(|p| new_ids.get(&p).copied())
                        .unwrap_or(folder);
                    let id = new_ids.get(&item.id).copied().unwrap_or_else(ItemId::new);
                    self.write(id, body, vec![("parent", Value::from(parent))])
                        .await?;
                }
                ItemKind::Bookmark => match id_of(&body, "site_id") {
                    Some(site) => match new_ids.get(&site) {
                        Some(new_site) => {
                            self.write(
                                ItemId::new(),
                                body,
                                vec![("site_id", Value::from(*new_site))],
                            )
                            .await?;
                        }
                        None => self.report.conflicts.push(format!(
                            "{}: its site isn't in the backup; skipped",
                            label(&body)
                        )),
                    },
                    None => {
                        self.global_bookmark(ItemId::new(), body, &mut globals)
                            .await?;
                    }
                },
                // SSH keys and credential overrides are referenced by id.
                _ => self.merge(item, Vec::new()).await?,
            }
        }
        Ok(())
    }

    /// Host keys and certificates, unless the server already has a
    /// different one.
    async fn trust(&mut self, items: &[BackupItem]) -> Result<(), VaultError> {
        type Key = (ItemKind, String, i64, String);
        let identity = |b: &ItemBody| -> Key {
            let extra = match b.kind {
                ItemKind::KnownHost => text_of(b, "key_type").unwrap_or_default(),
                _ => String::new(),
            };
            (
                b.kind,
                text_of(b, "host").unwrap_or_default().to_lowercase(),
                int_of(b, "port").unwrap_or_default(),
                extra,
            )
        };
        let material = |b: &ItemBody| -> Option<Value> {
            b.get(match b.kind {
                ItemKind::KnownHost => "public_key",
                _ => "der",
            })
            .cloned()
        };
        let mut stored: BTreeMap<Key, (ItemId, Option<Value>)> = BTreeMap::new();
        for kind in [ItemKind::KnownHost, ItemKind::TrustedCert] {
            for item in self.vault.list(kind).await? {
                stored.insert(identity(&item.body), (item.id, material(&item.body)));
            }
        }
        for item in items {
            let key = identity(&item.body);
            match stored.get(&key) {
                Some((id, _)) if *id == item.id => {}
                Some((_, m)) if *m == material(&item.body) => {
                    self.report.unchanged += 1;
                    continue;
                }
                Some(_) => {
                    let what = match item.body.kind {
                        ItemKind::KnownHost => "host key",
                        _ => "certificate",
                    };
                    self.report.conflicts.push(format!(
                        "{}:{}: a different {what} is already trusted; kept it",
                        key.1, key.2
                    ));
                    continue;
                }
                None => {}
            }
            stored.insert(key, (item.id, material(&item.body)));
            self.merge(item, Vec::new()).await?;
        }
        Ok(())
    }
}

/// Folders first (parents before children), then sites, then the rest, so
/// names are claimed top-down.
fn ordered(items: &[BackupItem]) -> Vec<&BackupItem> {
    let rank = |k: ItemKind| match k {
        ItemKind::SiteFolder => 0,
        ItemKind::Site => 1,
        _ => 2,
    };
    let mut out: Vec<&BackupItem> = items.iter().collect();
    out.sort_by_key(|i| rank(i.body.kind));
    out
}

/// `base`, or `base (2)`, `base (3)`… — the first not in `taken`.
fn unique(taken: &HashSet<String>, base: &str) -> String {
    if !taken.contains(base) {
        return base.to_owned();
    }
    (2..)
        .map(|n| format!("{base} ({n})"))
        .find(|n| !taken.contains(n))
        .unwrap_or_else(|| base.to_owned())
}

/// Applies an imported config: computes the new settings (leniently, like
/// loading: bad values become defaults and are reported) and, with
/// `config_dir`, writes them with the keybindings and styles to its
/// `config.json`. Keybindings and styles are read at start, so they apply
/// at the next start.
///
/// # Errors
/// When `config.json` can't be read or written.
pub fn apply_settings(
    doc: &SettingsDoc,
    mode: SettingsMode,
    current: &Settings,
    config_dir: Option<&Path>,
) -> crate::Result<(Settings, LoadReport)> {
    let empty = || Json::Object(Map::new());
    let imported = doc.settings.clone().unwrap_or_else(empty);
    let user = match mode {
        SettingsMode::Replace => imported,
        SettingsMode::Merge => merge_values(current.user_value()?.unwrap_or_else(empty), &imported),
    };
    let (settings, report) = Settings::from_value(&user);
    if let Some(dir) = config_dir.filter(|d| !d.as_os_str().is_empty()) {
        let mut file = read_user_config(dir)?;
        for (key, value) in [("keybindings", &doc.keybindings), ("styles", &doc.styles)] {
            let new = match (mode, value, file.remove(key)) {
                (_, Some(v), Some(old)) if mode == SettingsMode::Merge => {
                    Some(merge_values(old, v))
                }
                (_, Some(v), _) => Some(v.clone()),
                (SettingsMode::Merge, None, old) => old,
                (SettingsMode::Replace, None, _) => None,
            };
            if let Some(v) = new {
                file.insert(key.to_owned(), v);
            }
        }
        match settings.user_value()? {
            Some(v) => {
                file.insert("settings".to_owned(), v);
            }
            None => {
                file.remove("settings");
            }
        }
        write_user_config(dir, &file)?;
    }
    Ok((settings, report))
}

/// The queue items of `archive` to add, with sites imported into a new
/// folder pointing at their new ids; items of sites that `site_exists`
/// denies are dropped and counted. `None` when the archive has no queue.
///
/// # Errors
/// [`ExportError`] for a malformed or newer queue export.
pub fn queue_items(
    archive: &Archive,
    report: &RestoreReport,
    site_exists: impl Fn(ItemId) -> bool,
) -> Result<Option<ImportReport>, ExportError> {
    let Some(json) = &archive.queue else {
        return Ok(None);
    };
    let map = |id: ItemId| report.new_ids.get(&id).copied().unwrap_or(id);
    let mut out = import_json(json, |id| site_exists(map(id)))?;
    for item in &mut out.items {
        if let QueueServer::Site(id) = &mut item.server {
            *id = map(*id);
        }
    }
    Ok(Some(out))
}
