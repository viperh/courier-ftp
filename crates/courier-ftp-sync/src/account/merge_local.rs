//! Importing a local personal vault into the account's personal vault at
//! login: the dry-run duplicate preview and the id-remapping importer.
//!
//! * **Likely duplicates**: sites with the same protocol, host, port and
//!   user (host compared case-insensitively, a missing port is the
//!   protocol's default). Each gets a choice: keep both (default), keep
//!   local, keep account.
//! * **Import**: every live local item is re-created in the account vault
//!   with a **new** item id. All references between items (a site's
//!   `parent` folder and `logon.key_id`, a bookmark's site, a credential
//!   override's site, …) are rewritten through the id map. References are
//!   found structurally (any 16-byte value at any depth that names a local
//!   item), so new reference fields are covered without a list here.
//! * "Keep account" drops the local copy and points references to it at the
//!   account item; "keep local" writes the local values over the account
//!   item (fresh stamps, so they win the merge) and also remaps references.
//!
//! Adapted from sverb's `sverb-sync/src/account/merge_local.rs` (D13).

use std::collections::{BTreeMap, HashMap};

use courier_ftp_core::model::Protocol;
use courier_ftp_core::model::item::{DeviceId, HlcClock, ItemBody, ItemId, ItemKind, WireEnum};

/// What to do with one likely duplicate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DuplicateChoice {
    /// Import the local item as a new item next to the account's.
    #[default]
    KeepBoth,
    /// The local values replace the account item's.
    KeepLocal,
    /// The local item is dropped; the account item stays as it is.
    KeepAccount,
}

impl DuplicateChoice {
    /// The label used by the preview.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::KeepBoth => "keep both",
            Self::KeepLocal => "keep local",
            Self::KeepAccount => "keep account",
        }
    }
}

/// One likely duplicate in the preview.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DuplicateRow {
    /// The local item.
    pub local: ItemId,
    /// The account item it matches.
    pub account: ItemId,
    /// Their kind.
    pub kind: ItemKind,
    /// A display label (the local item's name).
    pub label: String,
    /// What matched, e.g. `sftp root@db.example.com:22`.
    pub matched: String,
    /// The user's choice.
    pub choice: DuplicateChoice,
}

/// The dry-run preview of an import.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ImportPreview {
    /// Live local items that will be imported as new items (duplicates
    /// excluded).
    pub new_items: usize,
    /// Likely duplicates, in local id order.
    pub duplicates: Vec<DuplicateRow>,
    /// Local tombstones, which are not imported.
    pub skipped_deleted: usize,
}

impl ImportPreview {
    /// Sets every duplicate's choice ("apply to all").
    pub fn set_all(&mut self, choice: DuplicateChoice) {
        for d in &mut self.duplicates {
            d.choice = choice;
        }
    }

    /// Sets the choice of the duplicate whose local item is `local`. Returns
    /// whether it exists.
    pub fn set(&mut self, local: ItemId, choice: DuplicateChoice) -> bool {
        self.duplicates
            .iter_mut()
            .find(|d| d.local == local)
            .map(|d| d.choice = choice)
            .is_some()
    }

    /// How many local items end up imported under new ids with the current
    /// choices.
    #[must_use]
    pub fn imported_count(&self) -> usize {
        self.new_items
            + self
                .duplicates
                .iter()
                .filter(|d| d.choice == DuplicateChoice::KeepBoth)
                .count()
    }
}

fn text<'a>(body: &'a ItemBody, field: &str) -> Option<&'a str> {
    body.get(field).and_then(|v| v.as_text())
}

/// The duplicate key of `body`, if its kind has one (sites only).
#[must_use]
pub fn dedupe_key(body: &ItemBody) -> Option<String> {
    if body.is_deleted() || body.kind != ItemKind::Site {
        return None;
    }
    let host = text(body, "host")?.trim().to_ascii_lowercase();
    if host.is_empty() {
        return None;
    }
    let protocol = text(body, "protocol").and_then(Protocol::from_wire)?;
    let port = body
        .get("port")
        .and_then(|v| v.as_integer())
        .and_then(|i| u16::try_from(i).ok())
        .unwrap_or_else(|| protocol.default_port());
    let user = text(body, "logon.user").unwrap_or("").trim();
    Some(format!("{} {user}@{host}:{port}", protocol.as_wire()))
}

fn label(body: &ItemBody, id: ItemId) -> String {
    text(body, "name")
        .filter(|s| !s.is_empty())
        .map_or_else(|| id.short(), ToOwned::to_owned)
}

/// Builds the preview of importing `local` into a vault holding `account`
/// (both decrypted).
#[must_use]
pub fn build_preview(
    local: &[(ItemId, ItemBody)],
    account: &[(ItemId, ItemBody)],
) -> ImportPreview {
    let mut by_key: HashMap<String, ItemId> = HashMap::new();
    for (id, body) in account {
        if let Some(k) = dedupe_key(body) {
            by_key.entry(k).or_insert(*id);
        }
    }
    let mut preview = ImportPreview::default();
    for (id, body) in local {
        if body.is_deleted() {
            preview.skipped_deleted += 1;
            continue;
        }
        match dedupe_key(body).and_then(|k| by_key.get(&k).map(|a| (k, *a))) {
            Some((matched, account)) => preview.duplicates.push(DuplicateRow {
                local: *id,
                account,
                kind: body.kind,
                label: label(body, *id),
                matched,
                choice: DuplicateChoice::default(),
            }),
            None => preview.new_items += 1,
        }
    }
    preview
}

/// Rewrites every id reference in `value` through `map`.
fn remap_value(value: &mut ciborium::Value, map: &HashMap<ItemId, ItemId>) -> bool {
    use ciborium::Value;
    match value {
        Value::Bytes(_) => match ItemId::from_value(value).and_then(|id| map.get(&id)) {
            Some(new) => {
                *value = Value::from(*new);
                true
            }
            None => false,
        },
        Value::Array(items) => items.iter_mut().fold(false, |c, v| remap_value(v, map) | c),
        Value::Map(entries) => entries.iter_mut().fold(false, |c, (k, v)| {
            remap_value(k, map) | remap_value(v, map) | c
        }),
        Value::Tag(_, inner) => remap_value(inner, map),
        _ => false,
    }
}

/// Rewrites the references of `body` through `map` (stamps are kept: the
/// imported item is new, so nothing merges against it). Returns whether
/// anything changed.
pub fn remap_body(body: &mut ItemBody, map: &HashMap<ItemId, ItemId>) -> bool {
    body.fields
        .values_mut()
        .fold(false, |c, f| remap_value(&mut f.value, map) | c)
}

/// One write of the import.
#[derive(Debug, Clone)]
pub struct PlannedWrite {
    /// The local item it comes from.
    pub from: ItemId,
    /// The id it is written under in the account vault (new, or the account
    /// item's for "keep local").
    pub to: ItemId,
    /// The body to seal.
    pub body: ItemBody,
}

/// The writes of an import (in local order) and the id map (local → account
/// vault) used for references and device-local rows.
#[derive(Debug, Clone, Default)]
pub struct ImportPlan {
    /// Items to write.
    pub writes: Vec<PlannedWrite>,
    /// Every local id that maps to an account-vault id.
    pub id_map: BTreeMap<ItemId, ItemId>,
}

/// Plans the import of `local` with the choices of `preview`. `account` are
/// the account items (needed for "keep local"); `clock`/`device` stamp the
/// fields written over an account item.
#[must_use]
pub fn plan_import(
    local: &[(ItemId, ItemBody)],
    account: &[(ItemId, ItemBody)],
    preview: &ImportPreview,
    clock: &mut HlcClock,
    device: DeviceId,
) -> ImportPlan {
    let dups: HashMap<ItemId, &DuplicateRow> =
        preview.duplicates.iter().map(|d| (d.local, d)).collect();
    let mut map: HashMap<ItemId, ItemId> = HashMap::new();
    for (id, body) in local {
        if body.is_deleted() {
            continue;
        }
        let to = match dups.get(id).map(|d| (d.choice, d.account)) {
            Some((DuplicateChoice::KeepAccount | DuplicateChoice::KeepLocal, acct)) => acct,
            _ => ItemId::new(),
        };
        map.insert(*id, to);
    }
    // Observe every stamp so the fresh ones below are newer.
    for (_, b) in local.iter().chain(account) {
        for s in b.fields.values() {
            let _ = clock.observe_stamp(s);
        }
    }
    let account_bodies: HashMap<ItemId, &ItemBody> = account.iter().map(|(i, b)| (*i, b)).collect();
    let mut writes = Vec::new();
    for (id, body) in local {
        let Some(&to) = map.get(id) else { continue };
        let choice = dups.get(id).map(|d| d.choice);
        let mut body = body.clone();
        remap_body(&mut body, &map);
        match choice {
            Some(DuplicateChoice::KeepAccount) => {}
            Some(DuplicateChoice::KeepLocal) => {
                let mut target = account_bodies.get(&to).map_or_else(
                    || ItemBody::new(body.kind, body.schema_version),
                    |b| (*b).clone(),
                );
                // Local values win: re-stamp every local field; account-only
                // fields are cleared.
                let stale: Vec<String> = target
                    .fields
                    .keys()
                    .filter(|k| !body.fields.contains_key(*k))
                    .cloned()
                    .collect();
                for k in stale {
                    target.unset(&k, clock, device);
                }
                for (k, v) in &body.fields {
                    if target.get(k) == Some(&v.value) {
                        continue;
                    }
                    target.set(k, v.value.clone(), clock, device);
                }
                writes.push(PlannedWrite {
                    from: *id,
                    to,
                    body: target,
                });
            }
            Some(DuplicateChoice::KeepBoth) | None => {
                writes.push(PlannedWrite {
                    from: *id,
                    to,
                    body,
                });
            }
        }
    }
    ImportPlan {
        writes,
        id_map: map.into_iter().collect(),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use courier_ftp_core::model::item::SystemClock;

    use super::*;

    fn site(
        clock: &mut HlcClock,
        dev: DeviceId,
        host: &str,
        user: &str,
        port: Option<u16>,
        parent: Option<ItemId>,
    ) -> ItemBody {
        let mut b = ItemBody::new(ItemKind::Site, 1);
        b.set("name", host, clock, dev);
        b.set("protocol", "sftp", clock, dev);
        b.set("host", host, clock, dev);
        b.set("logon.user", user, clock, dev);
        if let Some(p) = port {
            b.set("port", p, clock, dev);
        }
        if let Some(g) = parent {
            b.set("parent", g, clock, dev);
        }
        b
    }

    #[test]
    fn duplicates_and_remapping() {
        let mut clock = HlcClock::new(SystemClock);
        let dev = DeviceId::new();
        let folder = ItemId::new();
        let mut g = ItemBody::new(ItemKind::SiteFolder, 1);
        g.set("name", "prod", &mut clock, dev);
        let l1 = ItemId::new();
        let l2 = ItemId::new();
        let local = vec![
            (folder, g),
            (
                l1,
                site(
                    &mut clock,
                    dev,
                    "db.example.com",
                    "root",
                    None,
                    Some(folder),
                ),
            ),
            (
                l2,
                site(
                    &mut clock,
                    dev,
                    "web.example.com",
                    "deploy",
                    None,
                    Some(folder),
                ),
            ),
        ];
        let a1 = ItemId::new();
        // Same site: host case and the explicit default port don't matter.
        let account = vec![(
            a1,
            site(&mut clock, dev, "DB.example.com", "root", Some(22), None),
        )];
        let mut preview = build_preview(&local, &account);
        assert_eq!(preview.new_items, 2);
        assert_eq!(preview.duplicates.len(), 1);
        assert_eq!(preview.duplicates[0].account, a1);
        assert_eq!(preview.duplicates[0].matched, "sftp root@db.example.com:22");
        assert_eq!(preview.imported_count(), 3);
        preview.set_all(DuplicateChoice::KeepAccount);
        assert_eq!(preview.imported_count(), 2);
        let plan = plan_import(&local, &account, &preview, &mut clock, dev);
        assert_eq!(plan.writes.len(), 2);
        assert_eq!(plan.id_map[&l1], a1);
        let new_folder = plan.id_map[&folder];
        assert_ne!(new_folder, folder);
        let web = plan.writes.iter().find(|w| w.from == l2).unwrap();
        assert_ne!(web.to, l2);
        assert_eq!(
            web.body.get("parent"),
            Some(&ciborium::Value::from(new_folder))
        );

        preview.set_all(DuplicateChoice::KeepLocal);
        let plan = plan_import(&local, &account, &preview, &mut clock, dev);
        let over = plan.writes.iter().find(|w| w.from == l1).unwrap();
        assert_eq!(over.to, a1);
        assert_eq!(
            over.body.get("host"),
            Some(&ciborium::Value::from("db.example.com"))
        );
        // The account-only `port` field is cleared.
        assert_eq!(over.body.get("port"), None);
        assert_eq!(
            over.body.get("parent"),
            Some(&ciborium::Value::from(plan.id_map[&folder]))
        );
    }

    #[test]
    fn different_user_or_protocol_is_not_a_duplicate() {
        let mut clock = HlcClock::new(SystemClock);
        let dev = DeviceId::new();
        let mut ftp = site(&mut clock, dev, "h.example", "root", None, None);
        ftp.set("protocol", "ftp", &mut clock, dev);
        let local = vec![
            (
                ItemId::new(),
                site(&mut clock, dev, "h.example", "bob", None, None),
            ),
            (ItemId::new(), ftp),
        ];
        let account = vec![(
            ItemId::new(),
            site(&mut clock, dev, "h.example", "root", None, None),
        )];
        let preview = build_preview(&local, &account);
        assert!(preview.duplicates.is_empty());
        assert_eq!(preview.new_items, 2);
    }
}
